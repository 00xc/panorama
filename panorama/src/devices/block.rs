use super::block_backend::{DirtyFile, DirtyFileSnapshot};
use crate::defs::{BLK_SECTOR_SHIFT, QUEUE_MAX_SIZE};
use crate::Memory;
use crate::PanoramaError;

use event_manager::{
	EventManager, EventOps, EventSet, Events, MutEventSubscriber,
	RemoteEndpoint, SubscriberId,
};
use std::borrow::{Borrow, BorrowMut};
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use virtio_bindings::{
	virtio_blk::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO},
	virtio_config::{VIRTIO_F_IN_ORDER, VIRTIO_F_VERSION_1},
	virtio_ids::VIRTIO_ID_BLOCK,
	virtio_mmio::VIRTIO_MMIO_INT_VRING,
	virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use virtio_blk::request::Request;
use virtio_blk::stdio_executor::StdIoBackend;
use virtio_device::{
	VirtioConfig, VirtioDeviceActions, VirtioDeviceType,
	VirtioMmioDevice,
};
use virtio_queue::{
	DescriptorChain, Queue, QueueOwnedT, QueueState, QueueT,
};
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vmm_sys_util::eventfd::EventFd;

#[allow(dead_code)]
pub enum BlockType {
	Regular,
	Root,
}

/// A snapshot of the virtio configuration, except for the queue
/// state.
#[derive(Debug)]
struct VirtioConfigSnapshot {
	device_features: u64,
	driver_features: u64,
	device_features_select: u32,
	driver_features_select: u32,
	device_status: u8,
	queue_select: u16,
	config_generation: u8,
	config_space: Vec<u8>,
	device_activated: bool,
	interrupt_status: u8,
}

impl VirtioConfigSnapshot {
	fn new(
		config: &VirtioConfig<Queue>,
	) -> Result<Self, PanoramaError> {
		Ok(Self {
			device_features: config.device_features,
			driver_features: config.driver_features,
			device_features_select: config.device_features_select,
			driver_features_select: config.driver_features_select,
			device_status: config.device_status,
			queue_select: config.queue_select,
			config_generation: config.config_generation,
			config_space: config.config_space.clone(),
			device_activated: config.device_activated,
			interrupt_status: config
				.interrupt_status
				.load(Ordering::SeqCst),
		})
	}

	fn restore(
		&self,
		config: &mut VirtioConfig<Queue>,
	) -> Result<(), PanoramaError> {
		config.device_features = self.device_features;
		config.driver_features = self.driver_features;
		config.device_features_select = self.device_features_select;
		config.driver_features_select = self.driver_features_select;
		config.device_status = self.device_status;
		config.queue_select = self.queue_select;
		config.config_generation = self.config_generation;
		config.config_space.clear();
		config.config_space.extend(&self.config_space);
		config.device_activated = self.device_activated;
		config
			.interrupt_status
			.store(self.interrupt_status, Ordering::SeqCst);
		Ok(())
	}
}

/// A snapshot of the block device, including the virtio configuration
/// ([`VirtioConfigSnapshot`]) and the backing file for the device.
#[derive(Debug)]
pub struct BlockDeviceSnapshot {
	virtio: VirtioConfigSnapshot,
	queues: Vec<QueueState>,
	// TODO: figure out a way to avoid this Arc. Currently we need it
	// for `restore()`.
	backend: Arc<DirtyFileSnapshot>,
}

impl BlockDeviceSnapshot {
	fn new(dev: &mut BlockDevice) -> Result<Self, PanoramaError> {
		// Snapshot the virtio config
		let virtio = VirtioConfigSnapshot::new(&dev.virtio)?;

		// Snapshot the backend and queue state. We need a mutable
		// reference beacuse snapshotting the backend clears its
		// bitmap.
		let (backend, queues) = match &mut dev.handler {
			BlockHandlerState::Uninit(backend) => (
				backend.inner_mut().snapshot()?,
				dev.virtio.queues.iter().map(Queue::state).collect(),
			),
			BlockHandlerState::Reset(ref mut handler) => (
				handler.backend.inner_mut().snapshot()?,
				vec![handler.queue.state()],
			),
			BlockHandlerState::Active(id) => {
				let id = *id;
				dev.endpoint.call_blocking(move |mgr| {
					let handler = mgr.subscriber_mut(id)?;
					Ok::<_, PanoramaError>((
						handler.backend.inner_mut().snapshot()?,
						vec![handler.queue.state()],
					))
				})?
			}
			_ => unreachable!(),
		};

		let backend = Arc::new(backend);
		Ok(Self {
			virtio,
			queues,
			backend,
		})
	}

	fn restore(
		&self,
		dev: &mut BlockDevice,
	) -> Result<(), PanoramaError> {
		// Restore virtio config state
		self.virtio.restore(&mut dev.virtio)?;

		// Restore backend and queue state
		match &mut dev.handler {
			BlockHandlerState::Uninit(ref mut backend) => {
				backend.inner_mut().restore(self.backend.borrow())?;
				for (q, s) in
					dev.virtio.queues.iter_mut().zip(&self.queues)
				{
					*q = Queue::try_from(*s)?;
				}
			}
			BlockHandlerState::Reset(ref mut handler) => {
				handler
					.backend
					.inner_mut()
					.restore(self.backend.borrow())?;
				handler.queue = Queue::try_from(self.queues[0])?;
			}
			BlockHandlerState::Active(id) => {
				let id = *id;
				let be = self.backend.clone();
				let new_queue = Queue::try_from(self.queues[0])?;
				dev.endpoint.call_blocking(move |mgr| {
					let handler = mgr.subscriber_mut(id)?;
					handler.backend.inner_mut().restore(be)?;
					handler.queue = new_queue;
					Ok::<_, PanoramaError>(())
				})?;
			}
			_ => unreachable!(),
		};

		// Make state consistent
		if dev.virtio.device_activated && !dev.handler.is_active() {
			dev.activate().expect("Failed state change");
		} else if !dev.virtio.device_activated
			&& dev.handler.is_active()
		{
			dev.reset().expect("Failed state change");
		}

		Ok(())
	}
}

/// Configuration for the block device
pub struct BlockConfig<P> {
	pub path: P,
	pub read_only: bool,
	pub flush: bool,
}

/// The state of the virtio block handler.
/// Depending on the device state, the file backend ([`StdIoBackend`])
/// needs to live in a different place:
///
/// 1. On device creation, the device itself owns the backend so that
///    later, when it is activated, it can create a virtio handler.
/// 2. On device activation, the handler needs to own the backend to
///    run requests on it. The handler will run on a different thread
///    and will only be accessible via the device's `remote_endpoint`.
///    by supplying a [`SubscriberId`].
/// 3. On device reset, the handler is passed back to the device.
/// 4. `Activating` is a placeholder state that only happens within
///    `activate()` and should never be seen outside.
#[derive(Default, Debug)]
enum BlockHandlerState {
	Uninit(StdIoBackend<DirtyFile>),
	Active(SubscriberId),
	Reset(BlockHandler),
	#[default]
	Activating,
}

impl BlockHandlerState {
	fn is_active(&self) -> bool {
		matches!(self, Self::Active(..))
	}
}

pub struct BlockDevice {
	virtio: VirtioConfig<Queue>,
	irqfd: EventFd,
	iofds: Vec<EventFd>,
	endpoint: RemoteEndpoint<BlockHandler>,
	handler: BlockHandlerState,
	mem: Arc<Memory>,
}

impl BlockDevice {
	/// Prepare virtio features from the device configuration.
	fn get_features<P>(config: &BlockConfig<P>) -> u64 {
		let read_only = u64::from(config.read_only);
		let flush = u64::from(config.flush);
		1 << VIRTIO_F_VERSION_1
			| 1 << VIRTIO_F_IN_ORDER
			| 1 << VIRTIO_RING_F_EVENT_IDX
			| read_only << VIRTIO_BLK_F_RO
			| flush << VIRTIO_BLK_F_FLUSH
	}

	pub fn new<P: AsRef<Path>>(
		config: BlockConfig<P>,
		event_mgr: &EventManager<BlockHandler>,
		mem: Arc<Memory>,
	) -> Result<Self, PanoramaError> {
		let features = Self::get_features(&config);

		// Open the backing file
		let file = OpenOptions::new()
			.read(true)
			.write(!config.read_only)
			.open(config.path)
			.and_then(DirtyFile::new)?;
		let len = file.len();
		let backend = StdIoBackend::new(file, features)?;

		// Use a very minimal config space. Full implementation should
		// be a struct virtio_blk_config.
		assert_eq!(len & (BLK_SECTOR_SHIFT - 1), 0);
		let blk_config =
			(len >> BLK_SECTOR_SHIFT).to_le_bytes().to_vec();

		let queues = vec![Queue::new(QUEUE_MAX_SIZE)?];

		// Queue event fds. They will be registered on KVM by the VMM.
		let irqfd = EventFd::new(libc::EFD_NONBLOCK)?;
		let iofds = (0..queues.len())
			.map(|_| EventFd::new(libc::EFD_NONBLOCK))
			.collect::<Result<Vec<_>, _>>()?;

		let virtio = VirtioConfig::new(features, queues, blk_config);

		// A connection to the event manager that can be called from a
		// different thread
		let endpoint = event_mgr.remote_endpoint();

		Ok(Self {
			virtio,
			irqfd,
			iofds,
			endpoint,
			handler: BlockHandlerState::Uninit(backend),
			mem,
		})
	}

	pub fn cmdline_config(&self, blocktype: BlockType) -> String {
		let mut args = String::new();
		if matches!(blocktype, BlockType::Root) {
			args.push_str("root=/dev/vda");
			if self.virtio.device_features & (1 << VIRTIO_BLK_F_RO)
				!= 0
			{
				args.push_str(" ro");
			} else {
				args.push_str(" rw");
			}
		}
		args
	}

	pub fn irqfd(&self) -> &EventFd {
		&self.irqfd
	}

	pub fn iofds(&self) -> &[EventFd] {
		&self.iofds
	}

	pub fn snapshot(
		&mut self,
	) -> Result<BlockDeviceSnapshot, PanoramaError> {
		BlockDeviceSnapshot::new(self)
	}

	pub fn restore(
		&mut self,
		snapshot: &BlockDeviceSnapshot,
	) -> Result<(), PanoramaError> {
		snapshot.restore(self)
	}
}

// Implementing VirtioDeviceType together with VirtioDeviceActions
// enables an automatic VirtioDevice implementation for objects that
// also implement BorrowMut<VirtioConfig>
impl VirtioDeviceType for BlockDevice {
	fn device_type(&self) -> u32 {
		VIRTIO_ID_BLOCK
	}
}

impl Borrow<VirtioConfig<Queue>> for BlockDevice {
	fn borrow(&self) -> &VirtioConfig<Queue> {
		&self.virtio
	}
}

impl BorrowMut<VirtioConfig<Queue>> for BlockDevice {
	fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
		&mut self.virtio
	}
}

impl VirtioDeviceActions for BlockDevice {
	type E = PanoramaError;

	fn activate(&mut self) -> Result<(), Self::E> {
		if self.virtio.device_activated {
			return Err(PanoramaError::AlreadyActiveVirtio);
		}

		if self.virtio.driver_features & (1 << VIRTIO_F_VERSION_1)
			== 0
		{
			return Err(PanoramaError::InvalidVirtioDriver);
		}

		// Prepare a handler for I/O events on the queue. Then call
		// into the I/O manager, which lives in another thread, and
		// register it for events.
		let handler = match std::mem::take(&mut self.handler) {
			BlockHandlerState::Uninit(backend) => {
				BlockHandler::new(self, backend, self.mem.clone())
					.expect("Could not create block handler")
			}
			BlockHandlerState::Reset(handler) => handler,
			_ => unreachable!("inconsistent block handler state"),
		};

		// Register the handler
		let handler_id = self.endpoint.call_blocking(move |mgr| {
			Ok::<_, event_manager::Error>(mgr.add_subscriber(handler))
		})?;

		// Update state
		self.handler = BlockHandlerState::Active(handler_id);
		self.virtio.device_activated = true;

		Ok(())
	}

	fn reset(&mut self) -> Result<(), Self::E> {
		let BlockHandlerState::Active(id) = self.handler else {
			return Ok(());
		};

		// Deregister handler
		let handler = self
			.endpoint
			.call_blocking(move |mgr| mgr.remove_subscriber(id))?;

		// Update state
		self.handler = BlockHandlerState::Reset(handler);
		self.virtio.device_activated = false;

		Ok(())
	}
}

impl VirtioMmioDevice for BlockDevice {}

impl MutDeviceMmio for BlockDevice {
	fn mmio_read(
		&mut self,
		_base: MmioAddress,
		offset: u64,
		data: &mut [u8],
	) {
		self.read(offset, data);
	}

	fn mmio_write(
		&mut self,
		_base: MmioAddress,
		offset: u64,
		data: &[u8],
	) {
		self.write(offset, data);
	}
}

/// A handler for virtio blk events. Reads descriptor chains from
/// guest memory and processees them against the file backend.
/// On registration, this object will subscribe to events on the queue
/// file descriptor.
#[derive(Debug)]
pub struct BlockHandler {
	// A descriptor to deliver an IRQ to the guest.
	irqfd: EventFd,
	/// The interrupt status in the virtio config space.
	int_status: Arc<AtomicU8>,
	/// The file backend.
	backend: StdIoBackend<DirtyFile>,
	/// The queue from which to read descriptor chains.
	queue: Queue,
	/// Index of the queue above.
	queue_idx: u32,
	/// A descriptor to signal new descriptors are available for us to
	/// consume.
	iofd: EventFd,
	/// A reference to guest memory
	mem: Arc<Memory>,
}

impl BlockHandler {
	fn new(
		dev: &mut BlockDevice,
		backend: StdIoBackend<DirtyFile>,
		mem: Arc<Memory>,
	) -> Result<Self, PanoramaError> {
		Ok(Self {
			irqfd: dev.irqfd().try_clone()?,
			int_status: dev.virtio.interrupt_status.clone(),
			backend,
			queue: dev.virtio.queues.remove(0),
			queue_idx: dev.virtio.queues.len() as u32,
			iofd: dev.iofds.remove(0),
			mem,
		})
	}

	/// Processes all available descriptor chains against the file
	/// backend.
	fn process_queue(&mut self) -> Result<(), PanoramaError> {
		loop {
			self.queue.disable_notification(self.mem.inner())?;

			while let Some(chain) =
				self.queue.iter(&self.mem.inner().clone())?.next()
			{
				self.process_chain(chain)?;
			}

			if !self.queue.enable_notification(self.mem.inner())? {
				// Returns false if no new descriptors are available
				// since the last notification disable.
				return Ok(());
			}
		}
	}

	/// Processes a single descriptor chain against the file backend.
	/// Notifies the guest driver as well if necessary.
	fn process_chain<M>(
		&mut self,
		mut chain: DescriptorChain<M>,
	) -> Result<(), PanoramaError>
	where
		M: std::ops::Deref,
		M::Target: vm_memory::GuestMemory,
	{
		let req =
			Request::parse(&mut chain).expect("Invalid blk request");
		let mem = self.mem.inner();

		let used = self.backend.process_request(mem, &req)?;
		self.queue.add_used(mem, chain.head_index(), used)?;

		if self.queue.needs_notification(mem)? {
			self.notify_driver()?;
		}

		Ok(())
	}

	/// Notifies the guest driver by delivering an IRQ.
	fn notify_driver(&self) -> Result<(), PanoramaError> {
		self.int_status
			.fetch_or(VIRTIO_MMIO_INT_VRING as u8, Ordering::SeqCst);
		self.irqfd.write(1)?;
		Ok(())
	}
}

impl MutEventSubscriber for BlockHandler {
	fn init(&mut self, ops: &mut EventOps) {
		let ev = Events::with_data(
			&self.iofd,
			self.queue_idx,
			EventSet::IN,
		);
		ops.add(ev).unwrap();
	}

	fn process(&mut self, events: Events, ops: &mut EventOps) {
		if events.event_set() != EventSet::IN {
			panic!("Unexpected event");
		}
		if self.iofd.read().is_err() {
			panic!("Unexpected iofd read failure");
		};

		if self.process_queue().is_err() {
			ops.remove(events).unwrap();
		}
	}
}
