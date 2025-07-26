use std::io;

#[derive(Debug)]
pub enum PanoramaError {
	BlkProcessReq(virtio_blk::stdio_executor::ProcessReqError),
	EventManager(event_manager::Error),
	InactiveVirtio,
	AlreadyActiveVirtio,
	InvalidVirtioDriver,
	Allocator(vm_allocator::Error),
	BlkIo(virtio_blk::stdio_executor::Error),
	Memory(vm_memory::Error),
	VolatileMemory(vm_memory::volatile_memory::Error),
	GuestMemory(vm_memory::GuestMemoryError),
	Io(std::io::Error),
	Bus(vm_device::bus::Error),
	Object(object::read::Error),
	Gimli(gimli::Error),
	Serial(vm_superio::serial::Error<io::Error>),
	KvmIoctl(kvm_ioctls::Error),
	KvmVersion(i32),
	NoSerialDevice,
	NoKeyboardDevice,
	Fam(vmm_sys_util::fam::Error),
	Msrs((usize, usize)),
	KvmNoIrq,
	KvmNoImmExit,
	KvmNoUserMemory,
	KvmNoSyncMmu,
	Loader(linux_loader::loader::Error),
	LoaderConfig(linux_loader::configurator::Error),
	Cmdline(linux_loader::cmdline::Error),
	MpTable,
	InvalidGdtAddr,
	MsrInit,
	Queue(virtio_queue::Error),
	GvaNotPresent(u64),
}

impl From<vm_memory::volatile_memory::Error> for PanoramaError {
	fn from(e: vm_memory::volatile_memory::Error) -> Self {
		Self::VolatileMemory(e)
	}
}

impl From<vm_superio::serial::Error<io::Error>> for PanoramaError {
	fn from(e: vm_superio::serial::Error<io::Error>) -> Self {
		Self::Serial(e)
	}
}

impl From<virtio_blk::stdio_executor::ProcessReqError>
	for PanoramaError
{
	fn from(
		err: virtio_blk::stdio_executor::ProcessReqError,
	) -> Self {
		Self::BlkProcessReq(err)
	}
}

impl From<event_manager::Error> for PanoramaError {
	fn from(err: event_manager::Error) -> Self {
		Self::EventManager(err)
	}
}

impl From<virtio_blk::stdio_executor::Error> for PanoramaError {
	fn from(err: virtio_blk::stdio_executor::Error) -> Self {
		Self::BlkIo(err)
	}
}

impl From<virtio_queue::Error> for PanoramaError {
	fn from(err: virtio_queue::Error) -> Self {
		Self::Queue(err)
	}
}

impl From<vm_allocator::Error> for PanoramaError {
	fn from(err: vm_allocator::Error) -> Self {
		Self::Allocator(err)
	}
}

impl From<gimli::Error> for PanoramaError {
	fn from(err: gimli::Error) -> Self {
		Self::Gimli(err)
	}
}

impl From<object::read::Error> for PanoramaError {
	fn from(err: object::read::Error) -> Self {
		Self::Object(err)
	}
}

impl From<vm_memory::GuestMemoryError> for PanoramaError {
	fn from(err: vm_memory::GuestMemoryError) -> Self {
		Self::GuestMemory(err)
	}
}

impl From<vm_memory::Error> for PanoramaError {
	fn from(err: vm_memory::Error) -> Self {
		Self::Memory(err)
	}
}

impl From<vmm_sys_util::fam::Error> for PanoramaError {
	fn from(err: vmm_sys_util::fam::Error) -> Self {
		Self::Fam(err)
	}
}

impl From<vm_device::bus::Error> for PanoramaError {
	fn from(err: vm_device::bus::Error) -> Self {
		Self::Bus(err)
	}
}

impl From<std::io::Error> for PanoramaError {
	fn from(err: std::io::Error) -> Self {
		Self::Io(err)
	}
}

impl From<kvm_ioctls::Error> for PanoramaError {
	fn from(err: kvm_ioctls::Error) -> Self {
		Self::KvmIoctl(err)
	}
}

impl From<linux_loader::loader::Error> for PanoramaError {
	fn from(err: linux_loader::loader::Error) -> Self {
		Self::Loader(err)
	}
}

impl From<linux_loader::configurator::Error> for PanoramaError {
	fn from(err: linux_loader::configurator::Error) -> Self {
		Self::LoaderConfig(err)
	}
}

impl From<linux_loader::cmdline::Error> for PanoramaError {
	fn from(err: linux_loader::cmdline::Error) -> Self {
		Self::Cmdline(err)
	}
}
