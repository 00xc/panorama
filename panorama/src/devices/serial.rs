use crate::event_fd::ArcEventFd;
use crate::PanoramaError;

use std::io::{stdout, Stdout};
use vm_device::bus::{PioAddress, PioAddressOffset};
use vm_device::MutDevicePio;
use vm_superio::serial::{NoEvents, Serial, SerialState};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub struct SerialDevice {
	inner: Serial<ArcEventFd, NoEvents, Stdout>,
}

impl SerialDevice {
	pub fn new() -> Result<Self, PanoramaError> {
		// If we simply used an `EventFd`, when restoring a snapshot
		// we would need to dup(3) the fd owned by `inner` and
		// preparing a new device via `Serial::from_state(state, fd,
		// ...)`. Once the old state got dropped that would call
		// close(3) on the original fd.  Using an ArcEventFd saves us
		// two syscalls on every restore by simply reusing the same
		// file descriptor.
		let ev = ArcEventFd::new(libc::EFD_NONBLOCK)?;
		let inner = Serial::new(ev, stdout());
		Ok(Self { inner })
	}

	/// The file descriptor used to deliver IRQs to the guest. Will be
	/// registered in KVM by the VMM.
	pub fn irqfd(&self) -> &EventFd {
		&self.inner.interrupt_evt().0
	}

	/// Additional cmdline config appended by this device.
	pub fn cmdline_config(&self) -> &'static str {
		"console=ttyS0"
	}

	pub fn snapshot(&self) -> SerialDeviceSnapshot {
		SerialDeviceSnapshot::new(self)
	}

	pub fn restore(
		&mut self,
		snapshot: &SerialDeviceSnapshot,
	) -> Result<(), PanoramaError> {
		snapshot.restore(self)
	}
}

impl MutDevicePio for SerialDevice {
	fn pio_read(
		&mut self,
		_base: PioAddress,
		offset: PioAddressOffset,
		data: &mut [u8],
	) {
		if let Some(dst) = data.first_mut() {
			*dst = self.inner.read(offset as u8);
		}
	}

	fn pio_write(
		&mut self,
		_base: PioAddress,
		offset: PioAddressOffset,
		data: &[u8],
	) {
		if let Some(src) = data.first() {
			let _ = self.inner.write(offset as u8, *src);
		}
	}
}

#[derive(Debug, Clone)]
pub struct SerialDeviceSnapshot {
	state: SerialState,
}

impl SerialDeviceSnapshot {
	fn new(serial: &SerialDevice) -> Self {
		let state = serial.inner.state();
		Self { state }
	}

	fn restore(
		&self,
		serial: &mut SerialDevice,
	) -> Result<(), PanoramaError> {
		let ev = serial.inner.interrupt_evt().clone();
		serial.inner =
			Serial::from_state(&self.state, ev, NoEvents, stdout())?;
		Ok(())
	}
}
