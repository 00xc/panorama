use crate::event_fd::ArcEventFd;
use crate::PanoramaError;

use vm_device::bus::{PioAddress, PioAddressOffset};
use vm_device::MutDevicePio;
use vm_superio::i8042::I8042Device;
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub struct KeyboardDeviceSnapshot;

#[derive(Debug)]
pub struct KeyboardDevice {
	inner: I8042Device<ArcEventFd>,
	ev: ArcEventFd,
}

impl KeyboardDevice {
	pub fn new() -> Result<Self, PanoramaError> {
		let ev = ArcEventFd::new(libc::EFD_NONBLOCK)?;
		let inner = I8042Device::new(ev.clone());
		Ok(Self { inner, ev })
	}

	pub fn irqfd(&self) -> &EventFd {
		&self.ev.0
	}

	pub fn snapshot(&self) -> KeyboardDeviceSnapshot {
		KeyboardDeviceSnapshot
	}

	pub fn restore(&self, _: &KeyboardDeviceSnapshot) {}
}

impl MutDevicePio for KeyboardDevice {
	fn pio_read(
		&mut self,
		_base: PioAddress,
		offset: PioAddressOffset,
		data: &mut [u8],
	) {
		if let Some(val) = data.first_mut() {
			*val = self.inner.read(offset as u8);
		}
	}

	fn pio_write(
		&mut self,
		_base: PioAddress,
		offset: PioAddressOffset,
		data: &[u8],
	) {
		if let Some(val) = data.first() {
			let _ = self.inner.write(offset as u8, *val);
		}
	}
}
