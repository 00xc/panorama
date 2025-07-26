use crate::PanoramaError;
use std::io;
use std::sync::Arc;
use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;

#[derive(Clone, Debug)]
pub struct ArcEventFd(pub Arc<EventFd>);

impl ArcEventFd {
	pub fn new(flags: i32) -> Result<Self, PanoramaError> {
		let event_fd = EventFd::new(flags)?;
		Ok(Self(Arc::new(event_fd)))
	}
}

impl Trigger for ArcEventFd {
	type E = io::Error;

	fn trigger(&self) -> io::Result<()> {
		self.0.write(1)
	}
}
