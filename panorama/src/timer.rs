use nix::sys::signal::*;
use nix::sys::timer::*;
use nix::time::*;
use std::time::Duration;

#[macro_export]
macro_rules! time_it {
	($block:block) => {{
		let t = std::time::Instant::now();
		($block, t.elapsed())
	}};
}

#[derive(Debug)]
pub struct PTimer {
	timer: Timer,
	dur: Duration,
}

impl PTimer {
	pub fn new(
		handler: extern "C" fn(_: libc::c_int),
		dur: Duration,
	) -> Self {
		// Register handler
		let handler = SigHandler::Handler(handler);
		unsafe { signal(Signal::SIGALRM, handler) }.unwrap();

		// Create timer
		let sigevent = SigEvent::new(SigevNotify::SigevSignal {
			signal: Signal::SIGALRM,
			si_value: 0,
		});
		let timer =
			Timer::new(ClockId::CLOCK_MONOTONIC, sigevent).unwrap();

		Self { timer, dur }
	}

	pub fn start(&mut self) {
		let expiration = Expiration::Interval(self.dur.into());
		self.timer
			.set(expiration, TimerSetTimeFlags::empty())
			.unwrap();
	}

	pub fn stop(&mut self) {
		let expiration = Expiration::OneShot(Duration::ZERO.into());
		self.timer
			.set(expiration, TimerSetTimeFlags::empty())
			.unwrap();
	}
}
