use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

#[derive(Debug)]
pub struct Metrics {
	start: Instant,
	in_guest: AtomicF64,
	in_vmm: AtomicF64,
	num_resets: AtomicU64,
	restored_pages: AtomicU64,
}

impl Metrics {
	pub fn new() -> Self {
		Self {
			start: Instant::now(),
			in_vmm: AtomicF64::new(0.0),
			in_guest: AtomicF64::new(0.0),
			num_resets: AtomicU64::new(0),
			restored_pages: AtomicU64::new(0),
		}
	}

	pub fn set_restored(&self, val: u64) {
		self.restored_pages.store(val, Ordering::Relaxed);
	}

	pub fn restored_pages(&self) -> u64 {
		self.restored_pages.load(Ordering::Relaxed)
	}

	pub fn update_reset(&self) -> u64 {
		self.num_resets.fetch_add(1, Ordering::Relaxed)
	}

	pub fn resets(&self) -> u64 {
		self.num_resets.load(Ordering::Relaxed)
	}

	pub fn in_guest(&self) -> Duration {
		Duration::from_secs_f64(self.in_guest.load(Ordering::Relaxed))
	}

	pub fn in_vmm(&self) -> Duration {
		Duration::from_secs_f64(self.in_vmm.load(Ordering::Relaxed))
	}

	pub fn update_in_guest(&self, d: Duration) {
		let add = d.as_secs_f64();
		Self::add_f64(&self.in_guest, add);
	}

	pub fn update_in_vmm(&self, d: Duration) {
		let add = d.as_secs_f64();
		Self::add_f64(&self.in_vmm, add);
	}

	pub fn in_fuzz(&self) -> Duration {
		self.start.elapsed()
	}

	fn add_f64(dst: &AtomicF64, add: f64) {
		let mut old = dst.load(Ordering::Relaxed);
		while let Err(e) = dst.cas_weak(
			old,
			old + add,
			Ordering::Relaxed,
			Ordering::Relaxed,
		) {
			old = e;
		}
	}
}

#[derive(Debug)]
struct AtomicF64(AtomicU64);

impl AtomicF64 {
	fn new(value: f64) -> Self {
		let as_u64 = value.to_bits();
		Self(AtomicU64::new(as_u64))
	}

	fn cas_weak(
		&self,
		old: f64,
		new: f64,
		success: Ordering,
		failure: Ordering,
	) -> Result<f64, f64> {
		self.0
			.compare_exchange_weak(
				old.to_bits(),
				new.to_bits(),
				success,
				failure,
			)
			.map(f64::from_bits)
			.map_err(f64::from_bits)
	}

	#[allow(unused)]
	fn store(&self, value: f64, ordering: Ordering) {
		let as_u64 = value.to_bits();
		self.0.store(as_u64, ordering)
	}

	fn load(&self, ordering: Ordering) -> f64 {
		let as_u64 = self.0.load(ordering);
		f64::from_bits(as_u64)
	}
}
