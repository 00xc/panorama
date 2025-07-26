use bitflags::bitflags;

#[allow(dead_code)]
pub enum Register {
	Rax,
	Rbx,
	Rcx,
	Rdx,
	Rsi,
	Rdi,
	Rsp,
	Rbp,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	Rip,
	Rflags,
}

bitflags! {
	/// Configuration flags of the CR0 register.
	#[repr(transparent)]
	#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
	pub struct Cr0: u64 {
		/// Enables protected mode.
		const PE = 1;
		/// Enables monitoring of the coprocessor, typical for x87 instructions.
		///
		/// Controls (together with the [`TASK_SWITCHED`](Cr0Flags::TASK_SWITCHED)
		/// flag) whether a `wait` or `fwait` instruction should cause an `#NE` exception.
		const MONITOR_COPROCESSOR = 1 << 1;
		/// Force all x87 and MMX instructions to cause an `#NE` exception.
		const EMULATE_COPROCESSOR = 1 << 2;
		/// Automatically set to 1 on _hardware_ task switch.
		///
		/// This flags allows lazily saving x87/MMX/SSE instructions on hardware context switches.
		const TASK_SWITCHED = 1 << 3;
		/// Indicates support of 387DX math coprocessor instructions.
		///
		/// Always set on all recent x86 processors, cannot be cleared.
		const ET = 1 << 4;
		/// Enables the native (internal) error reporting mechanism for x87 FPU errors.
		const NUMERIC_ERROR = 1 << 5;
		/// Controls whether supervisor-level writes to read-only pages are inhibited.
		///
		/// When set, it is not possible to write to read-only pages from ring 0.
		const WRITE_PROTECT = 1 << 16;
		/// Enables automatic usermode alignment checking if [`RFlags::ALIGNMENT_CHECK`] is also set.
		const ALIGNMENT_MASK = 1 << 18;
		/// Ignored, should always be unset.
		///
		/// Must be unset if [`CACHE_DISABLE`](Cr0Flags::CACHE_DISABLE) is unset.
		/// Older CPUs used this to control write-back/write-through cache strategy.
		const NOT_WRITE_THROUGH = 1 << 29;
		/// Disables some processor caches, specifics are model-dependent.
		const CACHE_DISABLE = 1 << 30;
		/// Enables paging.
		///
		/// If this bit is set, [`PROTECTED_MODE_ENABLE`](Cr0Flags::PROTECTED_MODE_ENABLE) must be set.
		const PAGING = 1 << 31;
	}
}
