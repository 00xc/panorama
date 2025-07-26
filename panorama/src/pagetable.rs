use std::ops::Index;

/// A table of page table entries.
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PTEntries([PTEntry; 512]);

impl Default for PTEntries {
	fn default() -> Self {
		Self([PTEntry::default(); 512])
	}
}

impl Index<usize> for PTEntries {
	type Output = PTEntry;

	fn index(&self, idx: usize) -> &Self::Output {
		&self.0[idx]
	}
}

unsafe impl vm_memory::bytes::ByteValued for PTEntries {}

/// An entry in the page table
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PTEntry(u64);

impl PTEntry {
	/// The address that this entry points to
	pub fn address(&self) -> u64 {
		self.0 & 0x000f_ffff_ffff_f000
	}

	/// The flags for this entry
	pub fn flags(&self) -> PTEntryFlags {
		PTEntryFlags::from_bits_truncate(self.0)
	}
}

unsafe impl vm_memory::bytes::ByteValued for PTEntry {}

bitflags::bitflags! {
	#[repr(transparent)]
	#[derive(Clone, Copy, Debug)]
	pub struct PTEntryFlags: u64 {
		const PRESENT = 1;
		const WRITABLE = 1 << 1;
		const USER = 1 << 2;
		const WRITE_THROUGH = 1 << 3;
		const CACHE_DISABLE = 1 << 4;
		const ACCESSED = 1 << 5;
		const DIRTY = 1 << 6;
		const HUGE = 1 << 7;
		const GLOBAL = 1 << 8;
		const EXEC_DISABLE = 1 << 63;
	}
}
