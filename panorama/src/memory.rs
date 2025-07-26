use crate::defs::layout::{MMIO_GAP_END, MMIO_GAP_START};
use crate::defs::PAGE_SIZE;
use crate::pagetable::{PTEntries, PTEntryFlags};
use crate::{PanoramaError, Vm};

use crate::bitmap::AtomicBitmap2;
use std::mem::size_of;
use std::ops::Range;
use std::sync::atomic::Ordering;
use vm_memory::bytes::{ByteValued, Bytes};
use vm_memory::guest_memory::{
	GuestAddress, GuestMemory, GuestMemoryRegion, MemoryRegionAddress,
};
use vm_memory::mmap::{GuestMemoryMmap, GuestRegionMmap};

type InnerMemoryRegion = GuestRegionMmap<AtomicBitmap2>;
type InnerMemory = GuestMemoryMmap<AtomicBitmap2>;

/// Memory mappings for the guest
#[derive(Debug, Clone)]
pub struct Memory {
	mem: InnerMemory,
}

impl Memory {
	/// A struct representing memory for the guest
	pub fn new(size: usize) -> Result<Self, PanoramaError> {
		// Surround MMIO gap if necessary
		let ranges = match size.checked_sub(MMIO_GAP_START as usize) {
			None | Some(0) => vec![(GuestAddress(0), size)],
			Some(remaining) => vec![
				(GuestAddress(0), MMIO_GAP_START as usize),
				(GuestAddress(MMIO_GAP_END), remaining),
			],
		};

		let mem = InnerMemory::from_ranges(&ranges)?;
		for region in mem.iter() {
			Self::madvise_region(region);
		}
		Ok(Self { mem })
	}

	fn madvise_region(reg: &InnerMemoryRegion) {
		unsafe {
			libc::madvise(
				reg.as_ptr().cast::<libc::c_void>(),
				reg.len() as usize,
				libc::MADV_HUGEPAGE | libc::MADV_WILLNEED,
			)
		};
	}

	/// Get the inner representation of the guest memory.
	pub fn inner(&self) -> &InnerMemory {
		&self.mem
	}

	/// Write to guest memory without modifying the dirty bitmap at
	/// GPA `addr`.
	pub fn write_phys_nodirty<T>(
		&self,
		addr: GuestAddress,
		buf: &[T],
	) -> Result<(), PanoramaError> {
		use vm_memory::volatile_memory::Error as MemError;

		let nelements = buf.len();
		let size = size_of::<T>();
		let bytelen = nelements
			.checked_mul(size)
			.ok_or(MemError::TooBig { nelements, size })?;
		unsafe {
			self.mem
				.get_slice(addr, bytelen)?
				.ptr_guard_mut()
				.as_ptr()
				.copy_from_nonoverlapping(
					buf.as_ptr().cast(),
					bytelen,
				);
		}
		Ok(())
	}

	/// Read from guest memory at GPA `addr`.
	pub fn read_phys<T: ByteValued>(
		&self,
		addr: GuestAddress,
	) -> Result<T, PanoramaError> {
		let val = self.mem.read_obj(addr)?;
		Ok(val)
	}

	/// Translate a guest virtual address (GVA) to a guest physical
	/// address (GPA) by walking the guest page table. Assumes long
	/// mode.
	pub fn gva2gpa(
		&self,
		cr3: u64,
		gva: u64,
	) -> Result<GuestAddress, PanoramaError> {
		let mut table_addr = GuestAddress(cr3 & !0xfff);
		const SHIFTS: [u8; 4] = [39, 30, 21, 12];
		let mut page_off_bits = 12;

		for shift in &SHIFTS {
			let table: PTEntries = self.mem.read_obj(table_addr)?;
			let idx = ((gva >> shift) & 511) as usize;

			let entry = table[idx];
			let address = entry.address();
			let flags = entry.flags();

			if !flags.contains(PTEntryFlags::PRESENT) {
				return Err(PanoramaError::GvaNotPresent(gva));
			}

			table_addr = GuestAddress(address);

			if flags.contains(PTEntryFlags::HUGE) {
				page_off_bits = *shift;
				break;
			}
		}

		Ok(GuestAddress(
			table_addr.0 | lowestnbits(gva, page_off_bits),
		))
	}

	/// Take a snapshot can later be used to restore the memory state.
	/// Resets the dirty bitmap.
	pub fn snapshot(
		&self,
		vm: &Vm,
	) -> Result<MemorySnapshot, PanoramaError> {
		MemorySnapshot::new(self, vm)
	}

	/// Restore the memory state from a previous snapshot. Resets the
	/// dirty bitmap.
	pub fn restore(
		&self,
		snapshot: &MemorySnapshot,
		vm: &Vm,
	) -> Result<(), PanoramaError> {
		snapshot.restore(self, vm)
	}
}

fn is_dirty(bitmap: &[u64], addr: usize) -> bool {
	let idx = addr / PAGE_SIZE;
	let b = unsafe { bitmap.get_unchecked(idx >> 6) };
	(b & (1 << (idx & 63))) != 0
}

#[derive(Debug)]
pub struct MemorySnapshot {
	regions: Vec<RegionSnapshot>,
}

impl MemorySnapshot {
	fn new(mem: &Memory, vm: &Vm) -> Result<Self, PanoramaError> {
		let mut regions = Vec::with_capacity(mem.mem.num_regions());
		for (idx, region) in mem.mem.iter().enumerate() {
			let snap = RegionSnapshot::new(region);
			regions.push(snap);
			region.bitmap().reset();
			vm.get_dirty_log(idx as u32, region.len() as usize)?;
		}
		Ok(Self { regions })
	}

	fn restore(
		&self,
		mem: &Memory,
		vm: &Vm,
	) -> Result<(), PanoramaError> {
		for (idx, (region, rsnapshot)) in
			mem.mem.iter().zip(&self.regions).enumerate()
		{
			assert_eq!(region.start_addr(), rsnapshot.addr);
			let dirty =
				vm.get_dirty_log(idx as u32, region.len() as usize)?;
			rsnapshot.restore(region, dirty)?;
		}

		Ok(())
	}
}

/// A snapshot of a single memory region
#[derive(Debug)]
struct RegionSnapshot {
	addr: GuestAddress,
	bytes: Vec<u8>,
}

impl RegionSnapshot {
	/// Create a new snapshot from a memory region.
	fn new(region: &InnerMemoryRegion) -> Self {
		let addr = region.start_addr();
		let size = region.size();

		// Prepare the destination
		let mut bytes = Vec::new();
		bytes.reserve_exact(size);

		// Copy from guest memory
		let src = region.as_volatile_slice().unwrap();
		unsafe {
			src.ptr_guard().as_ptr().copy_to_nonoverlapping(
				bytes.as_mut_ptr(),
				region.size(),
			);
			bytes.set_len(region.size());
		}

		Self { addr, bytes }
	}

	/// Restore a memory region from its KVM dirty bitmap. Clears
	/// the region's internal dirty bitmap as well.
	fn restore(
		&self,
		region: &InnerMemoryRegion,
		mut kdirty: Vec<u64>,
	) -> Result<(), PanoramaError> {
		// Merge into a single dirty map
		for (k, g) in kdirty.iter_mut().zip(&region.bitmap().map) {
			*k |= g.swap(0, Ordering::SeqCst);
		}

		let mut restored = 0u64;

		// Iterate over the pages in this region, merging contiguous
		// dirty pages to reduce the amount of writes to guest mem.
		let mut last = None;
		for page in (0..region.size()).step_by(PAGE_SIZE) {
			if !is_dirty(&kdirty, page) {
				// This page is not dirty so there is no longer a
				// contiguous dirty span. Restore the one we had so
				// far, if any.
				if let Some(r) = last.take() {
					restored += self.restore_slice(region, &r)?;
				}
				continue;
			}

			// This page is dirty. If the previous one was also dirty,
			// merge them into a singe span. Otherwise, this is the
			// start of the span.
			let cur = MemRange::new(page, PAGE_SIZE);
			if let Some(r) = last.as_mut() {
				r.merge(cur);
			} else {
				last = Some(cur);
			}
		}

		// Restore if there is anything left over
		if let Some(r) = last.take() {
			restored += self.restore_slice(region, &r)?;
		}

		crate::metrics::METRICS.set_restored(restored);

		Ok(())
	}

	/// Restores the specified range in the given region
	fn restore_slice(
		&self,
		region: &InnerMemoryRegion,
		range: &MemRange,
	) -> Result<u64, PanoramaError> {
		let bytes = &self.bytes[range.as_range()];
		let slice = region.get_slice(range.as_addr(), bytes.len())?;
		unsafe {
			slice
				.ptr_guard_mut()
				.as_ptr()
				.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len())
		};
		Ok(range.len() as u64)
	}
}

/// A range within a memory region. Used to coalesce dirty pages in
/// order to reduce `memcpy()`'s.
#[derive(Clone, Copy, Debug)]
struct MemRange {
	start: usize,
	end: usize,
}

impl MemRange {
	fn new(start: usize, len: usize) -> Self {
		Self {
			start,
			end: start + len,
		}
	}

	fn merge(&mut self, other: MemRange) {
		self.end = other.end;
	}

	fn as_range(&self) -> Range<usize> {
		self.start..self.end
	}

	fn as_addr(&self) -> MemoryRegionAddress {
		MemoryRegionAddress(self.start as u64)
	}

	fn len(&self) -> usize {
		self.end.saturating_sub(self.start)
	}
}

/// Returns the lowest `bits` bits of `val`
#[inline]
fn lowestnbits(val: u64, bits: u8) -> u64 {
	val & (u64::MAX >> (64 - bits))
}

/*
#[cfg(test)]
mod test {
	use super::*;
	use vm_memory::address::Address;

	#[test]
	fn test_snapshot() {
		// Prepare the memory region
		let start_addr = GuestAddress(0x1000);
		let ranges =
			[(start_addr, 0x2000), (GuestAddress(0x4000), 0x4000)];
		let mem = Memory::from_ranges(&ranges).unwrap();

		// Take a snapshot
		let snapshot = mem.snapshot();

		// Write to the original memory
		mem.mem.write_slice(&[1, 2, 3], start_addr).unwrap();

		// Get the first region and the base address in that region
		let (region, base) =
			mem.mem.to_region_addr(start_addr).unwrap();
		assert_eq!(base, MemoryRegionAddress(0));
		let base = base.raw_value() as usize;

		// Sanity check the dirty bitmap
		assert!(region.bitmap().is_addr_set(base));
		assert!(!region.bitmap().is_addr_set(base + 0x1000));

		let mut tmp = [0; 3];

		// Check that the bytes got written
		mem.mem.read_slice(&mut tmp, start_addr).unwrap();
		assert_eq!(tmp, [1, 2, 3]);

		// Restore the snapshot and verify
		let num_pages = mem.restore(&snapshot).unwrap();
		assert_eq!(num_pages, 1);
		mem.mem.read_slice(&mut tmp, start_addr).unwrap();
		assert_eq!(tmp, [0, 0, 0]);
	}
}
*/
