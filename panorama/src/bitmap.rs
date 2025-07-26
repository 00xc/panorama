// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::bitmap::Bitmap;
use vm_memory::bitmap::RefSlice;
use vm_memory::bitmap::WithBitmapSlice;
use vm_memory::mmap::NewBitmap;

/// A copy of [`vm_memory::bitmap::AtomicBitmap`] with access to the inner
/// map.
#[derive(Debug)]
pub struct AtomicBitmap2 {
	pub map: Vec<AtomicU64>,
	size: usize,
	page_size: usize,
}

#[allow(clippy::len_without_is_empty)]
impl AtomicBitmap2 {
	/// Create a new bitmap of `byte_size`, with one bit per page. This is effectively
	/// rounded up, and we get a new vector of the next multiple of 64 bigger than `bit_size`.
	pub fn new(byte_size: usize, page_size: usize) -> Self {
		let num_pages = byte_size.div_ceil(page_size);

		// Adding one entry element more just in case `num_pages` is not a multiple of `64`.
		//let map_size = num_pages / 64 + 1;
		let map_size = num_pages.div_ceil(u64::BITS as usize);
		let map: Vec<AtomicU64> =
			(0..map_size).map(|_| AtomicU64::new(0)).collect();

		Self {
			map,
			size: num_pages,
			page_size,
		}
	}

	/// Is bit `n` set? Bits outside the range of the bitmap are always unset.
	pub fn is_bit_set(&self, index: usize) -> bool {
		if index < self.size {
			(self.map[index >> 6].load(Ordering::SeqCst)
				& (1 << (index & 63)))
				!= 0
		} else {
			// Out-of-range bits are always unset.
			false
		}
	}

	/// Is the bit corresponding to address `addr` set?
	pub fn is_addr_set(&self, addr: usize) -> bool {
		self.is_bit_set(addr / self.page_size)
	}

	/// Set a range of `len` bytes starting at `start_addr`. The first bit set in the bitmap
	/// is for the page corresponding to `start_addr`, and the last bit that we set corresponds
	/// to address `start_addr + len - 1`.
	pub fn set_addr_range(&self, start_addr: usize, len: usize) {
		// Return early in the unlikely event that `len == 0` so the `len - 1` computation
		// below does not underflow.
		if len == 0 {
			return;
		}

		let first_bit = start_addr / self.page_size;
		// Handle input ranges where `start_addr + len - 1` would otherwise overflow an `usize`
		// by ignoring pages at invalid addresses.
		let last_bit =
			start_addr.saturating_add(len - 1) / self.page_size;
		for n in first_bit..=last_bit {
			if n >= self.size {
				// Attempts to set bits beyond the end of the bitmap are simply ignored.
				break;
			}
			self.map[n >> 6]
				.fetch_or(1 << (n & 63), Ordering::SeqCst);
		}
	}

	/// Reset all bitmap bits to 0.
	pub fn reset(&self) {
		for it in self.map.iter() {
			it.store(0, Ordering::Release);
		}
	}
}

impl Default for AtomicBitmap2 {
	fn default() -> Self {
		Self::new(0, 0x1000)
	}
}

impl Clone for AtomicBitmap2 {
	fn clone(&self) -> Self {
		let map = self
			.map
			.iter()
			.map(|i| i.load(Ordering::Acquire))
			.map(AtomicU64::new)
			.collect();
		Self {
			map,
			size: self.size,
			page_size: self.page_size,
		}
	}
}

impl<'a> WithBitmapSlice<'a> for AtomicBitmap2 {
	type S = RefSlice<'a, Self>;
}

impl Bitmap for AtomicBitmap2 {
	fn mark_dirty(&self, offset: usize, len: usize) {
		self.set_addr_range(offset, len)
	}

	fn dirty_at(&self, offset: usize) -> bool {
		self.is_addr_set(offset)
	}

	fn slice_at(
		&self,
		offset: usize,
	) -> <Self as WithBitmapSlice>::S {
		RefSlice::new(self, offset)
	}
}

impl NewBitmap for AtomicBitmap2 {
	fn with_len(len: usize) -> Self {
		// SAFETY: There's no unsafe potential in calling this function.
		let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };

		// The `unwrap` is safe to use because the above call should always succeed on the
		// supported platforms, and the size of a page will always fit within a `usize`.
		Self::new(len, usize::try_from(page_size).unwrap())
	}
}
