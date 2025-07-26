use crate::PanoramaError;

use aligned_vec::{AVec, ConstAlign};
use memmap2::{MmapMut, MmapOptions};
use range_set::RangeSet;
use std::borrow::Borrow;
use std::fs::File;
use std::io::{self, Cursor};
use std::ops::RangeInclusive;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::io::{ReadVolatile, WriteVolatile};
use vm_memory::{VolatileMemoryError, VolatileSlice};
use vmm_sys_util::file_traits::FileSync;

/// A snapshsot of a [`DirtyFile`].
#[derive(Debug, Clone)]
pub(super) struct DirtyFileSnapshot {
    bytes: AVec<u8, ConstAlign<4096>>,
    pos: u64,
}

impl DirtyFileSnapshot {
    fn new(file: &mut DirtyFile) -> Result<Self, PanoramaError> {
        file.dirty.clear();
        let bytes = AVec::from_slice(4096, file.map.get_ref());
        Ok(Self {
            bytes,
            pos: file.map.position(),
        })
    }

    fn restore(&self, file: &mut DirtyFile) -> Result<(), PanoramaError> {
        file.map.set_position(self.pos);
        assert_eq!(self.bytes.len(), file.map.get_ref().len());
        for range in file.dirty.as_ref().iter() {
            let src = &self.bytes[range.clone()];
            file.map.get_mut()[range.clone()].copy_from_slice(src);
        }
        file.dirty.clear();
        Ok(())
    }
}

/// A wrapper over a copy-on-write `mmap()`-ed file that keeps track
/// of dirty bytes.
#[derive(Debug)]
pub(super) struct DirtyFile {
    map: Cursor<MmapMut>,
    dirty: RangeSet<[RangeInclusive<usize>; 64]>,
}

impl DirtyFile {
    pub(super) fn new(file: File) -> io::Result<Self> {
        let map = unsafe { MmapOptions::new().map_copy(&file) }?;
        let map = Cursor::new(map);
        let dirty = RangeSet::with_capacity(64);
        Ok(Self { map, dirty })
    }

    pub(super) fn len(&self) -> usize {
        self.map.get_ref().len()
    }

    /// Take a snapshot of the file, resetting the dirty map.
    pub(super) fn snapshot(&mut self) -> Result<DirtyFileSnapshot, PanoramaError> {
        DirtyFileSnapshot::new(self)
    }

    /// Restore the file from a previous snapshot, clearing the dirty
    /// map.
    pub(super) fn restore<S>(&mut self, snapshot: S) -> Result<(), PanoramaError>
    where
        S: Borrow<DirtyFileSnapshot>,
    {
        snapshot.borrow().restore(self)
    }
}

impl ReadVolatile for DirtyFile {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<'_, B>,
    ) -> Result<usize, VolatileMemoryError> {
        self.map.read_volatile(buf)
    }

    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<'_, B>,
    ) -> Result<(), VolatileMemoryError> {
        self.map.read_exact_volatile(buf)
    }
}

impl WriteVolatile for DirtyFile {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<'_, B>,
    ) -> Result<usize, VolatileMemoryError> {
        let mem_len = self.map.get_ref().len();
        let pos = self.map.position().min(mem_len as u64) as usize;

        // Very ugly, taken from:
        // `impl WriteVolatile for Cursor<&mut [u8]>`
        let nwritten = WriteVolatile::write_volatile(&mut &mut self.map.get_mut()[pos..], buf)?;

        // Update position
        let newpos = pos + nwritten;
        self.map.set_position(newpos as u64);

        if nwritten > 0 {
            // Update dirty tracking
            let end = newpos - 1;
            self.dirty.insert_range(pos..=end);
        }

        Ok(nwritten)
    }
}

impl FileSync for DirtyFile {
    fn fsync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for DirtyFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.map.seek(pos)
    }
}

impl vmm_sys_util::write_zeroes::PunchHole for DirtyFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        let length = usize::try_from(length).ok();
        let Some((offset, length)) = usize::try_from(offset).ok().zip(length) else {
            return Ok(());
        };
        let Some(end) = offset.checked_add(length) else {
            return Ok(());
        };

        if let Some(dst) = self.map.get_mut().get_mut(offset..end) {
            dst.fill(0);
            if length > 0 {
                self.dirty.insert_range(offset..=(end - 1));
            }
        };

        Ok(())
    }
}

impl vmm_sys_util::write_zeroes::WriteZeroesAt for DirtyFile {
    fn write_zeroes_at(&mut self, _offset: u64, _length: usize) -> io::Result<usize> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use memfd::MemfdOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::mem::size_of_val;

    #[test]
    fn test_dirty() {
        let mut buf = [0xffu8; 256];

        let mut memfd = MemfdOptions::new()
            .create("dirty-test")
            .unwrap()
            .into_file();
        memfd.write_all(&buf).unwrap();
        let mut file = DirtyFile::new(memfd).unwrap();
        let snapshot = file.snapshot().unwrap();

        buf.fill(0xaf);

        // Prepare a volatile slice over `buf`
        let mut vs = unsafe { VolatileSlice::new(buf.as_mut_ptr(), size_of_val(&buf)) };

        // Read some contents and check
        file.read_volatile(&mut vs).unwrap();
        let val = unsafe { vs.ptr_guard().as_ptr().read() };
        assert_eq!(val, 0xff);

        // Write some stuff
        unsafe { vs.ptr_guard_mut().as_ptr().write_bytes(0xaf, 256) };
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_volatile(&vs.subslice(0, 32).unwrap()).unwrap();
        file.seek(SeekFrom::Start(64)).unwrap();
        file.write_volatile(&vs.subslice(0, 32).unwrap()).unwrap();

        // Reset the buffer
        unsafe { vs.ptr_guard_mut().as_ptr().write_bytes(0xff, 256) };

        // Check contents back
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_volatile(&mut vs).unwrap();
        let val = unsafe { vs.ptr_guard().as_ptr().read() };
        assert_eq!(val, 0xaf);

        // Check the dirty map
        let expected_dirty =
            RangeSet::<[RangeInclusive<usize>; 2]>::from_ranges(&[0..=31, 64..=95]);
        assert_eq!(file.dirty, expected_dirty);

        // Restore snapshot and check
        file.restore(&snapshot).unwrap();
        assert_eq!(file.map.position(), 0);
        assert!(file.dirty.is_empty());

        file.read_volatile(&mut vs).unwrap();
        let guard = vs.ptr_guard();
        for i in 0..size_of_val(&buf) {
            let val = unsafe { guard.as_ptr().add(i).read() };
            assert_eq!(val, 0xff)
        }
    }
}
