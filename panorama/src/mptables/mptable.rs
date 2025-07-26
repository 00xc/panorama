// Portions Copyright 2021 Amazon.com, Inc. or its affiliates. All
// Rights Reserved. SPDX-License-Identifier: Apache-2.0 OR
// BSD-3-Clause
//
// Portions Copyright 2017 The Chromium OS Authors. All rights
// reserved. Use of this source code is governed by a BSD-style
// license that can be found in the THIRD-PARTY file.

use crate::defs::layout::EBDA_START;
use crate::memory::Memory;
use crate::mptables::mpspec;
use crate::PanoramaError;

use libc::c_char;
use std::io;
use std::mem;
use std::slice;
use vm_memory::{
	Address, ByteValued, Bytes, GuestAddress, GuestMemory,
};

// This is a workaround to the Rust enforcement specifying that any
// implementation of a foreign trait (in this case `ByteValued`)
// where:
// * the type that is implementing the trait is foreign or
// * all of the parameters being passed to the trait (if there are
//   any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct MpcBus(mpspec::mpc_bus);
#[derive(Copy, Clone, Default)]
struct MpcCpu(mpspec::mpc_cpu);
#[derive(Copy, Clone, Default)]
struct MpcIntsrc(mpspec::mpc_intsrc);
#[derive(Copy, Clone, Default)]
struct MpcIoapic(mpspec::mpc_ioapic);
#[derive(Copy, Clone, Default)]
struct MpcTable(mpspec::mpc_table);
#[derive(Copy, Clone, Default)]
struct MpcLintsrc(mpspec::mpc_lintsrc);
#[derive(Copy, Clone, Default)]
struct MpfIntel(mpspec::mpf_intel);

// These `mpspec` wrapper types are POD (Plain Old Data), so reading
// them from data a slice of u8 (which is what ByteValued offers) is
// safe.
unsafe impl ByteValued for MpcBus {}
unsafe impl ByteValued for MpcCpu {}
unsafe impl ByteValued for MpcIntsrc {}
unsafe impl ByteValued for MpcIoapic {}
unsafe impl ByteValued for MpcTable {}
unsafe impl ByteValued for MpcLintsrc {}
unsafe impl ByteValued for MpfIntel {}

// Convenience macro for making arrays of diverse character types.
macro_rules! char_array {
    ($t:ty; $( $c:expr ),*) => ( [ $( $c as $t ),* ] )
}

// Most of these variables are sourced from the Intel MP Spec 1.4.
const SMP_MAGIC_IDENT: [c_char; 4] =
	char_array!(c_char; '_', 'M', 'P', '_');
const MPC_SIGNATURE: [c_char; 4] =
	char_array!(c_char; 'P', 'C', 'M', 'P');
const MPC_SPEC: i8 = 4;
const MPC_OEM: [c_char; 8] =
	char_array!(c_char; 'p', 'a', 'n', 'o', 'r', 'a', 'm', 'a');
const MPC_PRODUCT_ID: [c_char; 12] = ['0' as c_char; 12];
const BUS_TYPE_ISA: [u8; 6] =
	char_array!(u8; 'I', 'S', 'A', ' ', ' ', ' ');
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;

fn compute_checksum<T: Copy>(v: &T) -> u8 {
	// Safe because we are only reading the bytes within the size of
	// the `T` reference `v`.
	let v_slice = unsafe {
		slice::from_raw_parts(
			v as *const T as *const u8,
			mem::size_of::<T>(),
		)
	};

	v_slice.iter().fold(0, |acc, i| acc.wrapping_add(*i))
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
	let checksum = compute_checksum(v).wrapping_sub(v.checksum);
	(!checksum).wrapping_add(1)
}

#[derive(Debug, Clone, Copy)]
pub struct MpTable {
	irq_num: u8,
	cpu_num: u8,
}

impl MpTable {
	pub fn new(
		cpu_num: u8,
		max_irq: u8,
	) -> Result<Self, PanoramaError> {
		let irq_num =
			max_irq.checked_add(1).ok_or(PanoramaError::MpTable)?;
		Ok(Self { cpu_num, irq_num })
	}

	/// The size of this MP table based on its configuration.
	fn size(&self) -> usize {
		mem::size_of::<MpfIntel>()
			+ mem::size_of::<MpcTable>()
			+ mem::size_of::<MpcCpu>() * (self.cpu_num as usize)
			+ mem::size_of::<MpcIoapic>()
			+ mem::size_of::<MpcBus>()
			+ mem::size_of::<MpcIntsrc>() * (self.irq_num as usize)
			+ mem::size_of::<MpcLintsrc>() * 2
	}

	pub fn write(&self, mem: &Memory) -> Result<(), PanoramaError> {
		let mem = mem.inner();

		// Used to keep track of the next base pointer into the MP
		// table.
		let mut base_mp = GuestAddress(EBDA_START);
		let mp_size = self.size();
		// The checked_add here ensures the all of the following
		// base_mp.unchecked_add's will be without overflow.
		// Also throughout this function we're regularly using `as
		// u8`. These conversions are safe because both the values and
		// the fields that we are initializing with those values
		// are provided by the Linux kernel, and they're used as
		// intended.
		let Some(end_mp) = base_mp.checked_add((mp_size - 1) as u64)
		else {
			return Err(PanoramaError::MpTable);
		};

		if !mem.address_in_range(end_mp) {
			return Err(PanoramaError::MpTable);
		}

		let mut checksum: u8 = 0;
		let max_ioapic_id = self.cpu_num + 1;

		#[allow(deprecated)]
		mem.read_from(base_mp, &mut io::repeat(0), mp_size)?;

		{
			let size = mem::size_of::<MpfIntel>() as u64;
			let mut mpf_intel = MpfIntel(mpspec::mpf_intel {
				signature: SMP_MAGIC_IDENT,
				length: 1,
				specification: MPC_SPEC as u8,
				// The conversion to u32 is safe because the Base MP
				// address is the MPTABLE_START = 0x9fc00 and the size
				// of MpfIntel is 16 bytes. This value is much smaller
				// that u32::MAX.
				physptr: (base_mp.raw_value() + size) as u32,
				..Default::default()
			});
			mpf_intel.0.checksum =
				mpf_intel_compute_checksum(&mpf_intel.0);
			mem.write_obj(mpf_intel, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
		}

		// We set the location of the mpc_table here but we can't fill
		// it out until we have the length of the entire table later.
		let table_base = base_mp;
		base_mp =
			base_mp.unchecked_add(mem::size_of::<MpcTable>() as u64);

		{
			let size = mem::size_of::<MpcCpu>() as u64;
			for cpu_id in 0..self.cpu_num {
				let mpc_cpu = MpcCpu(mpspec::mpc_cpu {
					type_: mpspec::MP_PROCESSOR as u8,
					apicid: cpu_id,
					apicver: APIC_VERSION,
					cpuflag: mpspec::CPU_ENABLED as u8
						| if cpu_id == 0 {
							mpspec::CPU_BOOTPROCESSOR as u8
						} else {
							0
						},
					cpufeature: CPU_STEPPING,
					featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
					..Default::default()
				});
				mem.write_obj(mpc_cpu, base_mp)?;
				base_mp = base_mp.unchecked_add(size);
				checksum = checksum
					.wrapping_add(compute_checksum(&mpc_cpu.0));
			}
		}
		{
			let size = mem::size_of::<MpcBus>() as u64;
			let mpc_bus = MpcBus(mpspec::mpc_bus {
				type_: mpspec::MP_BUS as u8,
				busid: 0,
				bustype: BUS_TYPE_ISA,
			});
			mem.write_obj(mpc_bus, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
			checksum =
				checksum.wrapping_add(compute_checksum(&mpc_bus.0));
		}
		{
			let size = mem::size_of::<MpcIoapic>() as u64;
			let mpc_ioapic = MpcIoapic(mpspec::mpc_ioapic {
				type_: mpspec::MP_IOAPIC as u8,
				apicid: max_ioapic_id,
				apicver: APIC_VERSION,
				flags: mpspec::MPC_APIC_USABLE as u8,
				apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
			});
			mem.write_obj(mpc_ioapic, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
			checksum = checksum
				.wrapping_add(compute_checksum(&mpc_ioapic.0));
		}
		// Per kvm_setup_default_irq_routing() in kernel
		for i in 0..self.irq_num {
			let size = mem::size_of::<MpcIntsrc>() as u64;
			let mpc_intsrc = MpcIntsrc(mpspec::mpc_intsrc {
				type_: mpspec::MP_INTSRC as u8,
				irqtype: mpspec::mp_irq_source_types_mp_INT as u8,
				irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
				srcbus: 0,
				srcbusirq: i,
				dstapic: max_ioapic_id,
				dstirq: i,
			});
			mem.write_obj(mpc_intsrc, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
			checksum = checksum
				.wrapping_add(compute_checksum(&mpc_intsrc.0));
		}
		{
			let size = mem::size_of::<MpcLintsrc>() as u64;
			let mpc_lintsrc = MpcLintsrc(mpspec::mpc_lintsrc {
				type_: mpspec::MP_LINTSRC as u8,
				irqtype: mpspec::mp_irq_source_types_mp_ExtINT as u8,
				irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
				srcbusid: 0,
				srcbusirq: 0,
				destapic: 0,
				destapiclint: 0,
			});

			mem.write_obj(mpc_lintsrc, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
			checksum = checksum
				.wrapping_add(compute_checksum(&mpc_lintsrc.0));
		}
		{
			let size = mem::size_of::<MpcLintsrc>() as u64;
			let mpc_lintsrc = MpcLintsrc(mpspec::mpc_lintsrc {
				type_: mpspec::MP_LINTSRC as u8,
				irqtype: mpspec::mp_irq_source_types_mp_NMI as u8,
				irqflag: mpspec::MP_IRQDIR_DEFAULT as u16,
				srcbusid: 0,
				srcbusirq: 0,
				destapic: 0xFF, /* to all local APICs */
				destapiclint: 1,
			});

			mem.write_obj(mpc_lintsrc, base_mp)?;
			base_mp = base_mp.unchecked_add(size);
			checksum = checksum
				.wrapping_add(compute_checksum(&mpc_lintsrc.0));
		}

		// At this point we know the size of the mp_table.
		let table_end = base_mp;

		{
			let mut mpc_table = MpcTable(mpspec::mpc_table {
				signature: MPC_SIGNATURE,
				// It's safe to use unchecked_offset_from because
				// table_end > table_base. Also, the conversion to u16
				// is safe because the length of the table is in the
				// order of thousands for the maximum number of cpus
				// and maximum number of IRQs that we allow ( length =
				// 5328), which fits in a u16.
				length: table_end.unchecked_offset_from(table_base)
					as u16,
				spec: MPC_SPEC,
				oem: MPC_OEM,
				productid: MPC_PRODUCT_ID,
				lapic: APIC_DEFAULT_PHYS_BASE,
				..Default::default()
			});
			checksum =
				checksum.wrapping_add(compute_checksum(&mpc_table.0));
			mpc_table.0.checksum = (!checksum).wrapping_add(1) as i8;
			mem.write_obj(mpc_table, table_base)?;
		}

		Ok(())
	}
}
