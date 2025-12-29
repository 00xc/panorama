use crate::defs::layout::{BOOT_GDT_ADDR, BOOT_IDT_ADDR};
use crate::defs::msr::*;
use crate::defs::pvh::PVH_INFO_START;
use crate::memory::Memory;
use crate::x86::{Cr0, Register};
use crate::{BootInfo, BootProtocol, PanoramaError};

use kvm_bindings::bindings::__u32;
use kvm_bindings::{
	kvm_clock_data, kvm_debugregs, kvm_fpu, kvm_guest_debug,
	kvm_irqchip, kvm_lapic_state, kvm_mp_state, kvm_msr_entry,
	kvm_pit_config, kvm_pit_state2, kvm_regs, kvm_sregs,
	kvm_userspace_memory_region, kvm_vcpu_events, kvm_xcrs,
	kvm_xsave, CpuId, Msrs, KVM_CLOCK_TSC_STABLE,
	KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP, KVM_IRQCHIP_IOAPIC,
	KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
	KVM_MAX_CPUID_ENTRIES, KVM_MEM_LOG_DIRTY_PAGES,
	KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Cap, Kvm, SyncReg, VcpuExit, VcpuFd, VmFd};
use lapic::LocalApic;
use std::mem::{self, size_of};
use std::num::NonZeroU8;
use vm_memory::guest_memory::{GuestMemory, GuestMemoryRegion};
use vm_memory::Address;
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub struct Vm {
	pub fd: VmFd,
	pub cpus: Vec<Vcpu>,
	cpuid: CpuId,
	has_tsc_timer: bool,
	// TODO: dirty msrs
}

impl Vm {
	pub fn new(kvm: &Kvm) -> Result<Self, PanoramaError> {
		let fd = kvm.create_vm()?;
		let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
		let has_tsc_timer =
			kvm.check_extension(Cap::TscDeadlineTimer);
		Ok(Self {
			fd,
			cpus: Vec::new(),
			cpuid,
			has_tsc_timer,
		})
	}

	pub fn create_vcpus(
		&mut self,
		num_cpus: NonZeroU8,
		info: BootInfo,
		memory: &Memory,
	) -> Result<(), PanoramaError> {
		self.cpus.reserve(num_cpus.get() as usize);

		for id in 0..num_cpus.into() {
			let mut cpu = Vcpu::new(&self.fd, id)?;

			let cpuid = self.get_vcpu_cpuid(id, num_cpus);
			cpu.fd.set_cpuid2(&cpuid)?;
			cpu.init_regs(info)?;
			cpu.init_msrs()?;
			cpu.init_sregs(info, memory)?;
			cpu.init_lapic()?;
			cpu.init_fpu()?;

			self.cpus.push(cpu);
		}
		Ok(())
	}

	fn get_vcpu_cpuid(&self, id: u8, num_cpus: NonZeroU8) -> CpuId {
		const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8;
		const EBX_NCPUS_SHIFT: u32 = 16;
		const EBX_APICID_SHIFT: u32 = 24;
		const ECX_EPB_SHIFT: u32 = 3;
		const ECX_TSC_TIMER_SHIFT: u32 = 24;
		const ECX_HV_SHIFT: u32 = 31;
		const EDX_HTT_SHIFT: u32 = 28;

		let num_cpus = num_cpus.get();
		let mut cpuid = self.cpuid.clone();
		for entry in cpuid.as_mut_slice().iter_mut() {
			match entry.function {
				0x01 => {
					// X86 hypervisor feature.
					// TODO: why index == 0 only?
					if entry.index == 0 {
						entry.ecx |= 1 << ECX_HV_SHIFT;
					}

					// The TSC deadline timer feature (CPUID leaf 1,
					// ecx[24]) is always returned as false from
					// KVM_GET_SUPPORTED_CPUID, since the feature
					// depends on KVM_CREATE_IRQCHIP for local APIC
					// support.
					if self.has_tsc_timer {
						entry.ecx |= 1 << ECX_TSC_TIMER_SHIFT;
					}

					// TODO: why not OR?
					entry.ebx = (id as u32) << EBX_APICID_SHIFT;
					entry.ebx |= 8 << EBX_CLFLUSH_SIZE_SHIFT;
					entry.ebx |= (num_cpus as u32) << EBX_NCPUS_SHIFT;

					let htt = (num_cpus > 1) as u32;
					entry.edx |= htt << EDX_HTT_SHIFT;
				}
				0x06 => {
					// Clear X86 EPB feature. No frequency selection
					// in the hypervisor.
					entry.ecx &= !(1 << ECX_EPB_SHIFT);
				}
				0x0A => {
					// If the host has perf system running,
					// but no architectural events available
					// through kvm pmu -- disable perf support,
					// thus guest won't even try to access msr
					// registers.
					entry.eax = 0;
					/*if entry.eax != 0 {
						if entry.eax & 0xff != 2
							|| entry.eax & 0xff00 == 0
						{
							entry.eax = 0;
						}
					}*/
				}
				0x0B => {
					// EDX bits 31..0 contain x2APIC ID of current
					// logical processor.
					entry.edx = id as u32;
				}
				_ => (),
			}
		}
		cpuid
	}

	pub fn setup_irq(&mut self) -> Result<(), PanoramaError> {
		self.fd.create_irq_chip()?;

		let pit_config = kvm_pit_config {
			flags: KVM_PIT_SPEAKER_DUMMY,
			..Default::default()
		};
		self.fd.create_pit2(pit_config)?;

		Ok(())
	}

	/// Sets up the specified memory regions in KVM.
	pub fn setup_mem(
		&mut self,
		mem: &Memory,
	) -> Result<(), PanoramaError> {
		println!("KVM memory regions:");
		for (i, region) in mem.inner().iter().enumerate() {
			println!(
				"\t0x{:09x} size: 0x{:x}",
				region.start_addr().raw_value(),
				region.size()
			);
			let kregion = kvm_userspace_memory_region {
				slot: i as u32,
				guest_phys_addr: region.start_addr().raw_value(),
				memory_size: region.len(),
				userspace_addr: region.as_ptr() as u64,
				flags: KVM_MEM_LOG_DIRTY_PAGES,
			};
			unsafe {
				self.fd.set_user_memory_region(kregion)?;
			}
		}
		Ok(())
	}

	pub fn register_irqfd(
		&self,
		fd: &EventFd,
		gsi: u32,
	) -> Result<(), PanoramaError> {
		self.fd.register_irqfd(fd, gsi)?;
		Ok(())
	}

	pub fn get_dirty_log(
		&self,
		slot: u32,
		size: usize,
	) -> Result<Vec<u64>, PanoramaError> {
		Ok(self.fd.get_dirty_log(slot, size)?)
	}

	pub fn run(&mut self) -> Result<VcpuExit<'_>, PanoramaError> {
		// SAFETY: if you called this without .create_vcpus() first
		// fuck you
		let cpu = unsafe { self.cpus.get_unchecked_mut(0) };
		// Always sync regular registers
		cpu.run()
	}

	pub fn snapshot(&self) -> Result<VmSnapshot, PanoramaError> {
		VmSnapshot::new(self)
	}

	pub fn restore(
		&mut self,
		snapshot: &VmSnapshot,
	) -> Result<(), PanoramaError> {
		snapshot.restore(self)
	}
}

pub struct VmSnapshot {
	pit: kvm_pit_state2,
	master_pic: kvm_irqchip,
	slave_pic: kvm_irqchip,
	ioapic: kvm_irqchip,
	clock: kvm_clock_data,
	pub vcpus: Vec<VcpuSnapshot>,
}

impl VmSnapshot {
	#[inline]
	fn get_irqchip(
		vm: &VmFd,
		chip_id: __u32,
	) -> Result<kvm_irqchip, PanoramaError> {
		let mut pic = kvm_irqchip {
			chip_id,
			..Default::default()
		};
		vm.get_irqchip(&mut pic)?;
		Ok(pic)
	}

	pub fn new(vm: &Vm) -> Result<Self, PanoramaError> {
		// This bit is not accepted in SET_CLOCK, clear it.
		let mut clock = vm.fd.get_clock()?;
		clock.flags &= !KVM_CLOCK_TSC_STABLE;

		let vcpus = vm
			.cpus
			.iter()
			.map(Vcpu::snapshot)
			.collect::<Result<Vec<_>, PanoramaError>>()?;

		Ok(Self {
			pit: vm.fd.get_pit2()?,
			master_pic: Self::get_irqchip(
				&vm.fd,
				KVM_IRQCHIP_PIC_MASTER,
			)?,
			slave_pic: Self::get_irqchip(
				&vm.fd,
				KVM_IRQCHIP_PIC_SLAVE,
			)?,
			ioapic: Self::get_irqchip(&vm.fd, KVM_IRQCHIP_IOAPIC)?,
			clock,
			vcpus,
		})
	}

	pub fn restore(&self, vm: &mut Vm) -> Result<(), PanoramaError> {
		for (cpu, snap) in vm.cpus.iter_mut().zip(&self.vcpus) {
			cpu.restore(snap)?;
		}
		vm.fd.set_pit2(&self.pit)?;
		vm.fd.set_irqchip(&self.master_pic)?;
		vm.fd.set_irqchip(&self.slave_pic)?;
		vm.fd.set_irqchip(&self.ioapic)?;
		vm.fd.set_clock(&self.clock)?;
		Ok(())
	}
}

#[derive(Debug)]
pub struct Vcpu {
	id: u8,
	pub fd: VcpuFd,
}

impl Vcpu {
	fn new(vmfd: &VmFd, id: u8) -> Result<Self, PanoramaError> {
		let fd = vmfd.create_vcpu(id as u64)?;
		let cpu = Self { id, fd };
		Ok(cpu)
	}

	pub fn enable_debug(&self) -> Result<(), PanoramaError> {
		let dbg = kvm_guest_debug {
			control: KVM_GUESTDBG_ENABLE
				//| KVM_GUESTDBG_USE_SW_BP
				| kvm_bindings::KVM_GUESTDBG_USE_HW_BP
				| kvm_bindings::KVM_GUESTDBG_SINGLESTEP,
			pad: 0,
			arch: kvm_bindings::kvm_guest_debug_arch {
				debugreg: [0, 0, 0, 0, 0, 0, 0, 0x400],
			},
			//arch: Default::default(),
		};
		self.fd.set_guest_debug(&dbg)?;
		Ok(())
	}

	fn run(&mut self) -> Result<VcpuExit<'_>, PanoramaError> {
		self.fd.set_sync_valid_reg(SyncReg::Register);
		let exit = self.fd.run()?;
		// self.fd.kvmclock_ctrl()?;
		Ok(exit)
	}

	fn init_msrs(&self) -> Result<(), PanoramaError> {
		let msr_entry = |index, data| kvm_msr_entry {
			index,
			data,
			..Default::default()
		};

		let msrs = [
			msr_entry(MSR_IA32_SYSENTER_CS, 0),
			msr_entry(MSR_IA32_SYSENTER_ESP, 0),
			msr_entry(MSR_IA32_SYSENTER_EIP, 0),
			msr_entry(MSR_STAR, 0),
			msr_entry(MSR_CSTAR, 0),
			msr_entry(MSR_KERNEL_GS_BASE, 0),
			msr_entry(MSR_SYSCALL_MASK, 0),
			msr_entry(MSR_LSTAR, 0),
			msr_entry(MSR_IA32_TSC, 0),
			msr_entry(
				MSR_IA32_MISC_ENABLE,
				1 << MSR_IA32_MISC_ENABLE_FAST_STRING_BIT,
			),
		];

		let msrs = Msrs::from_entries(&msrs)?;
		let nmsrs = self.fd.set_msrs(&msrs)?;

		if nmsrs != msrs.as_fam_struct_ref().nmsrs as usize {
			return Err(PanoramaError::MsrInit);
		}

		Ok(())
	}

	/// Initialize the registers for this CPU according to the
	/// expected initial state for the corresponding boot protocol.
	fn init_regs(
		&mut self,
		info: BootInfo,
	) -> Result<(), PanoramaError> {
		match info.protocol {
			// https://xenbits.xen.org/docs/unstable/misc/pvh.html
			BootProtocol::Pvh => {
				// * ebx: contains the physical memory address where
				//   the loader has placed the boot start info
				//   structure.
				// * eflags: bit 17 (VM) must be cleared. Bit 9
				//   (IF) must be cleared. Bit 8 (TF) must be
				//   cleared. Other bits are all unspecified.
				self.set_reg(Register::Rflags, 0x0000_0000_0000_0002);
				self.set_reg(
					Register::Rbx,
					PVH_INFO_START.raw_value(),
				);
				self.set_reg(Register::Rip, info.entry.raw_value());
			}
			BootProtocol::Linux => todo!(),
		};

		Ok(())
	}

	fn init_sregs(
		&mut self,
		info: BootInfo,
		mem: &Memory,
	) -> Result<(), PanoramaError> {
		use crate::gdt::{
			gdt_entry, kvm_segment_from_gdt, write_gdt_table,
			write_idt_value,
		};

		let mut sregs = self.fd.get_sregs()?;

		match info.protocol {
			BootProtocol::Pvh => {
				let gdt = [
					gdt_entry(0, 0, 0),                // NULL
					gdt_entry(0xc09b, 0, 0xffff_ffff), // CODE
					gdt_entry(0xc093, 0, 0xffff_ffff), // DATA
					gdt_entry(0x008b, 0, 0x67),        // TSS
				];

				let cs = kvm_segment_from_gdt(gdt[1], 1);
				let ds = kvm_segment_from_gdt(gdt[2], 2);
				let tss = kvm_segment_from_gdt(gdt[3], 3);

				// * cs: must be a 32-bit read/execute code segment
				//   with a base of ‘0’ and a limit of ‘0xFFFFFFFF’.
				//   The selector value is unspecified.
				sregs.cs = cs;

				// * ds, es, ss: must be a 32-bit read/write data
				//   segment with a base of ‘0’ and a limit
				//   of ‘0xFFFFFFFF’. The selector values are all
				//   unspecified.
				sregs.ds = ds;
				sregs.es = ds;
				sregs.fs = ds;
				sregs.gs = ds;
				sregs.ss = ds;

				// * tr: must be a 32-bit TSS (active) with a base
				//   of ‘0’ and a limit of ‘0x67’.
				sregs.tr = tss;

				// Write GDT to memory
				write_gdt_table(&gdt, mem)?;
				sregs.gdt.base = BOOT_GDT_ADDR.raw_value();
				sregs.gdt.limit = mem::size_of_val(&gdt) as u16 - 1;

				// Write IDT to memory
				write_idt_value(0, mem)?;
				sregs.idt.base = BOOT_IDT_ADDR.raw_value();
				sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

				// * cr0: bit 0 (PE) must be set. All the other
				//   writeable bits are cleared. NOTE: ET is always
				//   set.
				sregs.cr0 = (Cr0::PE | Cr0::ET).bits();

				// * cr4: all bits are cleared.
				sregs.cr4 = 0;
			}
			BootProtocol::Linux => todo!("Linux boot protocol"),
		}

		self.set_sregs_sync(sregs);
		Ok(())
	}

	/// Configures the local APIC to deliver LINT0 via external
	/// interrupt and LINT1 via NMI.
	fn init_lapic(&self) -> Result<(), PanoramaError> {
		let raw_lapic = self.fd.get_lapic()?;

		assert_eq!(
			size_of::<kvm_lapic_state>(),
			size_of::<LocalApic>()
		);

		// SAFETY: both types have the same size and no invalid
		// representations.
		let mut lapic =
			unsafe { mem::transmute::<_, LocalApic>(raw_lapic) };

		// Interrupt 0 EVT: external interrupts
		lapic.lint0_lvt.set_delivery_mode(7);
		// Interrupt 1 EVT: NMI
		lapic.lint1_lvt.set_delivery_mode(4);

		// SAFETY: We did not alter the layout, so transmuting back is
		// safe.
		let lapic =
			unsafe { mem::transmute::<_, kvm_lapic_state>(lapic) };

		self.fd.set_lapic(&lapic)?;
		Ok(())
	}

	fn init_fpu(&self) -> Result<(), PanoramaError> {
		let fpu = kvm_fpu {
			fcw: 0x37f,
			mxcsr: 0x1f80,
			..Default::default()
		};
		self.fd.set_fpu(&fpu)?;
		Ok(())
	}

	/// Get regular registers from kvm_run without an ioctl
	pub fn get_regs_sync(&self) -> kvm_regs {
		self.fd.sync_regs().regs
		//self.fd.get_regs().unwrap()
	}

	/// Set regular registers via kvm_run without an ioctl
	#[inline(always)]
	fn set_regs_sync(&mut self, regs: kvm_regs) {
		/*self.fd.sync_regs_mut().regs = regs;
		self.fd.set_sync_dirty_reg(SyncReg::Register);*/
		self.fd.set_regs(&regs).unwrap();
	}

	/// Set system registers via kvm_run without an ioctl
	#[inline(always)]
	fn set_sregs_sync(&mut self, sregs: kvm_sregs) {
		/*self.fd.sync_regs_mut().sregs = sregs;
		self.fd.set_sync_dirty_reg(SyncReg::SystemRegister);*/
		self.fd.set_sregs(&sregs).unwrap();
	}

	/// Set cpu events via kvm_run without an ioctl
	#[inline(always)]
	pub fn set_events_sync(&mut self, events: kvm_vcpu_events) {
		/*self.fd.sync_regs_mut().events = events;
		self.fd.set_sync_dirty_reg(SyncReg::VcpuEvents);*/
		self.fd.set_vcpu_events(&events).unwrap();
	}

	#[inline]
	pub fn set_reg(&mut self, reg: Register, val: u64) {
		//let regs = self.fd.sync_regs_mut();
		let mut regs = self.fd.get_regs().unwrap();
		match reg {
			Register::Rax => regs.rax = val,
			Register::Rbx => regs.rbx = val,
			Register::Rcx => regs.rcx = val,
			Register::Rdx => regs.rdx = val,
			Register::Rsi => regs.rsi = val,
			Register::Rdi => regs.rdi = val,
			Register::Rsp => regs.rsp = val,
			Register::Rbp => regs.rbp = val,
			Register::R8 => regs.r8 = val,
			Register::R9 => regs.r9 = val,
			Register::R10 => regs.r10 = val,
			Register::R11 => regs.r11 = val,
			Register::R12 => regs.r12 = val,
			Register::R13 => regs.r13 = val,
			Register::R14 => regs.r14 = val,
			Register::R15 => regs.r15 = val,
			Register::Rip => regs.rip = val,
			Register::Rflags => regs.rflags = val,
		}
		//self.fd.set_sync_dirty_reg(SyncReg::Register);
		self.fd.set_regs(&regs).unwrap();
	}

	fn snapshot(&self) -> Result<VcpuSnapshot, PanoramaError> {
		VcpuSnapshot::new(self)
	}

	fn restore(
		&mut self,
		snapshot: &VcpuSnapshot,
	) -> Result<(), PanoramaError> {
		snapshot.restore(self)
	}
}

#[derive(Debug)]
pub struct VcpuSnapshot {
	id: u8,
	pub regs: kvm_regs,
	sregs: kvm_sregs,
	dregs: kvm_debugregs,
	fpu: kvm_fpu,
	lapic: kvm_lapic_state,
	events: kvm_vcpu_events,
	xcrs: kvm_xcrs,
	xsave: kvm_xsave,
	mpstate: kvm_mp_state,
	//cpuid: CpuId,
}

impl VcpuSnapshot {
	fn new(vcpu: &Vcpu) -> Result<Self, PanoramaError> {
		Ok(Self {
			id: vcpu.id,
			regs: vcpu.get_regs_sync(),
			sregs: vcpu.fd.get_sregs()?,
			events: vcpu.fd.get_vcpu_events()?,
			dregs: vcpu.fd.get_debug_regs()?,
			fpu: vcpu.fd.get_fpu()?,
			lapic: vcpu.fd.get_lapic()?,
			xcrs: vcpu.fd.get_xcrs()?,
			xsave: vcpu.fd.get_xsave()?,
			mpstate: vcpu.fd.get_mp_state()?,
			//cpuid: vcpu.fd.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?,
		})
	}

	fn restore(&self, vcpu: &mut Vcpu) -> Result<(), PanoramaError> {
		assert_eq!(self.id, vcpu.id);
		vcpu.set_regs_sync(self.regs);
		vcpu.set_sregs_sync(self.sregs);
		vcpu.set_events_sync(self.events);
		//vcpu.fd.set_vcpu_events(&self.events)?;
		vcpu.fd.set_debug_regs(&self.dregs)?;
		vcpu.fd.set_fpu(&self.fpu)?;
		vcpu.fd.set_lapic(&self.lapic)?;
		vcpu.fd.set_xcrs(&self.xcrs)?;
		// SAFETY: we check that this won't copy more than the size
		// of kvm_xsave
		unsafe { vcpu.fd.set_xsave(&self.xsave) }?;
		vcpu.fd.set_mp_state(self.mpstate)?;
		//vcpu.fd.set_cpuid2(&self.cpuid)?;
		Ok(())
	}
}
