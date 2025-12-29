//use crate::fuzz::Fuzzer;
use crate::fuzz::{Fuzzer, PFuzzer};
use crate::metrics::METRICS;
use crate::time_it;
use crate::timer::PTimer;
use crate::x86::Register;
use crate::{PanoramaError, Vmm, VmmSnapshot};

use kvm_bindings::{kvm_regs, kvm_run};
use std::ptr::{self, addr_of_mut};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Duration;
use vm_memory::GuestAddress;

const PANORAMA_MAGICK: u64 = 0x10410150666;

static KVM_RUN_PTR: AtomicPtr<kvm_run> =
	AtomicPtr::new(ptr::null_mut());

extern "C" fn handle_timer(_signal: libc::c_int) {
	let ptr = KVM_RUN_PTR.swap(ptr::null_mut(), Ordering::SeqCst);
	if !ptr.is_null() {
		let exit = unsafe { &raw mut (*ptr).immediate_exit };
		unsafe { exit.write_volatile(1) };
		KVM_RUN_PTR.store(ptr, Ordering::SeqCst);
	}
}

/// A type that tracks the state of the guest harness. It keeps
/// the snapshot requested by the guest, as well as the location of
/// the input buffer for the testcase.
pub struct GuestState {
	buf_gpa: GuestAddress,
	snapshot: Option<VmmSnapshot>,
	// pub fuzzer: NftFuzzer,
	pub fuzzer: Fuzzer,
	//pub fuzzer: crate::fuzz::Fuzzer,
	// TODO: maybe we can get rid of this Option
	timer: Option<PTimer>,
	ptr: *mut kvm_bindings::kvm_run,
}

impl GuestState {
	fn create_timer(&mut self, ptr: *mut kvm_bindings::kvm_run) {
		self.ptr = ptr;
		//KVM_RUN_PTR.store(ptr, Ordering::Release);
		let timer = PTimer::new(handle_timer, Duration::from_secs(2));
		assert!(self.timer.replace(timer).is_none());
	}

	pub fn take_timer(&mut self) -> Option<PTimer> {
		let mut timer = self.timer.take()?;
		timer.start();
		KVM_RUN_PTR.store(self.ptr, Ordering::SeqCst);
		Some(timer)
	}

	pub fn put_timer(&mut self, mut t: PTimer) {
		while KVM_RUN_PTR
			.compare_exchange_weak(
				self.ptr,
				ptr::null_mut(),
				Ordering::SeqCst,
				Ordering::SeqCst,
			)
			.is_err()
		{}
		t.stop();
		assert!(self.timer.replace(t).is_none());
	}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct PanoramaPayload {
	data: usize,
	len: u64,
}

unsafe impl vm_memory::bytes::ByteValued for PanoramaPayload {}

impl Vmm {
	pub fn handle_hypercall(&mut self) -> Result<(), PanoramaError> {
		let regs = self.vm.cpus[0].get_regs_sync();

		let res = match regs.rax {
			0 => self.handle_hypercall_init(),
			1 => self.handle_hypercall_set_payload(regs),
			2 => self.handle_hypercall_snapshot(),
			3 => self.handle_hypercall_restore(),
			_ => Ok(self.handle_hypercall_error()?),
		};

		if let Err(e) = res {
			println!("ERR: {:?}", e);
			self.handle_hypercall_error()?;
		}

		Ok(())
	}

	fn handle_hypercall_init(&mut self) -> Result<(), PanoramaError> {
		self.vm.cpus[0].set_reg(Register::Rax, PANORAMA_MAGICK);
		Ok(())
	}

	/// Initializes the guest state to keep track of the location of
	/// the input buffer.
	fn handle_hypercall_set_payload(
		&mut self,
		regs: kvm_regs,
	) -> Result<(), PanoramaError> {
		let metrics = &METRICS;

		println!(
			"[{:10.4}] Guest communicated payload buffer",
			metrics.in_fuzz().as_secs_f64(),
		);

		let gva = regs.rbx;
		let sregs = self.vm.cpus[0].fd.get_sregs()?;
		let cr3 = sregs.cr3;

		// Read the payload
		let gpa = self.memory.gva2gpa(cr3, gva)?;
		let payload =
			self.memory.read_phys::<PanoramaPayload>(gpa)?;
		println!(
			"[{:10.4}] payload: gva: 0x{:x} | gpa: 0x{:x}",
			metrics.in_fuzz().as_secs_f64(),
			gva,
			gpa.0
		);

		// Get the address of the data buffer
		let gpa = self.memory.gva2gpa(cr3, payload.data as u64)?;
		println!(
            "[{:10.4}] data:    gva: 0x{:x} | gpa: 0x{:x} (len = 0x{:x})",
            metrics.in_fuzz().as_secs_f64(),
            payload.data,
            gpa.0,
            payload.len,
        );

		// Update the guest state
		self.guest_state.replace(GuestState {
			buf_gpa: gpa,
			snapshot: None,
			fuzzer: Fuzzer::new(
				PANORAMA_MAGICK.wrapping_add(rand::random()),
				payload.len as usize,
				self.corpus_path.clone(),
			),
			timer: None,
			ptr: ptr::null_mut(),
		});

		self.vm.cpus[0].set_reg(Register::Rax, payload.len);
		Ok(())
	}

	fn handle_hypercall_snapshot(
		&mut self,
	) -> Result<(), PanoramaError> {
		let metrics = &METRICS;

		println!(
			"[{:10.4}] Guest requested snapshot",
			metrics.in_fuzz().as_secs_f64()
		);

		let Some(mut state) = self.guest_state.take() else {
			return self.handle_hypercall_error();
		};

		// Take the snapshot and make RIP point to the next
		// instruction, otherwise on restore the guest will request
		// another snapshot.
		self.vm.cpus[0].enable_debug()?;
		let (mut snapshot, t) = time_it!({ self.snapshot()? });
		let rip = snapshot.vm.vcpus[0].regs.rip;
		snapshot.vm.vcpus[0].regs.rip += 2;
		snapshot.vm.vcpus[0].regs.rax = 1;
		println!(
			"[{:10.4}] Snapshotted VM in {:?}",
			metrics.in_fuzz().as_secs_f64(),
			t
		);

		// Insert snapshot
		state.snapshot.replace(snapshot);

		// Prepare a timer
		let ptr = self.vm.cpus[0].fd.get_kvm_run();
		state.create_timer(ptr);

		// Save state back
		self.guest_state = Some(state);

		self.vm.cpus[0].set_reg(Register::Rax, 1);
		self.vm.cpus[0].set_reg(Register::Rip, rip + 2);
		self.vm.cpus[0].enable_debug()?;

		//crate::ENABLE_DBG.fetch_add(1, Ordering::SeqCst);
		//let _ = self.vm.cpus[0].enable_debug();
		Ok(())
	}

	/*fn init_coverage(
		&mut self,
		state: &mut GuestState,
	) -> Result<(), PanoramaError> {
		self.vm.cpus[0].enable_debug()?;

		let cr3 = self.vm.cpus[0].fd.get_sregs().unwrap().cr3;

		for sym in self.syms.syms() {
			/*if sym.name().starts_with("asm_") {
				continue;
			}*/
			let Ok(paddr) = self.memory.gva2gpa(cr3, sym.addr())
			else {
				continue;
			};
			let orig = self.memory.read_phys::<u8>(paddr)?;
			//self.memory.write_phys_nodirty::<u8>(paddr, &[0xcc])?;
			state.fuzzer.insert_cov(sym.addr(), orig);
		}

		Ok(())
	}*/

	fn handle_hypercall_restore(
		&mut self,
	) -> Result<(), PanoramaError> {
		let metrics = &METRICS;
		let resets = metrics.update_reset();

		let rbx = self.vm.cpus[0].get_regs_sync().rbx;
		if rbx > 1 {
			println!("{:?}", rbx);
		}

		// Get the guest state. Take out of `guest_state` to please
		// the borrow checker.
		let Some(mut state) = self.guest_state.take() else {
			return self.handle_hypercall_error();
		};

		// Get the snapshot
		let Some(snapshot) = state.snapshot.as_ref() else {
			self.guest_state.replace(state);
			return self.handle_hypercall_error();
		};

		// Restore VM
		let (_, restore_time) = time_it!({ self.restore(snapshot)? });

		// Inject new input and communicate the length to the guest
		let buf = state.fuzzer.next_input(&self.syms);
		self.memory.write_phys_nodirty(state.buf_gpa, buf)?;
		self.vm.cpus[0].set_reg(Register::Rax, buf.len() as u64);

		if resets & 63 == 0 && resets != 0 {
			let in_fuzz = metrics.in_fuzz().as_secs_f64();
			let psec = resets as f64 / in_fuzz;
			let total = metrics.in_vmm() + metrics.in_guest();
			let ing = metrics.in_guest().as_secs_f64()
				/ total.as_secs_f64();
			let tid = std::thread::current().id();
			println!(
				"[{:10.4}] {:?}: Restored VM in {:>10.3?} ({} pages) | {:7} execs ({:4.4} / sec) | {:4.4?}% in guest",
				in_fuzz, tid, restore_time, metrics.restored_pages(),
				resets, psec, ing * 100.0,
			);

			state.fuzzer.save_all();
		}

		// Store the state back
		self.guest_state.replace(state);

		Ok(())
	}

	fn handle_hypercall_error(
		&mut self,
	) -> Result<(), PanoramaError> {
		self.vm.cpus[0].set_reg(Register::Rax, 0);
		Ok(())
	}
}
