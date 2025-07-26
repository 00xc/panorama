#![deny(missing_copy_implementations)]

mod bitmap;
mod boot;
mod defs;
mod devices;
mod error;
mod event_fd;
mod fuzz;
mod gdt;
mod hypercall;
mod memory;
mod metrics;
mod mptables;
mod pagetable;
mod symbols;
mod timer;
mod vm;
mod x86;

use crate::boot::{BootInfo, BootProtocol};
use crate::defs::{
    irq::{BLOCK_IRQ, KEYBOARD_IRQ, MAX_IRQ, SERIAL_IRQ},
    layout::{CMDLINE_ADDR, MMIO_GAP_SIZE, MMIO_GAP_START},
    CMDLINE_CAP, COM1_PORT, I8042_PORT,
};
use crate::devices::{
    block::{BlockConfig, BlockDevice, BlockDeviceSnapshot, BlockHandler, BlockType},
    keyboard::{KeyboardDevice, KeyboardDeviceSnapshot},
    serial::{SerialDevice, SerialDeviceSnapshot},
};
pub use crate::error::PanoramaError;
use crate::hypercall::GuestState;
use crate::memory::{Memory, MemorySnapshot};
use crate::metrics::METRICS;
use crate::mptables::MpTable;
use crate::symbols::KernelSyms;
use crate::vm::{Vm, VmSnapshot};

use event_manager::EventManager;
use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{Cap, IoEventAddress, Kvm, VcpuExit};
use linux_loader::cmdline::Cmdline;
use linux_loader::loader;
use once_cell::sync::Lazy;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use virtio_bindings::virtio_mmio::VIRTIO_MMIO_QUEUE_NOTIFY;
use vm_allocator::{AddressAllocator, AllocPolicy};
use vm_device::bus::{MmioAddress, MmioRange, PioAddress, PioRange};
use vm_device::device_manager::{IoManager, MmioManager, PioManager};
use vm_memory::address::Address;
use vm_memory::guest_memory::GuestAddress;

pub struct Vmm {
    _kvm: Kvm,
    vm: Vm,
    memory: Arc<Memory>,
    io_mgr: Arc<Mutex<IoManager>>,
    event_mgr: Option<EventManager<BlockHandler>>,
    cmdline: Cmdline,
    syms: KernelSyms,
    allocator: AddressAllocator,
    serial: Option<Arc<Mutex<SerialDevice>>>,
    keyboard: Option<Arc<Mutex<KeyboardDevice>>>,
    block: Option<Arc<Mutex<BlockDevice>>>,
    guest_state: Option<GuestState>,
    corpus_path: PathBuf,
}

impl Vmm {
    pub fn new<P: AsRef<Path>>(
        kernel: P,
        disk: P,
        mem_mib: usize,
        num_cpus: NonZeroU8,
        corp: P,
    ) -> Result<Self, PanoramaError> {
        let kvm = Kvm::new()?;
        let version = kvm.get_api_version();
        if version != KVM_API_VERSION as i32 {
            return Err(PanoramaError::KvmVersion(version));
        }
        if !kvm.check_extension(Cap::Irqchip) {
            return Err(PanoramaError::KvmNoIrq);
        }
        if !kvm.check_extension(Cap::Irqfd) {
            return Err(PanoramaError::KvmNoIrq);
        }
        if !kvm.check_extension(Cap::ImmediateExit) {
            return Err(PanoramaError::KvmNoImmExit);
        }
        if !kvm.check_extension(Cap::UserMemory) {
            return Err(PanoramaError::KvmNoUserMemory);
        }
        if !kvm.check_extension(Cap::SyncMmu) {
            return Err(PanoramaError::KvmNoSyncMmu);
        }
        if !kvm.check_extension(Cap::SyncRegs) {
            return Err(PanoramaError::KvmNoSyncMmu);
        }
        if kvm.check_extension_int(Cap::Xsave2)
            > std::mem::size_of::<kvm_bindings::kvm_xsave>() as i32
        {
            // TODO: use xsave2 FAM and avoid this entirely
            // This makes set_xsave() safe
            panic!("xsave too big");
        }

        let mut vm = Vm::new(&kvm)?;
        let memory = Arc::new(Memory::new(mem_mib << 20)?);
        let io_mgr = Arc::new(Mutex::new(IoManager::new()));
        let event_mgr = Some(EventManager::new()?);
        let allocator = AddressAllocator::new(MMIO_GAP_START, MMIO_GAP_SIZE)?;

        let mut cmdline = Cmdline::new(CMDLINE_CAP)?;
        cmdline.insert("panic", "-1")?;
        cmdline.insert("pci", "off")?;
        cmdline.insert("acpi", "off")?;
        cmdline.insert_str("quiet")?;
        cmdline.insert_str("i8042.noaux")?;
        cmdline.insert_str("i8042.nomux")?;
        cmdline.insert_str("i8042.nopnp")?;
        cmdline.insert_str("i8042.dumbkbd")?;
        cmdline.insert("msr.allow_writes", "off")?;
        //cmdline.insert("tsc", "reliable")?;
        cmdline.insert("oops", "panic")?;

        let syms = KernelSyms::new(&kernel)?;
        println!("Loaded {} kernel symbols", syms.len());

        // Initial VM setup
        vm.setup_mem(&memory)?;
        vm.setup_irq()?;

        let corpus_path = corp.as_ref().to_path_buf();

        // Initial VMM setup
        let mut vmm = Self {
            _kvm: kvm,
            vm,
            memory,
            io_mgr,
            event_mgr,
            serial: None,
            keyboard: None,
            block: None,
            cmdline,
            syms,
            allocator,
            guest_state: None,
            corpus_path,
        };
        vmm.early_init(kernel, disk, num_cpus)?;
        Ok(vmm)
    }

    /// Sets up the MP tables, registers devices, loads the cmdline
    /// and the kernel and initializes the vCPUs.
    fn early_init<P: AsRef<Path>>(
        &mut self,
        kernel: P,
        disk: P,
        num_cpus: NonZeroU8,
    ) -> Result<(), PanoramaError> {
        self.setup_mptables(num_cpus.get())?;
        self.register_devices(disk)?;
        self.load_cmdline()?;
        let bootinfo = self.load_kernel(kernel)?;
        self.vm.create_vcpus(num_cpus, bootinfo, &self.memory)?;

        let entry_loc = self
            .syms
            .location(bootinfo.entry.raw_value() + 0xffffffff80000000);
        println!(
            "Entry point: {:#x}: {}",
            bootinfo.entry.raw_value(),
            entry_loc,
        );

        Ok(())
    }

    fn setup_mptables(&self, num_cpus: u8) -> Result<(), PanoramaError> {
        MpTable::new(num_cpus, MAX_IRQ)?.write(&self.memory)
    }

    /// Registers the appropriate devices in KVM and updates the
    /// cmdline.
    fn register_devices<P: AsRef<Path>>(&mut self, disk: P) -> Result<(), PanoramaError> {
        // Serial console
        let serial = SerialDevice::new()?;
        self.register_serial_console(serial)?;

        // i8042 keyboard
        let keyboard = KeyboardDevice::new()?;
        self.register_i8042_device(keyboard)?;

        // Virtio block device
        let block = BlockDevice::new(
            BlockConfig {
                path: disk,
                read_only: false,
                flush: true,
            },
            self.event_mgr.as_ref().unwrap(),
            self.memory.clone(),
        )?;
        self.register_block_device(block)?;

        Ok(())
    }

    /// Register a generic MMIO device. Does not perform IRQ fd
    /// registration against KVM.
    fn register_mmio(
        &mut self,
        irq: u32,
        size: u64,
        dev: <IoManager as MmioManager>::D,
    ) -> Result<MmioRange, PanoramaError> {
        // Allocate an MMIO range
        let range = self.allocator.allocate(size, 4, AllocPolicy::FirstMatch)?;

        // Register the address range for the device
        let start = MmioAddress(range.start());
        let mmio_range = MmioRange::new(start, range.len())?;
        self.io_mgr.lock().unwrap().register_mmio(mmio_range, dev)?;

        // Add to cmdline
        self.cmdline.add_virtio_mmio_device(
            mmio_range.size(),
            GuestAddress(mmio_range.base().0),
            irq,
            None,
        )?;

        Ok(mmio_range)
    }

    fn register_block_device(&mut self, block: BlockDevice) -> Result<(), PanoramaError> {
        // Register IRQ
        self.vm.register_irqfd(block.irqfd(), BLOCK_IRQ)?;

        // Register MMIO
        let block = Arc::new(Mutex::new(block));
        let mmio_range = self.register_mmio(BLOCK_IRQ, 0x1000, block.clone())?;

        let guard = block.lock().unwrap();

        // Register I/O events for queues
        // TODO: we might have to do this later instead?
        let notify_addr = mmio_range.base().0 + VIRTIO_MMIO_QUEUE_NOTIFY as u64;
        for (i, fd) in guard.iofds().iter().enumerate() {
            self.vm.fd.register_ioevent(
                fd,
                &IoEventAddress::Mmio(notify_addr),
                u32::try_from(i).unwrap(),
            )?;
        }

        // Extra cmdline arguments
        self.cmdline
            .insert_str(guard.cmdline_config(BlockType::Root))?;

        // Keep reference to device
        drop(guard);
        self.block = Some(block);

        Ok(())
    }

    fn register_pio(
        &self,
        range: PioRange,
        dev: <IoManager as PioManager>::D,
    ) -> Result<(), PanoramaError> {
        Ok(self.io_mgr.lock().unwrap().register_pio(range, dev)?)
    }

    fn register_serial_console(&mut self, serial: SerialDevice) -> Result<(), PanoramaError> {
        // Register IRQ
        self.vm.register_irqfd(serial.irqfd(), SERIAL_IRQ)?;

        // Extra cmdline arguments
        self.cmdline.insert_str(serial.cmdline_config())?;

        // Register port I/O
        let serial = Arc::new(Mutex::new(serial));
        let pio_range = PioRange::new(PioAddress(COM1_PORT), 0x8)?;
        self.register_pio(pio_range, serial.clone())?;

        // Keep reference to device
        self.serial = Some(serial);
        Ok(())
    }

    fn register_i8042_device(&mut self, keyboard: KeyboardDevice) -> Result<(), PanoramaError> {
        // Register IRQ
        self.vm.register_irqfd(keyboard.irqfd(), KEYBOARD_IRQ)?;

        // Register port I/O
        let keyboard = Arc::new(Mutex::new(keyboard));
        let pio_range = PioRange::new(PioAddress(I8042_PORT), 0x5)?;
        self.register_pio(pio_range, keyboard.clone())?;

        // Keep reference to device
        self.keyboard = Some(keyboard);
        Ok(())
    }

    fn load_cmdline(&self) -> Result<(), PanoramaError> {
        loader::load_cmdline(self.memory.inner(), CMDLINE_ADDR, &self.cmdline)?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), PanoramaError> {
        // The event loop thread
        fn event_worker(
            mut mgr: EventManager<BlockHandler>,
            stop: &AtomicBool,
        ) -> Result<EventManager<BlockHandler>, PanoramaError> {
            while !stop.load(Ordering::Acquire) {
                mgr.run()?;
            }
            println!("Event manager done");
            Ok(mgr)
        }

        Lazy::force(&METRICS);

        let stop = AtomicBool::new(false);

        // Run the VM exit loop in parallel to the event thread.
        std::thread::scope(|s| -> Result<(), PanoramaError> {
            let event_mgr = self.event_mgr.take().unwrap();
            // Start the event thread
            let handle = s.spawn(|| event_worker(event_mgr, &stop));
            // Run the loop until done
            let res = self.vm_loop();
            stop.store(true, Ordering::Release);
            // Wait for the thread to exit
            self.event_mgr = Some(handle.join().unwrap()?);
            res
        })
    }

    fn vm_loop(&mut self) -> Result<(), PanoramaError> {
        let metrics = &METRICS;
        let mut in_vmm = Instant::now();

        let tsc = self.vm.cpus[0].fd.get_tsc_khz().unwrap();
        self.vm.cpus[0].fd.set_tsc_khz(tsc / 2).unwrap();

        loop {
            let exit = loop {
                // No longer in VMM, stop timer
                metrics.update_in_vmm(in_vmm.elapsed());

                // Run the VM, enabling and disabling the alarm timer.
                let (exit, in_guest) = crate::time_it!({
                    self.vm.cpus[0].fd.set_kvm_immediate_exit(0);
                    /*if ENABLE_DBG.load(Ordering::SeqCst) == 1 {
                        let _ = self.vm.cpus[0].enable_debug();
                        ENABLE_DBG.fetch_add(1, Ordering::SeqCst);
                    }*/
                    let mut timer = self.guest_state.as_mut().and_then(GuestState::take_timer);
                    /*if timer.is_some() {
                        self.vm.cpus[0].enable_debug()?;
                    }*/
                    let exit = self.vm.run();
                    if let Some(t) = timer.take() {
                        self.guest_state.as_mut().unwrap().put_timer(t);
                    }
                    exit
                });

                // Back to VMM, update timers
                metrics.update_in_guest(in_guest);
                in_vmm = Instant::now();

                // If the exit is Ok handle it below. If it is EINTR
                // we timed out. Otherwise return it.
                match exit {
                    Ok(exit) => break exit,
                    Err(PanoramaError::KvmIoctl(e)) => {
                        if e.errno() != libc::EINTR {
                            return Err(PanoramaError::KvmIoctl(e));
                        }
                        // Timed out
                        println!("VM timed out");

                        let regs = self.vm.cpus[0].get_regs_sync();
                        println!("regs: {:x?}", regs);

                        let loc = self.syms.location(regs.rip);
                        println!("{}", loc);

                        if let Some(state) = self.guest_state.as_mut() {
                            state.fuzzer.save_last();
                        };

                        return Err(PanoramaError::KvmIoctl(e));
                    }
                    _ => unreachable!(),
                }
            };

            match exit {
                VcpuExit::IoOut(34, _) => {
                    self.handle_hypercall()?;
                }
                VcpuExit::IoOut(addr, data) => {
                    let addr = PioAddress(addr);
                    // TODO: log err
                    let _ = self.io_mgr.lock().unwrap().pio_write(addr, data);
                }
                VcpuExit::IoIn(addr, data) => {
                    let addr = PioAddress(addr);
                    // TODO: log err
                    let _ = self.io_mgr.lock().unwrap().pio_read(addr, data);
                }
                VcpuExit::MmioRead(addr, data) => {
                    let addr = MmioAddress(addr);
                    // TODO: log err
                    let _ = self.io_mgr.lock().unwrap().mmio_read(addr, data);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    let addr = MmioAddress(addr);
                    // TODO: log err
                    let _ = self.io_mgr.lock().unwrap().mmio_write(addr, data);
                }
                VcpuExit::Debug(dbg) => {
                    use crate::fuzz::PFuzzer;
                    if let Some(state) = self.guest_state.as_mut() {
                        let rip = self.vm.cpus[0].get_regs_sync().rip;
                        state.fuzzer.visit_addr(rip);
                        //println!("0x{rip:x} | {}", self.syms.location(rip));
                    }
                }
                _ => {
                    println!("Unhandled exit: {:x?}", exit);
                    break;
                }
            };

            /*if ENABLE_DBG.load(Ordering::SeqCst) > 0 {
                if let Some(state) = self.guest_state.as_mut() {
                    let rip = self.vm.cpus[0].get_regs_sync().rip;
                    state.fuzzer.visit_addr(rip);
                };
            }*/
        }

        let regs = self.vm.cpus[0].get_regs_sync();
        println!("Regs: {:x?}", regs);
        println!("Sregs: {:x?}", self.vm.cpus[0].fd.get_sregs()?);
        let loc = self.syms.location(regs.rip);
        println!("Exited with RIP = {}", loc);

        Ok(())
    }

    pub fn snapshot(&self) -> Result<VmmSnapshot, PanoramaError> {
        VmmSnapshot::new(self)
    }

    pub fn restore(&mut self, snapshot: &VmmSnapshot) -> Result<(), PanoramaError> {
        snapshot.restore(self)
    }
}

pub struct VmmSnapshot {
    memory: MemorySnapshot,
    serial: SerialDeviceSnapshot,
    keyboard: KeyboardDeviceSnapshot,
    block: Option<BlockDeviceSnapshot>,
    vm: VmSnapshot,
}

impl VmmSnapshot {
    fn new(vmm: &Vmm) -> Result<Self, PanoramaError> {
        let serial = vmm.serial.as_ref().ok_or(PanoramaError::NoSerialDevice)?;
        let keyboard = vmm
            .keyboard
            .as_ref()
            .ok_or(PanoramaError::NoKeyboardDevice)?;
        let block = vmm
            .block
            .as_ref()
            .map(|b| b.lock().unwrap().snapshot())
            .transpose()?;

        Ok(Self {
            memory: vmm.memory.snapshot(&vmm.vm)?,
            serial: serial.lock().unwrap().snapshot(),
            keyboard: keyboard.lock().unwrap().snapshot(),
            block,
            vm: vmm.vm.snapshot()?,
        })
    }

    fn restore(&self, vmm: &mut Vmm) -> Result<(), PanoramaError> {
        vmm.serial
            .as_ref()
            .ok_or(PanoramaError::NoSerialDevice)?
            .lock()
            .unwrap()
            .restore(&self.serial)?;
        vmm.keyboard
            .as_ref()
            .ok_or(PanoramaError::NoKeyboardDevice)?
            .lock()
            .unwrap()
            .restore(&self.keyboard);
        if let Some(bs) = self.block.as_ref() {
            vmm.block
                .as_ref()
                .expect("Block device snapshot present but no device")
                .lock()
                .unwrap()
                .restore(bs)?;
        }
        vmm.vm.restore(&self.vm)?;
        vmm.memory.restore(&self.memory, &vmm.vm)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
}
