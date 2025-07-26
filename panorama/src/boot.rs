use crate::defs::{
	layout::{
		CMDLINE_ADDR, EBDA_START, HIGHMEM_ADDR, MMIO_GAP_END,
		MMIO_GAP_SIZE, MMIO_GAP_START,
	},
	pvh::{
		MEMMAP_START, MEMMAP_TYPE_RAM, MODLIST_START, PVH_INFO_START,
		XEN_HVM_START_MAGIC_VALUE,
	},
};
use crate::PanoramaError;
use crate::Vmm;

use linux_loader::configurator::pvh::PvhBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::elf::start_info::{
	hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use linux_loader::loader::elf::{Elf, PvhBootCapability};
use linux_loader::loader::{KernelLoader, KernelLoaderResult};
use std::fs::File;
use std::path::Path;
use vm_memory::{Address, GuestAddress, GuestMemory};

#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
	pub protocol: BootProtocol,
	pub entry: GuestAddress,
}

#[derive(Clone, Copy, Debug)]
pub enum BootProtocol {
	Linux,
	Pvh,
}

impl Vmm {
	/// Loads the kernel into memory, selects an available boot
	/// protocol and sets up for it.
	pub fn load_kernel<P: AsRef<Path>>(
		&mut self,
		image: P,
	) -> Result<BootInfo, PanoramaError> {
		// Load the kernel into memory
		let mut kernel_file = File::open(image)?;
		let load = Elf::load(
			self.memory.inner(),
			None,
			&mut kernel_file,
			None,
		)?;

		// Select boot protocol
		let (entry, protocol) = match load.pvh_boot_cap {
			PvhBootCapability::PvhEntryPresent(entry) => {
				(entry, BootProtocol::Pvh)
			}
			_ => (load.kernel_load, BootProtocol::Linux),
		};

		println!("Boot protocol: {:?}", protocol);

		match protocol {
			BootProtocol::Pvh => self.setup_pvh_boot(),
			BootProtocol::Linux => self.setup_linux_boot(&load),
		}?;

		Ok(BootInfo { protocol, entry })
	}

	/// Sets up the appropriate memory regions and PVH header, and
	/// writes them to memory.
	fn setup_pvh_boot(&self) -> Result<(), PanoramaError> {
		//let highmem_addr = load.kernel_load;
		let last_addr = self.memory.inner().last_addr();

		// Memory maps which need to be written to guest memory at
		// MEMMAP_START
		let mut memmap = Vec::with_capacity(3);

		let modules = Vec::<hvm_modlist_entry>::new();

		// EBDA mapping
		memmap.push(hvm_memmap_table_entry {
			addr: 0,
			size: EBDA_START,
			type_: MEMMAP_TYPE_RAM,
			reserved: 0,
		});

		// Regular regions above highmem, avoding MMIO region
		if last_addr.raw_value() < MMIO_GAP_START {
			memmap.push(hvm_memmap_table_entry {
				addr: HIGHMEM_ADDR.raw_value(),
				size: last_addr.unchecked_offset_from(HIGHMEM_ADDR)
					+ 1,
				type_: MEMMAP_TYPE_RAM,
				reserved: 0,
			});
		} else {
			memmap.push(hvm_memmap_table_entry {
				addr: HIGHMEM_ADDR.raw_value(),
				size: GuestAddress(MMIO_GAP_START)
					.unchecked_offset_from(HIGHMEM_ADDR),
				type_: MEMMAP_TYPE_RAM,
				reserved: 0,
			});
			if last_addr > GuestAddress(MMIO_GAP_END) {
				memmap.push(hvm_memmap_table_entry {
					addr: MMIO_GAP_END,
					size: last_addr.unchecked_offset_from(
						GuestAddress(MMIO_GAP_END),
					) + 1,
					type_: MEMMAP_TYPE_RAM,
					reserved: 0,
				});
			}
		}

		println!("Boot memory regions:");
		for mr in &memmap {
			println!(
				"\tRegion: 0x{:09x}, size: 0x{:x}",
				mr.addr, mr.size
			);
		}
		println!(
			"\tMMIO:   0x{:09x}, size: 0x{:x}",
			MMIO_GAP_START, MMIO_GAP_SIZE
		);

		// Now prepare the PVH header
		let start_info = hvm_start_info {
			magic: XEN_HVM_START_MAGIC_VALUE,
			version: 1,
			cmdline_paddr: CMDLINE_ADDR.raw_value(),
			memmap_paddr: MEMMAP_START.raw_value(),
			memmap_entries: memmap.len() as u32,
			nr_modules: modules.len() as u32,
			..Default::default()
		};

		// Prepare the full structure and write to memory
		let mut params = BootParams::new(&start_info, PVH_INFO_START);
		params.set_sections(&memmap, MEMMAP_START);
		params.set_modules(&modules, MODLIST_START);
		PvhBootConfigurator::write_bootparams(
			&params,
			self.memory.inner(),
		)?;

		Ok(())
	}

	fn setup_linux_boot(
		&self,
		_load: &KernelLoaderResult,
	) -> Result<(), PanoramaError> {
		todo!("Linux boot protocol")
	}
}
