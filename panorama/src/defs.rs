use vm_memory::guest_memory::GuestAddress;

pub const COM1_PORT: u16 = 0x3f8;
pub const I8042_PORT: u16 = 0x060;

pub const PAGE_SIZE: usize = 0x1000;
pub const CMDLINE_CAP: usize = 0x1000;
pub const QUEUE_MAX_SIZE: u16 = 256;

pub const BLK_SECTOR_SHIFT: usize = 9;

pub mod irq {
	pub const KEYBOARD_IRQ: u32 = 1;
	pub const SERIAL_IRQ: u32 = 4;
	pub const BLOCK_IRQ: u32 = 5;
	pub const MAX_IRQ: u8 = 23;
}

pub mod layout {
	use super::*;

	pub const BOOT_GDT_ADDR: GuestAddress = GuestAddress(0x500);
	pub const BOOT_IDT_ADDR: GuestAddress = GuestAddress(0x520);

	/// Extended BIOS Data Area (EBDA)
	pub const EBDA_START: u64 = 0x9fc00;

	pub const CMDLINE_ADDR: GuestAddress = GuestAddress(0x20000);

	pub const HIGHMEM_ADDR: GuestAddress = GuestAddress(0x100000);

	pub const MMIO_GAP_END: u64 = 0x100000000; // 1 << 32
	pub const MMIO_GAP_SIZE: u64 = 0x30000000; // 768 << 20
	pub const MMIO_GAP_START: u64 = MMIO_GAP_END - MMIO_GAP_SIZE;
}

pub mod pvh {
	use super::*;

	/// Magic value in the hvm_start_info struct
	pub const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;

	/// Type for RAM regions in PVH map table.
	pub const MEMMAP_TYPE_RAM: u32 = 1;

	/// Address of the hvm_start_info struct. It points to the memory
	/// map table.
	pub const PVH_INFO_START: GuestAddress = GuestAddress(0x6000);

	pub const MODLIST_START: GuestAddress = GuestAddress(0x6040);

	/// Address of memory map table used in PVH boot. Can overlap
	/// with the zero page address since they are mutually exclusive.
	pub const MEMMAP_START: GuestAddress = GuestAddress(0x7000);
}

#[allow(unused)]
pub mod linux {
	use super::*;

	/// Address of the zeropage, where Linux kernel boot parameters
	/// are written.
	const ZEROPG_START: GuestAddress = GuestAddress(0x7000);
	const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
	const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
	const KERNEL_LOADER_OTHER: u8 = 0xff;
	const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;
}

pub mod msr {
	pub const MSR_IA32_SYSENTER_CS: u32 = 0x00000174;
	pub const MSR_IA32_SYSENTER_ESP: u32 = 0x00000175;
	pub const MSR_IA32_SYSENTER_EIP: u32 = 0x00000176;
	pub const MSR_STAR: u32 = 0xc0000081;
	pub const MSR_LSTAR: u32 = 0xc0000082;
	pub const MSR_CSTAR: u32 = 0xc0000083;
	pub const MSR_SYSCALL_MASK: u32 = 0xc0000084;
	pub const MSR_KERNEL_GS_BASE: u32 = 0xc0000102;
	pub const MSR_IA32_TSC: u32 = 0x00000010;
	pub const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;

	pub const MSR_IA32_MISC_ENABLE_FAST_STRING_BIT: u32 = 0;
}
