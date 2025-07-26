use crate::PanoramaError;

use addr2line::Context;
use gimli::read::EndianRcSlice;
use gimli::RunTimeEndian;
use object::{Object, ObjectSymbol};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct KernelSym {
	name: Rc<str>,
	addr: u64,
	_size: u64,
}

impl KernelSym {
	pub fn addr(&self) -> u64 {
		self.addr
	}

	pub fn name(&self) -> &str {
		self.name.as_ref()
	}
}

impl From<object::read::Symbol<'_, '_>> for KernelSym {
	fn from(sym: object::read::Symbol) -> Self {
		Self {
			name: Rc::from(sym.name().unwrap()),
			addr: sym.address(),
			_size: sym.size(),
		}
	}
}

/// A type to store mappings from addresses to file locations and
/// symbol names.
pub struct KernelSyms {
	// TODO: use a more specialized reader
	ctx: Context<EndianRcSlice<RunTimeEndian>>,
	syms: BTreeMap<u64, KernelSym>,
}

impl KernelSyms {
	/// Load symbol information from an ELF file.
	pub fn new<P: AsRef<Path>>(
		kernel: P,
	) -> Result<Self, PanoramaError> {
		let bytes = std::fs::read(kernel)?;
		let obj = object::File::parse(bytes.as_slice())?;
		let syms = obj
			.symbols()
			.map(|sym| (sym.address(), KernelSym::from(sym)))
			.collect::<BTreeMap<_, _>>();
		let ctx = Context::new(&obj)?;
		Ok(Self { ctx, syms })
	}

	/// The number of symbols stored.
	pub fn len(&self) -> usize {
		self.syms.len()
	}

	pub fn syms(&self) -> impl Iterator<Item = &KernelSym> + '_ {
		self.syms.values()
	}

	/// Get symbol information related to the given address.
	pub fn location(&self, addr: u64) -> SymLocation<'_> {
		// Get the file location
		let loc = self.ctx.find_location(addr).unwrap();
		let file = loc.as_ref().and_then(|s| s.file);
		let line = loc.as_ref().and_then(|s| s.line);

		// Get the symbol with the next lowest address
		let sym = self.syms.range(..=addr).last();
		let func = sym.as_ref().map(|(_, sym)| sym.name.clone());
		let offset = sym.map(|(_, sym)| addr - sym.addr).unwrap_or(0);
		SymLocation {
			file,
			line,
			func,
			offset,
		}
	}
}

/// Symbol information related to a specific address.
#[derive(Debug, Clone)]
pub struct SymLocation<'a> {
	pub file: Option<&'a str>,
	pub line: Option<u32>,
	pub func: Option<Rc<str>>,
	pub offset: u64,
}

impl fmt::Display for SymLocation<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let file = self.file.unwrap_or("??");
		let line = self
			.line
			.map(|ln| ln.to_string())
			.unwrap_or("??".to_string());
		let func =
			self.func.as_ref().map(|r| r.as_ref()).unwrap_or("??");
		write!(f, "{}+0x{:x} in {}:{}", func, self.offset, file, line)
	}
}
