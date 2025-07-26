use arbitrary::{Arbitrary, Unstructured};
use basic_mutator::{InputDatabase, Mutator};
// use nftables_json::command::Commands;
use rand::rngs::SmallRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::HashSet;
use std::path::PathBuf;

pub trait PFuzzer {
	fn new(seed: u64, max_len: usize, path: PathBuf) -> Self;
	fn visit_addr(&mut self, addr: u64);
	fn next_input(&mut self) -> &[u8];
}

/*
pub struct DumbFuzzer {
	mutator: Mutator,
	corpus: Corpus,
	rng: SmallRng,
	new_cov: Vec<u64>,
	total_cov: HashSet<u64>,
	max_len: usize,
}

impl DumbFuzzer {
	fn update_cov(&mut self) {
		let len = self.total_cov.len();
		self.total_cov.extend(self.new_cov.drain(..));
		if len != self.total_cov.len() {
			let inp = self.mutator.input.clone();
			self.corpus.push(inp);

			let metrics = &crate::METRICS;
			let in_fuzz = metrics.in_fuzz().as_secs_f64();
			let resets = metrics.resets();
			println!("[{:10.4}] cov: {} PCs | corp: {} | {} execs",
				in_fuzz, self.total_cov.len(), self.corpus.len(), resets);
		}
	}

	fn gen_input(&mut self) -> &[u8] {
		self.update_cov();
		if self.corpus.is_empty() || self.rng.gen_ratio(1, 2) {
			self.gen_new_input();
		} else {
			self.gen_from_corpus();
		}
		self.mutator.input.as_slice()
	}

	fn gen_new_input(&mut self) {
		let len = self.rng.gen_range(1..self.max_len);
		self.mutator.input.resize(len, 0);
		let dst = &mut self.mutator.input;
		self.rng.fill_bytes(dst);
	}

	fn gen_from_corpus(&mut self) {
		let idx = self.rng.gen_range(0..self.corpus.num_inputs());
		let src = &self.corpus.0[idx];
		self.mutator.input.clear();
		self.mutator.input.extend_from_slice(src);
		let nmut = self.rng.gen_range(3..=6);
		self.mutator.mutate(nmut, &self.corpus);
		if self.mutator.input.is_empty() {
			self.mutator.input.push(self.rng.gen::<u8>())
		}
	}
}

impl PFuzzer for DumbFuzzer {
	fn new(seed: u64, max_len: usize, path: PathBuf) -> Self {
		let mutator =
			Mutator::new().seed(seed).max_input_size(max_len).printable(true);
		Self {
			rng: SmallRng::seed_from_u64(seed),
			max_len,
			corpus: Corpus::new(path),
			mutator,
			new_cov: Vec::new(),
			total_cov: HashSet::new(),
		}
	}

	fn next_input(&mut self) -> &[u8] {
		self.update_cov();
		self.gen_input()
	}

	fn visit_addr(&mut self, addr: u64) {
		self.new_cov.push(addr);
	}
}*/

/*
pub struct NftFuzzer {
	mutator: Mutator,
	corpus: Corpus,
	rng: SmallRng,
	new_cov: HashSet<u64>,
	total_cov: HashSet<u64>,
	json: Vec<u8>,
	max_len: usize,
	saved: usize,
}

impl NftFuzzer {
	fn gen_input(&mut self) -> Commands {
		if self.corpus.is_empty() || self.rng.gen_ratio(1, 4) {
			self.gen_new_input();
		} else {
			self.gen_from_corpus();
		}
		self.deser_input()
	}

	/// Fill the mutator's input with random bytes
	fn gen_new_input(&mut self) {
		let len = self.rng.gen_range(1..self.max_len);
		self.mutator.input.clear();
		self.mutator.input.resize_with(len, || self.rng.gen::<u8>());
	}

	/// Fill the mutator's input with a random item from the corpus
	/// and mutate it.
	fn gen_from_corpus(&mut self) {
		let idx = self.rng.gen_range(0..self.corpus.num_inputs());
		let src = &self.corpus.0[idx];
		self.mutator.input.clear();
		self.mutator.input.extend_from_slice(src);
		let nmut = self.rng.gen_range(3..=6);
		self.mutator.mutate(nmut, &self.corpus);
		if self.mutator.input.is_empty() {
			self.mutator.input.push(self.rng.gen::<u8>())
		}
	}

	fn deser_input(&mut self) -> Commands {
		loop {
			let bytes = self.mutator.input.as_slice();
			if let Ok(cmds) =
				Unstructured::new(bytes).arbitrary::<Commands>()
			{
				return cmds;
			};
			self.mutator.mutate(1, &self.corpus);
		}
	}

	fn update_cov(&mut self, syms: &crate::symbols::KernelSyms) {
		let len = self.total_cov.len();
		let mut new = false;
		for addr in self.new_cov.drain() {
			if self.total_cov.insert(addr) {
				new = true;
				let loc = syms.location(addr);
				if loc.file.is_some() {
					println!("NEW: {addr:x} {loc}");	
				}
			}
		}

		if new {
			let metrics = &crate::METRICS;

			let inp = self.mutator.input.clone();
			self.corpus.push(inp);

			let in_fuzz = metrics.in_fuzz().as_secs_f64();
			let resets = metrics.resets();
			println!(
				"[{:10.4}] cov: {} PCs | corp: {} | {} execs",
				in_fuzz,
				self.total_cov.len(),
				self.corpus.len(),
				resets
			);
		}
	}

	pub fn new(seed: u64, max_len: usize, path: PathBuf) -> Self {
		let mutator = Mutator::new()
			.seed(seed)
			.max_input_size(max_len)
			.printable(true);
		Self {
			rng: SmallRng::seed_from_u64(seed),
			max_len,
			corpus: Corpus::new(path),
			mutator,
			new_cov: HashSet::new(),
			total_cov: HashSet::new(),
			json: Vec::with_capacity(max_len),
			saved: 0,
		}
	}

	pub fn next_input(&mut self, syms: &crate::symbols::KernelSyms) -> &[u8] {
		self.update_cov(syms);
		let cmd = self.gen_input();

		self.json.clear();
		serde_json::to_writer(&mut self.json, &cmd).unwrap();
		let len = self.max_len.min(self.json.len());
		self.json.resize(len, 0);
		self.json.as_slice()
	}

	pub fn visit_addr(&mut self, addr: u64) -> bool {
		self.new_cov.insert(addr)
	}

	#[inline]
	fn hash_inp(&self, bytes: &[u8]) -> u64 {
		use std::hash::{DefaultHasher, Hasher};

		let mut hash = DefaultHasher::new();
		hash.write(bytes);
		hash.finish()
	}

	pub fn save_all(&mut self) {
		for (i, corp) in self.corpus.0.iter().enumerate().skip(self.saved) {
			let hash = self.hash_inp(corp);
			let f = format!("corpus/{:x}.fuzz", hash);
			let _ = std::fs::write(f, corp);
			self.saved = i;
		}
	}

	pub fn save_last(&self) {
		let hash = self.hash_inp(&self.mutator.input);
		let f = format!("corpus/{:x}.fuzz", hash);
		std::fs::write(
			f,
			&self.mutator.input,
		)
		.unwrap();
	}
}
*/

#[derive(Debug, Clone)]
struct Corpus(Vec<Vec<u8>>);

impl Corpus {
	fn new(path: PathBuf) -> Self {
		let mut corp = Vec::new();
		for f in std::fs::read_dir(path).unwrap() {
			let f = f.unwrap();
			if f.file_type().unwrap().is_file() {
				let bytes = std::fs::read(f.path()).unwrap();
				corp.push(bytes);
			}
		}
		Self(corp)
	}

	fn push(&mut self, inp: Vec<u8>) {
		self.0.push(inp);
	}

	fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	fn len(&self) -> usize {
		self.0.len()
	}
}

impl InputDatabase for Corpus {
	fn num_inputs(&self) -> usize {
		self.0.len()
	}

	fn input(&self, idx: usize) -> Option<&[u8]> {
		self.0.get(idx).map(Vec::as_slice)
	}
}

#[derive(Debug, Clone)]
pub struct Fuzzer {
	rng: SmallRng,
	max_len: usize,
	corpus: Corpus,
	mutator: Mutator,
	pub seen_cov: HashSet<u64>,
	new_cov: Vec<u64>,
	saved: usize,
}

impl Fuzzer {
	pub fn new(seed: u64, max_len: usize, path: PathBuf) -> Self {
		let mutator =
			Mutator::new().seed(seed).max_input_size(max_len);
		Self {
			rng: SmallRng::seed_from_u64(seed),
			max_len,
			corpus: Corpus::new(path),
			mutator,
			seen_cov: HashSet::new(),
			new_cov: Vec::new(),
			saved: 0,
		}
	}

	pub fn visit_addr(&mut self, addr: u64) {
		self.new_cov.push(addr);
	}

	#[inline]
	fn hash_inp(&self, bytes: &[u8]) -> u64 {
		use std::hash::{DefaultHasher, Hasher};

		let mut hash = DefaultHasher::new();
		hash.write(bytes);
		hash.finish()
	}

	pub fn save_last(&self) {
		let hash = self.hash_inp(&self.mutator.input);
		let f = format!("corpus/{:x}.fuzz", hash);
		std::fs::write(
			f,
			&self.mutator.input,
		)
		.unwrap();
	}

	pub fn save_all(&mut self) {
		for (i, corp) in self.corpus.0.iter().enumerate().skip(self.saved) {
			let hash = self.hash_inp(corp);
			let f = format!("corpus/{:x}.fuzz", hash);
			let _ = std::fs::write(f, corp);
			self.saved = i;
		}
	}

	fn update_cov(&mut self, syms: &crate::symbols::KernelSyms) {
		/*for addr in
			self.new_cov.iter().filter(|a| **a >= 0xffffffff80000000)
		{
			if !self.seen_cov.contains(addr) {
				let loc = syms.location(*addr);
				println!("NEW: {addr:x} {}", loc);
			}
		}*/

		/*for addr in self.new_cov.iter().copied() {
			if !self.seen_cov.contains(&addr) {
				let loc = syms.location(addr);
				println!("NEW: {addr:x} {}", loc);
			}
		}*/

		let len = self.seen_cov.len();
		self.seen_cov.extend(self.new_cov.drain(..));
		if self.seen_cov.len() != len {
			let inp = self.mutator.input.clone();
			self.corpus.push(inp);

			let in_fuzz = crate::METRICS.in_fuzz().as_secs_f64();
			let resets = crate::METRICS.resets();
			println!(
				"[{:10.4}] cov: {} PCs | corp: {} | {} execs",
				in_fuzz,
				self.seen_cov.len(),
				self.corpus.len(),
				resets
			);
		}
	}

	/// Generate a new input and return a slice to it
	pub fn next_input(
		&mut self,
		syms: &crate::symbols::KernelSyms,
	) -> &[u8] {
		self.update_cov(syms);
		if self.corpus.is_empty() || self.rng.gen_ratio(1, 2) {
			self.gen_new_input();
		} else {
			self.gen_from_corpus();
		}

		self.mutator.input.as_slice()
	}

	fn gen_from_corpus(&mut self) {
		let idx = self.rng.gen_range(0..self.corpus.num_inputs());
		let src = &self.corpus.0[idx];
		self.mutator.input.clear();
		self.mutator.input.extend_from_slice(src);
		let nmut = self.rng.gen_range(3..=6);
		self.mutator.mutate(nmut, &self.corpus);
		if self.mutator.input.is_empty() {
			self.mutator.input.push(self.rng.gen::<u8>())
		}
	}

	fn gen_new_input(&mut self) {
		let len = self.rng.gen_range(1..self.max_len);
		self.mutator.input.clear();
		self.mutator.input.resize_with(len, || self.rng.gen::<u8>());
		let nmut = self.rng.gen_range(0..=4);
		self.mutator.mutate(nmut, &self.corpus);
	}
}
