pub trait Snapshot {
	type E;
	fn snapshot(&mut self) -> Result<Self, E>;
}