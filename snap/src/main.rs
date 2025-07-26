use panorama::Vmm;
use std::num::NonZeroU8;

fn main() {
	let kernel = "./vmlinux";
	let disk = "/home/carlos/dev/panorama/bookworm.img";
	let ncpus = NonZeroU8::MIN;
	let corpus = "/home/carlos/dev/panorama/snap/corpus";
	core_affinity::set_for_current(core_affinity::CoreId { id: 4 });
	let mut vmm = Vmm::new(kernel, disk, 128, ncpus, corpus).unwrap();
	let _ = vmm.run();

	/*std::thread::scope(|s| {
		for i in 0..4 {
			s.spawn(move || {
				core_affinity::set_for_current(core_affinity::CoreId { id: i + 4 });
				let mut vmm = Vmm::new(&kernel, &disk, 128, ncpus, &corpus).unwrap();
				let _ = vmm.run();
			});
		}
	});*/
}
