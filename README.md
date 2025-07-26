# panorama

A KVM-based VMM for snapshot fuzzing.

WORK IN PROGRESS, DO NOT USE

## Repository contents

* `panorama/`: the VMM crate
* `snap/`: binary using the VMM crate to perform a fuzzing run
* `harness/`: guest-side harness
* `scripts/`: scripts to create initramfs and copy guest-side harness
