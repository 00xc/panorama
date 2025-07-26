#!/bin/bash

git_base=$(git rev-parse --show-toplevel)

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <initramfs> [<mountpoint (default=/mnt/chroot)>]"
    echo "Hint: create initramfs with ${git_base}/scripts/create-image.sh"
    exit 1
fi

img=$1
mnt="${2:-/mnt/chroot}"

make -C "${git_base}"/harness harness || exit 1

sudo mount -o loop "$img" "$mnt"

sudo cp "${git_base}"/harness/harness "$mnt"/root/
sudo ls -alh "$mnt"/root/harness

sudo rm -f "$mnt"/etc/rc.local
sudo touch "$mnt"/etc/rc.local
echo "#!/bin/sh -e" | sudo tee -a "$mnt"/etc/rc.local
echo "/root/harness" | sudo tee -a "$mnt"/etc/rc.local
echo "" | sudo tee -a "$mnt"/etc/rc.local

sudo chmod +x "$mnt"/etc/rc.local

sudo umount "$mnt"
