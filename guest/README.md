# The microVM guest side

The two artifacts a node needs before kamaji can run a workload in its own KVM
guest, and the script that builds them reproducibly.

```
build-guest-image.sh                 builds both, from the pins in its header
kernel/base-x86_64-6.1.config        firecracker v1.16.1's own CI guest config, verbatim
kernel/microvm.config                our delta over it (one symbol, and why)
rootfs/busybox.config                busybox deltas (static, minus the applets we must own)
rootfs/etc/                          the image's /etc, checked in
../crates/kamaji-guest-init/         /sbin/init: reads job.json, mounts, runs argv, halts
```

Output (git-ignored, ~75 MB):

```
out/vmlinux         uncompressed ELF kernel   ← Firecracker boots this, never a bzImage
out/rootfs.ext4     read-only root filesystem
```

## Build

x86_64 Linux only — it compiles an x86_64 kernel. The camp Mac cannot run it;
`.yah/infra/machines/us-west-003.toml` is a node that can (KVM, non-voter, LAN).

```
sudo apt-get install -y build-essential bc bison flex libelf-dev libssl-dev \
    xz-utils bzip2 e2fsprogs curl
rustup target add x86_64-unknown-linux-musl
./build-guest-image.sh --jobs "$(nproc)"        # ~4 min on 16 threads
```

Every download is sha256-pinned, so an upstream that changes bytes under a
version fails the build rather than silently changing the guest.

## Install on a node

```
install -D -m 0644 out/vmlinux     /var/lib/yah/kamaji/microvm/vmlinux
install -D -m 0644 out/rootfs.ext4 /var/lib/yah/kamaji/microvm/rootfs.ext4
```

then give `kamaji` `--microvm-dir /var/lib/yah/kamaji/microvm`. **The filenames
are not negotiable**: `MicroVmRuntime::new` looks for exactly those two, and a
node with a typo advertises *no* microVM backend rather than failing a build —
so the symptom is "my microvm workload was refused", nowhere near the cause.

The node also needs `firecracker` on `PATH`, `e2fsprogs` (`mkfs.ext4` +
`debugfs`, in `/usr/sbin`), and a `/dev/kvm` the kamaji user can open read-write.
That last one is `usermod -aG kvm <user>` plus a **restart** of `kamaji.service`,
not a reload: group membership is read at process start (R605-T15).

## Verify

```
KAMAJI_MICROVM_DIR=$PWD/out cargo test -p kamaji \
    --features microvm-integration --test microvm_guest_e2e -- --nocapture
```

Two tests, both against a real guest: a forge-shaped job whose artifact must
reach the host, and a job that exits non-zero which must not be reported as a
clean stop. They skip with a specific reason when the substrate is missing.

## What the guest does, in order

1. Kernel boots `/dev/vda` (the read-only rootfs) and runs `/sbin/init`.
   Firecracker appends `root=/dev/vda ro` and `virtio_mmio.device=` arguments to
   the command line kamaji built — measured, and the reason
   `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` is required.
2. The init mounts the scratch disk (`/dev/vdb`, kamaji's second drive), reads
   `job.json` from its root, and refuses a `schema` it does not know.
3. It assembles a **writable root**: overlayfs with the read-only image as the
   lower layer and a tmpfs as the upper, then `pivot_root`. This is what lets it
   create the arbitrary mount targets the job document names (`/yah/produced`,
   `/etc/certs`, …) without writing to an image that serves every other job on
   the node.
4. It bind-mounts each `slug` at its `target`, writes `resolv.conf`, brings up
   `lo`, and runs the argv with exactly the document's environment.
5. It reaps the job, writes `job-status.json` back to the scratch disk, unmounts
   it, and **resets** the machine. The reset is what makes the VMM process exit,
   which is kamaji's only completion signal — which is also why the status file
   exists, since Firecracker exits `0` whether the job passed, failed, or
   panicked the guest kernel.

## Bumping the kernel or firecracker

The base config is Firecracker's, pinned by sha256 and vendored verbatim so it
can be diffed against upstream. To move:

1. Fetch the new
   `resources/guest_configs/microvm-kernel-ci-x86_64-<series>.config` from the
   firecracker tag, replace `kernel/base-x86_64-6.1.config`, update
   `KERNEL_BASE_CONFIG_SHA256` and `FIRECRACKER_VERSION`.
2. Update `KERNEL_VERSION` / `KERNEL_SHA256` from
   `https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc`.
3. Rebuild and run the e2e tests on a KVM host. The build re-asserts
   `REQUIRED_SYMBOLS` after `olddefconfig`, so a symbol that silently stopped
   surviving the merge fails the build instead of the boot.
