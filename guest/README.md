# The microVM guest side

The two artifacts a node needs before kamaji can run a workload in its own KVM
guest, and the script that builds them reproducibly.

```
build-guest-image.sh                 builds them, from the pins in its header
kernel/base-x86_64-6.1.config        firecracker v1.16.1's own CI guest config, verbatim
kernel/base-aarch64-6.1.config       the same, for aarch64 (R605-F32)
kernel/microvm.config                our delta over either (one symbol, and why)
rootfs/busybox.config                busybox deltas (static, minus the applets we must own)
rootfs/etc/                          the job image's /etc, checked in
service-rootfs/                      files the service image adds (kamaji-job.service, ...)
../crates/kamaji-guest-init/         /sbin/init of the job image: reads job.json, mounts,
                                     runs argv, halts; `--unit` in the service image
```

Output (git-ignored):

```
out/vmlinux               the kernel Firecracker boots: the ELF vmlinux on x86_64
                          (never a bzImage), the arm64 boot Image on aarch64
                          (never Image.gz) — named vmlinux on both
out/rootfs.ext4           the JOB image: busybox + kamaji-guest-init as PID 1, ~30 MB
out/service-rootfs.ext4   the SERVICE image: Debian + systemd, ~2.5 GB sparse
                          (only with --only service-rootfs)
```

## Build

On Linux, for the **host's** arch (x86_64 or aarch64). There is no cross-build
flag: the kernel, busybox and the musl init would each need a cross toolchain.
`.yah/infra/machines/us-west-003.toml` is an x86_64 node that can build and boot
the x86 guest (KVM, non-voter, LAN):

```
sudo apt-get install -y build-essential bc bison flex libelf-dev libssl-dev \
    xz-utils bzip2 e2fsprogs curl
rustup target add x86_64-unknown-linux-musl
./build-guest-image.sh --jobs "$(nproc)"        # ~4 min on 16 threads
```

The **aarch64** guest (the Raspberry Pis, R605-F32) is built natively on the
camp Mac in an arm64 Linux container — ~3 min for the kernel, and nothing gets
installed on the Pis, which are the live dev raft. `--privileged` is only for
the service image (mmdebstrap mounts /proc in its chroot). The two cargo
overrides undo the repo's `.cargo/config.toml`, which forces sccache and names
the Mac's *cross* musl linker:

```
docker run -d --privileged --name guest-builder --platform linux/arm64 \
    -v "$PWD/../../..":/yah -v guest-build:/build debian:trixie sleep infinity
docker exec guest-builder bash -c 'apt-get update && apt-get install -y \
    build-essential bc bison flex libelf-dev libssl-dev xz-utils bzip2 \
    e2fsprogs curl ca-certificates git mmdebstrap &&
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal \
        -t aarch64-unknown-linux-musl'
docker exec guest-builder bash -c '. ~/.cargo/env && cd /yah/oss/kamaji/guest &&
    RUSTC_WRAPPER= CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=gcc \
    CARGO_TARGET_DIR=/build/target ./build-guest-image.sh --out /build/out'
```

The service image is opt-in (`--only init,service-rootfs --authorized-keys
<yah.pub>`): its `yah` user is how a member guest is provisioned, and the key is
a deployment input rather than something to commit.

Every download is sha256-pinned, so an upstream that changes bytes under a
version fails the build rather than silently changing the guest.

## Install on a node

```
install -D -m 0644 out/vmlinux     /var/lib/yah/kamaji/microvm/vmlinux
install -D -m 0644 out/rootfs.ext4 /var/lib/yah/kamaji/microvm/rootfs.ext4
# only on a node that runs service-shaped (server/appliance) guests:
install -D -m 0644 out/service-rootfs.ext4 /var/lib/yah/kamaji/microvm/service-rootfs.ext4
```

then give `kamaji` `--microvm-dir /var/lib/yah/kamaji/microvm`. **The filenames
are not negotiable**: `MicroVmRuntime::new` looks for exactly those, and a
node with a typo advertises *no* microVM backend rather than failing a build —
so the symptom is "my microvm workload was refused", nowhere near the cause.
A node without `service-rootfs.ext4` runs job-shaped guests only and refuses a
service-shaped deploy by name; it never seeds a service from the job image.

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
