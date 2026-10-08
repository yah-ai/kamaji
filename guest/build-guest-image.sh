#!/usr/bin/env bash
# Build the guest kernel + rootfs kamaji's microVM backend boots (R605-F14 / W325 §5).
#
# Produces exactly the two artifacts MicroVmRuntime::new refuses to construct
# without, under the names it looks for:
#
#   <out>/vmlinux       the uncompressed kernel Firecracker boots. On x86_64
#                       that is the ELF `vmlinux` (NOT a bzImage); on aarch64
#                       it is the arm64 `Image` (NOT Image.gz, and NOT the ELF
#                       vmlinux) — R605-F32. The filename is `vmlinux` on both
#                       because MicroVmRuntime::new looks for exactly that name.
#   <out>/rootfs.ext4   read-only root filesystem, /sbin/init = kamaji-guest-init
#
# Install them as <microvm-dir>/vmlinux and <microvm-dir>/rootfs.ext4 on a node,
# and start kamaji with --microvm-dir pointing at that directory.
#
# ── Why a script and not a documented recipe ─────────────────────────────────
#
# Because "the node has a rootfs" is otherwise unfalsifiable. A hand-built image
# on one box cannot be rebuilt after a kernel CVE, cannot be diffed when a guest
# starts failing, and cannot be reproduced on the second build node. Everything
# that ends up in the guest comes from this file plus kernel/microvm.config,
# rootfs/busybox.config and rootfs/etc/ — all of them in git.
#
# ── Where it runs, and which arch it builds ──────────────────────────────────
#
# Linux, and the guest is the HOST's arch: x86_64 or aarch64 (R605-F32). There
# is deliberately no --arch flag. A cross build needs a cross toolchain for each
# of the three things built here — the kernel, a static busybox and a static
# musl init — and every one of them is a different way to get a subtly wrong
# binary. A native build in a container of the target arch needs none of that
# and is already the cheaper path on every box this camp has: the camp Mac is
# arm64, so `docker run --platform linux/arm64 debian:trixie` builds the Pis'
# guest natively (see README.md), and us-west-003 builds the x86_64 one.
set -euo pipefail

# ── Pins ─────────────────────────────────────────────────────────────────────
# Both tarballs are checked by sha256, so an upstream that changes bytes under a
# version fails the build instead of quietly changing the guest. 6.1 is the
# series Firecracker documents as a supported guest kernel, on both arches.
KERNEL_VERSION=${KERNEL_VERSION:-6.1.187}
KERNEL_SHA256=${KERNEL_SHA256:-1b6e798aeaa708ca670a426ad5a6c86dc2237b8e59e8822876976c383873642b}
# kernel/base-<arch>-6.1.config is Firecracker's own CI guest config for that
# arch, vendored verbatim from firecracker v1.16.1
# (resources/guest_configs/microvm-kernel-ci-<arch>-6.1.config). Checked here so
# a local edit to a 3500-line generated file is caught: the way to change the
# guest's configuration is kernel/microvm.config, which is merged over this.
# Re-pin every arch when bumping the firecracker version — see microvm.config's
# header for what the base buys and what happened without it.
FIRECRACKER_VERSION=v1.16.1
BUSYBOX_VERSION=${BUSYBOX_VERSION:-1.37.0}
BUSYBOX_SHA256=${BUSYBOX_SHA256:-3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4}

# ── Arch ─────────────────────────────────────────────────────────────────────
# Everything that differs between the two guests, in one place. The aarch64
# column applies F14's reasoning for the x86 one rather than porting its
# conclusions: the base is again the VMM's own CI config (the only party that
# tests the contract between a guest kernel and Firecracker's emulated
# hardware), and the arch-specific REQUIRED symbols are the ones whose absence
# was measured, or is structurally certain, to cost a boot.
GUEST_ARCH=$(uname -m)
case $GUEST_ARCH in
x86_64)
	KERNEL_ARCH=x86_64
	KERNEL_MAKE_TARGET=vmlinux
	KERNEL_ARTIFACT=vmlinux
	KERNEL_BASE_CONFIG=base-x86_64-6.1.config
	KERNEL_BASE_CONFIG_SHA256=adbc70ab5e89213ba00594b12d25e09bdf8bb1ed3c252d7449326bb14c22963b
	RUST_TARGET=x86_64-unknown-linux-musl
	BUSYBOX_ARCH_CONFIG=()
	ARCH_REQUIRED_SYMBOLS=(
		CONFIG_KVM_GUEST CONFIG_ACPI
		# How firecracker v1.16.1 advertises its virtio devices to an x86 guest —
		# as `virtio_mmio.device=` command-line arguments, not through ACPI.
		# (An aarch64 guest is told through the device tree instead.)
		CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES
	)
	;;
aarch64)
	KERNEL_ARCH=arm64
	# Firecracker on aarch64 loads the arm64 boot `Image` (a PE/arm64 image
	# header, magic "ARMd" at offset 56), not the ELF vmlinux it wants on x86.
	# Measured on us-west-014: the aarch64 kernel the June probe left at
	# /data/fc/kernels/vmlinux-6.1.128 is such an Image despite its name.
	KERNEL_MAKE_TARGET=Image
	KERNEL_ARTIFACT=arch/arm64/boot/Image
	KERNEL_BASE_CONFIG=base-aarch64-6.1.config
	KERNEL_BASE_CONFIG_SHA256=1df6e14391ef65eceac0f65cac4e431fefd8e04e4584d261184059320ad492b7
	RUST_TARGET=aarch64-unknown-linux-musl
	# busybox 1.37.0's defconfig turns the SHA hardware paths on, and those are
	# x86 SHA-NI code: on aarch64 libbb/hash_md5_sha.c fails to compile
	# ("sha1_process_block64_shaNI undeclared"), measured in the arm64 builder.
	BUSYBOX_ARCH_CONFIG=(
		"# CONFIG_SHA1_HWACCEL is not set"
		"# CONFIG_SHA256_HWACCEL is not set"
	)
	ARCH_REQUIRED_SYMBOLS=(
		# PSCI is the reset path, which is this backend's only completion
		# signal: the guest's reboot(2) becomes a PSCI SYSTEM_RESET call that
		# KVM hands Firecracker as a system event, and Firecracker exits. It is
		# also how secondary vCPUs are brought up. Without it a finished job's
		# VMM never exits, which presents as a build that hangs.
		CONFIG_ARM_PSCI_FW
		# The console. Firecracker describes its 16550A UART in the device tree
		# as an `ns16550a`, which binds through 8250_of; without it the guest
		# boots silently and its log — the workload's log — is empty.
		CONFIG_SERIAL_OF_PLATFORM
	)
	;;
*)
	# Refused by preflight with a message; these only keep `set -u` from
	# failing first, on the arrays below, with a less useful one.
	GUEST_ARCH_UNSUPPORTED=1
	ARCH_REQUIRED_SYMBOLS=()
	BUSYBOX_ARCH_CONFIG=()
	;;
esac

GUEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KAMAJI_DIR=$(cd "$GUEST_DIR/.." && pwd)
OUT=$GUEST_DIR/out
JOBS=$(nproc 2>/dev/null || echo 4)
STAGES=all

usage() {
	cat <<'EOF'
usage: build-guest-image.sh [options]

  --out DIR        where vmlinux and rootfs.ext4 land (default: guest/out)
  --jobs N         parallelism for the kernel build (default: nproc)
  --only STAGE     one of: init, kernel, rootfs, service-rootfs
                   (repeatable via commas)
  --authorized-keys FILE
                   public key(s) the service image's `yah` user accepts;
                   required by the service-rootfs stage
  --clean          remove the whole out dir first, including fetched tarballs
  -h, --help       this

Stages: `init` cross-compiles kamaji-guest-init, `kernel` builds vmlinux,
`rootfs` assembles rootfs.ext4 (and needs `init` to have run at least once).
`service-rootfs` assembles service-rootfs.ext4, the Debian + systemd image a
service-shaped guest's private root is seeded from (R605-F32). It is not part
of the default `all` — it needs --authorized-keys and mmdebstrap — so name it.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--out) OUT=$2; shift 2 ;;
	--jobs) JOBS=$2; shift 2 ;;
	--only) STAGES=$2; shift 2 ;;
	--authorized-keys) AUTHORIZED_KEYS=$2; shift 2 ;;
	--clean) CLEAN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

WORK=$OUT/work
DL=$OUT/downloads

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }
wants() { [[ $STAGES == all ]] || [[ ",$STAGES," == *",$1,"* ]]; }
# Named stages only — see usage.
wants_named() { [[ ",$STAGES," == *",$1,"* ]]; }

# ── Preflight ────────────────────────────────────────────────────────────────

preflight() {
	[[ $(uname -s) == Linux ]] || die "this builds a Linux kernel; run it on Linux (or in a Linux container of the guest's arch — see README.md), not $(uname -s)"
	[[ -z ${GUEST_ARCH_UNSUPPORTED:-} ]] || die "no guest recipe for $GUEST_ARCH; this builds x86_64 and aarch64 guests, each on a host of that arch"

	local missing=()
	# `mkfs.ext4` and `debugfs` live in /usr/sbin, which a non-login ssh does not
	# have on PATH — hence the explicit PATH rather than a bare command lookup.
	export PATH=$PATH:/usr/sbin:/sbin
	local tool
	for tool in curl tar xz bzip2 make gcc ld bc flex bison sha256sum mkfs.ext4 cargo rustc; do
		command -v "$tool" >/dev/null || missing+=("$tool")
	done
	# The kernel build needs these headers/libs; the error it gives without them
	# is thirty lines into a compile and names a header, not a package.
	[[ -e /usr/include/elf.h ]] || missing+=("libelf-dev (elf.h)")
	[[ -e /usr/include/openssl/opensslv.h ]] || missing+=("libssl-dev (openssl headers)")
	if ((${#missing[@]})); then
		die "missing build prerequisites: ${missing[*]}
  Debian/Ubuntu: sudo apt-get install -y build-essential bc bison flex \\
      libelf-dev libssl-dev xz-utils bzip2 e2fsprogs curl"
	fi
	rustup target list --installed 2>/dev/null | grep -qx "$RUST_TARGET" ||
		die "rust target $RUST_TARGET is not installed — rustup target add $RUST_TARGET"
}

fetch() {
	local url=$1 sha=$2 dest=$3
	mkdir -p "$(dirname "$dest")"
	if [[ -f $dest ]] && [[ $(sha256sum "$dest" | cut -d' ' -f1) == "$sha" ]]; then
		say "cached $(basename "$dest")"
		return
	fi
	say "fetching $(basename "$dest")"
	curl -fsSL --retry 3 -o "$dest.part" "$url"
	local got
	got=$(sha256sum "$dest.part" | cut -d' ' -f1)
	[[ $got == "$sha" ]] || die "sha256 mismatch for $url
  expected $sha
  got      $got"
	mv "$dest.part" "$dest"
}

# ── Stage: the init binary ───────────────────────────────────────────────────

build_init() {
	say "building kamaji-guest-init for $RUST_TARGET"
	# musl links statically by default, which is the whole requirement: the guest
	# rootfs has no dynamic loader. Built from the kamaji workspace so it shares
	# the lockfile with the microvm backend it has a contract with.
	(cd "$KAMAJI_DIR" && cargo build --release --target "$RUST_TARGET" -p kamaji-guest-init)
	# CARGO_TARGET_DIR honoured, so a container build can keep its target dir
	# off a bind-mounted checkout (and out of the host's own target dir).
	local bin=${CARGO_TARGET_DIR:-$KAMAJI_DIR/target}/$RUST_TARGET/release/kamaji-guest-init
	[[ -x $bin ]] || die "cargo did not produce $bin"
	# Proof, not assumption: a dynamically-linked init in a rootfs with no libc.so
	# is a guest that panics before it prints anything. Both spellings count —
	# rustc's musl target emits a static-PIE, which the kernel loads without an
	# interpreter exactly as it does a non-PIE static binary.
	if command -v file >/dev/null && ! file "$bin" | grep -qE 'statically linked|static-pie linked'; then
		die "$bin is not statically linked — $(file "$bin")"
	fi
	mkdir -p "$OUT"
	install -m 0755 "$bin" "$OUT/kamaji-guest-init"
	say "init: $(du -h "$OUT/kamaji-guest-init" | cut -f1) static binary"
}

# ── Stage: the kernel ────────────────────────────────────────────────────────

# Symbols the guest cannot boot or cannot do its job without. Re-checked after
# olddefconfig because a fragment line is a *request*: kconfig drops any symbol
# whose dependencies are unmet, silently, and the result is an image that fails
# at boot with no reference to the config that caused it.
REQUIRED_SYMBOLS=(
	CONFIG_64BIT CONFIG_SMP
	# CONFIG_PCI is here despite a Firecracker guest having no PCI bus and kamaji
	# passing `pci=off`: turning it off is measured ON x86_64 to break
	# virtio_blk's probe and leave the guest with no root device. See
	# kernel/microvm.config. Kept for aarch64 too, where it is unmeasured: the
	# base config has it on, and the lesson of that bisection is not to be the
	# one who finds out.
	CONFIG_PCI
	# `+` form: an empty array is "unbound" to bash < 4.4 under `set -u`, and
	# this line runs before preflight can say why the host is refused.
	${ARCH_REQUIRED_SYMBOLS[@]+"${ARCH_REQUIRED_SYMBOLS[@]}"}
	CONFIG_BLOCK CONFIG_EXT4_FS CONFIG_OVERLAY_FS CONFIG_TMPFS CONFIG_TMPFS_XATTR
	CONFIG_DEVTMPFS CONFIG_DEVTMPFS_MOUNT CONFIG_PROC_FS CONFIG_SYSFS
	CONFIG_VIRTIO CONFIG_VIRTIO_MMIO CONFIG_VIRTIO_BLK CONFIG_VIRTIO_NET
	CONFIG_SERIAL_8250 CONFIG_SERIAL_8250_CONSOLE CONFIG_TTY
	CONFIG_NET CONFIG_INET CONFIG_IP_PNP CONFIG_UNIX
	# A member guest's tailscaled needs a real TUN (R605-F36, kernel/microvm.config).
	CONFIG_TUN
	CONFIG_BINFMT_ELF CONFIG_BINFMT_SCRIPT CONFIG_FUTEX CONFIG_EPOLL
	CONFIG_MULTIUSER CONFIG_POSIX_TIMERS CONFIG_SHMEM CONFIG_FILE_LOCKING
)

build_kernel() {
	local tarball=$DL/linux-$KERNEL_VERSION.tar.xz
	fetch "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" \
		"$KERNEL_SHA256" "$tarball"

	local src=$WORK/linux-$KERNEL_VERSION
	if [[ ! -d $src ]]; then
		say "unpacking linux-$KERNEL_VERSION"
		mkdir -p "$WORK"
		tar -C "$WORK" -xf "$tarball"
	fi

	local base=$GUEST_DIR/kernel/$KERNEL_BASE_CONFIG
	local got
	got=$(sha256sum "$base" | cut -d' ' -f1)
	[[ $got == "$KERNEL_BASE_CONFIG_SHA256" ]] || die "kernel/$KERNEL_BASE_CONFIG has been edited.
  It is firecracker $FIRECRACKER_VERSION's guest config, vendored verbatim so it can be
  diffed against upstream on a bump. Put guest changes in kernel/microvm.config,
  which is merged over it; if you really did mean to re-vendor, update
  KERNEL_BASE_CONFIG_SHA256 in this script.
  expected $KERNEL_BASE_CONFIG_SHA256
  got      $got"

	say "configuring $GUEST_ARCH: firecracker $FIRECRACKER_VERSION base config + kernel/microvm.config"
	install -m 0644 "$base" "$src/.config"
	"$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" \
		"$GUEST_DIR/kernel/microvm.config" >/dev/null
	make -C "$src" ARCH="$KERNEL_ARCH" olddefconfig >/dev/null

	local dropped=()
	local sym
	for sym in "${REQUIRED_SYMBOLS[@]}"; do
		grep -qx "$sym=y" "$src/.config" || dropped+=("$sym")
	done
	if ((${#dropped[@]})); then
		die "kconfig dropped required symbols: ${dropped[*]}
  Each is either misspelled in kernel/microvm.config or has an unmet dependency
  in linux-$KERNEL_VERSION. Check with: make -C $src ARCH=$KERNEL_ARCH menuconfig"
	fi
	# Modules would need a /lib/modules tree in a read-only image that ships
	# separately from the kernel; the config says n and this makes sure of it.
	grep -qx 'CONFIG_MODULES=y' "$src/.config" && die "CONFIG_MODULES survived; the image ships no /lib/modules"

	say "building $KERNEL_MAKE_TARGET with -j$JOBS (this is the slow part)"
	make -C "$src" ARCH="$KERNEL_ARCH" -j"$JOBS" "$KERNEL_MAKE_TARGET"
	local image=$src/$KERNEL_ARTIFACT
	[[ -f $image ]] || die "no $KERNEL_ARTIFACT produced"
	# The gotcha this ticket carries, asserted rather than trusted: Firecracker
	# boots one specific uncompressed format per arch, and the wrong one here
	# would present as a node that advertises the microVM backend and fails
	# every guest at boot. Checked by magic rather than with `file`, which a
	# minimal build container does not necessarily have.
	case $GUEST_ARCH in
	x86_64)
		[[ $(head -c 4 "$image" | od -An -tx1 | tr -d ' \n') == 7f454c46 ]] ||
			die "$image is not an ELF image (a bzImage would be the usual mistake)"
		;;
	aarch64)
		[[ $(head -c 60 "$image" | tail -c 4) == ARMd ]] ||
			die "$image has no arm64 Image magic (\"ARMd\" at offset 56)"
		;;
	esac
	mkdir -p "$OUT"
	install -m 0644 "$image" "$OUT/vmlinux"
	install -m 0644 "$src/.config" "$OUT/vmlinux.config"
	say "vmlinux ($GUEST_ARCH $KERNEL_MAKE_TARGET): $(du -h "$OUT/vmlinux" | cut -f1) (config beside it as vmlinux.config)"
}

# ── Stage: busybox ───────────────────────────────────────────────────────────

build_busybox() {
	local tarball=$DL/busybox-$BUSYBOX_VERSION.tar.bz2
	fetch "https://busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2" \
		"$BUSYBOX_SHA256" "$tarball"
	local src=$WORK/busybox-$BUSYBOX_VERSION
	if [[ ! -d $src ]]; then
		say "unpacking busybox-$BUSYBOX_VERSION"
		mkdir -p "$WORK"
		tar -C "$WORK" -xf "$tarball"
	fi

	say "configuring busybox: defconfig + rootfs/busybox.config (+ ${#BUSYBOX_ARCH_CONFIG[@]} $GUEST_ARCH line(s))"
	make -C "$src" defconfig >/dev/null
	# Hand-rolled overlay: busybox vendors an old kconfig with no
	# merge_config.sh. Each line of the fragment is either `CONFIG_X=v` (set it)
	# or `# CONFIG_X is not set` (clear it), and both forms replace whatever
	# defconfig chose.
	local line sym
	while read -r line; do
		[[ $line =~ ^[[:space:]]*$ ]] && continue
		if [[ $line =~ ^CONFIG_([A-Z0-9_]+)= ]]; then
			sym=CONFIG_${BASH_REMATCH[1]}
		elif [[ $line =~ ^#[[:space:]]*CONFIG_([A-Z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set ]]; then
			sym=CONFIG_${BASH_REMATCH[1]}
		else
			continue
		fi
		sed -i -e "/^${sym}=/d" -e "/^# ${sym} is not set$/d" "$src/.config"
		printf '%s\n' "$line" >>"$src/.config"
	done < <(
		cat "$GUEST_DIR/rootfs/busybox.config"
		((${#BUSYBOX_ARCH_CONFIG[@]})) && printf '%s\n' "${BUSYBOX_ARCH_CONFIG[@]}"
		true
	)
	yes '' | make -C "$src" oldconfig >/dev/null 2>&1 || true
	grep -qx 'CONFIG_STATIC=y' "$src/.config" ||
		die "busybox CONFIG_STATIC did not survive oldconfig; a dynamic busybox cannot run in this rootfs"

	say "building busybox with -j$JOBS"
	make -C "$src" -j"$JOBS" >/dev/null
	[[ -x $src/busybox ]] || die "no busybox binary produced"
	if command -v file >/dev/null && ! file "$src/busybox" | grep -q 'statically linked'; then
		die "busybox is not statically linked: $(file "$src/busybox")"
	fi
	BUSYBOX_BIN=$src/busybox
}

# ── Stage: the rootfs image ──────────────────────────────────────────────────

# Directories the image must carry. Empty directories are not tracked by git, and
# several of them are load-bearing rather than conventional: /mnt is where the
# init mounts the scratch disk before it has a writable root, /overlay is where
# the tmpfs holding the overlay's upper layer goes, /oldroot is the pivot's
# destination for the read-only image, and /toolchain is where the build
# toolchain volume is mounted so it can be the overlay's second lower layer
# (R605-F23). A missing one of those is a guest that cannot assemble a writable
# root, or one that boots without a compiler on a node that staged one.
ROOTFS_DIRS=(
	bin sbin etc root proc sys dev tmp run var/tmp usr/bin usr/sbin usr/lib
	mnt overlay oldroot workspace toolchain
)

build_rootfs() {
	[[ -x $OUT/kamaji-guest-init ]] || die "no $OUT/kamaji-guest-init — run the init stage first"
	build_busybox

	local staging=$WORK/rootfs.d
	rm -rf "$staging"
	mkdir -p "$staging"
	local dir
	for dir in "${ROOTFS_DIRS[@]}"; do mkdir -p "$staging/$dir"; done
	chmod 1777 "$staging/tmp" "$staging/var/tmp"

	install -m 0755 "$BUSYBOX_BIN" "$staging/bin/busybox"
	# Every applet as a symlink, because the rootfs is read-only at runtime and
	# `busybox --install` could not create them then. `init` and `linuxrc` are
	# skipped even though the config already drops them: /sbin/init is ours, and
	# a busybox init silently winning that path would boot a guest that ignores
	# the job document entirely.
	local applet
	while read -r applet; do
		[[ -z $applet || $applet == init || $applet == linuxrc ]] && continue
		ln -sf busybox "$staging/bin/$applet"
	done < <("$BUSYBOX_BIN" --list)
	[[ -L $staging/bin/sh ]] || ln -sf busybox "$staging/bin/sh"

	install -m 0755 "$OUT/kamaji-guest-init" "$staging/sbin/init"
	cp -a "$GUEST_DIR/rootfs/etc/." "$staging/etc/"
	ln -sf /proc/self/mounts "$staging/etc/mtab"

	# What is in this image, readable from inside the guest and from `debugfs` on
	# the host. No build timestamp on purpose: the same inputs must produce the
	# same bytes, and a date would make every image differ from every other.
	local git_sha
	git_sha=$(cd "$KAMAJI_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
	cat >"$staging/etc/kamaji-guest-image.json" <<EOF
{
  "arch": "$GUEST_ARCH",
  "kernel": "$KERNEL_VERSION",
  "busybox": "$BUSYBOX_VERSION",
  "init": "$("$OUT/kamaji-guest-init" --version 2>/dev/null || echo kamaji-guest-init)",
  "source_commit": "$git_sha",
  "job_schema": 1
}
EOF

	# Size from content: a read-only image has no reason to be bigger than what it
	# holds plus enough slack for ext4's own metadata.
	local used_kb size_mb
	used_kb=$(du -sk "$staging" | cut -f1)
	size_mb=$(((used_kb / 1024) * 2 + 24))
	say "assembling rootfs.ext4 (${used_kb}K of content, ${size_mb}M image)"
	rm -f "$OUT/rootfs.ext4"
	truncate -s "${size_mb}M" "$OUT/rootfs.ext4"
	# WITH a journal, as of R605-F33, reversing the `-O ^has_journal` this used to
	# carry. That flag was justified by "the image is attached read-only and never
	# recovered", and that premise is now false for half of its uses: a
	# service-shaped guest boots a private writable copy of this image
	# (`RootDisk::provision`) and the init keeps it as the real root rather than
	# overlaying it, so it IS written, and a guest that panics or is torn down
	# mid-write resets without a clean unmount. Nothing in the guest or on the
	# host runs e2fsck, so without a journal that filesystem is simply damaged and
	# the service's state is gone. 4 MB against a 30 MB image, and jobs — which
	# still mount it read-only from a clean, never-written node image — pay only
	# the size.
	# Unprivileged by construction — `mkfs.ext4 -d` needs no loop mount, which is
	# the same reason kamaji can build the scratch disk without root.
	mkfs.ext4 -q -F -d "$staging" "$OUT/rootfs.ext4"
	# Provenance sidecar, read and logged by MicroVmRuntime::new at kamaji
	# startup so a running node says which rootfs it boots guests from without
	# anyone having to ssh in and hash 30 MB. The toolchain volume gets the same
	# treatment, and for a stronger reason — see build-toolchain-image.sh.
	sha256sum "$OUT/rootfs.ext4" | cut -d' ' -f1 >"$OUT/rootfs.ext4.sha256"
	say "rootfs: $(du -h "$OUT/rootfs.ext4" | cut -f1), sha256 $(cat "$OUT/rootfs.ext4.sha256")"
}

# ── Stage: the service image (R605-F32) ──────────────────────────────────────
#
# What a service-shaped guest's private root is seeded from
# (MicroVmConfig::service_rootfs_image), and a different OPERATING SYSTEM from
# rootfs.ext4 on purpose. A job wants the minimal image whose PID 1 is the job
# runner. A long-lived guest that hosts a cluster member wants a real init, so
# that the provisioning path a metal node runs — .yah/infra/cloud-init/
# stand-up-yubaba.sh over ssh: apt-get, systemd units, drop-ins — runs inside it
# unchanged, and a VM member is provisioned exactly like a metal one instead of
# by a second, VM-only path. So: Debian (the same suite the Pis run) with
# systemd as PID 1, and kamaji-guest-init demoted to service-rootfs/'s
# kamaji-job.service, which still speaks the job-document contract to the host.
#
# Pinned to a snapshot.debian.org timestamp, so the same inputs fetch the same
# package versions; the image's runtime apt sources are then pointed at the
# live mirror, because a snapshot's Release files expire and the guest has to
# be able to `apt-get install` the way a metal node does.
DEBIAN_SUITE=trixie
DEBIAN_SNAPSHOT=${DEBIAN_SNAPSHOT:-20261001T000000Z}
SERVICE_PACKAGES=(
	systemd systemd-sysv udev dbus
	openssh-server sudo
	# What stand-up-yubaba.sh calls before it installs anything itself.
	curl ca-certificates iproute2 procps
)
# Room for what a member installs after boot (containerd, the yubaba/kamaji
# pair, journald, raft state). The image file is sparse until a guest writes.
SERVICE_IMAGE_SLACK_MB=2048

build_service_rootfs() {
	[[ -x $OUT/kamaji-guest-init ]] || die "no $OUT/kamaji-guest-init — run the init stage first"
	[[ -n ${AUTHORIZED_KEYS:-} && -f $AUTHORIZED_KEYS ]] ||
		die "the service-rootfs stage needs --authorized-keys FILE: the image's \`yah\` user is
  how a guest is provisioned (ssh yah@<guest>), and the key is a deployment input,
  not something to commit"
	command -v mmdebstrap >/dev/null || die "mmdebstrap is not installed — apt-get install -y mmdebstrap"

	local staging=$WORK/service-rootfs.d
	rm -rf "$staging"
	say "bootstrapping debian $DEBIAN_SUITE @ snapshot $DEBIAN_SNAPSHOT for $GUEST_ARCH"
	local packages
	packages=$(IFS=,; echo "${SERVICE_PACKAGES[*]}")
	# Root mode: mmdebstrap mounts /proc, /sys and /dev inside the chroot for
	# maintainer scripts, so in a container this needs --privileged.
	SOURCE_DATE_EPOCH=$(date -u -d "${DEBIAN_SNAPSHOT:0:8}" +%s) \
		mmdebstrap --mode=root --variant=minbase --include="$packages" \
		--aptopt='Acquire::Check-Valid-Until "false"' \
		"$DEBIAN_SUITE" "$staging" \
		"deb http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT/ $DEBIAN_SUITE main"

	say "installing the job runner, the yah user and per-guest identity hooks"
	install -D -m 0755 "$OUT/kamaji-guest-init" "$staging/usr/lib/kamaji/kamaji-guest-init"
	cp -a "$GUEST_DIR/service-rootfs/." "$staging/"
	mkdir -p "$staging/etc/systemd/system/multi-user.target.wants"
	ln -sf /etc/systemd/system/kamaji-job.service \
		"$staging/etc/systemd/system/multi-user.target.wants/kamaji-job.service"
	# The /workspace mount point the job document names by default; the runner
	# creates any other on its own.
	mkdir -p "$staging/workspace"

	chroot "$staging" useradd --create-home --shell /bin/bash --groups sudo yah
	install -m 0440 /dev/stdin "$staging/etc/sudoers.d/yah" <<<'yah ALL=(ALL) NOPASSWD:ALL'
	install -d -m 0700 "$staging/home/yah/.ssh"
	install -m 0600 "$AUTHORIZED_KEYS" "$staging/home/yah/.ssh/authorized_keys"
	chroot "$staging" chown -R yah:yah /home/yah/.ssh

	# Per-guest, not per-image: every service root is a copy of this file, so
	# anything identifying baked here would be shared by every member. Host keys
	# come from 10-kamaji-hostkeys.conf on first boot; an empty machine-id is
	# systemd's documented "generate me" state.
	rm -f "$staging"/etc/ssh/ssh_host_*
	: >"$staging/etc/machine-id"
	echo kamaji-guest >"$staging/etc/hostname"
	# minbase ships no /etc/hosts, and sudo — the provisioning path's first
	# command — resolves the hostname on every call.
	printf '127.0.0.1\tlocalhost\n127.0.1.1\tkamaji-guest\n::1\tlocalhost ip6-localhost ip6-loopback\n' \
		>"$staging/etc/hosts"

	# Runtime sources: the live mirror, as on a metal node.
	rm -f "$staging/etc/apt/sources.list"
	cat >"$staging/etc/apt/sources.list.d/debian.sources" <<EOF
Types: deb
URIs: http://deb.debian.org/debian
Suites: $DEBIAN_SUITE $DEBIAN_SUITE-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: $DEBIAN_SUITE-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
	rm -rf "$staging"/var/lib/apt/lists/* "$staging"/var/cache/apt/*.bin

	local git_sha
	git_sha=$(cd "$KAMAJI_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
	cat >"$staging/etc/kamaji-guest-image.json" <<EOF
{
  "image": "service",
  "arch": "$GUEST_ARCH",
  "debian": "$DEBIAN_SUITE@$DEBIAN_SNAPSHOT",
  "init": "systemd; job runner $("$OUT/kamaji-guest-init" --version 2>/dev/null || echo kamaji-guest-init)",
  "source_commit": "$git_sha",
  "job_schema": 1
}
EOF

	local used_kb size_mb
	used_kb=$(du -sk "$staging" | cut -f1)
	size_mb=$(((used_kb / 1024) * 5 / 4 + SERVICE_IMAGE_SLACK_MB))
	say "assembling service-rootfs.ext4 (${used_kb}K of content, ${size_mb}M image)"
	rm -f "$OUT/service-rootfs.ext4"
	truncate -s "${size_mb}M" "$OUT/service-rootfs.ext4"
	# Journalled for the reason rootfs.ext4 now is (R605-F33): a service writes
	# its root and a torn-down guest resets mid-write.
	mkfs.ext4 -q -F -d "$staging" "$OUT/service-rootfs.ext4"
	sha256sum "$OUT/service-rootfs.ext4" | cut -d' ' -f1 >"$OUT/service-rootfs.ext4.sha256"
	say "service rootfs: ${size_mb}M, sha256 $(cat "$OUT/service-rootfs.ext4.sha256")"
}

# ── Run ──────────────────────────────────────────────────────────────────────

[[ -n ${CLEAN:-} ]] && rm -rf "$OUT"
preflight
mkdir -p "$OUT" "$WORK" "$DL"
wants init && build_init
wants kernel && build_kernel
wants rootfs && build_rootfs
wants_named service-rootfs && build_service_rootfs

say "done. artifacts in $OUT:"
ls -lh "$OUT" | sed 's/^/    /'
cat <<EOF

Install on a node:
    install -D -m 0644 $OUT/vmlinux     /var/lib/yah/kamaji/microvm/vmlinux
    install -D -m 0644 $OUT/rootfs.ext4 /var/lib/yah/kamaji/microvm/rootfs.ext4
then start kamaji with --microvm-dir /var/lib/yah/kamaji/microvm.
The filenames are not negotiable: MicroVmRuntime::new looks for exactly
vmlinux and rootfs.ext4 and advertises no microVM backend if either is absent.
EOF
