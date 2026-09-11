#!/usr/bin/env bash
# Build the guest kernel + rootfs kamaji's microVM backend boots (R605-F14 / W325 §5).
#
# Produces exactly the two artifacts MicroVmRuntime::new refuses to construct
# without, under the names it looks for:
#
#   <out>/vmlinux       uncompressed ELF kernel (NOT a bzImage — Firecracker
#                       boots the former only)
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
# ── Where it runs ────────────────────────────────────────────────────────────
#
# x86_64 Linux, because it compiles an x86_64 Linux kernel; there is no
# cross-build shortcut worth carrying for a step that is already gated on having
# a Linux host with /dev/kvm to boot-test on. The camp Mac cannot run this. See
# the machine files under .yah/infra/machines/ for a node that can.
set -euo pipefail

# ── Pins ─────────────────────────────────────────────────────────────────────
# Both tarballs are checked by sha256, so an upstream that changes bytes under a
# version fails the build instead of quietly changing the guest. 6.1 is the
# series Firecracker documents as a supported guest kernel.
KERNEL_VERSION=${KERNEL_VERSION:-6.1.187}
KERNEL_SHA256=${KERNEL_SHA256:-1b6e798aeaa708ca670a426ad5a6c86dc2237b8e59e8822876976c383873642b}
# kernel/base-x86_64-6.1.config is Firecracker's own CI guest config, vendored
# verbatim from firecracker v1.16.1
# (resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config). Checked here so
# a local edit to a 3500-line generated file is caught: the way to change the
# guest's configuration is kernel/microvm.config, which is merged over this.
# Re-pin both when bumping the firecracker version — see that file's header for
# what the base buys and what happened without it.
KERNEL_BASE_CONFIG_SHA256=adbc70ab5e89213ba00594b12d25e09bdf8bb1ed3c252d7449326bb14c22963b
FIRECRACKER_VERSION=v1.16.1
BUSYBOX_VERSION=${BUSYBOX_VERSION:-1.37.0}
BUSYBOX_SHA256=${BUSYBOX_SHA256:-3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4}
RUST_TARGET=x86_64-unknown-linux-musl

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
  --only STAGE     one of: init, kernel, rootfs  (repeatable via commas)
  --clean          remove the whole out dir first, including fetched tarballs
  -h, --help       this

Stages: `init` cross-compiles kamaji-guest-init, `kernel` builds vmlinux,
`rootfs` assembles rootfs.ext4 (and needs `init` to have run at least once).
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--out) OUT=$2; shift 2 ;;
	--jobs) JOBS=$2; shift 2 ;;
	--only) STAGES=$2; shift 2 ;;
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

# ── Preflight ────────────────────────────────────────────────────────────────

preflight() {
	[[ $(uname -s) == Linux ]] || die "this builds a Linux kernel; run it on the x86_64 Linux build node, not $(uname -s)"
	[[ $(uname -m) == x86_64 ]] || die "this builds an x86_64 guest; this host is $(uname -m)"

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
	local bin=$KAMAJI_DIR/target/$RUST_TARGET/release/kamaji-guest-init
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
	CONFIG_64BIT CONFIG_SMP CONFIG_KVM_GUEST CONFIG_ACPI
	# CONFIG_PCI is here despite a Firecracker guest having no PCI bus and kamaji
	# passing `pci=off`: turning it off is measured to break virtio_blk's probe
	# and leave the guest with no root device. See kernel/microvm.config.
	CONFIG_PCI
	# How firecracker v1.16.1 actually advertises its virtio devices — as
	# `virtio_mmio.device=` command-line arguments, not through ACPI.
	CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES
	CONFIG_BLOCK CONFIG_EXT4_FS CONFIG_OVERLAY_FS CONFIG_TMPFS CONFIG_TMPFS_XATTR
	CONFIG_DEVTMPFS CONFIG_DEVTMPFS_MOUNT CONFIG_PROC_FS CONFIG_SYSFS
	CONFIG_VIRTIO CONFIG_VIRTIO_MMIO CONFIG_VIRTIO_BLK CONFIG_VIRTIO_NET
	CONFIG_SERIAL_8250 CONFIG_SERIAL_8250_CONSOLE CONFIG_TTY
	CONFIG_NET CONFIG_INET CONFIG_IP_PNP CONFIG_UNIX
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

	local base=$GUEST_DIR/kernel/base-x86_64-6.1.config
	local got
	got=$(sha256sum "$base" | cut -d' ' -f1)
	[[ $got == "$KERNEL_BASE_CONFIG_SHA256" ]] || die "kernel/base-x86_64-6.1.config has been edited.
  It is firecracker $FIRECRACKER_VERSION's guest config, vendored verbatim so it can be
  diffed against upstream on a bump. Put guest changes in kernel/microvm.config,
  which is merged over it; if you really did mean to re-vendor, update
  KERNEL_BASE_CONFIG_SHA256 in this script.
  expected $KERNEL_BASE_CONFIG_SHA256
  got      $got"

	say "configuring: firecracker $FIRECRACKER_VERSION base config + kernel/microvm.config"
	install -m 0644 "$base" "$src/.config"
	"$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" \
		"$GUEST_DIR/kernel/microvm.config" >/dev/null
	make -C "$src" ARCH=x86_64 olddefconfig >/dev/null

	local dropped=()
	local sym
	for sym in "${REQUIRED_SYMBOLS[@]}"; do
		grep -qx "$sym=y" "$src/.config" || dropped+=("$sym")
	done
	if ((${#dropped[@]})); then
		die "kconfig dropped required symbols: ${dropped[*]}
  Each is either misspelled in kernel/microvm.config or has an unmet dependency
  in linux-$KERNEL_VERSION. Check with: make -C $src ARCH=x86_64 menuconfig"
	fi
	# Modules would need a /lib/modules tree in a read-only image that ships
	# separately from the kernel; the config says n and this makes sure of it.
	grep -qx 'CONFIG_MODULES=y' "$src/.config" && die "CONFIG_MODULES survived; the image ships no /lib/modules"

	say "building vmlinux with -j$JOBS (this is the slow part)"
	make -C "$src" ARCH=x86_64 -j"$JOBS" vmlinux
	[[ -f $src/vmlinux ]] || die "no vmlinux produced"
	# The gotcha this ticket carries, asserted rather than trusted: Firecracker
	# boots an uncompressed ELF, and a bzImage here would present as a node that
	# advertises the microVM backend and fails every guest at boot.
	if command -v file >/dev/null && ! file "$src/vmlinux" | grep -q 'ELF 64-bit'; then
		die "$src/vmlinux is not an ELF image: $(file "$src/vmlinux")"
	fi
	mkdir -p "$OUT"
	install -m 0644 "$src/vmlinux" "$OUT/vmlinux"
	install -m 0644 "$src/.config" "$OUT/vmlinux.config"
	say "vmlinux: $(du -h "$OUT/vmlinux" | cut -f1) (config beside it as vmlinux.config)"
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

	say "configuring busybox: defconfig + rootfs/busybox.config"
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
	done <"$GUEST_DIR/rootfs/busybox.config"
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
	# No journal: the image is attached read-only and never recovered, so a
	# journal is 4 MB of an artifact that gets copied to every build node.
	# Unprivileged by construction — `mkfs.ext4 -d` needs no loop mount, which is
	# the same reason kamaji can build the scratch disk without root.
	mkfs.ext4 -q -F -O ^has_journal -d "$staging" "$OUT/rootfs.ext4"
	# Provenance sidecar, read and logged by MicroVmRuntime::new at kamaji
	# startup so a running node says which rootfs it boots guests from without
	# anyone having to ssh in and hash 30 MB. The toolchain volume gets the same
	# treatment, and for a stronger reason — see build-toolchain-image.sh.
	sha256sum "$OUT/rootfs.ext4" | cut -d' ' -f1 >"$OUT/rootfs.ext4.sha256"
	say "rootfs: $(du -h "$OUT/rootfs.ext4" | cut -f1), sha256 $(cat "$OUT/rootfs.ext4.sha256")"
}

# ── Run ──────────────────────────────────────────────────────────────────────

[[ -n ${CLEAN:-} ]] && rm -rf "$OUT"
preflight
mkdir -p "$OUT" "$WORK" "$DL"
wants init && build_init
wants kernel && build_kernel
wants rootfs && build_rootfs

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
