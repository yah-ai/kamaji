#!/usr/bin/env bash
# Build the guest BUILD-TOOLCHAIN volume kamaji attaches as a third drive
# (R605-F23 / W325 §5).
#
# Produces one artifact, plus its provenance sidecar:
#
#   <out>/toolchain.ext4          read-only ext4 image: a Rust + C build
#                                 environment, laid out as a filesystem root
#   <out>/toolchain.ext4.sha256   the bytes' identity, for the machine file
#
# Install as <microvm-dir>/toolchain.ext4 on a build node. kamaji picks it up
# by that exact filename and attaches it `is_read_only: true`; a node without
# one still boots guests, they just cannot compile anything.
#
# ── Why a separate volume rather than a layer in the rootfs ──────────────────
#
# R605-F23's framing assumed the choice was "baked into the read-only rootfs"
# vs "a mutable per-node mount", and that mounted implied mutable. It does not.
# Firecracker takes a list of drives and kamaji already attaches the rootfs
# with `is_read_only: true`, so a toolchain on its own drive is attached the
# same way and is exactly as immutable to the guest as a baked layer would be —
# the correctness property the read-only rootfs exists for ("job N must not
# leave state for job N+1") is about JOB-WRITABLE state, and there is none
# here.
#
# What the separate volume buys is the update path. MEASURED on us-west-003 on
# 2026-09-10, and it is the reason the fork is not close: this image is 1166 MB
# (1003 MiB of content) against a 30 MB rootfs. R605-F23 priced baking it in at
# "a ~75MB image rebuild"; the real number is fifteen times that. Baking would
# grow the artifact redistributed on every busybox, kernel or init change from
# 30 MB to 1.2 GB, and couple the cadence of a Rust release to that of a kernel
# CVE. Two files on a node, versioned and hashed independently, is the cheaper
# shape by a wide margin.
#
# ── Why the staging tree is filesystem-root-shaped ───────────────────────────
#
# The guest init adds this image as a SECOND OVERLAYFS LOWER LAYER beneath the
# rootfs image, so everything in here appears at its natural absolute path:
# /usr/bin/cc, /lib64/ld-linux-x86-64.so.2, /usr/local/bin/cargo. Nothing has
# to be relocated, no wrapper scripts, no LD_LIBRARY_PATH — a build sees an
# ordinary Debian userland because that is literally what the layer is. The
# busybox rootfs stays the TOP lower layer, so its /bin applets and its
# checked-in /etc still win where the two collide.
#
# ── Where it runs ────────────────────────────────────────────────────────────
#
# x86_64 Debian, because it takes the C toolchain from that host's own apt
# repository (unprivileged: `apt-get download` + `dpkg-deb -x`, no root, no
# chroot). The camp Mac cannot run this. Same node as build-guest-image.sh.
set -euo pipefail

# ── Pins ─────────────────────────────────────────────────────────────────────
# The Rust tarballs are sha256-checked against upstream's published .sha256, so
# an upstream that changes bytes under a version fails the build rather than
# quietly changing what the fleet compiles with.
RUST_VERSION=${RUST_VERSION:-1.98.0}
RUST_HOST=x86_64-unknown-linux-gnu
RUST_SHA256=${RUST_SHA256:-ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f}
# The musl std, so a guest can produce the static binaries this fleet ships.
RUST_MUSL_TARGET=x86_64-unknown-linux-musl
RUST_STD_MUSL_SHA256=${RUST_STD_MUSL_SHA256:-1a76f782db2d540e1cd16ea47829b323f4a8f4dda64bca4b23be189109c510f8}

# The C half. Deliberately NOT `build-essential`: that drags in perl, dpkg-dev
# and g++ for a machine that compiles Rust crates whose `cc`-crate build
# scripts want a C compiler, a linker, headers and make. Everything below is
# expanded to its full dependency closure by apt-cache, so this is the
# intent-level list and not the install list.
#
# `ca-certificates` is here for a load-bearing reason rather than tidiness: the
# busybox rootfs carries four files in /etc and none of them is a trust store,
# so before this layer existed a guest could open a TCP connection to
# static.crates.io (R605-F22 proved that) and still fail every `cargo fetch` at
# certificate verification.
APT_PACKAGES=${APT_PACKAGES:-"gcc libc6-dev binutils make pkg-config ca-certificates"}

GUEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=$GUEST_DIR/out

usage() {
	cat <<'EOF'
usage: build-toolchain-image.sh [options]

  --out DIR    where toolchain.ext4 lands (default: guest/out)
  --clean      remove the staging tree and fetched tarballs first
  -h, --help   this
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--out) OUT=$2; shift 2 ;;
	--clean) CLEAN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

WORK=$OUT/toolchain-work
DL=$OUT/downloads

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────

preflight() {
	[[ $(uname -s) == Linux ]] || die "this assembles a Linux build environment from Debian packages; run it on the x86_64 Linux build node, not $(uname -s)"
	[[ $(uname -m) == x86_64 ]] || die "this builds an x86_64 guest toolchain; this host is $(uname -m)"

	# mkfs.ext4 lives in /usr/sbin, which a non-login ssh does not have on PATH.
	export PATH=$PATH:/usr/sbin:/sbin
	local missing=() tool
	for tool in curl tar xz sha256sum mkfs.ext4 apt-get apt-cache dpkg-deb; do
		command -v "$tool" >/dev/null || missing+=("$tool")
	done
	((${#missing[@]})) && die "missing prerequisites: ${missing[*]}"
	return 0
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

# ── Stage: the Rust toolchain ────────────────────────────────────────────────

# Installed under /usr/local rather than unpacked wholesale, because rustc
# locates its own sysroot RELATIVE TO ITS BINARY (<exe>/../lib/rustlib) and
# finds librustc_driver through an $ORIGIN/../lib RPATH. Put the two halves
# anywhere inconsistent and rustc starts, then fails on the first crate with
# "can't find crate for `std`" — a message that reads like a missing target.
install_rust() {
	local staging=$1
	local base=https://static.rust-lang.org/dist
	local full=$DL/rust-$RUST_VERSION-$RUST_HOST.tar.xz
	local std=$DL/rust-std-$RUST_VERSION-$RUST_MUSL_TARGET.tar.xz
	fetch "$base/$(basename "$full")" "$RUST_SHA256" "$full"
	fetch "$base/$(basename "$std")" "$RUST_STD_MUSL_SHA256" "$std"

	mkdir -p "$WORK"
	local fdir=$WORK/rust-$RUST_VERSION-$RUST_HOST
	local sdir=$WORK/rust-std-$RUST_VERSION-$RUST_MUSL_TARGET
	[[ -d $fdir ]] || { say "unpacking $(basename "$full")"; tar -C "$WORK" -xf "$full"; }
	[[ -d $sdir ]] || { say "unpacking $(basename "$std")"; tar -C "$WORK" -xf "$std"; }

	# rust-docs is ~900 MB of the ~1.8 GB a default rustup profile occupies, and
	# nothing in a guest will ever read it. clippy/rustfmt are left out for the
	# same reason: a forge step that wants them is a different ticket, and this
	# image is already the largest artifact the fleet distributes.
	say "installing rustc + cargo + std($RUST_HOST) into /usr/local"
	"$fdir/install.sh" --prefix="$staging/usr/local" --disable-ldconfig \
		--components="rustc,cargo,rust-std-$RUST_HOST" >/dev/null
	say "installing std($RUST_MUSL_TARGET)"
	"$sdir/install.sh" --prefix="$staging/usr/local" --disable-ldconfig \
		--components="rust-std-$RUST_MUSL_TARGET" >/dev/null

	# The uninstall manifests are the installer's own bookkeeping and reference
	# host paths that mean nothing inside a guest.
	rm -rf "$staging/usr/local/lib/rustlib/uninstall.sh" "$staging/usr/local/lib/rustlib/manifest-"* \
		"$staging/usr/local/share/doc" "$staging/usr/local/share/man"
	[[ -x $staging/usr/local/bin/rustc ]] || die "rust install.sh produced no rustc"
	[[ -x $staging/usr/local/bin/cargo ]] || die "rust install.sh produced no cargo"
}

# ── Stage: the C toolchain ───────────────────────────────────────────────────

# Taken from the build node's own apt repository rather than from a tarball,
# because there is no upstream tarball for "gcc plus the exact glibc it was
# built against" and hand-assembling one is how you get a linker that half
# works. Unprivileged by construction: `apt-get download` needs no lock and
# `dpkg-deb -x` needs no root, so this runs as the same user that builds the
# rootfs. The exact resolved versions land in the image's manifest, which is
# what makes a node's C toolchain identifiable after the fact.
install_c_toolchain() {
	local staging=$1
	say "resolving apt closure of: $APT_PACKAGES"
	local list
	# shellcheck disable=SC2086
	list=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
		--no-breaks --no-replaces --no-enhances --no-pre-depends $APT_PACKAGES |
		grep -v '^ ' | grep -v '^<' | sort -u)
	[[ -n $list ]] || die "apt-cache resolved no packages for: $APT_PACKAGES"
	say "$(echo "$list" | wc -l) packages"

	local debs=$DL/debs
	mkdir -p "$debs"
	say "downloading .debs"
	# shellcheck disable=SC2086
	(cd "$debs" && apt-get download $list >/dev/null 2>&1) ||
		die "apt-get download failed — run 'apt-get update' on this node first"

	say "extracting into the staging tree"
	local deb
	for deb in "$debs"/*.deb; do dpkg-deb -x "$deb" "$staging"; done

	# Documentation, locales and changelogs: ~40 MB of an image that gets
	# copied to every build node, read by nothing.
	rm -rf "$staging/usr/share/doc" "$staging/usr/share/man" \
		"$staging/usr/share/locale" "$staging/usr/share/info"

	# usr-merge compatibility. Debian has been usr-merged since bookworm, so
	# every .deb puts its payload under /usr and the `/lib -> usr/lib` and
	# `/lib64 -> usr/lib64` symlinks that make the old paths work live in
	# `base-files`, which is not — and should not be — in this closure. Without
	# them the ELF interpreter path baked into every binary here
	# (/lib64/ld-linux-x86-64.so.2) resolves to nothing and the guest reports
	# "No such file or directory" for a cargo that is plainly present.
	#
	# Only these two. The extracted tree has no /bin or /sbin of its own, so
	# there is nothing to reconcile against the busybox rootfs layered above it,
	# and inventing symlinks for those names would put this image in a fight with
	# the layer that is supposed to win.
	ln -sfn usr/lib "$staging/lib"
	ln -sfn usr/lib64 "$staging/lib64"

	[[ -x $staging/usr/bin/gcc ]] || die "no gcc in the extracted tree"
	[[ -e $staging/lib64/ld-linux-x86-64.so.2 ]] || die "no dynamic loader — rustc and cargo are glibc-dynamic and could not start"

	# `cc` is a dpkg alternative, i.e. a symlink update-alternatives creates in
	# a postinst — and nothing runs postinsts here. Without it the `cc` crate
	# fails looking for a compiler that is sitting right next to it under
	# another name.
	ln -sf gcc "$staging/usr/bin/cc"

	# Likewise ca-certificates: the .deb ships the individual PEMs and leaves
	# the bundle to update-ca-certificates. Assembling it here is exactly what
	# that postinst does, and without it every HTTPS fetch in the guest fails
	# certificate verification rather than failing to connect — which looks
	# like a network problem and is not one.
	mkdir -p "$staging/etc/ssl/certs"
	cat "$staging"/usr/share/ca-certificates/mozilla/*.crt >"$staging/etc/ssl/certs/ca-certificates.crt"
	local n
	n=$(grep -c 'BEGIN CERTIFICATE' "$staging/etc/ssl/certs/ca-certificates.crt")
	((n > 100)) || die "only $n certificates in the assembled trust store — expected the full Mozilla set"
	say "trust store: $n certificates"
	# Named for the three env vars the tools in this image read.
	ln -sf ca-certificates.crt "$staging/etc/ssl/certs/ca-bundle.crt"
}

# ── Stage: the image ─────────────────────────────────────────────────────────

build_image() {
	local staging=$WORK/toolchain.d
	rm -rf "$staging"
	mkdir -p "$staging"

	install_rust "$staging"
	install_c_toolchain "$staging"

	# What is in this image. Read by the guest init to decide whether a drive is
	# the toolchain at all, and by an operator asking what a node compiles with.
	# No build timestamp, for the same reason the rootfs manifest carries none:
	# the same inputs must produce the same bytes.
	# One `dpkg-deb --show` per archive. It takes a SINGLE archive and silently
	# reports only the first when handed a glob, which produced a manifest
	# claiming one package where there are sixty-four — caught by reading the
	# line the guest init logs at boot, not by the script failing.
	local pkgs deb
	pkgs=$(for deb in "$DL"/debs/*.deb; do
		dpkg-deb --show --showformat='    "${Package}": "${Version}",\n' "$deb"
	done | sort | sed '$ s/,$//')
	[[ $(grep -c . <<<"$pkgs") -ge 2 ]] || die "manifest would record $(grep -c . <<<"$pkgs") package(s) — dpkg-deb read only part of $DL/debs"
	cat >"$staging/kamaji-toolchain.json" <<EOF
{
  "schema": 1,
  "rust": "$RUST_VERSION",
  "rust_host": "$RUST_HOST",
  "rust_targets": ["$RUST_HOST", "$RUST_MUSL_TARGET"],
  "prefix": "/usr/local",
  "debian_packages": {
$pkgs
  }
}
EOF

	local used_kb size_mb
	used_kb=$(du -sk "$staging" | cut -f1)
	size_mb=$(((used_kb / 1024) * 11 / 10 + 64))
	say "assembling toolchain.ext4 (${used_kb}K of content, ${size_mb}M image)"
	rm -f "$OUT/toolchain.ext4"
	truncate -s "${size_mb}M" "$OUT/toolchain.ext4"
	# No journal, same reasoning as the rootfs: attached read-only, never
	# recovered, and every megabyte is copied to every build node.
	mkfs.ext4 -q -F -O ^has_journal -d "$staging" "$OUT/toolchain.ext4"

	# Provenance. A separate volume can drift per-node in a way a baked layer
	# cannot, so the bytes get an identity that travels with them into the
	# machine file. This is the sidecar the ticket asks for.
	sha256sum "$OUT/toolchain.ext4" | cut -d' ' -f1 >"$OUT/toolchain.ext4.sha256"
	say "toolchain: $(du -h "$OUT/toolchain.ext4" | cut -f1), sha256 $(cat "$OUT/toolchain.ext4.sha256")"
}

# ── Run ──────────────────────────────────────────────────────────────────────

[[ -n ${CLEAN:-} ]] && rm -rf "$WORK" "$DL"
preflight
mkdir -p "$OUT" "$WORK" "$DL"
build_image

cat <<EOF

Install on a node:
    install -D -m 0644 $OUT/toolchain.ext4 /var/lib/yah/kamaji/microvm/toolchain.ext4
kamaji picks it up by that filename with no flag change. Record
$(cat "$OUT/toolchain.ext4.sha256")
in the node's machine file next to the rootfs sha256.
EOF
