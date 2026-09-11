//! `/sbin/init` for a kamaji microVM guest (R605-F14 / W325 §5).
//!
//! kamaji's microVM backend boots a node-owned kernel and a node-owned
//! read-only rootfs, and tells the guest what it was booted for by writing
//! `job.json` at the root of the per-job scratch disk. This binary is the other
//! side of that contract: it is PID 1 in that guest, it reads the document,
//! stages the mounts the document declares, runs its argv, records the result
//! and resets the machine so the VMM exits and kamaji's supervisor fires.
//!
//! It is the *only* thing in the image that has to stay in step with kamaji, and
//! the two ship separately — a rootfs built months before the kamaji that boots
//! it. So the contract is the serialized JSON and nothing else; see [`job`] for
//! why the document type is redeclared here rather than imported.
//!
//! Build and image assembly: `oss/kamaji/guest/build-guest-image.sh`.
//!
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)

// Off Linux only the parser and its tests are reachable, and its accessors are
// called from the boot path that does not compile there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod job;

#[cfg(target_os = "linux")]
mod boot;

/// Exit status for "you ran this on the wrong thing".
///
/// Deliberately outside the range [`boot::exit`] uses: an operator who runs the
/// binary by hand must not get a code that looks like a job result.
const EXIT_NOT_A_GUEST: i32 = 2;

/// On Linux: boot, run, halt. Anywhere else: refuse.
///
/// The non-Linux arm exists so the crate stays a member of the `oss/kamaji`
/// workspace and its parser tests run in the camp's ordinary `cargo test` on
/// macOS. Everything a guest init actually *does* is a Linux mount syscall, so
/// there is nothing to emulate — only a reason not to pretend.
#[cfg(target_os = "linux")]
fn main() {
    if version_only() {
        return;
    }

    // Refusing off PID 1 is not politeness. This binary's first act is to mount
    // a block device over /mnt and pivot the root filesystem; run as root on a
    // *host* by someone poking at an artifact, that is a real mess. Inside the
    // guest it is always PID 1, so the guard costs nothing where it runs for
    // real.
    if std::process::id() != 1 && std::env::var_os("KAMAJI_GUEST_INIT_FORCE").is_none() {
        eprintln!(
            "kamaji-guest-init is PID 1 inside a kamaji microVM guest: it mounts the scratch \
             disk, pivots onto an overlay root and resets the machine. Running it as an ordinary \
             process would do that to whatever host you are on. Set KAMAJI_GUEST_INIT_FORCE=1 if \
             that is genuinely what you want."
        );
        std::process::exit(EXIT_NOT_A_GUEST);
    }

    let outcome = boot::run();
    if std::process::id() == 1 {
        // As PID 1 there is no exit: returning from init is a kernel panic, and
        // a panic is a worse way to end a successful build than a clean reset.
        boot::halt(outcome.code);
    }
    eprintln!("[guest-init] not PID 1; exiting {} instead of resetting the VM", outcome.code);
    std::process::exit(outcome.code);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if version_only() {
        return;
    }
    eprintln!(
        "kamaji-guest-init is a Linux guest init: it mounts, pivots and resets a Firecracker VM. \
         Build it for x86_64-unknown-linux-musl — see oss/kamaji/guest/build-guest-image.sh."
    );
    std::process::exit(EXIT_NOT_A_GUEST);
}

/// `--version` is answered on every platform: the image build calls it to stamp
/// the init's version into `/etc/kamaji-guest-image.json`, and that stamp is how
/// an operator on a node tells which guest image is installed.
fn version_only() -> bool {
    let asked = std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V");
    if asked {
        println!("kamaji-guest-init {}", env!("CARGO_PKG_VERSION"));
    }
    asked
}
