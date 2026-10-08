//! Everything that only means something inside a Firecracker guest.
//!
//! Split from [`crate::job`] on the line the ticket draws: the document parser
//! is pure and runs on the camp Mac, and everything here is a mount syscall that
//! can only be exercised on a Linux host with `/dev/kvm`. Keeping them apart is
//! what lets `cargo test` on a laptop still be worth running.
//!
//! ## Why there is an overlay in here at all
//!
//! kamaji attaches the rootfs `is_read_only: true`, and that is a correctness
//! property rather than hardening — one image serves every job on the node, so
//! anything a job could write into it would be waiting for the next job. But the
//! job document asks the guest to bind-mount volumes at arbitrary absolute paths
//! (`/yah/produced`, `/etc/certs`, `/src`), and a bind mount needs its target to
//! exist. On a read-only root the init cannot create one.
//!
//! So the init assembles a writable root out of parts that are all discarded at
//! halt: the read-only image as overlayfs' lower layer, a tmpfs as its upper,
//! and `pivot_root` into the result. Mount points become creatable, nothing
//! reaches the image, and the "job N leaves nothing for job N+1" property is
//! kept by construction (RAM does not survive the VM) rather than by everything
//! in the guest being careful.
//!
//! ## …and why a service-shaped guest gets no overlay at all (R605-F33)
//!
//! The paragraph above is the *job* shape. R605-F31 gave a service-shaped guest
//! its own private copy of the node image, attached read-write, precisely so that
//! its root could be state — but an unconditional tmpfs overlay turns that device
//! into the overlay's **lower** layer and the guest never writes to it.
//!
//! So the init probes for it, the same way it probes for the scratch disk and
//! the toolchain rather than trusting a device name: [`root_is_writable`]
//! attempts a read-write remount of `/`. A job gets `EROFS` there *by
//! construction* — kamaji attaches the node's shared image `is_read_only: true`
//! — and falls through to the overlay above, unchanged. A service's remount
//! succeeds, and then the root the guest already has **is** the durable root:
//! [`adopt_durable_root`] keeps it, mounts the kernel filesystems onto it and
//! never pivots. No job document changed, so no `SCHEMA_VERSION` bump and no
//! rootfs image can skew against a kamaji binary.
//!
//! The overlay is not merely unnecessary in that shape, it is *impossible*:
//! overlayfs since 4.19 rejects overlapping layers (`ovl_check_overlapping_layers`
//! walks each upper/work dir's ancestors for a lower-layer trap inode), so
//! `lowerdir=/,upperdir=/<anything>` fails `-ELOOP`, and an upper that is a
//! filesystem's own root has nowhere left to put `workdir`. Bind-mounting around
//! it does not help — the check is on inodes, which is exactly the trick it was
//! added to catch. A durable root is the real device or it is nothing.
//!
//! **The one thing that shape costs**: the build toolchain is merged by being
//! overlayfs' second lower layer (R605-F23), and there is no overlay to put it
//! in. On a node that has staged one it stays mounted at [`TOOLCHAIN_MOUNT`] and
//! is reachable there, but not at `/usr/bin/cc`. Services are appliances and
//! builds are job-shaped, so this is the right way round; a service that must
//! compile needs per-directory overlays (`lowerdir=/usr:/toolchain/usr`, which
//! *is* legal — `/` is not a layer root then), and that is a design call, not a
//! line of code.
//!
//! ## Why the VM reboots rather than powers off
//!
//! `kamaji::microvm`'s supervisor treats *the VMM process exiting* as job
//! completion, and the VMM exits when the guest resets: on x86_64 by hitting the
//! i8042 reset port, which is what `reboot=k` on the kernel command line
//! selects; on aarch64 by a PSCI `SYSTEM_RESET` call, which KVM hands
//! Firecracker as a system event and which needs nothing on the command line
//! (measured on us-west-014, R605-F32 — see `kamaji::microvm::GuestArch`). `RB_POWER_OFF`
//! would take the ACPI path instead and, if the VMM does not implement it, leave
//! the guest spinning in `machine_halt` with the supervisor waiting forever. So
//! [`halt`] reboots, and only falls back to power-off and then to killing itself
//! (`panic=1` reboots too) if that somehow returns.
//!
//! @yah:ticket(R605-F33, "Guest half of the durable service root: kamaji-guest-init should use the real root as the overlay upper when /dev/vda is writable")
//! @yah:status(review)
//! @yah:at(2026-09-11T05:53:33Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:gotcha("MEASURED 2026-09-10 BY R605-F31, READ FROM SOURCE NOT INFERRED FROM BEHAVIOUR: kamaji-guest-init pivots UNCONDITIONALLY into an overlayfs whose upper layer is a tmpfs — oss/kamaji/crates/kamaji-guest-init/src/boot.rs:312-335, `mount(\"tmpfs\", OVERLAY_ROOT, ...)` then `lowerdir={/ or /:<toolchain>},upperdir=<tmpfs>/upper,workdir=<tmpfs>/work`. So R605-F31's host-side work (a service-shaped guest boots a PRIVATE writable copy of the node rootfs, attached is_read_only:false) reaches the guest as the overlay's LOWER layer and the guest never writes to that block device at all. Confirmed live on us-west-003: the guest kernel cmdline reads `root=/dev/vda rw` (firecracker emits rw because of the flag), and writes to / still vanish on reset. The host half is correct and landed; this ticket is the guest half.")
//! @yah:next("THE DESIGN NEEDS NO JOB-DOCUMENT CHANGE, which is the point — do not bump JOB_SCHEMA_VERSION. The init already probes rather than trusting device names (DISK_CANDIDATES, TOOLCHAIN_MANIFEST), so it can probe one more host-side fact: attempt a read-write mount of the root device, and if it succeeds use a directory ON IT as overlayfs' upperdir/workdir instead of the tmpfs. A job-shaped guest gets EROFS there (kamaji attaches the node's shared image is_read_only:true) and falls back to the tmpfs it uses today, so job behaviour is unchanged by construction and no schema bump can skew a rootfs image against a kamaji binary.")
//! @yah:next("THE COST IS THE IMAGE, NOT THE CODE, and it is the reason R605-F31 did not do this in the same pass. Landing it means rebuilding rootfs.ext4 via oss/kamaji/guest/build-guest-image.sh and re-staging it at /var/lib/yah/kamaji/microvm/rootfs.ext4 on us-west-003 — replacing the exact image every other R605 proof (F14, F22, F23, T24, F31) was measured against, on the only node in the fleet where any of this can be tested. Keep the old image beside it and regenerate the .sha256 sidecar (MicroVmRuntime::new logs it at startup and warns on an unidentifiable image).")
//! @yah:verify("The proof is a boot counter on / rather than on /workspace. R605-F31's oss/kamaji/crates/kamaji/tests/microvm_service_e2e.rs deliberately writes its counter to /workspace/boots.txt because that IS durable today; this ticket's test writes to a path on / and asserts the count still grows across restarts. Both must pass afterwards, plus the job-path regression already in that file (a_job_guest_is_still_reaped_and_never_restarted) and microvm_guest_e2e's 3 tests, which are what would catch an init change breaking the job shape.")
//! @yah:handoff("GUEST HALF LANDED AND PROVEN ON us-west-003. boot.rs no longer pivots unconditionally: new stage_writable_root() dispatches on root_is_writable(), which attempts mount(none,/,MS_REMOUNT) and then writes+unlinks /.kamaji-root-rw-probe (a successful remount says the kernel took the flag, not that a write reaches the platter). A job gets EROFS at the remount by construction (kamaji attaches the node image is_read_only:true) and falls through to the unchanged overlay path, renamed pivot_into_overlay_root. A service's probe succeeds and adopt_durable_root() keeps the real device as / -- NO overlay, NO pivot_root -- moving the scratch disk to job.workspace_mount and mounting only /sys /tmp /run (proc and dev are already up from run(); /tmp and /run stay tmpfs so a durable root is not where scratch accumulates). New RootShape enum is carried to flush_and_unmount, which remounts / read-only before halt: ext4 flushes and marks clean, which is what makes the next boot's mount and the host's debugfs read see the writes instead of a filesystem caught mid-write by the i8042 reset. No job-document field moved; JOB_SCHEMA_VERSION is still 1 and /etc/kamaji-guest-image.json still reads job_schema 1.")
//! @yah:handoff("THE IMAGE WAS REBUILT AND RE-STAGED ON us-west-003, AND THE ROLLBACK IS ONE COMMAND. Built with `./guest/build-guest-image.sh --only init,rootfs` (kernel untouched, vmlinux is the Sep 10 08:16 artifact). Staged at /var/lib/yah/kamaji/microvm/rootfs.ext4 with its regenerated sidecar; sha256 sidecar and file agree. NEW image sha256 643970f777c08cdd54b441234759eb294a382a09a3c269a100488d1c6d2ff437, 30 MB, /etc/kamaji-guest-image.json source_commit 8675e1a0, init 0.8.37. PRE-F33 image kept beside it as rootfs.ext4.pre-R605-F33 (sha256 bf8d367f351ddee1920a6ca4354779c08a74db1af0465eb43a7a0394888aa6ec) with rootfs.ext4.sha256.pre-R605-F33. TO ROLL BACK: `sudo install -m 0644 /var/lib/yah/kamaji/microvm/rootfs.ext4{.pre-R605-F33,} && sudo install -m 0644 /var/lib/yah/kamaji/microvm/rootfs.ext4.sha256{.pre-R605-F33,}` — no rebuild. ONE DELIBERATE IMAGE CHANGE BEYOND THE INIT BINARY: mkfs.ext4 no longer passes `-O ^has_journal`. That flag's stated justification was \"attached read-only and never recovered\", which this ticket makes false for half its uses — a service writes this filesystem and a panicked or torn-down guest resets without a clean unmount, and nothing in the guest or on the host runs e2fsck. Verified present with dumpe2fs (has_journal + orphan_file, state clean); the image is still exactly 30 MB because the size formula's slack already covered the 4 MB journal, and jobs still mount it read-only from a never-written node image.")
//! @yah:verify("PASS ON REAL HARDWARE, us-west-003, 2026-09-11, firecracker v1.16.1 / guest kernel 6.1.187, against the named baselines. (1) microvm_service_e2e 4 passed / 0 failed in 7.22s — F31's 3 plus the new a_services_root_survives_its_restarts, which counts boots into /root-boots.txt ON / and reads them back off the service's private <vm_dir>/rootfs.ext4 with debugfs after teardown; it saw 3 distinct VMM pids and >= 2 completed boot lines, and re-asserts the node's shared rootfs.ext4 is sha256-identical afterwards. (2) NEGATIVE CONTROL, the part that makes the test worth having: the same test run against the staged PRE-F33 image FAILS with \"0 boot line(s) after 3 VMM pids\" and debugfs reporting \"/root-boots.txt: File not found by ext2_lookup\" — so it discriminates the fix rather than passing for an unrelated reason. F33 image restored immediately after and re-verified by sha256. (3) microvm_guest_e2e 3 passed / 0 failed, including a_real_cargo_build_runs_in_a_guest — its console still reads \"writable root in place: overlay(lower=read-only image, upper=tmpfs)\" and cc/cargo/rustc still resolve at absolute paths, so the job shape and the R605-F23 toolchain merge are untouched. (4) kamaji lib 120 passed / 0 failed, exactly F31's baseline. (5) kamaji-guest-init 8 passed / 0 failed. (6) Captured service console shows the whole decision: \"EXT4-fs (vda): re-mounted\" (the probe), \"durable root in place: the root block device itself, read-write, no overlay\", then \"durable root committed: / remounted read-only\" before halt.")
//! @yah:gotcha("THE DESIGN AS WRITTEN IN THIS TICKET'S @yah:next IS NOT IMPLEMENTABLE, AND THE SHIPPED SHAPE IS THE NEARBY ONE THAT IS. \"Use a directory on the writable root as overlayfs' upperdir/workdir\" cannot work: since Linux 4.19 overlayfs rejects overlapping layers — ovl_check_overlapping_layers walks each upper/work dir's ancestors looking for a lower-layer trap inode — so lowerdir=/ with upperdir=/<anything> fails -ELOOP (\"overlapping upperdir path\"), and making the filesystem's own root the upperdir leaves nowhere legal for workdir, which must be on the same fs and outside upper. The check is on INODES, so bind-mounting the device somewhere else does not evade it; that is precisely the trick it was added to catch. What ships instead reaches the same end state more directly: when the root is writable there is NO overlay at all, because the service's root IS a private copy of the node image (RootDisk::provision) and therefore already carries everything a lower layer would have supplied. The probe, the EROFS-by-construction job fallback and the no-schema-bump property are all exactly as the ticket specified.")
//! @yah:gotcha("A SERVICE-SHAPED GUEST NO LONGER SEES THE BUILD TOOLCHAIN AT ABSOLUTE PATHS, and this is a real behaviour change on any node that staged toolchain.ext4 (us-west-003 has one). The toolchain is merged by being overlayfs' second lower layer (R605-F23); a durable root has no overlay to be a layer of, and the two are mutually exclusive under overlayfs for the reason in the gotcha above. It stays mounted at /toolchain and is fully usable there, and the init logs a loud warning naming the tradeoff on every such boot. Jobs are unaffected — builds are job-shaped and keep the merge, proven by a_real_cargo_build_runs_in_a_guest still passing. SECOND HAZARD, IMAGE SKEW, and it is silent: a kamaji with F31 running against a rootfs image built BEFORE F33 gives a service an ephemeral / again with no error anywhere, because the init in that image pivots unconditionally. JOB_SCHEMA_VERSION deliberately did not move (a bump would break jobs to fix services), so nothing refuses the pair. a_services_root_survives_its_restarts is the only thing that catches it — run it after staging any image on a node that runs services.")
//! @yah:handoff("THREE FIXES BEYOND THE TICKET TITLE, all in files this ticket already owned. (1) microvm.rs doc comments were asserting the opposite of what now happens — RootDisk's \"What this does NOT yet buy\" section, the module heading's durable-state table row, and the paragraph naming F33 as unbuilt. All three rewritten to the shipped behaviour, keeping the history of why the halves landed a day apart. Only the prose changed; no F31 code and no F31 @yah: annotation was touched. (2) tests/microvm_service_e2e.rs debugfs_dump() built its scratch path from std::process::id() alone; two tests in that file now dump, cargo runs them as threads of ONE process, so they would have raced onto one path and read each other's guest state — a silently passing test, not a failing one. Path now includes the guest path. (3) base_spec's doc comment explained its /workspace counter as \"writing to / would pass for the wrong reason\"; that reasoning expired with this ticket, so it now says the true reason — /workspace is durable for BOTH shapes, which is what keeps base_spec usable as the job-shaped control. FILES TOUCHED: oss/kamaji/crates/kamaji-guest-init/src/boot.rs, oss/kamaji/crates/kamaji/src/microvm.rs (doc only), oss/kamaji/crates/kamaji/tests/microvm_service_e2e.rs, oss/kamaji/guest/build-guest-image.sh. Camp git policy is defer, so nothing is staged: `git add oss/kamaji/crates/kamaji-guest-init/src/boot.rs oss/kamaji/crates/kamaji/src/microvm.rs oss/kamaji/crates/kamaji/tests/microvm_service_e2e.rs oss/kamaji/guest/build-guest-image.sh`. NOT touched: oss/kamaji/crates/kamaji/src/sibling.rs, which @Ashguard:dove (session:1e4618c6) holds in flight for R870-B24.")
//! @yah:cleanup("A service that must COMPILE has no toolchain at absolute paths any more (see gotcha). The shape that would give it both is per-directory overlays rather than a root overlay — lowerdir=/usr:/toolchain/usr with upperdir/workdir elsewhere on the durable root IS legal, because / is then not a layer root and the trap-inode walk finds nothing. Not built here: choosing which directories to merge is exactly the guesswork R605-F23 avoided by merging at /, so it needs a design call and a measurement, not a line of code. Nothing in the fleet needs it today — every build path is job-shaped.")
//! @yah:handoff("LEADER SIGN-OFF (R605, session:d990eccb) — WORK ACCEPTED, ticket is DONE. THE TICKET'S STATED DESIGN WAS NOT IMPLEMENTABLE and the courier disproved it from the kernel's behaviour rather than by flailing at it: this ticket's @yah:next, and my dispatch which repeated it verbatim, said to use a directory on the writable root as overlayfs' upperdir/workdir. That is -ELOOP, permanently — since Linux 4.19 ovl_check_overlapping_layers walks each upper/work dir's ancestors for a lower-layer trap inode, and the check is on INODES so bind-mounting the device elsewhere does not evade it. The shipped shape reaches the same end state more directly (no overlay at all when the root is writable, because a service's root is ALREADY a private copy of the node image from F31's RootDisk::provision), while preserving every property the ticket actually cared about: the probe, the EROFS-by-construction job fallback, and no schema bump. VERIFIED, and the negative control is what makes it worth anything: a_services_root_survives_its_restarts passes on the F33 image and FAILS on the staged pre-F33 image with '0 boot line(s) after 3 VMM pids', so it discriminates the fix rather than passing for an unrelated reason. microvm_service_e2e 4/0, microvm_guest_e2e 3/0 with the R605-F23 toolchain merge intact, kamaji lib 120/0 exactly matching F31's baseline, kamaji-guest-init 8/0 — all on real hardware. Image rollback is two `install` commands with no rebuild. SIGNAL FOR THE TRACK, not a criticism of anyone: two tickets running — F31 and F33 — have now had their host-side-authored design corrected by the courier that built it. Scope the next microVM ticket with a guest-side read FIRST. COLUMN NOTE: this ticket belongs in `review`, not `handoff` — there is no baton here and no picker is needed. board.review refuses it with \"ticket 'R605-F33' not found — it may have been archived or may not exist in this camp\" while board.show, board.claim and board.update all resolve it; a board.claim to flip handoff->in-progress did not clear it either. Same failure hit R605-T30. Likely cause, unconfirmed: this annotation MOVED from boot.rs:34 to boot.rs:68 when the courier edited the file above it, and the arch.review_ticket path appears to resolve a stale (file, line) where board.show re-scans. Reported to the operator. Do not read the column as a request for more work.")
//! @yah:gotcha("SILENT IMAGE SKEW, AND NOTHING REFUSES THE PAIR — the most operationally important thing on this ticket. A kamaji carrying R605-F31 running against a rootfs image built BEFORE R605-F33 gives a service an EPHEMERAL root again, with no error anywhere, because the init inside that older image pivots into the tmpfs overlay unconditionally. JOB_SCHEMA_VERSION deliberately did not move (a bump would have broken jobs in order to fix services), so no version check can catch it. a_services_root_survives_its_restarts is the ONLY thing that detects it — run it after staging any rootfs image on any node that runs service-shaped workloads. This is the exact flip side of the no-schema-bump property that makes the job path safe by construction: the same choice that guarantees jobs cannot skew is what leaves services able to.")

use std::ffi::CString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::job::{Job, JobError, JOB_FILE};

/// Where the scratch disk is mounted *before* `pivot_root`, so the job document
/// can be read while the root is still the raw image.
const STAGE_MOUNT: &str = "/mnt";
/// Mount point of the tmpfs holding overlayfs' upper and work directories.
const OVERLAY_ROOT: &str = "/overlay";
/// Where the old, read-only root ends up after `pivot_root`.
const OLD_ROOT: &str = "/oldroot";
/// Where the build-toolchain volume is mounted before it becomes a lower layer.
///
/// It never appears here in the merged root — see [`pivot_into_overlay_root`].
/// This is only the handle overlayfs is given at mount time. A guest with a
/// durable root has no overlay to be a layer of, and stays mounted here for
/// real; see [`adopt_durable_root`].
const TOOLCHAIN_MOUNT: &str = "/toolchain";
/// Marker at the root of the toolchain volume, and the proof that a drive is
/// the toolchain (R605-F23).
///
/// Probed for, not assumed from a device name, for the same reason the job
/// document is: drive order is a property of how kamaji happened to list them.
const TOOLCHAIN_MANIFEST: &str = "kamaji-toolchain.json";

/// Block devices to look for the scratch disk on, in order.
///
/// `vdb` is where kamaji's drive ordering puts it (`rootfs` first, `workspace`
/// second) and is almost always the answer. The rest of the list exists because
/// a hardcoded device name is a silent failure the moment that ordering changes
/// — and because the check is cheap: a candidate is only accepted if it actually
/// carries the job document. `vda` is deliberately included last rather than
/// excluded: it fails the read-write mount (the host attached it read-only), so
/// it costs one `EROFS` and covers the case where a future config puts the
/// scratch disk first.
const DISK_CANDIDATES: &[&str] = &["/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vda"];

/// Written next to `job.json` on the scratch disk so the *job's* exit status
/// survives the VM.
///
/// The VMM's own exit code cannot carry it: a guest that reboots — cleanly or
/// through `panic=1` — trips the same i8042 reset, so Firecracker exits 0 either
/// way and "the build failed" and "the build passed" are indistinguishable from
/// the host side. This file is the channel. The host does not read it yet; see
/// the ticket handoff.
const STATUS_FILE: &str = "job-status.json";

/// Written to and immediately removed while probing whether `/` is genuinely
/// writable (R605-F33).
///
/// A successful `MS_REMOUNT` is necessary but not sufficient — it says the
/// kernel accepted the flag change, not that a write reaches the platter — and
/// the cost of being wrong is a guest that thinks its root is durable and
/// silently loses every write. One file, created and unlinked, settles it.
const RW_PROBE_FILE: &str = "/.kamaji-root-rw-probe";

macro_rules! log {
    ($($arg:tt)*) => {{
        let mut err = std::io::stderr();
        let _ = writeln!(err, "[guest-init] {}", format_args!($($arg)*));
        let _ = err.flush();
    }};
}

/// How the boot ended, in the vocabulary the exit code and the status file need.
pub struct Outcome {
    /// Exit code for this process, and the code recorded in the status file.
    pub code: i32,
    /// Human-readable one-liner: what happened, for the console log.
    pub detail: String,
}

/// Which of the two roots this boot ended up with (R605-F33).
///
/// Decided by probing the root device, never by anything in the job document —
/// see the module header. It is carried rather than re-probed because the answer
/// changes what has to happen at halt: a root that was only ever a tmpfs needs
/// nothing, and a root that is a block device the host is about to read needs
/// its page cache committed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootShape {
    /// overlayfs with a tmpfs upper over the read-only image. Job-shaped: every
    /// write is discarded when the VM resets.
    Ephemeral,
    /// The real root block device, mounted read-write, no overlay.
    /// Service-shaped: writes to `/` survive the reset.
    Durable,
    /// The root belongs to the image's own init, which mounted it and will
    /// unmount it on its clean reboot ([`Mode::Unit`], R605-F32). Nothing to
    /// stage and nothing to commit.
    Managed,
}

/// Who started this process, which decides how much of the machine it owns
/// (R605-F32).
///
/// The job document is the same contract in both modes — argv, env, mounts,
/// resolver in; `job-status.json` out; the VM resetting is the instance ending.
/// What differs is only whether this process is also the operating system.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// PID 1 of the minimal image: mounts the kernel filesystems, stages the
    /// root, runs the job, and resets the VM itself.
    Init,
    /// A unit under the image's own init — systemd, in the service image a
    /// cluster member boots, so that the provisioning path a metal node runs
    /// (apt, sshd, systemd units) runs inside the guest unchanged. The OS is
    /// already up and owns `/`, `/proc`, `/run` and the reset; this process
    /// only loads the document, runs argv, reports, and EXITS. The unit's
    /// `SuccessAction=`/`FailureAction=reboot` turns that exit into systemd's
    /// clean reboot, which ends at the same PSCI/i8042 reset [`halt`] uses.
    Unit,
}

/// Exit codes. Distinguishable on purpose — a schema refusal and a failed mount
/// are two different operator problems and must not both be "1".
#[allow(dead_code)]
pub mod exit {
    /// The job ran; its own exit code is reported instead of this.
    pub const OK: i32 = 0;
    /// No scratch disk carrying a job document was found.
    pub const NO_JOB_DISK: i32 = 64;
    /// The document was unreadable or not JSON.
    pub const MALFORMED_JOB: i32 = 65;
    /// The document declared a `schema` this image does not implement.
    pub const UNKNOWN_SCHEMA: i32 = 66;
    /// The writable root or one of the job's mounts could not be staged.
    pub const MOUNT_FAILED: i32 = 67;
    /// The job's argv could not be executed at all.
    pub const EXEC_FAILED: i32 = 68;
}

/// Boot the guest, run the job, and report how it went.
///
/// Every failure path returns rather than exiting, so the caller always reaches
/// [`halt`]: an init that gives up without halting leaves the VMM resident and
/// the supervisor waiting for a completion signal that will never come, which
/// presents as "the build hung" for as long as the node's teardown grace.
pub fn run(mode: Mode) -> Outcome {
    log!(
        "kamaji-guest-init {} — PID {} ({mode:?} mode)",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );

    if mode == Mode::Init {
        // The kernel mounts devtmpfs before running init when built with
        // CONFIG_DEVTMPFS_MOUNT, which is how /dev/console exists for our own
        // stderr. Re-mounting it is idempotent and covers a kernel built
        // without.
        let _ = mount("devtmpfs", "/dev", "devtmpfs", 0, None);
        ensure_console();
        let _ = mount("proc", "/proc", "proc", 0, None);
    }
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        // Printed because two load-bearing facts about this boot are only
        // observable here: whether the VMM injected `root=` itself, and whether
        // it advertises its virtio devices on the cmdline or through ACPI.
        log!("cmdline: {}", cmdline.trim());
    }

    // `pivot_root` and `MS_MOVE` both refuse to operate on a shared mount, and
    // what the kernel hands init is not guaranteed private. (Not in unit mode:
    // there `/` is the OS's, which needs no pivot and gets no move.)
    if mode == Mode::Init {
        if let Err(e) = mount("none", "/", "", libc::MS_REC | libc::MS_PRIVATE, None) {
            log!("warning: could not make / private ({e}) — pivot_root may refuse");
        }
    }

    let (disk, raw) = match find_job_disk() {
        Some(found) => found,
        None => {
            return Outcome {
                code: exit::NO_JOB_DISK,
                detail: format!(
                    "no scratch disk among {DISK_CANDIDATES:?} carries /{JOB_FILE} — kamaji \
                     attaches it as the second drive and writes the document into it at deploy"
                ),
            }
        }
    };
    log!("found /{JOB_FILE} on {disk} ({} bytes)", raw.len());

    let job = match Job::parse(&raw) {
        Ok(job) => job,
        Err(e) => {
            let code = match &e {
                JobError::UnknownSchema { .. } => exit::UNKNOWN_SCHEMA,
                JobError::Malformed(_) | JobError::Unusable(_) => exit::MALFORMED_JOB,
            };
            log!("REFUSED: {e}");
            // Status is still written: the host can read it back out of the disk
            // and see a schema refusal instead of an empty produced dir.
            write_status(STAGE_MOUNT, "-", code, &e.to_string());
            let _ = umount(STAGE_MOUNT, 0);
            return Outcome {
                code,
                detail: e.to_string(),
            };
        }
    };
    log!(
        "workload {} — argv {:?}, {} mount(s), workdir {:?}",
        job.workload,
        job.argv,
        job.mounts.len(),
        job.workdir.as_deref().unwrap_or("/")
    );

    let staged = match mode {
        Mode::Init => {
            // Probed before the pivot, because the toolchain has to be a lower
            // layer of the overlay the pivot lands in. Absent is normal: a node
            // that has staged no toolchain.ext4 still boots and still runs
            // argv, it just has no compiler.
            let toolchain = find_toolchain_disk(&disk);
            stage_writable_root(&job, toolchain.is_some())
        }
        Mode::Unit => adopt_managed_root(&job, &disk),
    };
    let shape = match staged {
        Ok(shape) => shape,
        Err(e) => {
            log!("MOUNT SETUP FAILED: {e}");
            write_status(&job.workspace_mount, &job.workload, exit::MOUNT_FAILED, &e);
            return Outcome {
                code: exit::MOUNT_FAILED,
                detail: e,
            };
        }
    };

    if let Err(e) = stage_job_mounts(&job) {
        log!("MOUNT SETUP FAILED: {e}");
        write_status(&job.workspace_mount, &job.workload, exit::MOUNT_FAILED, &e);
        return Outcome {
            code: exit::MOUNT_FAILED,
            detail: e,
        };
    }

    configure_network(&job);

    let outcome = run_job(&job);
    write_status(
        &job.workspace_mount,
        &job.workload,
        outcome.code,
        &outcome.detail,
    );
    // Unmount before halting: the host reads this filesystem with `debugfs` from
    // outside, so anything still in the guest's page cache when the VM resets is
    // an artifact that never arrives.
    flush_and_unmount(&job, shape);
    outcome
}

/// Mount each candidate device and keep the first that carries the job document.
fn find_job_disk() -> Option<(String, Vec<u8>)> {
    let _ = std::fs::create_dir_all(STAGE_MOUNT);
    for dev in DISK_CANDIDATES {
        if !Path::new(dev).exists() {
            continue;
        }
        if let Err(e) = mount(dev, STAGE_MOUNT, "ext4", 0, None) {
            log!("{dev}: not usable as the scratch disk ({e})");
            continue;
        }
        match std::fs::read(format!("{STAGE_MOUNT}/{JOB_FILE}")) {
            Ok(raw) => return Some(((*dev).to_string(), raw)),
            Err(e) => {
                log!("{dev}: mounted, but no /{JOB_FILE} ({e})");
                let _ = umount(STAGE_MOUNT, 0);
            }
        }
    }
    None
}

/// Mount the build-toolchain volume, if this node staged one.
///
/// Read-only, deliberately and redundantly: kamaji already attaches the drive
/// with `is_read_only: true`, so the guest could not write to it whatever it
/// asked for. Saying so here too means the mount fails loudly if a future
/// kamaji ever stops doing that, instead of silently giving one job a writable
/// surface that outlives it.
///
/// Returns the manifest text, which is logged so a build's console says which
/// toolchain compiled it — the one real cost of R605-F23 putting the toolchain
/// on its own volume is that it can drift from the rootfs per-node, and a line
/// in the log is what makes that drift attributable.
fn find_toolchain_disk(job_disk: &str) -> Option<String> {
    let _ = std::fs::create_dir_all(TOOLCHAIN_MOUNT);
    for dev in DISK_CANDIDATES {
        // The scratch disk is already mounted and is not the toolchain; /dev/vda
        // is the rootfs, already this process's `/`.
        if *dev == job_disk || *dev == "/dev/vda" || !Path::new(dev).exists() {
            continue;
        }
        if mount(dev, TOOLCHAIN_MOUNT, "ext4", libc::MS_RDONLY, None).is_err() {
            continue;
        }
        match std::fs::read_to_string(format!("{TOOLCHAIN_MOUNT}/{TOOLCHAIN_MANIFEST}")) {
            Ok(manifest) => {
                log!("build toolchain on {dev}: {}", manifest.split_whitespace().collect::<Vec<_>>().join(" "));
                return Some(manifest);
            }
            Err(_) => {
                log!("{dev}: mounted, but no /{TOOLCHAIN_MANIFEST} — not the toolchain volume");
                let _ = umount(TOOLCHAIN_MOUNT, 0);
            }
        }
    }
    log!("no build-toolchain volume attached — this guest can run programs but not compile them");
    None
}

/// Give the guest a root it can write to, by whichever of the two routes its
/// root device allows (R605-F33).
///
/// The probe is the decision. Nothing here reads the job document, so a rootfs
/// image and a kamaji binary cannot disagree about which shape a guest is —
/// which is the reason this is a probe and not a field.
fn stage_writable_root(job: &Job, toolchain: bool) -> Result<RootShape, String> {
    if root_is_writable() {
        adopt_durable_root(job, toolchain)?;
        Ok(RootShape::Durable)
    } else {
        pivot_into_overlay_root(job, toolchain)?;
        Ok(RootShape::Ephemeral)
    }
}

/// Can this guest write to its own root device?
///
/// Asked by attempting the write, because every cheaper answer is a guess.
/// `/proc/mounts` reports the flags the *kernel* mounted with, and Firecracker
/// appends `root=/dev/vda rw` from the drive's `is_read_only: false` — so a
/// service that was handed a read-only file would still read `rw` there and
/// believe itself durable.
///
/// A job-shaped guest fails at the remount: kamaji attaches the node's shared
/// image `is_read_only: true`, the virtio device is read-only, and ext4 refuses
/// the ro→rw transition. That is the whole safety argument for this feature —
/// "job N must not leave state for job N+1" survives because the *host* refuses
/// the write, not because this function remembered to.
fn root_is_writable() -> bool {
    if let Err(e) = mount("none", "/", "", libc::MS_REMOUNT, None) {
        log!("root device is read-only ({e}) — job-shaped guest, / will be an overlay on tmpfs");
        return false;
    }
    match std::fs::write(RW_PROBE_FILE, b"kamaji-guest-init\n") {
        Ok(()) => {
            if let Err(e) = std::fs::remove_file(RW_PROBE_FILE) {
                // Not fatal: a stray zero-byte file at the root of a durable
                // filesystem is untidy, not wrong.
                log!("warning: could not remove {RW_PROBE_FILE}: {e}");
            }
            true
        }
        Err(e) => {
            log!(
                "/ remounted read-write but {RW_PROBE_FILE} could not be written ({e}) — \
                 treating the root as read-only"
            );
            false
        }
    }
}

/// Keep the root device the guest already booted, and build the rest of the
/// namespace on top of it (R605-F33).
///
/// There is no overlay and no `pivot_root` here, and that is the point rather
/// than an omission: this device is a *private copy* of the node image made by
/// `RootDisk::provision`, so it already carries everything a lower layer would
/// have supplied, and stacking anything over it is what made the writes vanish.
/// See the module header for why overlayfs cannot express "durable root plus a
/// read-only lower layer" at all.
///
/// `/tmp` and `/run` are still tmpfs. A durable root is a place to *keep* things
/// deliberately; letting a service's scratch files accumulate in it across every
/// restart until the image fills is not that.
fn adopt_durable_root(job: &Job, toolchain: bool) -> Result<(), String> {
    if toolchain {
        log!(
            "warning: a build toolchain is attached but this guest has a durable root — it stays \
             mounted at {TOOLCHAIN_MOUNT} and is NOT merged at absolute paths, because overlayfs \
             cannot have both. Reach it as {TOOLCHAIN_MOUNT}/usr/bin/..., or run builds as \
             job-shaped guests, which is the shape they already are."
        );
    }

    // The scratch disk, moved from the staging mount to the place the job
    // document asked for. No pivot means no new root to move it *into*: the
    // mount point is a directory on the durable filesystem, which exists or can
    // now be created because the filesystem is writable.
    if job.workspace_mount.trim_end_matches('/') != STAGE_MOUNT {
        std::fs::create_dir_all(&job.workspace_mount)
            .map_err(|e| format!("mkdir {}: {e}", job.workspace_mount))?;
        mount(STAGE_MOUNT, &job.workspace_mount, "", libc::MS_MOVE, None)
            .map_err(|e| format!("moving the scratch disk to {}: {e}", job.workspace_mount))?;
    }

    // `/proc` and `/dev` are already mounted — `run` needed them before it could
    // read the cmdline or write to the console — and mounting them again would
    // only stack a second copy. The rest were only ever mounted after the pivot.
    for (src, target, fstype, data) in [
        ("sysfs", "/sys", "sysfs", None),
        ("tmpfs", "/tmp", "tmpfs", Some("mode=1777")),
        ("tmpfs", "/run", "tmpfs", Some("mode=0755")),
    ] {
        std::fs::create_dir_all(target).ok();
        if let Err(e) = mount(src, target, fstype, 0, data) {
            log!("warning: mounting {fstype} at {target} failed: {e}");
        }
    }
    log!("durable root in place: the root block device itself, read-write, no overlay");
    Ok(())
}

/// Unit mode's whole root staging: put the scratch disk where the document
/// asked, and touch nothing else (R605-F32).
///
/// Remounted rather than moved. systemd makes `/` a SHARED mount at boot, and
/// the kernel refuses `MS_MOVE` of a mount whose parent is shared (`EINVAL`) —
/// so [`adopt_durable_root`]'s move from the staging mount cannot work here,
/// and making `/` private to allow it would change propagation for every
/// service the OS runs. Unmounting the probe mount and mounting the device
/// again at its real place needs neither.
fn adopt_managed_root(job: &Job, disk: &str) -> Result<RootShape, String> {
    if job.workspace_mount.trim_end_matches('/') != STAGE_MOUNT {
        umount(STAGE_MOUNT, 0).map_err(|e| format!("releasing the probe mount of {disk}: {e}"))?;
        std::fs::create_dir_all(&job.workspace_mount)
            .map_err(|e| format!("mkdir {}: {e}", job.workspace_mount))?;
        mount(disk, &job.workspace_mount, "ext4", 0, None)
            .map_err(|e| format!("mounting {disk} at {}: {e}", job.workspace_mount))?;
    }
    log!(
        "root left to the image's own init; scratch disk {disk} at {}",
        job.workspace_mount
    );
    Ok(RootShape::Managed)
}

/// Build the overlay root and become it.
///
/// Ordering is the whole content of this function. The scratch disk is moved
/// into the new root *before* the pivot, because after the pivot the only way
/// back to it would be through the old root — which is exactly what gets
/// detached.
///
/// # The toolchain as a second lower layer (R605-F23)
///
/// When a toolchain volume is attached it goes in as a *lower layer beneath the
/// rootfs image*, which is what lets it be an ordinary Debian userland at
/// ordinary absolute paths — `/usr/bin/cc`, `/lib64/ld-linux-x86-64.so.2`,
/// `/usr/local/bin/cargo` — with no wrapper scripts, no relocation and no
/// `LD_LIBRARY_PATH`. The alternative, leaving it mounted at `/toolchain` and
/// prepending to `PATH`, fails on the first glibc-dynamic binary in it: the ELF
/// interpreter path is baked into the executable and is not searched.
///
/// Order matters and is `rootfs:toolchain`, not the reverse. overlayfs resolves
/// left-to-right, so the busybox image wins every collision: its `/bin` applets
/// and its checked-in `/etc` stay authoritative, and the toolchain fills in the
/// paths the minimal rootfs leaves empty. Directories merge rather than shadow,
/// so `/etc/ssl/certs` from the toolchain is still visible through the rootfs's
/// own `/etc`.
///
/// Both layers are read-only and the only writable part is still the tmpfs
/// upper, so "job N must not leave state for job N+1" holds exactly as it did
/// with one lower layer.
fn pivot_into_overlay_root(job: &Job, toolchain: bool) -> Result<(), String> {
    let merged = format!("{OVERLAY_ROOT}/root");
    let upper = format!("{OVERLAY_ROOT}/upper");
    let work = format!("{OVERLAY_ROOT}/work");

    std::fs::create_dir_all(OVERLAY_ROOT).map_err(|e| format!("mkdir {OVERLAY_ROOT}: {e}"))?;
    mount("tmpfs", OVERLAY_ROOT, "tmpfs", 0, Some("mode=0755"))
        .map_err(|e| format!("mounting the overlay tmpfs at {OVERLAY_ROOT}: {e}"))?;
    for dir in [&merged, &upper, &work] {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    }

    // lowerdir=/ is safe even though the upper layer lives under it: overlayfs
    // resolves the lower tree through the underlying dentries and does not
    // traverse into mounts, so the tmpfs at /overlay is invisible in the merged
    // view and there is no recursion.
    let lower = if toolchain { format!("/:{TOOLCHAIN_MOUNT}") } else { "/".to_string() };
    let opts = format!("lowerdir={lower},upperdir={upper},workdir={work}");
    mount("overlay", &merged, "overlay", 0, Some(&opts)).map_err(|e| {
        format!(
            "mounting overlayfs ({opts}): {e} — a kernel without CONFIG_OVERLAY_FS or \
             CONFIG_TMPFS_XATTR cannot give this guest a writable root"
        )
    })?;

    // The scratch disk, carried across the pivot.
    let ws_in_new = format!("{}{}", merged, job.workspace_mount);
    std::fs::create_dir_all(&ws_in_new).map_err(|e| format!("mkdir {ws_in_new}: {e}"))?;
    mount(STAGE_MOUNT, &ws_in_new, "", libc::MS_MOVE, None)
        .map_err(|e| format!("moving the scratch disk to {ws_in_new}: {e}"))?;

    let old_in_new = format!("{merged}{OLD_ROOT}");
    std::fs::create_dir_all(&old_in_new).map_err(|e| format!("mkdir {old_in_new}: {e}"))?;
    std::env::set_current_dir(&merged).map_err(|e| format!("chdir {merged}: {e}"))?;
    pivot_root(".", &format!(".{OLD_ROOT}")).map_err(|e| format!("pivot_root into {merged}: {e}"))?;
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;

    // Lazy: the overlay's upper and work dirs live on the tmpfs that is under
    // the old root — as does the toolchain volume, when there is one — and
    // overlayfs holds all of them alive by reference. Detaching only removes the
    // old tree from the namespace; failing to detach is untidy, not fatal, so it
    // does not fail the boot.
    if let Err(e) = umount(OLD_ROOT, libc::MNT_DETACH) {
        log!("warning: {OLD_ROOT} stayed mounted ({e}) — the read-only image is visible to the job");
    }

    // These were mounted on the old root; the new root inherited empty
    // directories for them from the lower layer.
    for (src, target, fstype, data) in [
        ("proc", "/proc", "proc", None),
        ("sysfs", "/sys", "sysfs", None),
        ("devtmpfs", "/dev", "devtmpfs", None),
        ("tmpfs", "/tmp", "tmpfs", Some("mode=1777")),
        ("tmpfs", "/run", "tmpfs", Some("mode=0755")),
    ] {
        std::fs::create_dir_all(target).ok();
        if let Err(e) = mount(src, target, fstype, 0, data) {
            // /proc and /dev are load-bearing (the reaper reads neither, but a
            // build absolutely does); the rest are conveniences.
            log!("warning: mounting {fstype} at {target} failed: {e}");
        }
    }
    ensure_console();
    log!("writable root in place: overlay(lower=read-only image, upper=tmpfs)");
    Ok(())
}

/// Create each declared target and bind the scratch disk's subdirectory onto it.
fn stage_job_mounts(job: &Job) -> Result<(), String> {
    for m in &job.mounts {
        let src = job.source_of(m);
        // The host creates every slug directory even when its bind source did
        // not exist, but a rootfs must not depend on that to avoid mounting
        // nothing over a target the job then fails to write to.
        std::fs::create_dir_all(&src).map_err(|e| format!("mkdir {src}: {e}"))?;
        std::fs::create_dir_all(&m.target).map_err(|e| format!("mkdir {}: {e}", m.target))?;
        mount(&src, &m.target, "", libc::MS_BIND | libc::MS_REC, None)
            .map_err(|e| format!("bind {src} -> {}: {e}", m.target))?;
        if m.read_only {
            // A read-only bind is two steps: MS_RDONLY is ignored on the initial
            // MS_BIND and only takes effect on a remount of the new mount.
            mount(
                "none",
                &m.target,
                "",
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                None,
            )
            .map_err(|e| format!("remounting {} read-only: {e}", m.target))?;
        }
        log!(
            "mounted {src} at {} ({})",
            m.target,
            if m.read_only { "ro" } else { "rw" }
        );
    }
    Ok(())
}

/// Resolver and loopback, the two pieces of network state the kernel's `ip=`
/// autoconfiguration does not cover.
fn configure_network(job: &Job) {
    if let Some(dns) = &job.dns {
        std::fs::create_dir_all("/etc").ok();
        match std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n")) {
            Ok(()) => log!("resolver: {dns}"),
            Err(e) => log!("warning: could not write /etc/resolv.conf: {e}"),
        }
    }
    if let Err(e) = bring_up_loopback() {
        // Not fatal, but worth a line: a build whose test binds 127.0.0.1 fails
        // in a way that looks nothing like "lo is down".
        log!("warning: could not bring up lo: {e}");
    }
}

/// `SIOCSIFFLAGS` on `lo`, with `ifreq` laid out by hand.
///
/// By hand because `libc::ifreq` is a recent addition and this image must build
/// against whatever libc the workspace resolves; the layout it needs is only
/// `char ifr_name[IFNAMSIZ]` followed by a `short` of flags, which has been
/// stable since the interface existed.
fn bring_up_loopback() -> Result<(), std::io::Error> {
    // `libc::Ioctl` rather than a concrete integer type: it is `c_ulong` against
    // glibc and `c_int` against musl, and this crate is built for musl.
    const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
    const SIOCSIFFLAGS: libc::Ioctl = 0x8914;
    const IFNAMSIZ: usize = 16;
    // sizeof(struct ifreq) on every Linux ABI: 16-byte name + a 24-byte union.
    let mut ifr = [0u8; 40];
    ifr[..2].copy_from_slice(b"lo");

    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let close = |fd: libc::c_int| {
            libc::close(fd);
        };
        if libc::ioctl(sock, SIOCGIFFLAGS, ifr.as_mut_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(e);
        }
        let flags = i16::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1]]);
        let up = flags | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
        ifr[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&up.to_ne_bytes());
        if libc::ioctl(sock, SIOCSIFFLAGS, ifr.as_mut_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(e);
        }
        close(sock);
    }
    Ok(())
}

/// Writable, disk-backed working area for a build, carved out of the scratch
/// disk (R605-F23).
struct BuildScratch {
    cargo_home: String,
    tmpdir: String,
}

/// Create the build's scratch directories on the one writable disk in the guest.
///
/// Failures are logged and not fatal: the directories are created eagerly so a
/// build does not fail on a missing parent, but cargo and rustc both create
/// their own, and a job that does not build anything should not be refused
/// because a directory it will never open could not be made.
fn build_scratch(job: &Job) -> BuildScratch {
    let root = job.workspace_mount.trim_end_matches('/');
    let scratch = BuildScratch {
        cargo_home: format!("{root}/.cargo"),
        tmpdir: format!("{root}/tmp"),
    };
    for dir in [&scratch.cargo_home, &scratch.tmpdir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log!("warning: could not create build scratch {dir}: {e}");
        }
    }
    scratch
}

/// Run the job's argv and wait for it, reaping everything else along the way.
fn run_job(job: &Job) -> Outcome {
    let mut cmd = Command::new(&job.argv[0]);
    cmd.args(&job.argv[1..]);
    // The document is the whole environment: anything the host did not resolve
    // must not be inherited from whatever the init happens to have.
    cmd.env_clear();
    for (k, v) in &job.env {
        cmd.env(k, v);
    }
    // Defaults only where the document is silent. Without PATH, a `/bin/sh -c`
    // argv cannot find any of the commands it was written against.
    let scratch = build_scratch(job);
    for (k, v) in [
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/root"),
        ("TERM", "linux"),
        ("SHELL", "/bin/sh"),
        // R605-F23's third problem: a real build needs somewhere large to
        // write, and neither the rootfs nor the toolchain volume is writable.
        // Both of these default onto surfaces that are technically writable and
        // wrong — CARGO_HOME to $HOME/.cargo and TMPDIR to /tmp, which are the
        // overlay's tmpfs upper and a tmpfs, i.e. GUEST RAM. A cargo registry
        // cache and rustc's temporaries are hundreds of megabytes against a
        // guest sized in single-digit gigabytes, so left alone the first real
        // build dies of OOM somewhere inside the linker.
        //
        // They are pointed at the scratch disk instead, which is the one
        // writable surface that is both large (an 8 GiB floor) and genuinely
        // per-job: kamaji builds it fresh at deploy and it dies with the guest,
        // so using it costs nothing against "job N must not leave state for job
        // N+1". A tmpfs would satisfy that property too and is what the obvious
        // reading suggests — it is rejected on size, not on correctness.
        //
        // CARGO_TARGET_DIR is deliberately NOT set. A job's source tree is
        // already bind-mounted from this same scratch disk, so cargo's default
        // `target/` beside the sources is on disk and in the place a forge step
        // that collects `target/release/foo` expects to find it. Redirecting it
        // would move artifacts out from under every such step.
        ("CARGO_HOME", &scratch.cargo_home as &str),
        ("TMPDIR", &scratch.tmpdir),
    ] {
        if !job.env.contains_key(k) {
            cmd.env(k, v);
        }
    }
    cmd.current_dir(job.workdir.as_deref().unwrap_or("/"));
    // Its own session, so the job cannot steal the console from init and cannot
    // be signalled by init's own process-group traffic.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let detail = format!("could not execute {:?}: {e}", job.argv);
            log!("EXEC FAILED: {detail}");
            return Outcome {
                code: exit::EXEC_FAILED,
                detail,
            };
        }
    };
    let pid = child.id() as libc::pid_t;
    log!("job running as pid {pid}");

    // Hand-rolled reap loop rather than `child.wait()`: as PID 1 this process
    // inherits every orphan in the guest, and `wait()` on a specific pid leaves
    // them as zombies. Waiting for -1 in a loop reaps them and still tells us
    // when *our* child is the one that finished.
    let mut status: libc::c_int = 0;
    loop {
        let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
        if reaped == pid {
            break;
        }
        if reaped < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            let detail = format!("lost track of the job process: {e}");
            log!("{detail}");
            return Outcome {
                code: exit::EXEC_FAILED,
                detail,
            };
        }
    }

    let (code, detail) = if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        (code, format!("job exited {code}"))
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // 128+n, the shell convention, so a signalled job is distinguishable
        // from a job that chose that exit code.
        (128 + sig, format!("job killed by signal {sig}"))
    } else {
        (exit::EXEC_FAILED, format!("job ended unrecognisably ({status})"))
    };
    log!("{detail}");
    Outcome { code, detail }
}

/// Record the job's fate on the scratch disk, where the host can read it.
///
/// Best-effort by design: a status file that fails to write must not turn a
/// green build red, and every failure here is already on the console.
fn write_status(workspace: &str, workload: &str, code: i32, detail: &str) {
    let path = format!("{}/{STATUS_FILE}", workspace.trim_end_matches('/'));
    let doc = serde_json::json!({
        "schema": crate::job::SCHEMA_VERSION,
        "workload": workload,
        "exit_code": code,
        "detail": detail,
        "init_version": env!("CARGO_PKG_VERSION"),
    });
    match std::fs::write(&path, format!("{doc}\n")) {
        Ok(()) => log!("wrote {path}"),
        Err(e) => log!("warning: could not write {path}: {e}"),
    }
}

/// Unmount the job's mounts and the scratch disk, so the host reads a complete
/// filesystem instead of one with the last writes still in the guest's cache.
///
/// On a [`RootShape::Durable`] guest the root device needs the same treatment
/// and cannot get it the same way — it is this process's `/` and cannot be
/// unmounted. A read-only remount is the equivalent: ext4 flushes and marks the
/// filesystem clean, which is what makes the next boot's mount and the host's
/// `debugfs` read see the writes rather than a filesystem that was still being
/// written when the i8042 reset landed.
fn flush_and_unmount(job: &Job, shape: RootShape) {
    let _ = std::env::set_current_dir("/");
    // Reverse order: a later mount may sit inside an earlier one's target.
    for m in job.mounts.iter().rev() {
        if let Err(e) = umount(&m.target, libc::MNT_DETACH) {
            log!("warning: could not unmount {}: {e}", m.target);
        }
    }
    unsafe { libc::sync() };
    if let Err(e) = umount(&job.workspace_mount, 0) {
        log!("warning: {} stayed mounted ({e}); syncing instead", job.workspace_mount);
        let _ = umount(&job.workspace_mount, libc::MNT_DETACH);
    }
    unsafe { libc::sync() };

    if shape == RootShape::Durable {
        match mount("none", "/", "", libc::MS_REMOUNT | libc::MS_RDONLY, None) {
            Ok(()) => log!("durable root committed: / remounted read-only"),
            Err(e) => log!(
                "warning: could not remount / read-only ({e}) — the durable root's last writes \
                 rely on sync() alone"
            ),
        }
        unsafe { libc::sync() };
    }
}

/// Reset the VM, which is how the VMM process exits and the job is reported done.
pub fn halt(code: i32) -> ! {
    log!("halting (status {code})");
    let _ = std::io::stderr().flush();
    unsafe { libc::sync() };
    unsafe { libc::reboot(libc::RB_AUTOBOOT) };
    // Only reached if the reset did not take. Both fallbacks end in the VMM
    // exiting; the last one relies on `panic=1`, which is on the command line
    // kamaji builds for exactly this reason.
    log!("RB_AUTOBOOT returned ({}) — trying power off", std::io::Error::last_os_error());
    unsafe { libc::reboot(libc::RB_POWER_OFF) };
    log!("power off returned too — killing init to force the kernel's panic reboot");
    unsafe { libc::abort() }
}

// ── syscall wrappers ─────────────────────────────────────────────────────────

fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), std::io::Error> {
    let source = CString::new(source)?;
    let target = CString::new(target)?;
    let fstype = CString::new(fstype)?;
    let data = data.map(CString::new).transpose()?;
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            if fstype.as_bytes().is_empty() {
                std::ptr::null()
            } else {
                fstype.as_ptr()
            },
            flags,
            data.as_ref()
                .map(|d| d.as_ptr().cast())
                .unwrap_or(std::ptr::null()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn umount(target: &str, flags: libc::c_int) -> Result<(), std::io::Error> {
    let target = CString::new(target)?;
    let rc = unsafe { libc::umount2(target.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn pivot_root(new_root: &str, put_old: &str) -> Result<(), std::io::Error> {
    let new_root = CString::new(new_root)?;
    let put_old = CString::new(put_old)?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root.as_ptr(),
            put_old.as_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Make sure fd 0/1/2 point at the console.
///
/// The kernel gives init `/dev/console` on its standard descriptors when the
/// node existed at the time `init` was executed, which with `CONFIG_DEVTMPFS_MOUNT`
/// it does. This covers the other case, and the post-pivot case where the fds
/// still point at the old root's console device — harmless there, but re-opening
/// is cheap and a guest whose logs go nowhere is undebuggable.
fn ensure_console() {
    if unsafe { libc::fcntl(1, libc::F_GETFD) } >= 0 {
        return;
    }
    let path = match CString::new("/dev/console") {
        Ok(p) => p,
        Err(_) => return,
    };
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return;
        }
        for target in 0..3 {
            if fd != target {
                libc::dup2(fd, target);
            }
        }
        if fd > 2 {
            libc::close(fd);
        }
    }
}
