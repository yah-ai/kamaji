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
//! ## Why the VM reboots rather than powers off
//!
//! `kamaji::microvm`'s supervisor treats *the VMM process exiting* as job
//! completion, and the VMM exits when the guest hits the i8042 reset port —
//! which is what `reboot=k` on the kernel command line selects. `RB_POWER_OFF`
//! would take the ACPI path instead and, if the VMM does not implement it, leave
//! the guest spinning in `machine_halt` with the supervisor waiting forever. So
//! [`halt`] reboots, and only falls back to power-off and then to killing itself
//! (`panic=1` reboots too) if that somehow returns.

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
/// It never appears here in the merged root — see [`pivot_into_writable_root`].
/// This is only the handle overlayfs is given at mount time.
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
pub fn run() -> Outcome {
    log!("kamaji-guest-init {} — PID {}", env!("CARGO_PKG_VERSION"), std::process::id());

    // The kernel mounts devtmpfs before running init when built with
    // CONFIG_DEVTMPFS_MOUNT, which is how /dev/console exists for our own
    // stderr. Re-mounting it is idempotent and covers a kernel built without.
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0, None);
    ensure_console();
    let _ = mount("proc", "/proc", "proc", 0, None);
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        // Printed because two load-bearing facts about this boot are only
        // observable here: whether the VMM injected `root=` itself, and whether
        // it advertises its virtio devices on the cmdline or through ACPI.
        log!("cmdline: {}", cmdline.trim());
    }

    // `pivot_root` and `MS_MOVE` both refuse to operate on a shared mount, and
    // what the kernel hands init is not guaranteed private.
    if let Err(e) = mount("none", "/", "", libc::MS_REC | libc::MS_PRIVATE, None) {
        log!("warning: could not make / private ({e}) — pivot_root may refuse");
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

    // Probed before the pivot, because the toolchain has to be a lower layer of
    // the overlay the pivot lands in. Absent is normal: a node that has staged
    // no toolchain.ext4 still boots and still runs argv, it just has no
    // compiler.
    let toolchain = find_toolchain_disk(&disk);

    if let Err(e) = pivot_into_writable_root(&job, toolchain.is_some()) {
        log!("MOUNT SETUP FAILED: {e}");
        write_status(&job.workspace_mount, &job.workload, exit::MOUNT_FAILED, &e);
        return Outcome {
            code: exit::MOUNT_FAILED,
            detail: e,
        };
    }

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
    flush_and_unmount(&job);
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
fn pivot_into_writable_root(job: &Job, toolchain: bool) -> Result<(), String> {
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
fn flush_and_unmount(job: &Job) {
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
