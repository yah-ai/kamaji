//! The service-shaped microVM archetype against a real Firecracker guest
//! (R605-F31).
//!
//! [`microvm_guest_e2e`] proves the *job* shape: boot, run, halt, artifacts on
//! the host. This proves the shape that was impossible before R605-F31 — a guest
//! that kamaji brings back rather than reaps — and, just as importantly, that
//! adding it did not change what a job does.
//!
//! Four claims, each of which needs a real hypervisor and none of which any unit
//! test can reach:
//!
//! 1. A service-shaped guest that goes away is **re-booted** by the supervisor,
//!    with a new VMM pid, rather than parked as finished.
//! 2. A job-shaped guest is still reaped and never restarted. This is the
//!    regression half, and it is the one worth having: the change that gives a
//!    service a restart loop is the change that could silently give a *build*
//!    one.
//! 3. The node's shared `rootfs.ext4` is byte-identical after a service has run.
//!    A service boots a private writable copy; if that ever became the node's
//!    own image, every job on the node would inherit whatever a service wrote,
//!    which is the exact cross-contamination the read-only attachment exists to
//!    prevent — and nothing else on the host would notice.
//! 4. A service's scratch disk survives its restarts. This also exercises
//!    `workspace::clear_job_status`, the one new `debugfs` shell-out in F31 —
//!    a filesystem it corrupted would fail to mount on the next boot.
//! 5. A service's **root** survives its restarts (R605-F33). This is the claim
//!    F31 could not make and deliberately did not test for: it had given the
//!    guest a writable root device, but `kamaji-guest-init` pivoted
//!    unconditionally into a tmpfs overlay, so that device was the overlay's
//!    *lower* layer and every write to `/` died with the VM. Claims 4 and 5 are
//!    both here because they fail differently — 4 writes to a separate block
//!    device the init mounts, 5 writes to the root the init decided not to
//!    stack anything on.
//!
//! Skips (does not fail) when the substrate is absent, exactly as
//! `microvm_guest_e2e` and `docker_live` do.
//!
//! ## Running it
//!
//! ```text
//! KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm \
//!   cargo test -p kamaji --features microvm-integration --test microvm_service_e2e -- --nocapture
//! ```
//!
//! Part of R605-F31 — annotation in oss/kamaji/crates/kamaji/src/microvm.rs.

#![cfg(all(target_os = "linux", feature = "microvm-integration"))]

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use kamaji::microvm::{MicroVmConfig, MicroVmRuntime, RootDisk};
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{
    ImageRef, LifecycleArchetype, RestartPolicy, TierTag, WorkloadSpec, FORGE_MEMORY_REQUEST_MB,
};

fn microvm_dir() -> PathBuf {
    std::env::var("KAMAJI_MICROVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yah/kamaji/microvm"))
}

/// Every reason this test cannot run, named individually — same contract as
/// `microvm_guest_e2e::why_not`.
fn why_not() -> Option<String> {
    let dir = microvm_dir();
    for (what, path) in [
        ("guest kernel", dir.join("vmlinux")),
        ("guest rootfs", dir.join("rootfs.ext4")),
    ] {
        if !path.exists() {
            return Some(format!("no {what} at {}", path.display()));
        }
    }
    if let Err(e) = kamaji::microvm::find_vmm() {
        return Some(e.to_string());
    }
    ensure_sbin_on_path();
    if which("mkfs.ext4").is_none() || which("debugfs").is_none() {
        return Some("e2fsprogs (mkfs.ext4 + debugfs) is not installed".into());
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => None,
        Err(e) => Some(format!("/dev/kvm is not openable read-write: {e}")),
    }
}

/// `mkfs.ext4` and `debugfs` are spawned by bare name and live in `/usr/sbin`,
/// which a non-login `ssh host 'cargo test'` does not have on `PATH`.
fn ensure_sbin_on_path() {
    let path = std::env::var("PATH").unwrap_or_default();
    let missing: Vec<&str> = ["/usr/sbin", "/sbin"]
        .into_iter()
        .filter(|d| !path.split(':').any(|p| p == *d))
        .collect();
    if !missing.is_empty() {
        std::env::set_var("PATH", format!("{path}:{}", missing.join(":")));
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = path
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|dir| Path::new(dir).join(bin))
        .find(|p| p.is_file());
    found
}

fn node_config(state_dir: PathBuf) -> MicroVmConfig {
    let dir = microvm_dir();
    MicroVmConfig {
        vmm_bin: kamaji::microvm::find_vmm().expect("checked by why_not"),
        kernel_image: dir.join("vmlinux"),
        rootfs_image: dir.join("rootfs.ext4"),
        toolchain_image: Some(dir.join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE))
            .filter(|p| p.exists()),
        state_dir,
        // No TAP: a guest network needs CAP_NET_ADMIN and iptables, which is a
        // separate host-privilege question from "is this guest restarted".
        network: None,
        max_guest_memory_mb: FORGE_MEMORY_REQUEST_MB,
        max_guest_vcpus: 2,
    }
}

/// The base spec both shapes start from: boot, append one line to the scratch
/// disk, exit.
///
/// Writing to the scratch disk rather than to `/` on purpose — it is the
/// channel that is durable for *both* shapes, so this spec says nothing about
/// the root and stays usable as the job-shaped control. The `/` counter is
/// [`root_counter_spec`]'s job.
fn base_spec(id: &str) -> WorkloadSpec {
    let mut spec = WorkloadSpec::for_forge(
        id,
        ImageRef::parse_pinned(
            "ghcr.io/yah-ai/yah-rust:latest@sha256:\
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        TierTag("infra".into()),
        vec![],
    );
    spec.annotations.insert(
        workload_spec::NATIVE_EXEC_ANNOTATION.into(),
        workload_spec::MICROVM_EXEC_VALUE.into(),
    );
    spec.command = Some(vec![
        "/bin/sh".into(),
        "-c".into(),
        "echo booted >> /workspace/boots.txt; sync".into(),
    ]);
    spec
}

/// The same workload, declared as something meant to still be there tomorrow.
fn service_spec(id: &str) -> WorkloadSpec {
    let mut spec = base_spec(id);
    spec.archetype = Some(LifecycleArchetype::Server);
    spec.restart_policy = RestartPolicy::Always;
    spec
}

/// The same service, counting its boots on `/` instead of on the scratch disk
/// (R605-F33).
///
/// `/root-boots.txt` is at the root of the guest's own root filesystem, which is
/// the private writable copy `RootDisk::provision` made — so the file this
/// appends to is at `/root-boots.txt` inside `<vm_dir>/rootfs.ext4` and is
/// readable from the host with the same `debugfs` the scratch-disk test uses.
///
/// `sync` matters more here than it does there: the init remounts `/` read-only
/// before it halts, but a guest that is torn down mid-boot never reaches that,
/// and a counter that only sometimes lands is a flaky test rather than a proof.
fn root_counter_spec(id: &str) -> WorkloadSpec {
    let mut spec = service_spec(id);
    spec.command = Some(vec![
        "/bin/sh".into(),
        "-c".into(),
        "echo booted >> /root-boots.txt; sync".into(),
    ]);
    spec
}

/// A service that goes away comes back, with a new VMM, and the node's image is
/// untouched.
#[tokio::test]
async fn a_service_guest_is_restarted_instead_of_reaped() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let node_image = microvm_dir().join("rootfs.ext4");
    let before = sha256(&node_image);

    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone())).expect("node config");

    let spec = service_spec("r605f31-svc");
    let ident = spec.expose.mesh.identity.clone();
    let deployed = rt
        .deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .expect("deploy a service-shaped microVM workload");
    assert!(deployed.task_pid > 0, "expected a live VMM pid");

    let vm_dir = state_dir.join(sanitized(&ident.0));
    let console = vm_dir.join("console.log");

    // The claim: distinct VMM pids over time. A backend that reaped this guest
    // would sit on one pid (then zero) forever, which is what every microVM
    // workload did before R605-F31.
    let (pids, restarting_seen) = watch_for_reboots(&rt, &ident, 3, Duration::from_secs(180)).await;
    assert!(
        pids.len() >= 3,
        "a service-shaped guest was not re-booted: saw pids {pids:?}\n\
         --- console.log ---\n{}",
        read_console(&console)
    );
    assert!(
        restarting_seen,
        "the supervisor never published Restarting, so the caller could not tell a \
         cycling service from a healthy one"
    );

    // The private root exists, and is not the node's.
    let private_root = vm_dir.join(RootDisk::SERVICE_ROOT_FILE);
    assert!(
        private_root.is_file(),
        "no private root at {} — a service must not boot the node's shared image",
        private_root.display()
    );

    rt.teardown_workload(&ident).await.unwrap();

    // Torn down means torn down: no supervisor is quietly booting a replacement.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        rt.get_workload(&ident).await.unwrap().is_none(),
        "a torn-down service is still registered"
    );

    // The property a careless edit at this site destroys, and nothing else on
    // the host would report: one node image, never written.
    assert_eq!(
        before,
        sha256(&node_image),
        "the node's shared rootfs.ext4 changed while a service-shaped guest ran — every \
         job on this node now inherits whatever that guest wrote"
    );
}

/// The regression half: a job is still reaped, never restarted.
#[tokio::test]
async fn a_job_guest_is_still_reaped_and_never_restarted() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone())).expect("node config");

    // base_spec is `for_forge`: RestartPolicy::Never, no volumes → Job.
    let spec = base_spec("r605f31-job");
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .expect("deploy a job-shaped microVM workload");

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(180), &console).await;
    assert_eq!(
        status,
        WorkloadStatus::Stopped,
        "a job stopped reporting cleanly\n--- console.log ---\n{}",
        read_console(&console)
    );

    // Stays stopped. The window is generous against ALWAYS_RESTART_DELAY (1s),
    // so a job that had accidentally been given a restart loop would have
    // cycled several times inside it.
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let state = rt.get_workload(&ident).await.unwrap().unwrap();
        assert_eq!(
            state.status,
            WorkloadStatus::Stopped,
            "a job-shaped guest was restarted; re-running a build over its own output disk \
             is exactly what restart_workload refuses to do"
        );
    }

    // And a job still refuses an explicit restart, with the reason.
    let err = rt.restart_workload(&ident).await.unwrap_err().to_string();
    assert!(err.contains("job-shaped"), "got {err}");

    rt.teardown_workload(&ident).await.unwrap();
}

/// A service's scratch disk is its state, and it survives the restarts.
///
/// Also the only exercise `workspace::clear_job_status` gets on real hardware:
/// it runs `debugfs -w -R "rm /job-status.json"` before every re-boot, and a
/// filesystem it damaged would fail the guest's own mount on the next boot —
/// which would show up here as a boot count that stops growing.
#[tokio::test]
async fn a_services_scratch_disk_survives_its_restarts() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone())).expect("node config");

    let spec = service_spec("r605f31-state");
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .unwrap();

    let vm_dir = state_dir.join(sanitized(&ident.0));
    let console = vm_dir.join("console.log");
    let (pids, _) = watch_for_reboots(&rt, &ident, 3, Duration::from_secs(180)).await;
    assert!(
        pids.len() >= 3,
        "need at least three boots to say anything about persistence; saw {pids:?}\n\
         --- console.log ---\n{}",
        read_console(&console)
    );
    rt.teardown_workload(&ident).await.unwrap();

    // Read the guest's appends back off the scratch disk the same way the
    // backend does — debugfs, no loop mount, no root.
    let body = debugfs_dump(&vm_dir.join("workspace.ext4"), "/boots.txt");
    let boots = body.lines().filter(|l| l.trim() == "booted").count();
    // `pids.len() - 1`, not `pids.len()`: `watch_for_reboots` returns the moment
    // the Nth VMM is *seen*, and the teardown that follows powers that guest off
    // before its init has appended or unmounted. Every instance that was allowed
    // to finish must be in the file; the one killed mid-boot legitimately is not.
    // The property is "state crossed a restart", and N-1 >= 2 states it without
    // depending on how a torn-down guest is timed.
    assert!(
        boots >= pids.len() - 1,
        "the scratch disk did not carry state across restarts: {boots} boot line(s) after \
         {} VMM pids. boots.txt = {body:?}\n--- console.log ---\n{}",
        pids.len(),
        read_console(&console)
    );
    assert!(
        boots >= 2,
        "fewer than two completed boots — this says nothing about persistence: {body:?}"
    );
}

/// A service's **root** is its state too — the claim R605-F33 exists to make.
///
/// The counter is on `/`, not on `/workspace`, and that is the entire point. Run
/// against a guest image built before R605-F33 this test fails with zero boot
/// lines and `debugfs` reporting no such file: the init pivoted into an overlay
/// whose upper was a tmpfs, so every `echo >> /root-boots.txt` landed in guest
/// RAM, was visible to that same boot, and was gone before the host could look.
///
/// Two things have to be true for it to pass, and it cannot distinguish them —
/// which is fine, because both are required: the host has to attach a writable
/// root (R605-F31, `RootDisk::for_shape`), and the guest has to write to it
/// rather than to an overlay (R605-F33, `boot::stage_writable_root`).
#[tokio::test]
async fn a_services_root_survives_its_restarts() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let node_image = microvm_dir().join("rootfs.ext4");
    let before = sha256(&node_image);

    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone())).expect("node config");

    let spec = root_counter_spec("r605f33-root");
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .unwrap();

    let vm_dir = state_dir.join(sanitized(&ident.0));
    let console = vm_dir.join("console.log");
    let (pids, _) = watch_for_reboots(&rt, &ident, 3, Duration::from_secs(180)).await;
    assert!(
        pids.len() >= 3,
        "need at least three boots to say anything about persistence; saw {pids:?}\n\
         --- console.log ---\n{}",
        read_console(&console)
    );
    rt.teardown_workload(&ident).await.unwrap();

    let private_root = vm_dir.join(RootDisk::SERVICE_ROOT_FILE);
    let body = debugfs_dump(&private_root, "/root-boots.txt");
    let boots = body.lines().filter(|l| l.trim() == "booted").count();
    // `pids.len() - 1` for the same reason as the scratch-disk test: the teardown
    // that follows `watch_for_reboots` powers the last guest off before its init
    // has appended and remounted `/` read-only, so that instance legitimately
    // never lands.
    assert!(
        boots >= pids.len() - 1,
        "writes to / did not survive the guest's restarts: {boots} boot line(s) after {} VMM \
         pids. /root-boots.txt in {} = {body:?}\n--- console.log ---\n{}",
        pids.len(),
        private_root.display(),
        read_console(&console)
    );
    assert!(
        boots >= 2,
        "fewer than two completed boots wrote to / — this says nothing about a durable root: \
         {body:?}\n--- console.log ---\n{}",
        read_console(&console)
    );

    // The same property claim 3 makes, re-asserted for the shape that writes to
    // its root on purpose: a durable guest root must still be the guest's own
    // copy. If durability had been implemented by flipping the node's image
    // writable, this is the assertion that would catch it.
    assert_eq!(
        before,
        sha256(&node_image),
        "the node's shared rootfs.ext4 changed while a service wrote to its own / — every job \
         on this node now inherits those writes"
    );
}

/// Poll until `want` distinct VMM pids have been seen, reporting whether the
/// supervisor ever published `Restarting` along the way.
///
/// Polling `get_workload` rather than the watch channel because that is the
/// surface kamaji-bin uses: if this loop can see the cycle, so can a node.
async fn watch_for_reboots(
    rt: &MicroVmRuntime,
    ident: &workload_spec::MeshIdent,
    want: usize,
    limit: Duration,
) -> (BTreeSet<String>, bool) {
    let started = Instant::now();
    let mut pids = BTreeSet::new();
    let mut restarting = false;
    loop {
        if let Some(state) = rt.get_workload(ident).await.expect("get_workload") {
            if matches!(state.status, WorkloadStatus::Restarting { .. }) {
                restarting = true;
            }
            // `microvm-0` is the parked-between-instances value, not a boot.
            if state.container_id != "microvm-0" {
                pids.insert(state.container_id.clone());
            }
        }
        if pids.len() >= want || started.elapsed() > limit {
            eprintln!(
                "saw {} distinct VMM pid(s) in {:?}, restarting_published={restarting}",
                pids.len(),
                started.elapsed()
            );
            return (pids, restarting);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_exit(
    rt: &MicroVmRuntime,
    ident: &workload_spec::MeshIdent,
    limit: Duration,
    console: &Path,
) -> WorkloadStatus {
    let started = Instant::now();
    loop {
        let state = rt
            .get_workload(ident)
            .await
            .expect("get_workload")
            .expect("deployed workload is inspectable");
        if state.status != WorkloadStatus::Running {
            return state.status;
        }
        if started.elapsed() > limit {
            panic!(
                "guest still Running after {limit:?}\n--- console.log ---\n{}",
                read_console(console)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `debugfs -R "dump <path> <tmp>"`, the read side of how this backend already
/// talks to an ext4 image it does not mount.
fn debugfs_dump(image: &Path, guest_path: &str) -> String {
    // Per-call rather than per-process: two tests in this file dump now, cargo
    // runs them as threads of one process, and a shared scratch path would have
    // them reading each other's guest state — which is a silently passing test,
    // not a failing one.
    let tmp = std::env::temp_dir().join(format!(
        "r605f31-{}-{}",
        std::process::id(),
        guest_path.trim_matches('/').replace('/', "_")
    ));
    let _ = std::fs::remove_file(&tmp);
    let out = Command::new("debugfs")
        .arg("-R")
        .arg(format!("dump {guest_path} {}", tmp.display()))
        .arg(image)
        .output()
        .expect("run debugfs");
    let body = std::fs::read_to_string(&tmp).unwrap_or_else(|e| {
        format!(
            "(no {guest_path} in {}: {e}; debugfs said {})",
            image.display(),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let _ = std::fs::remove_file(&tmp);
    body
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("run sha256sum");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn read_console(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| format!("(no console log at {}: {e})", path.display()))
}

/// Mirror of `microvm::sanitize`, which is private.
fn sanitized(ident: &str) -> String {
    ident
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
