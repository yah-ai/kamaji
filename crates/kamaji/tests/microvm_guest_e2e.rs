//! The microVM backend against a real Firecracker guest (R605-F14 / W325 §5).
//!
//! Everything in `microvm.rs`'s own test module is pure: slot arithmetic, the
//! config document, the job contract, memory clamping. That was deliberate, and
//! it leaves exactly one thing unasserted — that the two artifacts the *node*
//! supplies (a guest kernel and a rootfs whose init reads the job document) work
//! with the code that boots them. Nothing on the camp Mac can check that: it has
//! no `/dev/kvm`, which is where R605-F8 stopped.
//!
//! So this is the gate for the pair. It drives the real
//! [`MicroVmRuntime::deploy_workload`] — the same `build_disk` → `write_job` →
//! `vmm_config` → spawn → supervisor → `extract_disk` sequence a forge run takes
//! — and asserts the two claims that matter to a caller: kamaji reports the
//! workload `Stopped`, and what the guest wrote to `/yah/produced` is on the host
//! afterwards.
//!
//! Skips (does not fail) when the substrate is absent, matching `docker_live.rs`:
//! most hosts in this camp have no KVM, and a red test on every one of them
//! trains people to ignore it.
//!
//! ## Running it
//!
//! ```text
//! oss/kamaji/guest/build-guest-image.sh                  # produces vmlinux + rootfs.ext4
//! KAMAJI_MICROVM_DIR=oss/kamaji/guest/out \
//!   cargo test -p kamaji --features microvm-integration --test microvm_guest_e2e -- --nocapture
//! ```
//!
//! The guest's console is captured to `<state_dir>/<ident>/console.log`, and this
//! test prints it on failure — a guest that fails to boot says why there and
//! nowhere else.
//!
//! Part of R605-F14 — annotation in oss/kamaji/crates/kamaji/src/microvm.rs.

#![cfg(all(target_os = "linux", feature = "microvm-integration"))]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kamaji::microvm::{MicroVmConfig, MicroVmRuntime};
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{
    ImageRef, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
    FORGE_MEMORY_REQUEST_MB,
};

/// Where `build-guest-image.sh` put `vmlinux` and `rootfs.ext4`.
///
/// `KAMAJI_MICROVM_DIR` is not this test's invention — it is `kamaji-bin`'s own
/// environment fallback for `--microvm-dir`, so a node already configured for
/// microVM workloads needs nothing extra set to run this.
///
/// Defaults to the node install path rather than the build output, because the
/// interesting run of this test is on a node that has been *provisioned*, not on
/// one that happens to have a build tree.
fn microvm_dir() -> PathBuf {
    std::env::var("KAMAJI_MICROVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yah/kamaji/microvm"))
}

/// Every reason this test cannot run, named individually.
///
/// One "SKIP: prerequisites missing" would be useless: an operator who
/// provisioned a node and expected this to run needs to know *which* of the four
/// things is not there.
fn why_not() -> Option<String> {
    let dir = microvm_dir();
    for (what, path) in [
        ("guest kernel", dir.join("vmlinux")),
        ("guest rootfs", dir.join("rootfs.ext4")),
    ] {
        if !path.exists() {
            return Some(format!(
                "no {what} at {} — run oss/kamaji/guest/build-guest-image.sh, or set \
                 KAMAJI_MICROVM_DIR",
                path.display()
            ));
        }
    }
    // R605-F22: `find_vmm` rather than a bare PATH lookup. Firecracker installs
    // from a tarball into /usr/local/bin, which a non-login `ssh host cargo test`
    // does not always have on PATH — the same class of miss as the /usr/sbin one
    // `ensure_sbin_on_path` exists for.
    if let Err(e) = kamaji::microvm::find_vmm() {
        return Some(e.to_string());
    }
    if which("mkfs.ext4").is_none() || which("debugfs").is_none() {
        return Some("e2fsprogs (mkfs.ext4 + debugfs) is not installed".into());
    }
    ensure_sbin_on_path();
    // Openable, not merely present: /dev/kvm is 0660 root:kvm on the fleet and
    // the service user is not always in that group (R605-T15). "Permission
    // denied on /dev/kvm" is a one-line usermod, and it is worth saying so here
    // rather than letting firecracker fail with it forty lines into a boot.
    match std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        Ok(_) => None,
        Err(e) => Some(format!("/dev/kvm is not openable read-write: {e}")),
    }
}

/// Put `/usr/sbin` and `/sbin` on this process's `PATH`.
///
/// `microvm.rs` spawns `mkfs.ext4` and `debugfs` by bare name, so they have to be
/// findable through `PATH` and not merely installed. On Debian they live in
/// `/usr/sbin`, which systemd's default `PATH` includes (so `kamaji.service`
/// finds them) and a non-login `ssh host 'cargo test'` does not — which presents
/// as "mkfs.ext4 failed — is e2fsprogs installed on this node?" on a node where
/// it plainly is. Aligning the test process with the service environment rather
/// than skipping: the interesting run of this test is over ssh on a build node.
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
    // /usr/sbin is not on a non-login shell's PATH on Debian, and both e2fsprogs
    // binaries live there.
    let path = std::env::var("PATH").unwrap_or_default();
    let found = path
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|dir| Path::new(dir).join(bin))
        .find(|p| p.is_file());
    found
}

/// A forge-shaped job that writes one artifact and exits.
///
/// `for_forge` on purpose rather than a minimal hand-built spec: it is the shape
/// this backend exists to run, and it carries the two values that have caught
/// this code before — a 32 GiB memory *ceiling* that must be clamped rather than
/// allocated, and a 512 MiB `ephemeral_storage_mb` that must be treated as a
/// floor rather than the scratch disk's size.
fn artifact_spec(forge_id: &str, produced_dir: &Path) -> WorkloadSpec {
    let mut spec = WorkloadSpec::for_forge(
        forge_id,
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
    // Nothing is pulled for a microVM workload — argv names a binary in the
    // node's rootfs image, which is why the image above is identity metadata.
    spec.command = Some(vec![
        "/bin/sh".into(),
        "-c".into(),
        // Three claims in one line: the bind mount is writable, the guest can
        // read the environment the document carried, and the working directory
        // took effect.
        "set -e; echo \"$GUEST_MARKER\" > /yah/produced/artifact.txt; pwd >> /yah/produced/artifact.txt"
            .into(),
    ]);
    spec.workdir = Some(PathBuf::from("/workspace"));
    spec.env = vec![workload_spec::EnvVar {
        name: "GUEST_MARKER".into(),
        value: workload_spec::EnvValue::Literal {
            value: "r605f14-round-trip".into(),
        },
    }];
    spec.volumes = vec![VolumeMount {
        source: VolumeSource::Bind {
            host_path: produced_dir.to_path_buf(),
        },
        target: PathBuf::from("/yah/produced"),
        read_only: false,
    }];
    spec
}

fn node_config(state_dir: PathBuf) -> MicroVmConfig {
    let dir = microvm_dir();
    MicroVmConfig {
        vmm_bin: kamaji::microvm::find_vmm().expect("checked by why_not"),
        kernel_image: dir.join("vmlinux"),
        rootfs_image: dir.join("rootfs.ext4"),
        // R605-F23: only if the node staged one. These tests assert the guest
        // contract, not the toolchain, so they must pass on a node that has no
        // toolchain.ext4 — but they must also exercise the three-drive shape
        // wherever one is present, since that is what the fleet now runs.
        toolchain_image: Some(dir.join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE)).filter(|p| p.exists()),
        state_dir,
        // No guest network: a TAP needs CAP_NET_ADMIN and an iptables rule, which
        // is a separate host-privilege question from "does the guest boot and run
        // the job". The `dns` field of the job document is `None` in this
        // configuration, which is itself worth exercising — an air-gapped node is
        // a supported shape.
        network: None,
        max_guest_memory_mb: FORGE_MEMORY_REQUEST_MB,
        max_guest_vcpus: 2,
    }
}

/// Deploy → boot → run → halt → artifacts on the host, through the real backend.
#[tokio::test]
async fn a_forge_job_runs_in_a_guest_and_its_artifacts_land_on_the_host() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let scratch = tempfile::tempdir().expect("tempdir");
    let produced = scratch.path().join("produced");
    std::fs::create_dir_all(&produced).unwrap();
    let state_dir = scratch.path().join("state");

    let rt = MicroVmRuntime::new(node_config(state_dir.clone()))
        .expect("node config: vmlinux + rootfs.ext4 + firecracker all present");

    let forge_id = "r605f14-e2e";
    let spec = artifact_spec(forge_id, &produced);
    let ident = spec.expose.mesh.identity.clone();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

    let deployed = rt
        .deploy_workload(&spec, &mesh)
        .await
        .expect("deploy a microVM workload");
    assert!(deployed.task_pid > 0, "expected a live VMM pid");

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(180), &console).await;

    // The claim a caller makes decisions on: the job is over and it succeeded.
    assert_eq!(
        status,
        WorkloadStatus::Stopped,
        "guest did not finish cleanly\n--- console.log ---\n{}",
        read_console(&console)
    );

    // …and the artifacts came back out of the scratch disk. This is the leg that
    // distinguishes a guest that booted from a guest that did the job: the file
    // was written inside the VM, to a bind mount the guest assembled from the
    // job document, and copied back by `extract_disk` after the VMM exited.
    let artifact = produced.join("artifact.txt");
    let body = std::fs::read_to_string(&artifact).unwrap_or_else(|e| {
        panic!(
            "no {} after a Stopped workload: {e}\n--- console.log ---\n{}",
            artifact.display(),
            read_console(&console)
        )
    });
    assert!(
        body.contains("r605f14-round-trip"),
        "the guest did not see the document's env; artifact reads {body:?}"
    );
    assert!(
        body.contains("/workspace"),
        "the guest did not honour the document's workdir; artifact reads {body:?}"
    );

    // Proof that *our* init ran, rather than something else in the image getting
    // to PID 1 first — a busybox `init` winning that race would boot a guest that
    // ignores the job document entirely, and the failure would look like an empty
    // produced directory.
    let log = read_console(&console);
    assert!(
        log.contains("kamaji-guest-init"),
        "console does not show kamaji-guest-init as PID 1:\n{log}"
    );

    rt.teardown_workload(&ident).await.unwrap();
    assert!(
        rt.get_workload(&ident).await.unwrap().is_none(),
        "workload still present after teardown"
    );
}

/// A **real cargo build** inside a guest, and its binary on the host afterwards
/// (R605-F23).
///
/// This is the assertion R605-F23 exists for, and the one F14 explicitly could
/// not make: F14's rootfs is busybox and `/sbin/init` and nothing else, so its
/// green e2e proved argv runs, not that anything can be compiled. The gap that
/// closes it is the toolchain volume — a third drive, attached read-only, folded
/// in as the overlay's second lower layer.
///
/// Three things have to hold at once for this to pass, and each one failed at
/// least once getting here:
///
/// 1. **The toolchain is reachable at ordinary paths.** `cargo` is a
///    glibc-dynamic binary and its ELF interpreter path is baked in, so a
///    `PATH`-only arrangement fails with "No such file or directory" naming a
///    file that is plainly present. The overlay layer is what puts
///    `/lib64/ld-linux-x86-64.so.2` where the loader looks.
/// 2. **There is writable, DISK-backed scratch.** `CARGO_HOME` defaults under
///    `$HOME` and `TMPDIR` to `/tmp`, which in this guest are the overlay's
///    tmpfs upper and a tmpfs — guest RAM. The init redirects both onto the
///    scratch disk; without that a real build OOMs partway in.
/// 3. **The artifact survives the VM.** Same `extract_disk` leg F14 proved, but
///    now carrying something a compiler produced.
///
/// Skips on a node with no `toolchain.ext4`, which is a supported configuration
/// rather than a broken one — see `MicroVmConfig::toolchain_image`.
#[tokio::test]
async fn a_real_cargo_build_runs_in_a_guest_and_its_binary_lands_on_the_host() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let toolchain = microvm_dir().join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE);
    if !toolchain.exists() {
        eprintln!(
            "SKIP: no build toolchain at {} — run oss/kamaji/guest/build-toolchain-image.sh",
            toolchain.display()
        );
        return;
    }

    let scratch = tempfile::tempdir().expect("tempdir");
    let produced = scratch.path().join("produced");
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&produced).unwrap();
    std::fs::create_dir_all(src.join("src")).unwrap();
    // A crate with no dependencies, built `--offline`: this test's claim is
    // "the guest can compile", and resolving crates.io would fold an unproven
    // network leg into an assertion about the toolchain. Guest egress is
    // R605-F22's ticket and is exercised by microvm_guest_net_e2e.
    std::fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"guestbuild\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src.join("src/main.rs"),
        "fn main() { println!(\"built inside a microVM guest\"); }\n",
    )
    .unwrap();

    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone()))
        .expect("node config: vmlinux + rootfs.ext4 + toolchain.ext4 + firecracker all present");
    assert!(
        rt.config().toolchain_image.is_some(),
        "node_config did not pick up the toolchain volume that is on disk"
    );

    let forge_id = "r605f23-cargo";
    let mut spec = artifact_spec(forge_id, &produced);
    spec.volumes.push(VolumeMount {
        source: VolumeSource::Bind {
            host_path: src.clone(),
        },
        target: PathBuf::from("/src"),
        read_only: false,
    });
    spec.workdir = Some(PathBuf::from("/src"));
    spec.command = Some(vec![
        "/bin/sh".into(),
        "-c".into(),
        // `set -x` because the console is the only channel a failed guest build
        // has, and knowing which of these five commands died is the whole
        // difference between a diagnosable failure and a rerun.
        "set -ex; cargo --version; rustc --version; cc --version | head -1; \
         cargo build --offline --release; \
         cp target/release/guestbuild /yah/produced/guestbuild; \
         /yah/produced/guestbuild > /yah/produced/artifact.txt"
            .into(),
    ]);

    let ident = spec.expose.mesh.identity.clone();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
    rt.deploy_workload(&spec, &mesh)
        .await
        .expect("deploy a microVM workload");

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    // Generous against the 180s the echo-shaped jobs get: this one boots a VM,
    // mounts a 1.2 GB layer and runs a compiler.
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(600), &console).await;
    // Printed on success too, unlike the other tests here. This one's whole
    // claim is that a compiler ran, and `cargo --version` / `rustc --version` /
    // `cc --version` on the console is the only place that is legible — a
    // passing assertion on a file's contents cannot distinguish "cargo built
    // this" from "something else put a binary there".
    eprintln!("--- guest console ---\n{}", read_console(&console));
    assert_eq!(
        status,
        WorkloadStatus::Stopped,
        "the guest build did not finish cleanly"
    );

    let binary = produced.join("guestbuild");
    assert!(
        binary.exists(),
        "no compiled binary at {} after a Stopped workload\n--- console.log ---\n{}",
        binary.display(),
        read_console(&console)
    );
    // Ran, not merely linked — a binary that cannot execute in the guest that
    // produced it would still satisfy the existence check above.
    let ran = std::fs::read_to_string(produced.join("artifact.txt")).unwrap_or_default();
    assert!(
        ran.contains("built inside a microVM guest"),
        "the compiled binary did not run in the guest; artifact reads {ran:?}\n\
         --- console.log ---\n{}",
        read_console(&console)
    );

    rt.teardown_workload(&ident).await.unwrap();
}

/// A guest whose job exits non-zero must not be reported as a clean stop.
///
/// This is the assertion that caught R605-F14's one real defect, and it failed
/// before `read_job_status` existed: a guest reboots to exit the VMM whether its
/// job passed, failed, or panicked the kernel, so Firecracker exits 0 in every
/// case and the supervisor's only completion signal cannot carry the job's
/// status. Every failed build reported `Stopped`. The guest init records the real
/// code in `job-status.json` on the scratch disk and the supervisor now reads it.
#[tokio::test]
async fn a_failing_job_is_not_reported_as_a_clean_stop() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let scratch = tempfile::tempdir().expect("tempdir");
    let produced = scratch.path().join("produced");
    std::fs::create_dir_all(&produced).unwrap();
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone())).unwrap();

    let mut spec = artifact_spec("r605f14-fail", &produced);
    spec.command = Some(vec!["/bin/sh".into(), "-c".into(), "exit 3".into()]);
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .unwrap();

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(180), &console).await;
    match &status {
        WorkloadStatus::Failed { reason } => assert!(
            reason.contains("exited 3"),
            "the failure names something other than the job's exit code: {reason:?}"
        ),
        other => panic!(
            "a job that exited 3 was reported as {other:?}\n--- console.log ---\n{}",
            read_console(&console)
        ),
    }
    rt.teardown_workload(&ident).await.unwrap();
}

/// Poll until the supervisor moves the workload off `Running`.
///
/// Polling `get_workload` rather than reaching into the watch channel because
/// that is the surface kamaji-bin uses; if this loop can see the transition, so
/// can a node.
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
            eprintln!("guest finished in {:?}: {:?}", started.elapsed(), state.status);
            return state.status;
        }
        if started.elapsed() > limit {
            panic!(
                "guest still Running after {limit:?} — the VMM never exited, which is the \
                 failure mode where a halted guest leaves firecracker resident and the \
                 supervisor never fires\n--- console.log ---\n{}",
                read_console(console)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn read_console(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("(no console log at {}: {e})", path.display()))
}

/// Mirror of `microvm::sanitize`, which is private: the per-workload state
/// directory is named after the mesh identity with `/` and `.` folded to `-`.
fn sanitized(ident: &str) -> String {
    ident
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}
