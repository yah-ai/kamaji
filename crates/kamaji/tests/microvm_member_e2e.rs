//! A service-shaped guest booted from the node's **service image** — Debian with
//! systemd as PID 1 — against a real Firecracker (R605-F32).
//!
//! `microvm_service_e2e` proves the service *archetype* on the minimal image,
//! whose PID 1 is kamaji-guest-init. This proves the image a cluster member
//! actually needs, and two claims no unit test can reach:
//!
//! 1. The service image speaks the same job-document contract as the minimal
//!    one. systemd boots, `kamaji-job.service` runs the spec's argv through
//!    `kamaji-guest-init --unit`, the argv ending becomes systemd's clean
//!    reboot, the VMM exits, and the supervisor boots the guest again — with
//!    writes to `/` surviving, and the node's service image byte-identical.
//! 2. A member is provisioned **exactly like a metal node**: the operator's own
//!    provisioning script is piped over ssh into the guest, and the daemon it
//!    installs answers `GET /health` from the host over the guest's TAP — and
//!    answers again after kamaji restarts the guest, with nobody re-running
//!    anything, because the units it enabled live on the durable root.
//!
//! Claim 2 is yah-agnostic on purpose. kamaji does not know what yubaba is; the
//! script, the remote command and the health port are inputs:
//!
//! ```text
//! KAMAJI_MICROVM_DIR=/data/r605-f32/microvm          # vmlinux + service-rootfs.ext4
//! KAMAJI_MEMBER_SSH_KEY=/root/.ssh/yah               # private half of --authorized-keys
//! KAMAJI_MEMBER_PROVISION=.yah/infra/cloud-init/stand-up-yubaba.sh
//! KAMAJI_MEMBER_PROVISION_CMD='SUDO=sudo YUBABA_BIND=0.0.0.0:7443 bash -s <group>'
//! KAMAJI_MEMBER_HEALTH_PORT=7443                     # default
//!   cargo test -p kamaji --features microvm-integration --test microvm_member_e2e -- --nocapture
//! ```
//!
//! Needs root (a guest TAP needs CAP_NET_ADMIN), `/dev/kvm`, and an uplink with
//! a default route. Each claim skips, naming why, when its substrate is absent.
//!
//! Part of R605-F32 — annotation in .yah/docs/working/W325-isolated-x86-build-capacity.md.

#![cfg(all(target_os = "linux", feature = "microvm-integration"))]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kamaji::microvm::{
    GuestNetwork, GuestSlot, MicroVmConfig, MicroVmRuntime, RootDisk, SERVICE_ROOTFS_IMAGE_FILE,
};
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{ImageRef, LifecycleArchetype, RestartPolicy, TierTag, WorkloadSpec};

/// A member's guest: yubaba + kamaji + containerd, with room to spare.
const MEMBER_MEMORY_MB: u32 = 1024;

fn microvm_dir() -> PathBuf {
    std::env::var("KAMAJI_MICROVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yah/kamaji/microvm"))
}

/// Every reason the service image cannot be booted here, named individually.
fn why_not() -> Option<String> {
    let dir = microvm_dir();
    for (what, path) in [
        ("guest kernel", dir.join("vmlinux")),
        ("service root image", dir.join(SERVICE_ROOTFS_IMAGE_FILE)),
    ] {
        if !path.exists() {
            return Some(format!("no {what} at {}", path.display()));
        }
    }
    if let Err(e) = kamaji::microvm::find_vmm(&dir) {
        return Some(e.to_string());
    }
    ensure_sbin_on_path();
    for tool in ["mkfs.ext4", "debugfs"] {
        if !on_path(tool) {
            return Some(format!("{tool} (e2fsprogs) is not installed"));
        }
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

/// Claim 2's extra substrate: a network, an ssh key, and a script to run.
fn why_not_member() -> Option<String> {
    if let Some(r) = why_not() {
        return Some(r);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Some("not root — a guest TAP needs CAP_NET_ADMIN".into());
    }
    for var in [
        "KAMAJI_MEMBER_SSH_KEY",
        "KAMAJI_MEMBER_PROVISION",
        "KAMAJI_MEMBER_PROVISION_CMD",
    ] {
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => {}
            _ => return Some(format!("{var} is not set")),
        }
    }
    for var in ["KAMAJI_MEMBER_SSH_KEY", "KAMAJI_MEMBER_PROVISION"] {
        let p = PathBuf::from(std::env::var(var).unwrap());
        if !p.is_file() {
            return Some(format!("{var}={} is not a file", p.display()));
        }
    }
    if !on_path("ssh") {
        return Some("no ssh client on PATH".into());
    }
    if let Err(e) = GuestNetwork::discover() {
        return Some(format!("no uplink for a guest network: {e:#}"));
    }
    None
}

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

fn on_path(bin: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|dir| Path::new(dir).join(bin).is_file())
}

fn node_config(state_dir: PathBuf, network: Option<GuestNetwork>) -> MicroVmConfig {
    let dir = microvm_dir();
    MicroVmConfig {
        vmm_bin: kamaji::microvm::find_vmm(&dir).expect("checked by why_not"),
        kernel_image: dir.join("vmlinux"),
        // Never booted by these tests — every guest here is service-shaped —
        // but a node always has one, and it is what kamaji-bin would stage.
        rootfs_image: dir.join("rootfs.ext4"),
        service_rootfs_image: Some(dir.join(SERVICE_ROOTFS_IMAGE_FILE)),
        toolchain_image: None,
        state_dir,
        network,
        max_guest_memory_mb: MEMBER_MEMORY_MB,
        max_guest_vcpus: 2,
    }
}

fn member_spec(id: &str, argv: &str) -> WorkloadSpec {
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
    spec.archetype = Some(LifecycleArchetype::Server);
    spec.restart_policy = RestartPolicy::Always;
    spec.resources.memory_request_mb = Some(MEMBER_MEMORY_MB);
    spec.command = Some(vec!["/bin/sh".into(), "-c".into(), argv.into()]);
    spec
}

/// Claim 1: systemd PID 1, the job runner as a unit, the argv's end as a clean
/// reboot, and a durable root — no network, no ssh, nothing yah-specific.
#[tokio::test]
async fn a_systemd_service_guest_runs_the_job_document_and_is_restarted() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let node_image = microvm_dir().join(SERVICE_ROOTFS_IMAGE_FILE);
    let before = sha256(&node_image);

    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone(), None)).expect("node config");

    // PID 1 is the thing being proven, so the argv records it: `systemd` here,
    // not `kamaji-guest-init`, or the image is not the one this test is about.
    let spec = member_spec(
        "r605f32-systemd",
        "echo \"booted pid1=$(cat /proc/1/comm)\" >> /root-boots.txt; sync",
    );
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .expect("deploy a service guest from the service image");

    let vm_dir = state_dir.join(sanitized(&ident.0));
    let console = vm_dir.join("console.log");
    let pids = watch_for_reboots(&rt, &ident, 3, Duration::from_secs(240)).await;
    rt.teardown_workload(&ident).await.unwrap();

    assert!(
        pids.len() >= 3,
        "a systemd service guest must be booted again when its argv ends; saw {} VMM pid(s)\n\
         --- console.log ---\n{}",
        pids.len(),
        read_console(&console)
    );
    let boots = debugfs_dump(&vm_dir.join(RootDisk::SERVICE_ROOT_FILE), "/root-boots.txt");
    let lines: Vec<&str> = boots.lines().filter(|l| l.starts_with("booted")).collect();
    eprintln!("root-boots.txt: {lines:?}");
    assert!(
        lines.len() >= 2,
        "writes to / must survive the reboot systemd performs; got {boots:?}\n\
         --- console.log ---\n{}",
        read_console(&console)
    );
    assert!(
        lines.iter().all(|l| *l == "booted pid1=systemd"),
        "PID 1 must be systemd in the service image: {lines:?}"
    );
    assert_eq!(
        sha256(&node_image),
        before,
        "the node's service image must never be written — every service root is a COPY"
    );
}

/// Claim 2: provisioned like metal, healthy over the TAP, healthy again after a
/// restart with nothing re-run.
#[tokio::test]
async fn a_member_is_provisioned_like_metal_and_stays_healthy_across_a_restart() {
    if let Some(reason) = why_not_member() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let key = std::env::var("KAMAJI_MEMBER_SSH_KEY").unwrap();
    let script = std::env::var("KAMAJI_MEMBER_PROVISION").unwrap();
    let remote = std::env::var("KAMAJI_MEMBER_PROVISION_CMD").unwrap();
    let port: u16 = std::env::var("KAMAJI_MEMBER_HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7443);

    let net = GuestNetwork::discover().expect("checked by why_not_member");
    let guest = GuestSlot::derive(&net, 0).unwrap().guest_ip;
    let scratch = tempfile::tempdir().expect("tempdir");
    let state_dir = scratch.path().join("state");
    let rt = MicroVmRuntime::new(node_config(state_dir.clone(), Some(net))).expect("node config");

    // The argv is the member's liveness anchor and nothing else: the member
    // itself is systemd's units, which the provisioning script installs.
    let spec = member_spec("r605f32-member", "exec sleep infinity");
    let ident = spec.expose.mesh.identity.clone();
    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .expect("deploy a networked service guest");
    let console = state_dir.join(sanitized(&ident.0)).join("console.log");

    let result = async {
        let t = Instant::now();
        wait_for_port(guest, 22, Duration::from_secs(180))
            .map_err(|e| format!("sshd never came up on {guest}: {e}"))?;
        eprintln!("sshd up on {guest} after {:?}", t.elapsed());

        let t = Instant::now();
        provision(&key, guest, &script, &remote)?;
        eprintln!("provisioned in {:?}", t.elapsed());
        let body = wait_for_health(guest, port, Duration::from_secs(120))?;
        eprintln!("GET /health -> {body}");

        // The restart: kamaji's, not the guest's — the same path a node takes.
        let first = rt.get_workload(&ident).await.unwrap().unwrap().container_id;
        rt.restart_workload(&ident)
            .await
            .map_err(|e| format!("restart: {e:#}"))?;
        let t = Instant::now();
        loop {
            let now = rt.get_workload(&ident).await.unwrap().unwrap().container_id;
            if now != first && now != "microvm-0" {
                break;
            }
            if t.elapsed() > Duration::from_secs(60) {
                return Err(format!("no new VMM after restart (still {first})"));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let body = wait_for_health(guest, port, Duration::from_secs(240))
            .map_err(|e| format!("after restart, nobody re-provisioning: {e}"))?;
        eprintln!("after restart ({:?}): GET /health -> {body}", t.elapsed());
        Ok::<(), String>(())
    }
    .await;

    rt.teardown_workload(&ident).await.unwrap();
    if let Err(e) = result {
        panic!("{e}\n--- console.log ---\n{}", read_console(&console));
    }
}

/// Pipe the operator's script into the guest over ssh, as the metal procedure does.
fn provision(key: &str, guest: Ipv4Addr, script: &str, remote: &str) -> Result<(), String> {
    let out = Command::new("ssh")
        .args(["-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"])
        // A fresh guest has fresh host keys every time this test runs.
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .args(["-o", "ConnectTimeout=10"])
        .arg(format!("yah@{guest}"))
        .arg(remote)
        .stdin(Stdio::from(
            std::fs::File::open(script).map_err(|e| e.to_string())?,
        ))
        .output()
        .map_err(|e| format!("spawning ssh: {e}"))?;
    let tail = |b: &[u8]| {
        let s = String::from_utf8_lossy(b);
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(25)..].join("\n")
    };
    eprintln!("--- provisioning stdout (tail) ---\n{}", tail(&out.stdout));
    if !out.status.success() {
        return Err(format!(
            "provisioning exited {}\n--- stderr (tail) ---\n{}",
            out.status,
            tail(&out.stderr)
        ));
    }
    Ok(())
}

fn wait_for_port(ip: Ipv4Addr, port: u16, limit: Duration) -> Result<(), String> {
    let addr = SocketAddr::from((ip, port));
    let t = Instant::now();
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_) => return Ok(()),
            Err(e) if t.elapsed() > limit => return Err(e.to_string()),
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// `GET /health` until it answers 200, returning the body.
fn wait_for_health(ip: Ipv4Addr, port: u16, limit: Duration) -> Result<String, String> {
    let t = Instant::now();
    let mut last = String::from("never connected");
    while t.elapsed() < limit {
        match http_get(ip, port, "/health") {
            Ok((200, body)) => return Ok(body),
            Ok((code, body)) => last = format!("HTTP {code}: {body}"),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "GET http://{ip}:{port}/health never answered 200 in {limit:?}; last: {last}"
    ))
}

fn http_get(ip: Ipv4Addr, port: u16, path: &str) -> Result<(u16, String), String> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {path} HTTP/1.0\r\nHost: {ip}\r\n\r\n").map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let code = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("not HTTP: {resp:.80}"))?;
    let body = resp
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok((code, body.chars().take(200).collect()))
}

async fn watch_for_reboots(
    rt: &MicroVmRuntime,
    ident: &workload_spec::MeshIdent,
    want: usize,
    limit: Duration,
) -> BTreeSet<String> {
    let started = Instant::now();
    let mut pids = BTreeSet::new();
    loop {
        if let Some(state) = rt.get_workload(ident).await.expect("get_workload") {
            if state.container_id != "microvm-0" {
                pids.insert(state.container_id.clone());
            }
            if let WorkloadStatus::Failed { reason, .. } = &state.status {
                eprintln!("instance reported Failed: {reason}");
            }
        }
        if pids.len() >= want || started.elapsed() > limit {
            eprintln!(
                "saw {} distinct VMM pid(s) in {:?}",
                pids.len(),
                started.elapsed()
            );
            return pids;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn debugfs_dump(image: &Path, guest_path: &str) -> String {
    let tmp = std::env::temp_dir().join(format!(
        "r605f32-{}-{}",
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
    let s = std::fs::read_to_string(path)
        .unwrap_or_else(|e| format!("(no console log at {}: {e})", path.display()));
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(80)..].join("\n")
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
