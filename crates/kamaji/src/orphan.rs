//! Orphans of a previous native runtime on the same state dir (R967-B1).
//!
//! `NativeRuntime` keeps its bookkeeping in memory, so a child that outlives its
//! runtime (daemon crash, SIGKILL, a quit path that skipped teardown) is
//! invisible to the next one. Worse, `LedgerPorts` deliberately hands the
//! remembered port back to the same owner, so the replacement dies with
//! `EADDRINUSE` against its own predecessor.
//!
//! **Scope since R1021-F3: the no-cgroup host only** (the desktop camp, macOS).
//! Where a delegated cgroup exists, a survivor's identity is its leaf: the boot
//! pass ([`crate::boot`]) adopts live shims and kills every unadoptable leaf
//! member before any replay, and `deploy_workload` empties the ident's leaves
//! before minting a new one. Only without a cgroup does it fall back to this.
//!
//! The identity of an orphan is a pid file, `<state_dir>/<ident>/pid`, holding
//! the pid and the process start time. The start time is what makes a recycled
//! pid distinguishable; argv / basename matching is deliberately NOT used,
//! because another workspace's camp runs a same-named binary on its own ports.
//!
//! @yah:relay(R1021, "Kamaji restart without workload downtime: shim-supervised native workloads, and the roll's drain becomes leader transfer only (W386)")
//! @yah:at(2026-10-27T04:22:07Z)
//! @yah:phase(P1)
//! @yah:next("Read W386 §Spike and §Design before claiming any child; the VM harness in W386-assets/ reproduces every claim in under a minute.")
//! @yah:next("Order: SIGTERM handler (independent, ships first) → shim → boot pass → unit flip (same release as boot pass, never earlier) → roll drain → LIVE. JIT custody and microVM are P2.")
//! @yah:verify("The R1020 Workloads card shows headscale and yah-marketing Running at the same pid on every step of a full prod roll.")
//! @yah:gotcha("Appliance subset first: headscale (native-exec) and yah-marketing (mesofact-static, default KeepAlive → BundleBackend.native) are BOTH NativeRuntime, so the native.rs shim covers both. On-demand bundles (JitRuntime) and microVMs are not covered until P2.")
//! @yah:gotcha("Not R858-T12's rejected carve-out: every voter still drains leadership. What changes is that a supervisor restart stops being a workload event for every workload class uniformly — keep it that way, no appliance-aware branch in the roll.")
//! @arch:see(.yah/docs/working/W386-kamaji-restart-without-workload-downtime.md)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Name of the pid file inside a workload's state dir.
const PID_FILE: &str = "pid";

pub(crate) fn pid_path(state_dir: &Path, ident: &str) -> PathBuf {
    state_dir.join(ident).join(PID_FILE)
}

/// Opaque process start time, comparable only against itself.
pub(crate) fn start_time(pid: u32) -> Option<String> {
    imp::start_time(pid)
}

/// Record `pid` (and its start time) as the live child of `ident`; if `pid` is
/// already dead, remove the file instead.
pub(crate) fn record(state_dir: &Path, ident: &str, pid: u32) {
    // No readable start time means the process is already gone: nothing is
    // running, so nothing should be recorded - and a file left from an earlier
    // child must not keep naming it.
    let Some(start) = start_time(pid) else {
        clear(state_dir, ident);
        return;
    };
    let path = pid_path(state_dir, ident);
    if let Err(e) = std::fs::write(&path, format!("{pid} {start}\n")) {
        tracing::warn!(path = %path.display(), "could not record the child's pid: {e}");
    }
}

/// Forget the recorded child (clean exit / teardown).
pub(crate) fn clear(state_dir: &Path, ident: &str) {
    let _ = std::fs::remove_file(pid_path(state_dir, ident));
}

fn read(state_dir: &Path, ident: &str) -> Option<(u32, String)> {
    let text = std::fs::read_to_string(pid_path(state_dir, ident)).ok()?;
    let (pid, start) = text.trim().split_once(' ')?;
    Some((pid.parse().ok()?, start.to_string()))
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for existence.
    unsafe {
        libc::kill(pid as i32, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

async fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while alive(pid) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// If `ident` has a recorded child from a previous runtime that is still the
/// same live process, SIGTERM it, wait `grace`, SIGKILL, and wait for exit.
/// Always leaves no pid file behind. Returns the pid reaped, if any.
///
/// @yah:ticket(R1021-F3, "Boot pass before any replay: adopt live shims, kill unadoptable leaf members and every stray in kamaji's own native/ subgroup")
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:at(2026-10-27T08:19:22Z)
/// @yah:phase(P1)
/// @yah:parent(R1021)
/// @yah:next("Run in kamaji-bin main.rs BEFORE resume_bundle_workloads / resume_native_workloads / resume_microvm_workloads. Per W386 §2 table: shim answers + proto ok + generation leaf matches → adopt (WorkloadHandle, status Running, spec from spec.json); leaf populated with no answering shim → TERM/grace/KILL every leaf member and wait empty; incompatible proto → stop and restart under a current shim; any process in native/ other than kamaji itself → kill.")
/// @yah:next("Replays skip idents already adopted with a matching spec digest; adopted workloads report spec_digest in List (R870-B24) so yubaba does not re-send them. An operator Deploy of a live in-map ident keeps replace semantics.")
/// @yah:next("orphan.rs narrows to the kill-unadoptable branch (identity by leaf on Linux; pid file + start time remains only where there is no cgroup, i.e. the desktop camp). Then rewrite native.rs's 'Crash semantics' header bullet to state adoption.")
/// @yah:verify("kamaji tests: (a) adopted workload keeps its pid across a NativeRuntime rebuild; (b) a populated leaf with no shim is emptied before replay; (c) a stray process placed in the native/ subgroup is killed before replay.")
/// @yah:gotcha("The native/-stray row is the floor KillMode=mixed provides today. microvm.rs mints no leaf, so Firecracker runs in kamaji's own native/ subgroup: once the unit is KillMode=process it SURVIVES a restart, and R605-F16's replay would boot a second VM on the same private root disk. This pass is what prevents that.")
/// @yah:gotcha("Never spawn beside a populated leaf: the leaf, not a socket path or pid file, is the ground truth of 'something runs for this ident' (W386 spike T3).")
/// @yah:gotcha("Adopting a running appliance is not R977-B14's start-after-absence: do not hold it pending owner confirmation — yubaba's leader loop already adopts the running appliance (R858-T3) and stops it if this node is not the owner.")
/// @arch:see(.yah/docs/working/W386-kamaji-restart-without-workload-downtime.md)
/// @yah:depends_on(R1021-F2)
/// @yah:handoff("Ashguard (courier session:038bd73e). BASELINE, before any edits: kamaji --features native-integration --lib 250 passed/0 failed; kamaji-bin --features native-exec,bundle-serving 314+2+2+1 passed/0 failed. POST-CHANGE: kamaji 253/0 (the 3 new tests below); kamaji-bin 314+2+2+1/0. cargo check -p kamaji-bin (default features) EXIT 0. cargo check -p kamaji --features native-integration --tests --target aarch64-unknown-linux-gnu EXIT 0. kamaji-bin on aarch64-linux could NOT be checked, because ring's C build script fails to cross-compile on this host. That is an environment limit, not this change. WHAT CHANGED. (1) ONE DIGEST. F2's fnv1a64 spec_digest is deleted. ShimRequest.spec_digest and Hello.spec_digest are now Option<String>: R870-B24's kamaji_proto::spec_digest, which kamaji-bin hex-encodes (server.rs digest_hex / digest_from_hex) and kamaji treats as opaque. spec.json now holds shim::PersistedSpec {spec_digest, mesh_ip, spec} (read_spec reads it), so a survivor with no deploy record can still be restarted. ShimConn::connect reads `proto` before the full parse and returns shim::IncompatibleProto on a mismatch. (2) native.rs: the deploy body moved into NativeRuntime::deploy_with_digest(spec, mesh, Option<String>), and Kamaji::deploy_workload calls it with None. WorkloadHandle and NativeProcess carry spec_digest, so respawns echo it. The graceful-upgrade spawn passes None. NEVER SPAWN BESIDE A POPULATED LEAF: with a cgroup, deploy now calls cg.destroy_workload(ident) before minting a leaf. orphan::reap runs only when there is no cgroup. New unix-only API: adopt_survivors() -> Adoption {adopted, keep, incompatible}, adopt_one, restart_incompatible(idents), deployed_digest(ident), cgroup_root(). Adoption requires all of: the shim answers within 2s, proto==PROTO, hello.ident == the dir name, the ident in spec.json matches, boot_id matches (when both are known), child_start matches the live pid (when it has not exited), and the generation leaf <root>/<ident>/<gen> exists and holds child_pid (when cgroup.procs is readable). With no cgroup, gen must be \"0\". An adopted workload gets a WorkloadHandle with status Running and a supervise() task whose initial instance is Proc::Shim(conn), so RestartPolicy carries on: a last_exit latched while kamaji was down settles immediately and respawns. The OOM baseline is taken from the node's current counter. The deadline is re-armed from adoption time; the original start is not recorded. There is no owner-confirmation hold. The 'Crash semantics' header bullet is rewritten to describe adoption. (3) NEW kamaji/src/boot.rs (unix + native-integration): reap_unadopted(cg, keep, grace). For each populated generation leaf that is not kept: TERM, then grace, then kill_and_drain (cgroup.kill, or freeze+sweep), then rmdir. Shims in `_shim` that are not kept, and every live process in kamaji's own cgroup (cg.own(), i.e. native/) other than kamaji itself: TERM, grace, KILL, signalled per pid and never via cgroup.kill. cgroup.rs adds CgroupV2::own(), a test-only with_own, CgroupHandle::existing, and pub live_members / kill_and_drain. (4) kamaji-bin: ServerCtx::boot_pass(), gated unix and (native-exec or bundle-serving), runs in main.rs before every resume_*. It adopts on ctx.native and on bundle.native (the yah-marketing class), records adopted digests in Registry.adopted (stamp_spec_digests falls back to it; set_deployed_spec and remove_deployed_spec clear it), runs one reap over the shared delegated root with a 5s grace, then restarts incompatibles from spec.json. The digest is threaded through dispatch_deploy -> deploy_container -> _inner -> _backend -> deploy_native_exec -> deploy_with_digest. BundleDeployRecord gains spec_digest (serde default, so old records read as None); admission sets it, and run_bundle_keepalive passes it to the serve fork. Revalidate and feed-tier forks carry None. REPLAY SKIP: resume_native_workloads skips a record whose live digest equals spec_digest(record.workload), re-registers its control probe and set_deployed_spec. resume_bundle_workloads skips when record.spec_digest equals the live digest, then reregister_adopted_bundle sets DeployStatus Running plus the TcpConnect probe. An operator Deploy still tears down first, so replace semantics are unchanged. VERIFY COVERAGE. (a) REAL processes and a real out-of-process shim: native::tests::an_adopted_workload_keeps_its_pid_across_a_runtime_rebuild. It deploys with a digest, drops the runtime and its tokio runtime, adopts in a new one, and asserts the same pid, Running, the digest, and that the reap spares it. It then triggers an exit and asserts a respawn under RestartPolicy::Always. The cgroup root is a tempdir, so the membership check takes the 'procs unreadable' branch. (b) boot::tests::a_populated_leaf_nobody_adopted_is_emptied and (c) boot::tests::a_stray_in_kamajis_own_cgroup_is_killed use a FIXTURE cgroupfs (tempdir with hand-written cgroup.procs) but REAL sleep processes that are actually killed. (c) also checks that kamaji's own pid in native/ is spared and that only the non-kept shim dies. Tests (b) and (c) call reap_unadopted directly; no test drives kamaji-bin's boot_pass end to end. The F2 test now asserts hello.spec_digest == None.")
/// @yah:handoff("Ashguard (session:038bd73e), leader delta. This closes limits (3) and (5); (4) is left as instructed. (3a) The bundle's revalidate receiver and feed-tier forks already went through the shimmed bundle.native runtime. They now also carry the record's digest: fork_revalidate_receiver and fork_feed_tier take spec_digest and call deploy_with_digest. The keep-alive path passes the record digest. The on-demand path passes None, because its JIT serve is never adopted, so a replay always runs and replaces the receiver. (3b) resume_bundle_workloads skips a replay ONLY when every process the record owns is live in bundle.native at record.spec_digest. The owned set comes from bundle_owned_idents: <id>, plus <id>-revalidate when a receiver is declared, plus <id>-feed when that receiver has feeds. adopted_with_digest(native, idents, digest) returns (complete, live), and a missing digest never counts as complete. When adoption is only partial, the live members are torn down and the whole bundle replays. TEST: server::tests::bundle_serving::a_bundle_is_fully_adopted_only_when_every_owned_process_is. It deploys real /bin/sleep processes straight into a NativeRuntime, which is the same as being in the map, i.e. adopted at boot. It asserts: serve-only is incomplete, with live==[site]; a sibling at the wrong digest is incomplete; all members at digest d are complete; a None digest is never complete. It tests the decision helper, NOT resume_bundle_workloads end to end; the existing bundle seams would need a materialized bundle plus a restart to drive the whole thing. (5) W386 now names the leaf `kamaji.service/_shim/` in the options table and in §1, with the reason: an ident can't contain `_`. COUNTS: kamaji-bin native-exec,bundle-serving 315+2+2+1/0 (was 314; +1 is the new test; the run had no skew). kamaji native-integration --lib 253/0.")
/// @yah:gotcha("R1021-F3 remaining limits: (1) The Linux-only paths are compiled but have not been run, so the three verify tests plus a live `systemctl restart kamaji` need to run on a delegated-cgroup node before R1021-T4. (2) The boot pass is compiled only with native-exec or bundle-serving. (4) On a host with no cgroup, a shim that speaks an incompatible proto is not killed; this is desktop-only. (6) kamaji-proto messages.rs was not touched.")
/// @yah:handoff("Leader: second pass closed both holes. yah-marketing's revalidate and feed-tier forks now go through the shim and carry the record digest. The bundle replay-skip applies only when every owned process is live at that digest; a mixed case tears down and replays the whole bundle. W386 updated to `_shim/`. Courier counts: kamaji-bin native-exec,bundle-serving 315+2+2+1/0; kamaji native-integration 253/0.")
/// @yah:verify("On a delegated-cgroup Linux node, before R1021-T4's KillMode flip ships: the three F3 verify tests, plus `systemctl restart kamaji` leaving headscale/yah-marketing at the same pids (R1021-T6)")
/// @yah:handoff("2026-10-27, @Ashguard:coffee (R1021-T6 live). BUG FOUND LIVE AND FIXED: boot_pass (kamaji-bin/src/server.rs) took the reap's cgroup from the runtimes' cgroup_root(), which is None whenever +cpu +memory cannot be enabled. Every dev Pi boots cgroup_disable=memory, so on 0.8.50-h5 the reap was skipped entirely (adopted=0 and no reap line logged). Pre-shim Firecrackers survived in native/, and the microVM replay's create_tap then stripped their NAT and failed EBUSY. The fix falls back to CgroupV2::delegated() (the reap needs the path, never the controllers). It shipped in hot 0.8.50-h6 and was VERIFIED LIVE on the rolling h5->h6 roll: 011 logged strays=[916,941,995] and 014 logged strays=[1283,1303,1333]. All six VMs replayed under `kamaji shim` parents with MASQUERADE restored, and 011 ADOPTED passway-inner-noisetable-marketing (pid 3224) across its restart. cargo check -p kamaji-bin --features native-exec,bundle-serving,microvm passes. No unit test was added: the path reads /proc/self/cgroup and is Linux-only.")
pub(crate) async fn reap(state_dir: &Path, ident: &str, grace: Duration) -> Option<u32> {
    let recorded = read(state_dir, ident);
    clear(state_dir, ident);
    let (pid, start) = recorded?;
    if pid == 0 || !alive(pid) || start_time(pid).as_deref() != Some(start.as_str()) {
        return None;
    }
    tracing::warn!(
        workload = ident,
        pid,
        "reaping the orphaned child of a previous native runtime on this state dir"
    );
    // SAFETY: plain kill(2) on a pid whose identity was just verified.
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if !wait_gone(pid, grace).await {
        // SAFETY: as above.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        wait_gone(pid, Duration::from_secs(5)).await;
    }
    Some(pid)
}

/// `true` when a listener already answers on `bind_ip:port`.
///
/// A connect probe rather than the ledger's bind probe (`ports::is_free`), for
/// two reasons measured while fixing R967-B1. (1) On macOS a SO_REUSEADDR bind
/// to a specific IP succeeds while another socket holds `*:P`, and the dev
/// drivers bind `0.0.0.0` against a loopback `bind_ip`; a bind probe misses
/// exactly the orphan this module exists for. (2) A bind probe also trips on
/// sockets that merely own the number (another process's ephemeral source
/// port), which flaked unrelated parallel deploys. A connect to `bind_ip:P` is
/// answered only by a listener that would conflict at that address - a wildcard
/// holder or one on the same IP, never one on a neighbouring mesh IP.
pub(crate) fn is_held(bind_ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(bind_ip), port);
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250))
        // A connect to an unbound loopback port in the ephemeral range can
        // TCP-simultaneous-open with ITSELF and "succeed"; that is not a holder.
        .is_ok_and(|c| c.local_addr().ok() != Some(addr))
}

/// [`is_held`], confirmed after a short settle. A number the ledger remembers
/// was released the moment it was picked, so a listener that is merely passing
/// through it (another process's ephemeral bind, a socket still closing) must
/// not fail a deploy; a real squatter is still there a moment later.
pub(crate) async fn is_held_settled(bind_ip: Ipv4Addr, port: u16) -> bool {
    if !is_held(bind_ip, port) {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    is_held(bind_ip, port)
}

/// Best-effort "who listens on `port`" for an error message only:
/// `pid 123 (name)`, or `pid unknown`.
pub(crate) fn describe_holder(port: u16) -> String {
    let out = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpc"])
        .output();
    let Ok(out) = out else {
        return "pid unknown".to_string();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.lines().find_map(|l| l.strip_prefix('p'));
    let cmd = text.lines().find_map(|l| l.strip_prefix('c'));
    match (pid, cmd) {
        (Some(p), Some(c)) => format!("pid {p} ({c})"),
        (Some(p), None) => format!("pid {p}"),
        _ => "pid unknown".to_string(),
    }
}

#[cfg(target_os = "macos")]
mod imp {
    pub fn start_time(pid: u32) -> Option<String> {
        let pid = i32::try_from(pid).ok().filter(|p| *p > 0)?;
        // SAFETY: proc_pidinfo writes at most `size` bytes into the POD struct
        // we hand it; zeroed is a valid starting value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let rc = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if rc < size {
            return None;
        }
        Some(format!("{}.{}", info.pbi_start_tvsec, info.pbi_start_tvusec))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub fn start_time(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm (field 2) may contain spaces/parens; fields resume after the last ')'.
        let rest = &stat[stat.rfind(')')? + 1..];
        // rest begins at field 3, so field 22 is index 19.
        rest.split_whitespace().nth(19).map(str::to_string)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    pub fn start_time(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn recording_a_dead_pid_removes_the_file_instead_of_leaving_a_stale_one() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("w")).unwrap();
        record(tmp.path(), "w", std::process::id());
        assert!(pid_path(tmp.path(), "w").exists());

        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        record(tmp.path(), "w", dead);
        assert!(!pid_path(tmp.path(), "w").exists());
    }
}
