//! The leaf half of kamaji's boot pass (R1021-F3, W386 §2): after every
//! shimmed [`crate::native::NativeRuntime`] has adopted what it can, empty
//! everything nobody adopted, BEFORE any recorded deploy replays.
//!
//! The leaf, not a socket path or pid file, is the ground truth of "something
//! runs for this ident" (W386 spike T3), so this walks the delegated root:
//!
//! | Found | Action |
//! |---|---|
//! | a populated generation leaf no runtime adopted | TERM → grace → `cgroup.kill` (or freeze + sweep) → wait drained |
//! | a process in the shared `_shim` leaf whose workload was not adopted | TERM → grace → KILL |
//! | any process in kamaji's own cgroup (`native/`) other than kamaji and an adopted shim's child | TERM → grace → KILL |
//!
//! The last row is the floor `KillMode=mixed` used to provide. Since R1021-F8 a
//! service microVM's Firecracker is shim-parented in its own leaf and adopted
//! like any native workload, so nothing current lands in `native/`; what still
//! does is a Firecracker forked leafless by a kamaji from before F8. That one
//! is killed exactly once and R605-F16's replay boots it into the new layout —
//! left alive, the replay would boot a second VM on the same private root disk.
//! An adopted shim's child is spared even here (`Keep::child_pids`), so the
//! row can never take a VM the adoption half just took back. Own-cgroup and `_shim` members are
//! signalled per pid, never via `cgroup.kill`, which would not exempt kamaji.
//!
//! On a host with no delegated cgroup (the desktop camp, macOS) there is no
//! leaf to read and this pass does not run; [`crate::orphan`]'s pid file +
//! start time is the identity there.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cgroup::{kill_and_drain, live_members, CgroupV2};

/// What the adoption half kept alive; everything else under the root goes.
#[derive(Debug, Default)]
pub struct Keep {
    /// Generation leaves of adopted workloads (`<root>/<ident>/<generation>`).
    pub leaves: HashSet<PathBuf>,
    /// The shims parenting them.
    pub shim_pids: HashSet<u32>,
    /// The adopted shims' live children (R1021-F8): spared wherever they
    /// are found, including kamaji's own cgroup.
    pub child_pids: HashSet<u32>,
}

/// What [`reap_unadopted`] killed.
#[derive(Debug, Default)]
pub struct Reaped {
    /// Processes in kamaji's own cgroup other than kamaji.
    pub strays: Vec<u32>,
    /// Shims of workloads nobody adopted.
    pub shims: Vec<u32>,
    /// Populated generation leaves nobody adopted, now emptied.
    pub leaves: Vec<PathBuf>,
    /// Leaves that would not drain — left in place, under their ceiling.
    pub leaked: Vec<String>,
}

/// Empty every leaf, shim and stray under `cg`'s root that `keep` does not
/// name. Blocks (async) until each is gone or reported leaked.
pub async fn reap_unadopted(cg: &CgroupV2, keep: &Keep, grace: Duration) -> Reaped {
    let mut reaped = Reaped::default();
    let root = cg.root();
    let own = cg.own().map(Path::to_path_buf);
    let shim_leaf = root.join(crate::shim::SHIM_LEAF);

    // Every doomed leaf is signalled at once under ONE grace, not one grace per
    // leaf. Serially, ten un-shimmed leaves on R1021-T6's first prod roll held
    // kamaji's socket closed ~15s; yubaba's 30s UDS budget lapsed during it, it
    // fell back to its in-process runtime, and yah.dev 503'd until yubaba was
    // restarted by hand.
    let mut doomed: Vec<PathBuf> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();
    for node in subdirs(root) {
        if Some(&node) == own.as_ref() || node == shim_leaf {
            continue;
        }
        for leaf in subdirs(&node) {
            if keep.leaves.contains(&leaf) {
                continue;
            }
            let live = live_members(&leaf);
            if live.is_empty() {
                continue;
            }
            tracing::warn!(
                leaf = %leaf.display(), pids = ?live,
                "boot pass: a populated workload leaf has no adoptable shim; emptying it before \
                 any replay (R1021-F3)"
            );
            pids.extend(live);
            doomed.push(leaf);
        }
    }
    if !pids.is_empty() {
        term_then_kill(&pids, grace).await;
    }
    for leaf in doomed {
        match blocking(|| kill_and_drain(&leaf)) {
            Ok(()) => {
                let _ = std::fs::remove_dir(&leaf);
                reaped.leaves.push(leaf);
            }
            Err(e) => reaped.leaked.push(e.to_string()),
        }
    }

    let shims: Vec<u32> = live_members(&shim_leaf)
        .into_iter()
        .filter(|p| !keep.shim_pids.contains(p))
        .collect();
    if !shims.is_empty() {
        tracing::warn!(pids = ?shims, "boot pass: ending shims whose workload was not adopted");
        term_then_kill(&shims, grace).await;
        reaped.shims = shims;
    }

    if let Some(own) = &own {
        let strays: Vec<u32> = live_members(own)
            .into_iter()
            .filter(|p| !keep.child_pids.contains(p) && !keep.shim_pids.contains(p))
            .collect();
        if !strays.is_empty() {
            tracing::warn!(
                cgroup = %own.display(), pids = ?strays,
                "boot pass: killing processes left in kamaji's own cgroup by a previous kamaji \
                 (a surviving Firecracker would otherwise run beside its replay; R1021-F3)"
            );
            term_then_kill(&strays, grace).await;
            reaped.strays = strays;
        }
    }
    reaped
}

/// The kill helpers are blocking `std::fs` (a drain sleeps up to its budget).
/// `block_in_place` keeps a multi-thread runtime's other tasks moving; a
/// current-thread runtime (kamaji-bin's) cannot use it, so it runs inline there.
fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for existence; `pid` is non-zero and not
    // ours (`live_members` excludes both).
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

async fn term_then_kill(pids: &[u32], grace: Duration) {
    for &pid in pids {
        // SAFETY: kill(2) on a pid read from a cgroup's membership just now.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    if wait_gone(pids, grace).await {
        return;
    }
    for &pid in pids {
        // SAFETY: as above.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    wait_gone(pids, Duration::from_secs(5)).await;
}

async fn wait_gone(pids: &[u32], within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if !pids.iter().any(|p| alive(*p)) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `sleep` whose zombie is reaped by a thread, so `kill(pid, 0)`
    /// stops answering the moment it dies.
    pub(crate) fn sleeper() -> u32 {
        let mut child = std::process::Command::new("sleep").arg("600").spawn().unwrap();
        let pid = child.id();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        pid
    }

    fn put(cgroup: &Path, pids: &[u32]) {
        std::fs::create_dir_all(cgroup).unwrap();
        let body: String = pids.iter().map(|p| format!("{p}\n")).collect();
        std::fs::write(cgroup.join("cgroup.procs"), body).unwrap();
    }

    /// Verify (b), FIXTURE cgroupfs + REAL process: a populated leaf with no
    /// adopter is emptied (the process is dead) and removed; a kept leaf and
    /// its process are untouched.
    #[tokio::test]
    async fn a_populated_leaf_nobody_adopted_is_emptied() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let cg = CgroupV2::with_own(&root, root.join("native"));
        let orphan = sleeper();
        let kept = sleeper();
        let orphan_leaf = root.join("headscale").join("0000000000000000001");
        let kept_leaf = root.join("site").join("0000000000000000002");
        put(&orphan_leaf, &[orphan]);
        put(&kept_leaf, &[kept]);
        put(&root.join("native"), &[std::process::id()]);

        let keep = Keep {
            leaves: [kept_leaf.clone()].into(),
            ..Keep::default()
        };
        let reaped = reap_unadopted(&cg, &keep, Duration::from_millis(500)).await;

        assert_eq!(reaped.leaves, vec![orphan_leaf.clone()]);
        assert!(!alive(orphan), "the unadopted leaf's process survived");
        assert!(alive(kept), "the adopted leaf's process was killed");
        assert!(reaped.strays.is_empty(), "kamaji itself was counted as a stray");
        // SAFETY: test cleanup of our own child.
        unsafe { libc::kill(kept as libc::pid_t, libc::SIGKILL) };
    }

    /// Verify (c), FIXTURE cgroupfs + REAL process: a process in kamaji's own
    /// `native/` cgroup (where a leafless Firecracker lives) is killed;
    /// kamaji's own pid in the same file is not. An unkept shim goes too.
    #[tokio::test]
    async fn a_stray_in_kamajis_own_cgroup_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let own = root.join("native");
        let cg = CgroupV2::with_own(&root, &own);
        let vmm = sleeper();
        let shim = sleeper();
        let kept_shim = sleeper();
        put(&own, &[std::process::id(), vmm]);
        put(&root.join(crate::shim::SHIM_LEAF), &[shim, kept_shim]);

        let keep = Keep {
            shim_pids: [kept_shim].into(),
            ..Keep::default()
        };
        let reaped = reap_unadopted(&cg, &keep, Duration::from_millis(500)).await;

        assert_eq!(reaped.strays, vec![vmm]);
        assert_eq!(reaped.shims, vec![shim]);
        assert!(!alive(vmm), "the stray in native/ survived the boot pass");
        assert!(!alive(shim), "an unadopted shim survived");
        assert!(alive(kept_shim), "an adopted shim was killed");
        // SAFETY: test cleanup of our own child.
        unsafe { libc::kill(kept_shim as libc::pid_t, libc::SIGKILL) };
    }

    /// R1021-F8, FIXTURE cgroupfs + REAL processes: the stray row spares an
    /// adopted VM shim's child even where it is found in `native/`, and still
    /// kills a firecracker-like process there that no shim adopted (the
    /// pre-F8 leafless VMM, which is killed once and replayed into a leaf).
    #[tokio::test]
    async fn an_adopted_vm_is_spared_while_a_leafless_vmm_in_native_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let own = root.join("native");
        let cg = CgroupV2::with_own(&root, &own);
        let adopted_vmm = sleeper();
        let vm_shim = sleeper();
        let legacy_vmm = sleeper();
        let vm_leaf = root.join("devbox").join("0000000000000000007");
        put(&vm_leaf, &[adopted_vmm]);
        put(&root.join(crate::shim::SHIM_LEAF), &[vm_shim]);
        put(&own, &[std::process::id(), adopted_vmm, legacy_vmm]);

        let keep = Keep {
            leaves: [vm_leaf.clone()].into(),
            shim_pids: [vm_shim].into(),
            child_pids: [adopted_vmm].into(),
        };
        let reaped = reap_unadopted(&cg, &keep, Duration::from_millis(500)).await;

        assert_eq!(reaped.strays, vec![legacy_vmm]);
        assert!(reaped.shims.is_empty() && reaped.leaves.is_empty(), "{reaped:?}");
        assert!(!alive(legacy_vmm), "the leafless VMM in native/ survived the boot pass");
        assert!(alive(adopted_vmm), "the adopted VM's VMM was killed");
        assert!(alive(vm_shim), "the adopted VM's shim was killed");
        for pid in [adopted_vmm, vm_shim] {
            // SAFETY: test cleanup of our own children.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
}
