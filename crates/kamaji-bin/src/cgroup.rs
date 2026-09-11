//! cgroup v2 driver for Kamaji's native workload backend.
//!
//! Native workloads each get their own cgroup under
//! `<slice_root>/native/<workload-id>/`. This module owns:
//!
//! - **Setup** — ensure `<slice_root>/native/` exists and has the controllers
//!   we need (`cpu`, `memory`) enabled on its `cgroup.subtree_control`.
//! - **Per-workload create/destroy** — `mkdir`/`rmdir` the per-workload
//!   directory.
//! - **Limits** — translate [`ResourceLimits`] into the strings written to
//!   `cpu.max` and `memory.max`.
//! - **Process attach** — write a pid into `cgroup.procs`; called from R406-T5
//!   in the post-fork pre-exec stub so the child inherits the cgroup before
//!   it runs the workload binary.
//!
//! cgroup v2 is the unified hierarchy on Linux. There are no dedicated
//! syscalls — every operation is a write to a virtual file under
//! `/sys/fs/cgroup`. The module therefore compiles everywhere; on non-Linux
//! hosts (and under tests) the writes target whatever root path the caller
//! supplies — typically a tempdir.
//!
//! @yah:ticket(R885-T2, "Add pids.max — nothing bounds a fork bomb today")
//! @yah:at(2026-09-10T07:29:37Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Cleric. Small and mechanical once R885-B1 has a live call site to hang it on.")
//! @yah:next("REQUIRED_CONTROLLERS at cgroup.rs:35 is &[\"cpu\", \"memory\"] — pids is not even enabled on cgroup.subtree_control, so this is an enable plus a write, not just a write. Verified absent tree-wide: the only \"pids\" hit outside cgroup.rs is prose about process IDs at kamaji/src/docker.rs:168.")
//! @yah:next("CARRY THE VALUE AS AN ANNOTATION, not a ResourceLimits field. WorkloadSpec crosses a postcard wire where every field is mandatory and always encoded; kamaji-proto/src/version.rs:63 states the rule three times, and V2/V4/V5/V6/V7/V8 were each a bump for exactly one added field. Follow the yah.placement.memory-request-mb precedent. Pick a defensible default rather than leaving it unset — an absent limit is the current behaviour and closes nothing.")
//! @yah:verify("rg -n \"pids\" oss/kamaji/crates/kamaji-bin/src/cgroup.rs — REQUIRED_CONTROLLERS contains it and pids.max is written in create_workload.")
//! @yah:verify("On a Linux node: cat /sys/fs/cgroup/<workload-leaf>/pids.max returns the configured bound, and a deliberate fork bomb inside a test workload is capped rather than taking the node.")
//! @yah:depends_on(R885-B1)
//!
//! @yah:ticket(R885-F3, "OOM classification: an OOM-kill is currently indistinguishable from a crash")
//! @yah:at(2026-09-10T07:30:00Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Warrior — the read path is easy, but reporting the distinction upward may cross the wire (see gotcha).")
//! @yah:next("THE DRIVER HAS NO READ PATH AT ALL. cgroup.rs only ever writes; there is no reader outside its own tests. memory.events oom_kill is the only counter separating an OOM from an ordinary signal, and nothing reads it — the restart loop sees Signaled(SIGKILL) via translate_wait_status and treats it as ordinary failure.")
//! @yah:next("THIS HAS A SCAR ALREADY: R590-B10 is a forge workload SIGKILLed by a 256 MB ceiling during a rusty-v8 checkout, diagnosed the slow way and stopgapped by raising the ceiling to 32 GiB. That 32 GiB stopgap is in turn what R605-T10 is about. A one-line oom_kill read would have collapsed that diagnosis.")
//! @yah:next("COLLECT THE REST WHILE THE READ PATH EXISTS — they are free once there is one: memory.peak, cpu.stat throttling counters, pids.current. Surface them as workload telemetry. PSI is optional and not required by this ticket.")
//! @yah:verify("rg -rn \"memory\\.events|memory\\.peak|cpu\\.stat|pids\\.current\" --type rust — returns real read sites, not doc comments.")
//! @yah:verify("On a Linux node: deploy a workload with a memory.max it will exceed; kamaji reports a state that names the OOM, distinct from the state a plain SIGKILL produces.")
//! @yah:gotcha("CHECK THE WIRE COST BEFORE DESIGNING THE REPORT. Surfacing an OOM distinction to yubaba may need a new WorkloadState shape, and WorkloadState crosses the postcard UDS where every field is mandatory — kamaji-proto/src/version.rs:63, currently V8. See whether an existing field or the annotations map can carry it before spending a ProtocolVersion bump. If a bump is genuinely needed, batch it with anything else under R885 that needs one rather than paying twice.")
//! @yah:depends_on(R885-B1)
//! @yah:gotcha("R885-T6 IS NOW A CERTAIN V9 BUMP (operator decided 2026-09-10 to delete ephemeral_storage_mb from ResourceLimits). If this ticket also needs a wire change to report the OOM distinction upward, check R885-T6 status first and batch both into one ProtocolVersion bump instead of paying two.")
//!
//! @yah:ticket(R885-B4, "Add a generation level and a safe teardown — redeploy races rmdir against mkdir, and EBUSY has no recovery")
//! @yah:at(2026-09-10T07:30:22Z)
//! @yah:status(open)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Warrior — teardown correctness and a race, on Linux-only paths the camp Mac cannot exercise.")
//! @yah:next("THE HIERARCHY IS TWO LEVELS AND ENFORCED FLAT: <slice_root>/native/<workload-id>/. validate_id at cgroup.rs:174 forbids a slash in the id, so the flatness is deliberate, not incidental. A rolling replacement of svc-a therefore puts outgoing and incoming processes in the SAME directory and races teardown rmdir against the new mkdir. Fix: extend to <workload-id>/<generation>/ and relax validate_id for exactly that one level.")
//! @yah:next("TEARDOWN IS A BARE remove_dir (cgroup.rs:113) whose own doc at :109-112 pushes the reap-before-rmdir obligation onto callers that do not exist. There is no cgroup.procs read-back, no cgroup.kill, no freeze-and-sweep. A workload that double-forked leaves rmdir failing EBUSY with no recovery path. Correct order: cgroup.kill -> reap -> read final counters (pairs with R885-F3) -> rmdir.")
//! @yah:next("The concept is already in this codebase on the other side: kamaji-containerd-core/src/lib.rs:665-666 reasons about cgroup-wide kill reaching every process in a task cgroup. Only the native side lacks it. cgroup.kill appears nowhere under oss/kamaji today.")
//! @yah:verify("rg -rn \"cgroup\\.kill\" oss/kamaji — a real write site in destroy_workload, ordered before the rmdir.")
//! @yah:verify("Unit test: a workload cgroup with a live double-forked descendant is torn down cleanly rather than leaving EBUSY.")
//! @yah:verify("On a Linux node: redeploy the same workload id twice in quick succession; both generations get distinct leaves and the first is fully removed.")
//! @yah:depends_on(R885-B1)

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use workload_spec::ResourceLimits;

/// Default slice root used in production. Kamaji's systemd unit sets
/// `Slice=yubaba.slice`, which causes systemd to materialize this directory.
pub const DEFAULT_SLICE_ROOT: &str = "/sys/fs/cgroup/yubaba.slice";

/// Controllers Kamaji's native driver requires enabled on the
/// `<slice_root>/native/cgroup.subtree_control` file.
const REQUIRED_CONTROLLERS: &[&str] = &["cpu", "memory"];

/// `cpu.max` period (microseconds). 100ms is the kernel default and what every
/// container runtime uses; keeping it makes quota arithmetic comparable across
/// native and container workloads.
const CPU_PERIOD_US: u64 = 100_000;

/// Millicores that make one full core (k8s convention: `1000m` = 1 CPU).
const MILLIS_PER_CORE: u64 = 1000;

/// Driver scoped to one `<slice_root>/native` sub-tree. Cheap to clone — only
/// holds a path.
#[derive(Debug, Clone)]
pub struct CgroupV2 {
    native_root: PathBuf,
}

impl CgroupV2 {
    /// Build a driver under the given slice root (e.g.
    /// `/sys/fs/cgroup/yubaba.slice`). The per-workload subtree is
    /// `<slice_root>/native`.
    pub fn new(slice_root: impl Into<PathBuf>) -> Self {
        let mut native_root: PathBuf = slice_root.into();
        native_root.push("native");
        Self { native_root }
    }

    /// Driver pointed at [`DEFAULT_SLICE_ROOT`] — the production layout.
    pub fn at_default_root() -> Self {
        Self::new(DEFAULT_SLICE_ROOT)
    }

    pub fn native_root(&self) -> &Path {
        &self.native_root
    }

    /// Create `<slice_root>/native/` if absent and enable `cpu` + `memory` on
    /// its `cgroup.subtree_control`. Idempotent; safe on every startup.
    ///
    /// Off-Linux (or against a tempdir) the controller file doesn't exist —
    /// we swallow `NotFound` so tests work without faking a cgroupfs.
    pub fn ensure_root(&self) -> Result<(), CgroupError> {
        create_dir_all(&self.native_root)?;
        let subtree_control = self.native_root.join("cgroup.subtree_control");
        let directive = enable_controllers_directive(REQUIRED_CONTROLLERS);
        match fs::write(&subtree_control, directive) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CgroupError::Io {
                path: subtree_control,
                source,
            }),
        }
    }

    /// Create the per-workload cgroup at `<native_root>/<id>` and write the
    /// resource limits. The returned [`CgroupHandle`] names the path so R406-T5
    /// can join its forked child via [`CgroupHandle::attach_pid`].
    pub fn create_workload(
        &self,
        id: &str,
        limits: &ResourceLimits,
    ) -> Result<CgroupHandle, CgroupError> {
        validate_id(id)?;
        let path = self.native_root.join(id);
        create_dir_all(&path)?;
        write_file(&path.join("cpu.max"), &format_cpu_max(limits.cpu_millis))?;
        write_file(
            &path.join("memory.max"),
            &format_memory_max(limits.memory_mb),
        )?;
        Ok(CgroupHandle { path })
    }

    /// `rmdir` the cgroup at `<native_root>/<id>`. The kernel refuses with
    /// `EBUSY` while any process is still in `cgroup.procs`; callers must
    /// reap or migrate every member first. `NotFound` is treated as success
    /// so destroy is idempotent.
    pub fn destroy_workload(&self, id: &str) -> Result<(), CgroupError> {
        validate_id(id)?;
        let path = self.native_root.join(id);
        match fs::remove_dir(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CgroupError::Io { path, source }),
        }
    }
}

/// Handle to one per-workload cgroup; returned by [`CgroupV2::create_workload`].
#[derive(Debug)]
pub struct CgroupHandle {
    path: PathBuf,
}

impl CgroupHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `pid` to this cgroup's `cgroup.procs`. R406-T5 calls this from
    /// the post-fork pre-exec stub so the child runs inside the cgroup before
    /// it execs the workload binary.
    pub fn attach_pid(&self, pid: u32) -> Result<(), CgroupError> {
        write_file(&self.path.join("cgroup.procs"), &pid.to_string())
    }
}

/// Translate `cpu_millis` (workload-spec millicore request, where 1000 = one
/// full core) into a cgroup v2 `cpu.max` line — `"<quota_us> <period_us>"`, or
/// `"max <period>"` for unlimited.
pub fn format_cpu_max(cpu_millis: u32) -> String {
    if cpu_millis == 0 {
        return format!("max {CPU_PERIOD_US}");
    }
    let quota = (u64::from(cpu_millis) * CPU_PERIOD_US) / MILLIS_PER_CORE;
    let quota = quota.max(1);
    format!("{quota} {CPU_PERIOD_US}")
}

/// Translate `memory_mb` into a cgroup v2 `memory.max` line — a byte count, or
/// the literal `"max"` for unlimited.
pub fn format_memory_max(memory_mb: u32) -> String {
    if memory_mb == 0 {
        "max".to_string()
    } else {
        let bytes = u64::from(memory_mb) * 1024 * 1024;
        bytes.to_string()
    }
}

fn enable_controllers_directive(controllers: &[&str]) -> String {
    controllers
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_id(id: &str) -> Result<(), CgroupError> {
    if id.is_empty() || id.contains('/') || id.contains('\0') || id == "." || id == ".." {
        return Err(CgroupError::InvalidWorkloadId(id.to_string()));
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), CgroupError> {
    fs::create_dir_all(path).map_err(|source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, contents: &str) -> Result<(), CgroupError> {
    fs::write(path, contents).map_err(|source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("workload id {0:?} is not a valid cgroup directory name")]
    InvalidWorkloadId(String),
    #[error("cgroup io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn limits(memory_mb: u32, cpu_millis: u32) -> ResourceLimits {
        ResourceLimits {
            memory_mb,
            cpu_millis,
            ephemeral_storage_mb: 0,
        }
    }

    fn driver() -> (TempDir, CgroupV2) {
        let tmp = TempDir::new().unwrap();
        let cg = CgroupV2::new(tmp.path());
        (tmp, cg)
    }

    #[test]
    fn ensure_root_creates_native_directory() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        assert!(cg.native_root().is_dir());
    }

    #[test]
    fn ensure_root_is_idempotent() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        cg.ensure_root().unwrap();
    }

    #[test]
    fn create_workload_writes_cpu_and_memory() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-a", &limits(256, 1000)).unwrap();

        let cpu = fs::read_to_string(handle.path().join("cpu.max")).unwrap();
        assert_eq!(cpu, "100000 100000");

        let mem = fs::read_to_string(handle.path().join("memory.max")).unwrap();
        assert_eq!(mem, (256u64 * 1024 * 1024).to_string());
    }

    #[test]
    fn cpu_max_translates_millis_to_quota_period() {
        // 1000m = one full core
        assert_eq!(format_cpu_max(1000), "100000 100000");
        // 2000m = two cores
        assert_eq!(format_cpu_max(2000), "200000 100000");
        // 500m = half a core
        assert_eq!(format_cpu_max(500), "50000 100000");
        // 1m rounds to a 100us quota, not zero.
        assert_eq!(format_cpu_max(1), "100 100000");
        // 0 means "no limit" — matches workload-spec's "leave it unbounded".
        assert_eq!(format_cpu_max(0), "max 100000");
    }

    #[test]
    fn memory_max_zero_means_max() {
        assert_eq!(format_memory_max(0), "max");
        assert_eq!(format_memory_max(1), (1024u64 * 1024).to_string());
        assert_eq!(format_memory_max(4096), (4096u64 * 1024 * 1024).to_string());
    }

    #[test]
    fn attach_pid_writes_to_cgroup_procs() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-b", &limits(64, 512)).unwrap();
        handle.attach_pid(4242).unwrap();
        let procs = fs::read_to_string(handle.path().join("cgroup.procs")).unwrap();
        assert_eq!(procs, "4242");
    }

    #[test]
    fn destroy_workload_removes_directory() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-c", &limits(64, 512)).unwrap();
        let path = handle.path().to_path_buf();
        drop(handle);
        // On a real cgroup v2 fs, `rmdir` succeeds even though `cpu.max` etc.
        // are visible — the kernel removes those control files atomically with
        // the directory. A tempdir-backed test has them as ordinary files, so
        // we clear them first to mirror that semantic.
        for f in ["cpu.max", "memory.max", "cgroup.procs"] {
            let p = path.join(f);
            if p.exists() {
                fs::remove_file(p).unwrap();
            }
        }
        cg.destroy_workload("svc-c").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn destroy_missing_workload_is_ok() {
        let (_tmp, cg) = driver();
        cg.ensure_root().unwrap();
        cg.destroy_workload("never-existed").unwrap();
    }

    #[test]
    fn invalid_id_with_slash_rejected() {
        let (_tmp, cg) = driver();
        let err = cg.create_workload("foo/bar", &limits(64, 512)).unwrap_err();
        assert!(matches!(err, CgroupError::InvalidWorkloadId(_)));
    }

    #[test]
    fn invalid_id_dotdot_rejected() {
        let (_tmp, cg) = driver();
        assert!(matches!(
            cg.create_workload("..", &limits(64, 512)).unwrap_err(),
            CgroupError::InvalidWorkloadId(_)
        ));
        assert!(matches!(
            cg.create_workload("", &limits(64, 512)).unwrap_err(),
            CgroupError::InvalidWorkloadId(_)
        ));
    }
}
