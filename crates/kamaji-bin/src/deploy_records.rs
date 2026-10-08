//! Deploy records: the admission input kamaji persists so a workload survives
//! kamaji itself (R755-B5 for serve bundles, R936-B11 for native-exec, R605-F16
//! for service-shaped microVM guests).
//!
//! Every native workload, every served bundle and every microVM's Firecracker
//! process lives in `kamaji.service`'s cgroup, so a kamaji restart (a reboot, a
//! control-plane roll) kills them all. Nothing else on the node remembers them:
//! yubaba keeps no spec for a direct `/workloads/deploy`. A record is the only
//! memory there is, and startup replays it through the same deploy path the
//! original request took.
//!
//! **Native and microVM records are opt-in per workload** —
//! [`workload_spec::RESUME_AFTER_RESTART_ANNOTATION`]. A workload whose
//! placement yubaba decides (the headscale appliance follows the raft ingress
//! owner) must never come back on a node just because it last ran there; after
//! a failover that is a second coordinator. The inner door is pinned to its
//! front door by construction, so it opts in; so does a dev-cluster member VM,
//! whose writable root lives on this node's disk and nowhere else.
//!
//! R605-F16 found the microVM half missing the hard way: rolling us-west-011's
//! kamaji SIGKILLed both member VMs and nothing brought them back.

use std::path::{Path, PathBuf};

use kamaji_proto::WorkloadId;
use tracing::warn;

/// Write `bytes` to `<dir>/<id>.json`, owner-only and atomically.
///
/// R876-B9: **0600 in a 0700 dir, and the mode is set on the TMP.** A record
/// carries the deploy's `env` verbatim, which is live credential material for
/// some workloads (measured on us-east-001: `CLOUDFLARE_API_TOKEN` and two
/// `MESOFACT_S3_*` keys inline, in cleartext). `std::fs::write` creates 0666 &
/// ~umask and `rename` preserves the source's mode, so tightening after the
/// rename would leave a window in which the *final* path is world-readable.
///
/// The dir is chmodded on every write rather than only at creation:
/// `DirBuilder::mode` applies solely to dirs it creates, so a node upgraded
/// from an older kamaji would otherwise keep a 0755 dir forever.
///
/// R925: the staging name is unique per WRITER, not per record — two Deploys
/// of the same id (a yubaba retry, two controllers) are handled on separate
/// tasks and would otherwise stage into one file. Not routed through
/// `kamaji::atomic_file::write_atomic`, which writes with default permissions;
/// only its staging NAME is borrowed.
pub fn write_owner_only(dir: &Path, id: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let final_path = dir.join(format!("{id}.json"));
    let tmp = kamaji::atomic_file::staging_path(&dir.join(format!(".{id}.json")));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        // `.mode()` only applies when THIS call creates the file — tighten the
        // open handle before any bytes land, so the 0600 claim is true of the
        // file and not just of the happy path.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(bytes)?;
    }
    // Remove the staging file if the rename fails: the name is unique per
    // writer, so nothing later reuses a leaked one.
    if let Err(e) = std::fs::rename(&tmp, &final_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Remove `<dir>/<id>.json`. Idempotent: a missing record is Ok.
pub fn remove_record(dir: &Path, id: &WorkloadId) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(format!("{}.json", id.0))) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Every `*.json` record in `dir`, parsed, in name order. A record that fails
/// to parse is logged and skipped — one corrupt file must not keep every
/// other workload on the node down. Staging files never match (`.<id>.json.tmp.*`).
pub fn read_records<T: serde::de::DeserializeOwned>(dir: &Path, what: &str) -> Vec<T> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "cannot read {what} records");
            return Vec::new();
        }
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter(|p| {
            !p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        let parsed = std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<T>(&b).map_err(|e| e.to_string()));
        match parsed {
            Ok(r) => out.push(r),
            Err(e) => warn!(path = %path.display(), error = %e, "skipping unreadable {what} record"),
        }
    }
    out
}

/// Which backend a [`ResumeRecords`] store replays through. The store knows
/// its backend, so a native record can never be replayed as a guest or the
/// reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeBackend {
    /// R936-B11: `yah.exec = native`.
    Native,
    /// R605-F16: `yah.exec = microvm`, service-shaped guests only.
    MicroVm,
}

impl ResumeBackend {
    fn noun(self) -> &'static str {
        match self {
            Self::Native => "native deploy",
            Self::MicroVm => "microVM deploy",
        }
    }
}

/// Everything a resumable `Deploy` handed kamaji, for a workload that asked to
/// be resumed ([`workload_spec::WorkloadSpec::wants_resume_after_restart`]).
/// The on-disk shape is the R936-B11 native record's, unchanged.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResumeRecord {
    pub id: String,
    pub workload: workload_spec::Workload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<kamaji_proto::MeshAssignment>,
}

impl ResumeRecord {
    /// The record for a `Deploy` that should outlive kamaji on `backend`, or
    /// `None` when the workload is not that backend's or did not opt in. The
    /// one place the opt-in is decided, so the write and the replay cannot
    /// disagree.
    ///
    /// A microVM is recorded only when it is SERVICE-shaped. A job guest's
    /// completion is its exit, and its record would outlive that exit until a
    /// Stop that never comes — so replaying one would run the job again on
    /// every restart.
    pub fn for_deploy(
        backend: ResumeBackend,
        id: &WorkloadId,
        workload: &workload_spec::Workload,
        mesh: Option<&kamaji_proto::MeshAssignment>,
    ) -> Option<Self> {
        let spec = workload.container_spec()?;
        let ours = match backend {
            ResumeBackend::Native => spec.wants_native_exec(),
            ResumeBackend::MicroVm => {
                spec.wants_microvm()
                    && !matches!(
                        spec.effective_archetype(),
                        workload_spec::LifecycleArchetype::Job
                    )
            }
        };
        (ours && spec.wants_resume_after_restart()).then(|| Self {
            id: id.0.clone(),
            workload: workload.clone(),
            mesh: mesh.cloned(),
        })
    }
}

/// The on-disk set of one backend's [`ResumeRecord`]s — a sibling of that
/// backend's per-ident dirs, dot-prefixed so it can never be an ident.
#[derive(Debug, Clone)]
pub struct ResumeRecords {
    backend: ResumeBackend,
    dir: PathBuf,
}

impl ResumeRecords {
    /// Records kept under `<backend_dir>/.deploys` — the native-exec dir, or
    /// the microVM dir (whose guests live in `<microvm_dir>/vms`).
    pub fn under(backend: ResumeBackend, backend_dir: &Path) -> Self {
        Self {
            backend,
            dir: backend_dir.join(".deploys"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// This store's record for a `Deploy`, per [`ResumeRecord::for_deploy`].
    pub fn for_deploy(
        &self,
        id: &WorkloadId,
        workload: &workload_spec::Workload,
        mesh: Option<&kamaji_proto::MeshAssignment>,
    ) -> Option<ResumeRecord> {
        ResumeRecord::for_deploy(self.backend, id, workload, mesh)
    }

    pub fn record(&self, record: &ResumeRecord) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
        write_owner_only(&self.dir, &record.id, &bytes)
    }

    pub fn forget(&self, id: &WorkloadId) -> std::io::Result<()> {
        remove_record(&self.dir, id)
    }

    pub fn recorded(&self) -> Vec<ResumeRecord> {
        read_records(&self.dir, self.backend.noun())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use workload_spec::{
        LifecycleArchetype, MICROVM_EXEC_VALUE, NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE,
        RESUME_AFTER_RESTART_ANNOTATION, RESUME_AFTER_RESTART_VALUE,
    };

    fn workload(annotations: &[(&str, &str)]) -> workload_spec::Workload {
        workload_shaped(annotations, None)
    }

    fn workload_shaped(
        annotations: &[(&str, &str)],
        archetype: Option<LifecycleArchetype>,
    ) -> workload_spec::Workload {
        use workload_spec::{
            ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits, RestartPolicy,
            StopPolicy, TierTag, WorkloadSpec,
        };
        let name = "passway-inner-noisetable-marketing";
        workload_spec::Workload::container(WorkloadSpec {
            name: name.into(),
            image: ImageRef {
                registry: "local".into(),
                repository: "passway".into(),
                tag: "inner-door".into(),
                digest: String::new(),
            },
            tier: TierTag("infra".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["/usr/local/bin/passway".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 128,
                cpu_millis: 256,
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.into()),
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            db: Vec::new(),
            capabilities: Vec::new(),
            annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            files: Vec::new(),
        })
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kamaji-deploy-records-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Only a native workload that opted in is recorded. Headscale is native
    /// but yubaba-placed: recording it would resurrect a coordinator on a node
    /// raft has moved it off.
    #[test]
    fn only_native_workloads_that_opted_in_are_recorded() {
        let id = WorkloadId::new("w");
        let native = (NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE);
        let resume = (RESUME_AFTER_RESTART_ANNOTATION, RESUME_AFTER_RESTART_VALUE);
        let native_rec = |w: &workload_spec::Workload| {
            ResumeRecord::for_deploy(ResumeBackend::Native, &id, w, None)
        };
        assert!(native_rec(&workload(&[native, resume])).is_some());
        assert!(native_rec(&workload(&[native])).is_none());
        assert!(native_rec(&workload(&[resume])).is_none());
        assert!(native_rec(&workload(&[native, (RESUME_AFTER_RESTART_ANNOTATION, "yes")])).is_none());
    }

    /// R605-F16: a microVM is recorded only when it opted in AND is
    /// service-shaped, and each store only ever records its own backend's
    /// workloads.
    #[test]
    fn only_service_shaped_microvms_that_opted_in_are_recorded() {
        let id = WorkloadId::new("vm-us-west-111");
        let vm = (NATIVE_EXEC_ANNOTATION, MICROVM_EXEC_VALUE);
        let resume = (RESUME_AFTER_RESTART_ANNOTATION, RESUME_AFTER_RESTART_VALUE);
        let vm_rec = |w: &workload_spec::Workload| {
            ResumeRecord::for_deploy(ResumeBackend::MicroVm, &id, w, None)
        };
        let server = Some(LifecycleArchetype::Server);
        assert!(vm_rec(&workload_shaped(&[vm, resume], server)).is_some());
        assert!(vm_rec(&workload_shaped(&[vm, resume], Some(LifecycleArchetype::Appliance))).is_some());
        // A job guest's completion is its exit; replaying it would re-run it.
        assert!(vm_rec(&workload_shaped(&[vm, resume], Some(LifecycleArchetype::Job))).is_none());
        assert!(vm_rec(&workload_shaped(&[vm], server)).is_none());
        // Each store records only its own backend's workloads.
        assert!(vm_rec(&workload_shaped(
            &[(NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE), resume],
            server
        ))
        .is_none());
        assert!(ResumeRecord::for_deploy(
            ResumeBackend::Native,
            &id,
            &workload_shaped(&[vm, resume], server),
            None
        )
        .is_none());
    }

    /// Round-trip, owner-only modes, idempotent forget, and a corrupt or
    /// staging file never blocks the rest.
    #[test]
    fn records_round_trip_owner_only_and_skip_junk() {
        let root = scratch("rt");
        let records = ResumeRecords::under(ResumeBackend::Native, &root);
        let w = workload(&[
            (NATIVE_EXEC_ANNOTATION, NATIVE_EXEC_VALUE),
            (RESUME_AFTER_RESTART_ANNOTATION, RESUME_AFTER_RESTART_VALUE),
        ]);
        let rec = records.for_deploy(&WorkloadId::new("door-a"), &w, None).unwrap();
        records.record(&rec).unwrap();
        std::fs::write(records.dir().join("broken.json"), b"{not json").unwrap();
        std::fs::write(records.dir().join(".door-b.json.tmp.1.2"), b"{}").unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(records.dir()), 0o700);
        assert_eq!(mode(&records.dir().join("door-a.json")), 0o600);

        let back = records.recorded();
        assert_eq!(back.len(), 1, "{back:?}");
        assert_eq!(back[0].id, "door-a");
        assert!(back[0].workload.container_spec().unwrap().wants_resume_after_restart());

        records.forget(&WorkloadId::new("door-a")).unwrap();
        records.forget(&WorkloadId::new("door-a")).unwrap();
        assert!(records.recorded().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
