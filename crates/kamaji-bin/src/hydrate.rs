//! R850-F1 — hydrate-on-place: fill a stateful workload's named volume from its
//! declared object store *before* the container starts.
//!
//! # The whole restore lives in another process
//!
//! Everything here is spec-reading and process-spawning. The restore itself —
//! object listing, page reassembly, WAL-frame replay, and the ownership fence
//! that makes any of it safe — is `turso-backup`, invoked as
//! `turso-backup-hydrate` (see that binary's module doc for why it is a
//! process).
//!
//! The short version: kamaji is the node's control plane, and linking a
//! database engine into the supervisor that runs every workload on every box
//! couples their failure domains and their build times for no gain. yubaba
//! already ships WAL sidecars rather than shipping WAL in-process
//! (`litestream.rs`, `tenant-streamer`); this is that shape for the restore
//! side.
//!
//! # An undeclared workload is untouched; a declared one is not started blind
//!
//! [`plan`] returns [`HydratePlan::NotDeclared`] for every spec without a
//! bytes-shipping `yah.durability.tier`, which is every spec in the tree today,
//! and [`run`] then does nothing at all.
//!
//! When a tier *is* declared and no helper is configured, the deploy is
//! **refused** rather than started. That is the same discipline
//! `--tenant-passway-dir` holds, and here it matters more: starting an
//! appliance whose declared restore never ran gives you a running workload with
//! an empty database and no error — which is indistinguishable from a healthy
//! first boot until somebody logs in and finds their account gone.

use std::path::PathBuf;
use std::process::Stdio;

use workload_spec::{DurabilityTier, VolumeSource, WorkloadSpec};

/// Host directory kamaji binds a [`VolumeSource::Named`] from.
///
/// The same literal `kamaji-containerd-core`'s `oci_spec` builder writes into
/// the `"source"` of a [`VolumeSource::Named`] mount, and the same one
/// `yah_cloud::migrate::KAMAJI_VOLUME_ROOT` renders into the operator's
/// migration procedure.
///
/// Three copies is two too many. Hoisting needs a crate all three depend on —
/// `workload-spec` is the only candidate, and putting a kamaji host path in the
/// leaf crate every fleet node links is a wider decision than this ticket.
/// Each copy is pinned by a literal assertion in its own crate
/// (`the_volume_root_is_the_path_the_oci_mount_uses` here,
/// `a_named_volume_renders_the_kamaji_host_path` in `migrate.rs`), so a change
/// on any one of them fails a test rather than silently restoring into a
/// directory nothing mounts.
pub const VOLUME_ROOT: &str = "/var/lib/yah/kamaji/volumes";

/// What a spec's durability declaration asks kamaji to do before starting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydratePlan {
    /// No bytes-shipping tier. Nothing happens — including for
    /// `tier = "none"`, which is a deliberate statement that there is no second
    /// copy, not a request to restore from one.
    NotDeclared,
    /// Run the helper with these parameters.
    Declared(HydrateArgs),
}

/// The environment `turso-backup-hydrate` is invoked with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrateArgs {
    /// Host path of the workload's single named volume.
    pub volume_root: PathBuf,
    /// `yah.durability.subjects`, volume-relative.
    pub subjects: Vec<String>,
    /// `yah.durability.tier`, guaranteed to ship bytes.
    pub tier: DurabilityTier,
    /// Bucket parsed out of `yah.durability.store`.
    pub bucket: String,
    /// Key prefix parsed out of `yah.durability.store`.
    pub prefix: String,
}

/// Read a spec's declaration into a plan. Pure — no filesystem, no process.
///
/// `Err` is a **refusal to deploy**, not a warning. Every case it returns is a
/// declaration that says "this workload has durable state" and then fails to
/// say something the restore needs; guessing the missing half would restore
/// somebody's database to the wrong place or not at all.
pub fn plan(spec: &WorkloadSpec) -> Result<HydratePlan, String> {
    let declared = spec
        .durability()
        .map_err(|e| format!("workload {}: {e}", spec.name))?;
    let Some(d) = declared.filter(|d| d.tier.ships_bytes()) else {
        return Ok(HydratePlan::NotDeclared);
    };

    // `validate::shape` already enforces exactly one named-or-bind volume for a
    // bytes-shipping tier, but a spec reaching kamaji has crossed a wire and
    // this decides where bytes get written, so it is re-derived rather than
    // assumed.
    //
    // R858-F17: a **bind** resolves to its own `host_path`, and it is not an
    // afterthought — headscale is the first real consumer of this whole path
    // and it is a native-exec appliance whose state lives at
    // `/var/lib/yah-cloud/headscale/`, with no named volume and no prospect of
    // one. A named-only rule would have excluded exactly the workload whose
    // loss took this camp's mesh down for 37 hours. Tmpfs is excluded on
    // purpose: it is the declaration that the data does not survive.
    let mut roots = spec.volumes.iter().filter_map(|v| match &v.source {
        VolumeSource::Named { name } => Some(PathBuf::from(VOLUME_ROOT).join(name)),
        VolumeSource::Bind { host_path } => Some(host_path.clone()),
        VolumeSource::Tmpfs { .. } => None,
    });
    let (Some(volume_root), None) = (roots.next(), roots.next()) else {
        return Err(format!(
            "workload {} declares yah.durability.tier = \"{}\" but not exactly one \
             named-or-bind volume; its subjects are relative to one and there is no way to pick",
            spec.name, d.tier
        ));
    };

    let store = d
        .store
        .as_deref()
        .ok_or_else(|| format!("workload {}: tier \"{}\" with no store", spec.name, d.tier))?;
    let (bucket, prefix) = split_store_url(store)
        .ok_or_else(|| format!("workload {}: yah.durability.store {store:?} is not s3://<bucket>/<prefix>", spec.name))?;

    Ok(HydratePlan::Declared(HydrateArgs {
        volume_root,
        subjects: d.subjects.clone(),
        tier: d.tier,
        bucket,
        prefix,
    }))
}

/// Split `s3://bucket/some/prefix` into `("bucket", "some/prefix")`.
///
/// A bucket with no prefix is refused: the prefix is what scopes one workload's
/// state inside a shared bucket, and defaulting it to the bucket root would put
/// two workloads' claims on the same key — so the *second* one to place would
/// fence out the first, on a bucket that looked fine.
fn split_store_url(store: &str) -> Option<(String, String)> {
    let rest = store.strip_prefix("s3://")?;
    let (bucket, prefix) = rest.split_once('/')?;
    let prefix = prefix.trim_end_matches('/');
    if bucket.is_empty() || prefix.is_empty() {
        return None;
    }
    Some((bucket.to_string(), prefix.to_string()))
}

/// Outcome of a hydrate attempt, from kamaji's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrateResult {
    /// Nothing was declared, or the helper says it is safe to start. The JSON
    /// line the helper printed, when there was one — worth logging, since it
    /// carries the measured restore time and the fencing epoch.
    Proceed(Option<String>),
}

/// Run the helper for `spec`, if it declares a tier.
///
/// `Err` means **do not start the workload**, and the string is the message to
/// hand back as a `BackendRefused`. Every failure direction lands there: a
/// refusal from the helper (torn volume, lost fence, unfenced sink), a helper
/// that could not reach a verdict, a helper that is not configured, and a
/// helper that could not be spawned. An unreachable object store is
/// indistinguishable from the partition the fence exists for, which is exactly
/// when starting anyway is worst.
pub async fn run(
    helper: Option<&std::path::Path>,
    spec: &WorkloadSpec,
) -> Result<HydrateResult, String> {
    let args = match plan(spec)? {
        HydratePlan::NotDeclared => return Ok(HydrateResult::Proceed(None)),
        HydratePlan::Declared(args) => args,
    };
    let Some(helper) = helper else {
        return Err(no_helper(spec, &args));
    };

    let output = tokio::process::Command::new(helper)
        .env("VOLUME_ROOT", &args.volume_root)
        .env("SUBJECTS", args.subjects.join(","))
        .env("TIER", args.tier.as_str())
        .env("OWNER", owner_label())
        .env("S3_BUCKET", &args.bucket)
        .env("BACKUP_PREFIX", &args.prefix)
        // Credentials and endpoint are inherited from kamaji's own
        // environment (S3_ACCESS_KEY / S3_SECRET_KEY / S3_ENDPOINT /
        // S3_REGION) rather than set here. kamaji never reads them, so they do
        // not pass through a supervisor that has no business holding them.
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "workload {}: could not run hydrate helper {}: {e}",
                spec.name,
                helper.display()
            )
        })?;

    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() {
        return Ok(HydrateResult::Proceed(Some(line)));
    }
    Err(format!(
        "workload {} was not hydrated and must not start: {line}",
        spec.name
    ))
}

/// Whether this node could hydrate `spec` if asked, without touching anything.
///
/// R850-F1 backup half: split out of [`run`] so the deploy path can check both
/// halves' preconditions together, before either does any work. `run` keeps its
/// own copy of the check because it is public and a caller that skipped this
/// must still be refused.
pub fn preflight(helper: Option<&std::path::Path>, spec: &WorkloadSpec) -> Result<(), String> {
    match plan(spec)? {
        HydratePlan::NotDeclared => Ok(()),
        HydratePlan::Declared(args) if helper.is_none() => Err(no_helper(spec, &args)),
        HydratePlan::Declared(_) => Ok(()),
    }
}

fn no_helper(spec: &WorkloadSpec, args: &HydrateArgs) -> String {
    format!(
        "workload {} declares yah.durability.tier = \"{}\" but this kamaji has no hydrate \
         helper configured — start it with --hydrate-helper PATH (or set \
         KAMAJI_HYDRATE_HELPER). Starting without one would bring the workload up against an \
         empty volume, which looks exactly like a healthy first boot",
        spec.name, args.tier
    )
}

/// Label recorded in the ownership claim.
///
/// Diagnostic only — the epoch is what fences, and two acquires under the same
/// label are still two takeovers (see `turso_backup::claim::ClaimRecord`). So a
/// missing node id degrades the 3am experience rather than the safety property,
/// and is not worth refusing a deploy over.
pub(crate) fn owner_label() -> String {
    for key in ["KAMAJI_NODE_ID", "HOSTNAME"] {
        if let Ok(v) = std::env::var(key) {
            let token = v.split_whitespace().next().unwrap_or("");
            if !token.is_empty() {
                return token.to_string();
            }
        }
    }
    format!("kamaji-pid-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `for_forge` is used purely as a constructor with every required field
    /// already filled — this module reads only `name`, `volumes` and
    /// `annotations`, and the two annotations it seeds (`yah.forge`,
    /// the memory request) are invisible to `durability()`.
    fn spec_with(
        annotations: &[(&str, &str)],
        volumes: Vec<workload_spec::VolumeMount>,
    ) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "acct",
            workload_spec::ImageRef {
                registry: "r".into(),
                repository: "acct".into(),
                tag: "v1".into(),
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.volumes = volumes;
        for (k, v) in annotations {
            spec.annotations.insert((*k).into(), (*v).into());
        }
        spec
    }

    fn named(name: &str) -> workload_spec::VolumeMount {
        workload_spec::VolumeMount {
            source: VolumeSource::Named { name: name.into() },
            target: "/var/lib/app".into(),
            read_only: false,
        }
    }

    const DECLARED: &[(&str, &str)] = &[
        ("yah.durability.tier", "stream"),
        ("yah.durability.engine", "turso"),
        ("yah.durability.store", "s3://yah-backups/noisetable-account"),
        ("yah.durability.subjects", "accounts.db,sessions.db"),
    ];

    /// The hydrate writes into the directory the container will mount. If this
    /// string and `kamaji-containerd-core`'s ever disagree, the restore lands
    /// somewhere the workload never sees and it comes up empty — the exact
    /// silent failure the whole path exists to prevent, so the literal is
    /// pinned rather than trusted.
    #[test]
    fn the_volume_root_is_the_path_the_oci_mount_uses() {
        assert_eq!(VOLUME_ROOT, "/var/lib/yah/kamaji/volumes");
    }

    /// Every spec in the tree today. The path must be inert for them — a
    /// supervisor that started refusing deploys because a new annotation exists
    /// would take the fleet down.
    #[test]
    fn a_spec_with_no_declaration_plans_nothing() {
        assert_eq!(
            plan(&spec_with(&[], vec![named("accounts")])).unwrap(),
            HydratePlan::NotDeclared
        );
    }

    /// `tier = "none"` is a statement that there is no second copy, not a
    /// request to look for one.
    #[test]
    fn tier_none_plans_nothing() {
        assert_eq!(
            plan(&spec_with(
                &[("yah.durability.tier", "none")],
                vec![named("accounts")]
            ))
            .unwrap(),
            HydratePlan::NotDeclared
        );
    }

    #[test]
    fn a_declaration_resolves_to_the_volume_host_path_and_the_store_split() {
        let HydratePlan::Declared(args) = plan(&spec_with(DECLARED, vec![named("accounts")])).unwrap()
        else {
            panic!("expected a plan");
        };
        assert_eq!(
            args.volume_root,
            PathBuf::from("/var/lib/yah/kamaji/volumes/accounts")
        );
        assert_eq!(args.subjects, vec!["accounts.db", "sessions.db"]);
        assert_eq!(args.tier, DurabilityTier::Stream);
        assert_eq!(args.bucket, "yah-backups");
        assert_eq!(args.prefix, "noisetable-account");
    }

    /// The prefix is what scopes one workload inside a shared bucket. Defaulting
    /// it to the root would put two workloads' ownership claims on one key, so
    /// placing the second would fence out the first.
    /// R858-F17: headscale's shape. A native-exec appliance keeps its state at
    /// a bind path and has no named volume, so a named-only rule excluded
    /// exactly the workload whose loss took this camp's mesh down for 37 hours.
    /// A bind resolves to its own host_path, NOT under `VOLUME_ROOT`.
    #[test]
    fn a_bind_volume_resolves_to_its_own_host_path() {
        let spec = spec_with(
            DECLARED,
            vec![workload_spec::VolumeMount {
                source: VolumeSource::Bind {
                    host_path: "/var/lib/yah-cloud/headscale".into(),
                },
                target: "/var/lib/headscale".into(),
                read_only: false,
            }],
        );
        let HydratePlan::Declared(args) = plan(&spec).unwrap() else {
            panic!("a bind-backed declaration must plan");
        };
        assert_eq!(
            args.volume_root,
            PathBuf::from("/var/lib/yah-cloud/headscale"),
            "a bind must not be rehomed under the named-volume root"
        );
    }

    /// A tmpfs is the declaration that the data does not survive the process,
    /// so it must not become the root a durable restore writes into.
    #[test]
    fn a_tmpfs_is_not_a_candidate_volume_root() {
        let spec = spec_with(
            DECLARED,
            vec![workload_spec::VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: "/scratch".into(),
                read_only: false,
            }],
        );
        assert!(plan(&spec).is_err(), "a tmpfs-only spec has nowhere durable to restore into");
    }

    /// One named AND one bind is still ambiguous — the widening added a second
    /// kind of candidate, not permission to guess between two.
    #[test]
    fn a_named_and_a_bind_together_are_still_refused() {
        let spec = spec_with(
            DECLARED,
            vec![
                named("acct-data"),
                workload_spec::VolumeMount {
                    source: VolumeSource::Bind { host_path: "/srv/acct".into() },
                    target: "/srv".into(),
                    read_only: false,
                },
            ],
        );
        let err = plan(&spec).expect_err("two candidate roots must refuse");
        assert!(err.contains("named-or-bind"), "got: {err}");
    }

    #[test]
    fn a_store_url_without_a_prefix_is_refused() {
        for bad in ["s3://yah-backups", "s3://yah-backups/", "yah-backups/acct", "s3:///acct"] {
            let mut ann = DECLARED.to_vec();
            ann.retain(|(k, _)| *k != "yah.durability.store");
            ann.push(("yah.durability.store", bad));
            let err = plan(&spec_with(&ann, vec![named("accounts")])).unwrap_err();
            assert!(err.contains("s3://<bucket>/<prefix>"), "{bad}: {err}");
        }
    }

    #[test]
    fn subjects_relative_to_no_volume_or_two_volumes_are_refused() {
        let err = plan(&spec_with(DECLARED, vec![])).unwrap_err();
        assert!(err.contains("exactly one \n             named-or-bind volume") || err.contains("named-or-bind"), "{err}");

        let err = plan(&spec_with(
            DECLARED,
            vec![named("accounts"), named("sessions")],
        ))
        .unwrap_err();
        assert!(err.contains("named-or-bind"), "{err}");
    }

    /// A malformed declaration is a refusal, not a shrug — `tier = "streem"`
    /// must not reach a backend as "no durability configured".
    #[test]
    fn a_malformed_declaration_refuses_the_deploy() {
        let err = plan(&spec_with(
            &[("yah.durability.tier", "streem")],
            vec![named("accounts")],
        ))
        .unwrap_err();
        assert!(err.contains("streem"), "{err}");
    }

    /// Declared, no helper: refuse. Starting would give a running workload with
    /// an empty database and no error anywhere.
    #[tokio::test]
    async fn a_declared_workload_with_no_helper_is_refused_not_started() {
        let err = run(None, &spec_with(DECLARED, vec![named("accounts")]))
            .await
            .unwrap_err();
        assert!(err.contains("--hydrate-helper"), "{err}");
    }

    /// ...and an undeclared one is untouched even with no helper, which is the
    /// property that keeps this inert for the existing fleet.
    #[tokio::test]
    async fn an_undeclared_workload_proceeds_with_no_helper() {
        assert_eq!(
            run(None, &spec_with(&[], vec![named("accounts")]))
                .await
                .unwrap(),
            HydrateResult::Proceed(None)
        );
    }

    /// A helper that exits non-zero stops the deploy and its message is carried
    /// through verbatim — the refusal an operator reads is the helper's, not a
    /// paraphrase.
    #[tokio::test]
    async fn a_refusing_helper_stops_the_deploy_and_carries_its_message() {
        let helper = fake_helper(
            "refuse",
            "#!/bin/sh\necho '{\"outcome\":\"refused\",\"reason\":\"torn_volume\"}'\nexit 2\n",
        );
        let err = run(Some(&helper), &spec_with(DECLARED, vec![named("accounts")]))
            .await
            .unwrap_err();
        assert!(err.contains("torn_volume"), "{err}");
        assert!(err.contains("must not start"), "{err}");
    }

    #[tokio::test]
    async fn a_succeeding_helper_lets_the_deploy_through_and_its_line_is_kept() {
        let helper = fake_helper(
            "ok",
            "#!/bin/sh\necho \"{\\\"outcome\\\":\\\"hydrated\\\",\\\"subjects\\\":$SUBJECTS}\"\n",
        );
        let out = run(Some(&helper), &spec_with(DECLARED, vec![named("accounts")]))
            .await
            .unwrap();
        let HydrateResult::Proceed(Some(line)) = out else {
            panic!("expected a line, got {out:?}");
        };
        // The subject list reaches the helper as the comma-joined declaration.
        assert!(line.contains("accounts.db,sessions.db"), "{line}");
    }

    /// A helper path that does not exist is a refusal, not a silent proceed.
    #[tokio::test]
    async fn an_unspawnable_helper_is_a_refusal() {
        let err = run(
            Some(std::path::Path::new("/nonexistent/turso-backup-hydrate")),
            &spec_with(DECLARED, vec![named("accounts")]),
        )
        .await
        .unwrap_err();
        assert!(err.contains("could not run hydrate helper"), "{err}");
    }

    fn fake_helper(tag: &str, script: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kamaji-hydrate-fake-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }
}
