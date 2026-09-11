//! R850-F1 — the backup half of hydrate-on-place: supervise one
//! `turso-backup-tail` per placed workload that declares a durability tier, and
//! **stop the workload when that tail says another node owns its state**.
//!
//! # Why this exists next to [`crate::hydrate`]
//!
//! `hydrate` restores an empty volume from the store before a workload starts.
//! Without something writing to that store, it is a restore path with nothing to
//! restore from: every hydrate against a real camp returns
//! `nothing_in_the_store`, forever. This spawns the writer.
//!
//! Both halves are separate processes for the reason `turso-backup-hydrate`'s
//! module doc gives, and it binds harder here: a tail keeps `turso` +
//! `turso_core` **resident** for the workload's whole life, so linking it in
//! would give kamaji — the process supervisor for every workload on the box — a
//! database engine's memory profile and failure domain.
//!
//! # The exit code is the fence, and it is not advisory
//!
//! `turso-backup-tail` exits `2` when it loses the ownership claim on the
//! workload's prefix. That is the supervisor half of at-most-one-live, and it is
//! the obligation R850-F1 created and could not discharge until a backup loop
//! existed to produce the signal: the claim stops a losing node from *writing to
//! the store*, and nothing stopped that node's workload from serving stale reads
//! and accepting writes it would never ship.
//!
//! So a `2` here calls [`crate::server::stop_workload`]. Anything else — a
//! crash, a bad config, an unreachable store — is logged and left alone: those
//! do not say another node owns the state, and stopping a healthy workload
//! because its backup is sick is a worse trade than an un-backed-up workload
//! that is loudly un-backed-up.
//!
//! # A node with no tail helper is not silently un-backed-up
//!
//! [`spawn`] mirrors [`crate::hydrate::run`]'s refusal exactly: a spec that
//! declares a bytes-shipping tier on a kamaji started without `--tail-helper` is
//! **refused**, not started. The failure it prevents is the same one, one step
//! later — a workload running happily with nothing shipping its state, which
//! looks identical to a healthy workload until the node dies.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kamaji_proto::WorkloadId;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};
use workload_spec::WorkloadSpec;

use crate::hydrate::{plan, HydrateArgs, HydratePlan};
use crate::server::ServerCtx;

/// Exit code meaning "another node owns this workload's state". Must match
/// `turso-backup-tail`'s `EXIT_FENCED`; pinned by
/// [`tests::a_fenced_tail_stops_the_workload`], which drives a fake helper that
/// exits with this literal.
const EXIT_FENCED: i32 = 2;

/// The tails this node is running, one per workload.
#[derive(Default)]
pub struct TailSupervisor {
    running: Mutex<HashMap<WorkloadId, RunningTail>>,
}

struct RunningTail {
    /// Diagnostic only — the kill goes through [`RunningTail::shutdown`], not
    /// through this. Logged because "which pid was that" is the first question
    /// anybody asks of a supervisor.
    pid: u32,
    /// Set by [`TailSupervisor::stop`] before it signals, so the watcher can
    /// tell a teardown we asked for from a tail that died on its own. Without
    /// it, a stop racing an exit could be read as a crash and logged as one.
    stopping: Arc<AtomicBool>,
    /// Woken by [`TailSupervisor::stop`]. The watcher owns the `Child` — it has
    /// to, to `wait()` on it — so the kill cannot be issued from here and is
    /// asked for instead.
    ///
    /// This is why there is no `libc::kill` in this file: `libc` is a
    /// Linux-only dependency of this crate (see its `Cargo.toml`), and a
    /// supervisor path that only compiles on the fleet is one that never runs
    /// under `cargo test` on a developer's machine.
    shutdown: Arc<Notify>,
}

impl TailSupervisor {
    /// Whether a tail is currently supervised for `id`.
    pub async fn is_running(&self, id: &WorkloadId) -> bool {
        self.running.lock().await.contains_key(id)
    }

    /// Stop the tail for `id`, if there is one. Idempotent, like every other
    /// teardown arm in [`crate::server::stop_workload`].
    ///
    /// Returns as soon as the watcher has been asked to kill, without waiting
    /// for the child to die, and there is no grace-then-escalate ladder:
    /// every round of a tail is already crash-atomic — one killed mid-upload
    /// leaves frames under keys no manifest references, invisible to restore,
    /// and the next round re-derives everything from the sidecar. A graceful
    /// window would buy nothing and could park a `Stop` behind a stalled
    /// object-store request.
    pub async fn stop(&self, id: &WorkloadId) {
        let Some(tail) = self.running.lock().await.remove(id) else {
            return;
        };
        tail.stopping.store(true, Ordering::SeqCst);
        tail.shutdown.notify_waiters();
        info!(id = %id.0, pid = tail.pid, "stopped the durability tail");
    }
}

/// Whether this node could tail `spec` if asked, without touching anything.
///
/// Split out of [`spawn`] so the refusal lands *before* the deploy: a node with
/// no tail helper should turn a declared workload away without having restored
/// its volume and started a container first. `spawn` re-derives the same plan
/// afterwards rather than carrying it across, because the two calls are on
/// opposite sides of a deploy that may have taken seconds.
pub fn preflight(ctx: &ServerCtx, spec: &WorkloadSpec) -> Result<(), String> {
    match plan(spec)? {
        HydratePlan::NotDeclared => Ok(()),
        HydratePlan::Declared(args) if ctx.tail_helper.is_none() => Err(no_helper(spec, &args)),
        HydratePlan::Declared(_) => Ok(()),
    }
}

fn no_helper(spec: &WorkloadSpec, args: &HydrateArgs) -> String {
    format!(
        "workload {} declares yah.durability.tier = \"{}\" but this kamaji has no tail helper \
         configured — start it with --tail-helper PATH (or set KAMAJI_TAIL_HELPER). Running \
         without one gives you a workload whose state nothing is shipping, which looks exactly \
         like a healthy workload until the node dies",
        spec.name, args.tier
    )
}

/// Start a tail for `spec`, if it declares a bytes-shipping tier.
///
/// `Err` is a **refusal to deploy**, handled by the caller exactly like
/// [`crate::hydrate::run`]'s: a declared tier with no helper, or a helper that
/// will not spawn. `Ok(false)` means the spec declared nothing and nothing was
/// started, which is every spec in the tree today.
///
/// Called *after* the backend has the workload running, not before: a tail
/// against a volume whose application has not started yet would take the
/// ownership claim for a workload that then fails to deploy, fencing whichever
/// node succeeds.
pub async fn spawn(ctx: &Arc<ServerCtx>, id: &WorkloadId, spec: &WorkloadSpec) -> Result<bool, String> {
    let args = match plan(spec)? {
        HydratePlan::NotDeclared => return Ok(false),
        HydratePlan::Declared(args) => args,
    };
    let Some(helper) = ctx.tail_helper.clone() else {
        return Err(no_helper(spec, &args));
    };

    // A redeploy of a live workload must not leave two tails on one prefix: the
    // second would take the claim and fence the first, and the first's exit
    // would then stop the workload the second is happily backing up.
    ctx.tail.stop(id).await;

    let mut child = command(&helper, &args)
        .spawn()
        .map_err(|e| format!("workload {}: could not run tail helper {}: {e}", spec.name, helper.display()))?;
    let pid = child.id().ok_or_else(|| {
        format!("workload {}: tail helper exited before it could be supervised", spec.name)
    })?;
    let stdout = child.stdout.take();
    let stopping = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(Notify::new());

    ctx.tail.running.lock().await.insert(
        id.clone(),
        RunningTail { pid, stopping: stopping.clone(), shutdown: shutdown.clone() },
    );
    info!(id = %id.0, pid, tier = args.tier.as_str(), "durability tail started");

    let watcher_ctx = Arc::clone(ctx);
    let watcher_id = id.clone();
    let workload = spec.name.clone();
    // The log drain is its own task rather than a step before the wait, so a
    // chatty tail cannot delay a `stop` and a silent one cannot hold the
    // watcher open. Each line carries the round's frame counts and RPO, which
    // is the only place an operator sees that a workload's state is moving.
    if let Some(stdout) = stdout {
        let log_id = id.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(id = %log_id.0, outcome = %line, "durability tail");
            }
        });
    }

    tokio::spawn(async move {
        let status = tokio::select! {
            status = child.wait() => status,
            _ = shutdown.notified() => {
                let _ = child.start_kill();
                child.wait().await
            }
        };
        watcher_ctx.tail.running.lock().await.remove(&watcher_id);
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let code = status.as_ref().ok().and_then(|s| s.code());
        if code == Some(EXIT_FENCED) {
            error!(
                id = %watcher_id.0, workload,
                "durability tail was FENCED — another node owns this workload's state, so every \
                 write this instance accepts is unrecoverable; stopping it"
            );
            // Removed from the map above, so this cannot recurse: `stop_workload`
            // calls `tail.stop`, which now finds nothing.
            let reply = crate::server::stop_workload(
                &watcher_ctx,
                kamaji_proto::RequestId(0),
                watcher_id.clone(),
            )
            .await;
            info!(id = %watcher_id.0, reply = ?reply, "stopped a fenced workload");
        } else {
            warn!(
                id = %watcher_id.0, workload, ?code,
                "durability tail exited without a fence verdict; the workload keeps running but \
                 its state is no longer being shipped"
            );
        }
    });
    Ok(true)
}

/// The helper's invocation. Split out so a test can assert the environment
/// without spawning: a tail pointed at the wrong prefix writes a backup where no
/// restore will look, and that is invisible until the restore.
fn command(helper: &std::path::Path, args: &HydrateArgs) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(helper);
    cmd.env("VOLUME_ROOT", &args.volume_root)
        .env("SUBJECTS", args.subjects.join(","))
        .env("TIER", args.tier.as_str())
        .env("OWNER", crate::hydrate::owner_label())
        .env("S3_BUCKET", &args.bucket)
        .env("BACKUP_PREFIX", &args.prefix)
        // Credentials, endpoint, region and the tail's own cadence are all
        // inherited from kamaji's environment rather than set here — the same
        // convention `hydrate::run` uses, and the reason is the same: kamaji
        // never reads them, so they do not pass through a supervisor with no
        // business holding them.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn fake_helper(tag: &str, script: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kamaji-tail-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("turso-backup-tail");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// `for_forge` is used purely as a constructor with every required field
    /// already filled — this module reads only `name`, `volumes` and
    /// `annotations`, exactly as `hydrate`'s own tests do.
    fn plain_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec::for_forge(
            name,
            workload_spec::ImageRef {
                registry: "r".into(),
                repository: name.into(),
                tag: "v1".into(),
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        )
    }

    fn spec_with_durability() -> WorkloadSpec {
        let mut spec = plain_spec("acct");
        spec.volumes = vec![workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Named { name: "acct-data".into() },
            target: "/data".into(),
            read_only: false,
        }];
        spec.annotations.insert("yah.durability.tier".into(), "stream".into());
        spec.annotations.insert("yah.durability.engine".into(), "turso".into());
        spec.annotations
            .insert("yah.durability.store".into(), "s3://backups/acct".into());
        spec.annotations
            .insert("yah.durability.subjects".into(), "accounts.db,sessions.db".into());
        spec
    }

    /// The environment is the contract with `turso-backup-tail`, and a wrong
    /// prefix is a backup nothing will ever restore from.
    #[test]
    fn the_helper_environment_matches_the_declaration() {
        let spec = spec_with_durability();
        let HydratePlan::Declared(args) = plan(&spec).unwrap() else {
            panic!("a declared spec must plan");
        };
        let cmd = command(std::path::Path::new("/bin/true"), &args);
        let env: HashMap<String, String> = cmd
            .as_std()
            .get_envs()
            .filter_map(|(k, v)| {
                Some((k.to_str()?.to_string(), v?.to_str()?.to_string()))
            })
            .collect();
        assert_eq!(env.get("S3_BUCKET").map(String::as_str), Some("backups"));
        assert_eq!(env.get("BACKUP_PREFIX").map(String::as_str), Some("acct"));
        assert_eq!(env.get("TIER").map(String::as_str), Some("stream"));
        assert_eq!(
            env.get("SUBJECTS").map(String::as_str),
            Some("accounts.db,sessions.db")
        );
        assert_eq!(
            env.get("VOLUME_ROOT").map(String::as_str),
            Some("/var/lib/yah/kamaji/volumes/acct-data")
        );
    }

    /// The twin of `a_declared_workload_with_no_helper_is_refused_not_started`
    /// on the hydrate side. A tier declared on a node that cannot ship it is a
    /// refusal, not a shrug.
    #[tokio::test]
    async fn a_declared_workload_with_no_tail_helper_is_refused() {
        let ctx = Arc::new(ServerCtx::new());
        let err = spawn(&ctx, &WorkloadId("acct".into()), &spec_with_durability())
            .await
            .expect_err("a declared tier with no helper must refuse");
        assert!(err.contains("--tail-helper"), "got: {err}");
    }

    /// Every spec in the tree declares nothing, and must stay untouched.
    #[tokio::test]
    async fn an_undeclared_workload_starts_no_tail_and_needs_no_helper() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = plain_spec("plain");
        assert!(!spawn(&ctx, &WorkloadId("plain".into()), &spec).await.unwrap());
        assert!(!ctx.tail.is_running(&WorkloadId("plain".into())).await);
    }

    /// A tail that keeps running is supervised, and `stop` reaps it.
    #[tokio::test]
    async fn a_live_tail_is_tracked_and_stoppable() {
        let helper = fake_helper("live", "#!/bin/sh\nexec sleep 30\n");
        let ctx = Arc::new(ServerCtx::new().with_tail_helper(helper));
        let id = WorkloadId("acct".into());
        assert!(spawn(&ctx, &id, &spec_with_durability()).await.unwrap());
        assert!(ctx.tail.is_running(&id).await);
        ctx.tail.stop(&id).await;
        assert!(!ctx.tail.is_running(&id).await);
        // Idempotent, like every other teardown arm.
        ctx.tail.stop(&id).await;
    }

    /// Redeploying must not leave two tails racing for one prefix — the second
    /// would fence the first, and the first's exit would stop the workload.
    #[tokio::test]
    async fn a_second_spawn_replaces_the_first_tail() {
        let helper = fake_helper("replace", "#!/bin/sh\nexec sleep 30\n");
        let ctx = Arc::new(ServerCtx::new().with_tail_helper(helper));
        let id = WorkloadId("acct".into());
        let spec = spec_with_durability();
        assert!(spawn(&ctx, &id, &spec).await.unwrap());
        let first = ctx.tail.running.lock().await.get(&id).map(|t| t.pid);
        assert!(spawn(&ctx, &id, &spec).await.unwrap());
        let second = ctx.tail.running.lock().await.get(&id).map(|t| t.pid);
        assert_ne!(first, second, "the first tail was left running");
        assert_eq!(ctx.tail.running.lock().await.len(), 1);
        ctx.tail.stop(&id).await;
    }

    /// The whole point of the exit-code contract: a fenced tail takes the
    /// workload down with it. Asserted through the supervisor's own bookkeeping
    /// — the fake helper exits 2, and the watcher must both drop the entry and
    /// run the stop path without recursing back into itself.
    #[tokio::test]
    async fn a_fenced_tail_stops_the_workload() {
        let helper = fake_helper(
            "fenced",
            "#!/bin/sh\necho '{\"outcome\":\"fenced\"}'\nexit 2\n",
        );
        let ctx = Arc::new(ServerCtx::new().with_tail_helper(helper));
        let id = WorkloadId("acct".into());
        assert!(spawn(&ctx, &id, &spec_with_durability()).await.unwrap());

        // Ten seconds, not two: this camp runs dozens of concurrent cargo
        // builds against one target dir, and a fork+exec of a shell script can
        // take real wall-clock time under that. The budget is generous because
        // the assertion below is the test — a wrong implementation never
        // reaps, so no deadline makes it pass.
        for _ in 0..1000 {
            if !ctx.tail.is_running(&id).await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            !ctx.tail.is_running(&id).await,
            "a fenced tail must be reaped, not left in the map"
        );
        // The stop path ran to completion rather than deadlocking on the
        // supervisor's own mutex: this call would block forever if it had not.
        ctx.tail.stop(&id).await;
    }
}
