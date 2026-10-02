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
//! crash, a bad config, an unreachable store — does not say another node owns
//! the state, so the workload keeps running: stopping a healthy workload
//! because its backup is sick is a worse trade than an un-backed-up workload
//! that is loudly un-backed-up.
//!
//! **The tail itself is restarted, though** (R932). Until that ticket this
//! module logged one line about the non-verdict exit and abandoned the
//! workload, which made "loudly un-backed-up" true for exactly one line in a
//! journal and false for every minute after it. [`supervise`] now retries on a
//! backoff ladder, and [`watch_freshness`] says so periodically when a tail is
//! alive but has stopped shipping.
//!
//! # An armed tail survives kamaji, because a container does
//!
//! A container outlives the supervisor that started it, so after a kamaji
//! restart the workload is still serving with no tail behind it and nothing
//! saying so. [`spawn`] therefore records each arming under
//! [`RECORDS_DIR`], and [`resume`] — called from `main` before the UDS answers,
//! next to `resume_bundle_workloads` — re-arms every record whose workload a
//! backend still reports as live. Liveness is checked rather than assumed: the
//! tail takes an ownership claim, and a claim taken for a workload running
//! somewhere *else* fences that node.
//!
//! # A node with no tail helper is not silently un-backed-up
//!
//! [`spawn`] mirrors [`crate::hydrate::run`]'s refusal exactly: a spec that
//! declares a bytes-shipping tier on a kamaji started without `--tail-helper` is
//! **refused**, not started. The failure it prevents is the same one, one step
//! later — a workload running happily with nothing shipping its state, which
//! looks identical to a healthy workload until the node dies.
//!
//! @yah:relay(R932, "A container workload's durability tail does not survive a kamaji restart: tail::spawn has one call site (Deploy), and resume_bundle_workloads is bundle-only")
//! @yah:status(review)
//! @yah:at(2026-09-22T02:13:50Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:handoff("FOUND FROM THE NOISETABLE CAMP (R131-B36), diagnosed read-only by @Miravel:polaris (session:438f225c) on 2026-09-21. Production symptom: the noisetable-account container workload on us-east-001 had its turso-backup stream tier armed 2026-09-13T18:10Z (owner-claim kamaji-pid-688306, yah R858-B26 / noisetable R131-T16), shipped state until 19:30:12Z, then went dark for eight days while the service stayed healthy and serving — kamaji now runs as a different pid, so it restarted at least once in between. Mechanism, read from source: crate::tail::spawn is called from the Deploy RPC handler only (server.rs ~:2096); when the turso-backup-tail child exits without a fence verdict kamaji logs 'durability tail exited without a fence verdict; the workload keeps running but its state is no longer being shipped' and never restarts it; resume_bundle_workloads (R755-B5, server.rs ~:3072) re-arms BUNDLE workloads after a restart and has no container-workload arm, so nothing re-arms a container workload's tail except a fresh Deploy. Ruled out: R2 auth (scoped pair still 200 on a signed ListObjectsV2). Side finding from the same journal pull: kamaji on us-east-001 logs 'duplicate workload id across backends id=yah-marketing kept_state=Running dropped_state=Pending' several times per second as of 2026-09-22T01:17Z — not investigated.")
//! @yah:next("Extend the restart-resume path to container workloads that declare yah.durability.*: on kamaji start, for every recorded container workload whose durability tier is stream, re-run the tail arming that Deploy does (owner-claim, fence check, spawn), and treat a tail child exit without a verdict as a supervised restart with backoff rather than a warn-and-forget. Test both: a unit test that a recorded container workload with durability gets its tail respawned on resume, and one that a non-verdict exit is retried.")
//! @yah:next("Retire the noisetable interim heartbeat language once the stream tier carries its own freshness signal, or give the stream tier a heartbeat/last-write check — the eight-day gap was invisible because the interim timer (retired 09-13T09:10Z) was the only freshness signal and the stream tier has none. Coordinate with noisetable R131-B36, which owns the re-arm on us-east-001 and the noisetable-side check.")
//! @yah:next("Tier: Warrior for the resume/retry change (kamaji supervision code, production node); Cleric for the freshness signal.")
//! @arch:see(.yah/docs/working/W124-noisetable-web-services.md)
//! @yah:handoff("FIXED IN SOURCE, oss/kamaji/crates/kamaji-bin. (1) RESTART-RESUME. tail::spawn now persists a TailRecord {id, workload, HydrateArgs} at <RECORDS_DIR>/<id>.json (0600 in a 0700 dir, tmp+rename, the same discipline BundleBackend::record_deploy uses) BEFORE it launches the helper, and REFUSES the deploy if the record cannot be written — a tail the next restart will not re-arm is exactly this bug. stop_workload forgets the record (best-effort warn, not a refusal: a stale record cannot resurrect anything because resume checks liveness). New tail::resume(ctx) is called from main.rs right after resume_bundle_workloads and before the UDS answers; it re-arms every record whose workload a backend still reports live. DELIBERATELY NOT THE WorkloadSpec on disk: HydrateArgs is the whole of what the tail needs and carries no credential material, so this record does not repeat R876-B2 (that one materializes the deploy's env verbatim, three live secrets inline on us-east-001). (2) SUPERVISED RESTART. supervise() replaces the old warn-and-forget watcher: a non-verdict exit is retried on a 2s-doubling ladder capped at 60s, reset after a 5-minute healthy run, unbounded attempts; the fence verdict (exit 2) and an explicit stop still terminate the loop. (3) FRESHNESS, the second next() item, kamaji side: every helper line stamps a per-workload last-write time (TailSupervisor::last_output_at), and a watchdog warns when a tail is ALIVE but has printed nothing for TAIL_INTERVAL_SECS x 4 — the helper's own RPO arithmetic, read from the same env var it reads. The workload is not stopped over silence; silence is not the fence.")
//! @yah:handoff("DISCOVERED WORK DONE IN THE SAME PASS, all inside the blast radius. (a) THE OLD WATCHER COULD UNSTOP A LIVE TAIL. It ran `running.remove(&id)` BEFORE checking the stopping flag, so on a redeploy — which is stop-then-insert under the same id — the superseded watcher deleted the NEW tail's map entry on its way out, leaving a helper running that nothing could ever stop or fence. Each arming now carries a monotonic token (TailSupervisor::next_token) and only releases an entry that is still its own (release/claim_pid/owns). (b) STOP COULD BE LOST. TailSupervisor::stop used Notify::notify_waiters, which wakes only waiters already registered; a supervisor in its restart backoff or mid-spawn is registered on nothing, so the stop vanished. Now notify_one, which stores a permit. (c) live_workload_entries(ctx) factored out of the List arm (server.rs) so resume and List cannot take two different views of what is running here; the Err strings the List arm puts in a BackendRefused are unchanged, and the spec-digest stamp stays at the arm. (d) resume_later: when the backend cannot be listed at startup (containerd a few seconds behind kamaji on a reboot is the realistic case), the resume retries in a detached task, 6 attempts on a 5s-doubling ladder, rather than leaving every durable workload on the node tail-less until someone redeploys it. (e) The module header's \"anything else is logged and left alone\" paragraph was made true again — it described the behaviour this ticket replaced.")
//! @yah:verify("FULL RADIUS, exit codes echoed rather than inferred. oss/kamaji `cargo test --workspace --all-features` = EXIT 0, zero failures on every target (kamaji lib 358, kamaji-bin lib 307, docker_live 5, the rest unchanged). Final tree re-run `cargo test -p kamaji-bin --lib --features bundle-serving` = 269 passed / 0 failed, EXIT 0. `cargo check -p kamaji-bin --all-targets` = EXIT 0 with no new warning (the three it prints are pre-existing: pidfd events_tx, control_sock_from_spec, free_port). kamaji-bin is consumed OUTSIDE its own workspace by exactly two crates — grep says both use only hydrate::{plan,HydratePlan} and server::{ServerCtx,serve_with_ctx}, none of which changed shape — and both were built anyway: root `cargo check -p camp-identity --all-targets` = EXIT 0 and root `cargo check --workspace --all-targets` = EXIT 0, oss/yubaba `cargo check --workspace --all-targets` = EXIT 0. EIGHT NEW TESTS, all in tail.rs: a_recorded_tail_is_re_armed_for_a_workload_that_is_still_running (the ticket's asked-for resume test), a_recorded_tail_is_not_re_armed_for_a_workload_this_node_is_not_running (four live-view shapes; the fencing guard), a_tail_that_exits_without_a_verdict_is_restarted (counts the helper's OWN re-executions through a file it appends to, then asserts a stop really stops the retry loop), the_restart_backoff_ladder_is_the_production_one (pure, asserted against the real 2s base that cfg(test) shortens), arming_a_tail_records_it_owner_only_and_stopping_forgets_it (0600/0700 + round-trip + stop-does-not-forget), a_tail_whose_record_cannot_be_written_refuses_the_deploy, a_tails_output_updates_its_last_write_stamp, the_stall_threshold_follows_the_helpers_round_cadence.")
//! @yah:gotcha("INERT ON EVERY NODE UNTIL A KAMAJI RELEASE IS ROLLED — do not read a green build as \"us-east-001 is shipping again\". Source only; no node has this binary. The live re-arm on us-east-001 is still owed and belongs to noisetable R131-B36, which this ticket was raised from.")
//! @yah:gotcha("THE FIRST RESTART AFTER THE ROLL STILL LOSES AN ALREADY-ARMED TAIL, and that is not a defect in the fix — it is its boundary. A record only exists for a tail armed BY THIS BINARY, so a workload whose tail was armed by the old kamaji has nothing under /var/lib/yah/kamaji/tails for resume to read. Closing that on a live node takes one redeploy of each durable workload after the roll (`yah cloud workload deploy <name>`), which writes the record; every restart after that is covered. Whoever rolls this should treat \"redeploy the durable workloads once\" as part of the roll, not as a separate task.")
//! @yah:assumes("NOTHING RAN AGAINST A LINUX NODE. No ssh, no roll, no deploy; the eight-day symptom itself was never reproduced, only the mechanism @Miravel:polaris read from source. Two specific things are therefore unproven by test: (a) resume_later's retry branch — no test drives it, because a failing `live_workload_entries` needs a configured backend that errors, and no backend can be attached to ServerCtx without one of the feature-gated runtimes and a real socket; the success branch it shares with the inline path IS tested. (b) The stall watchdog's threshold assumes `turso-backup-tail` prints one line per round unconditionally — read at oss/turso-backup/src/bin/tail.rs:149, where every non-fenced RoundOutcome::Backed prints round_json — so silence means a stopped tail rather than an idle database. If that ever becomes conditional, the warn turns into a false alarm on quiet workloads.")

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kamaji_proto::{WorkloadId, WorkloadState};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};
use workload_spec::WorkloadSpec;

use crate::hydrate::{plan, BucketCredentials, HydrateArgs, HydratePlan};
use crate::server::ServerCtx;

/// Exit code meaning "another node owns this workload's state". Must match
/// `turso-backup-tail`'s `EXIT_FENCED`; pinned by
/// [`tests::a_fenced_tail_stops_the_workload`], which drives a fake helper that
/// exits with this literal.
const EXIT_FENCED: i32 = 2;

/// Where a node remembers which of its workloads have a tail armed, so a
/// kamaji restart can re-arm them (R932). Sits beside
/// [`crate::hydrate::VOLUME_ROOT`] under the same node root, and is created on
/// first use — a node with no durable workload never grows the directory.
pub const RECORDS_DIR: &str = "/var/lib/yah/kamaji/tails";

/// First wait after a tail exits without a verdict; doubled per consecutive
/// failure up to [`RESTART_BACKOFF_CAP`].
///
/// Shortened under `cfg(test)` so the restart tests take milliseconds rather
/// than seconds. The production ladder is not thereby untested: it is a pure
/// function of `(base, attempt)` and
/// [`tests::the_restart_backoff_ladder_is_the_production_one`] asserts it
/// against the real two-second base.
#[cfg(not(test))]
const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(2);
#[cfg(test)]
const RESTART_BACKOFF_BASE: Duration = Duration::from_millis(20);

/// Ceiling on that ladder. A store that is down for an hour should be retried
/// every minute, not once at the start of the hour.
const RESTART_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// A round that lasted at least this long is treated as healthy, so the next
/// failure starts the ladder over. Without it a tail that runs for a week and
/// then dies once would inherit whatever backoff its birth had.
const HEALTHY_RUN: Duration = Duration::from_secs(300);

/// `base * 2^(attempt-1)`, capped. Pure so the ladder can be asserted without
/// waiting for it.
fn backoff_for(base: Duration, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(32);
    base.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(RESTART_BACKOFF_CAP)
}

/// What a restart needs to re-arm one workload's tail, and nothing else.
///
/// Deliberately not the `WorkloadSpec`: see [`HydrateArgs`]'s own note — a spec
/// on disk carries the deploy's `env` verbatim, which on a live node is
/// credential material (R876-B2). This carries a volume path, a bucket, a key
/// prefix and a tier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TailRecord {
    /// The workload id the tail belongs to — the key yubaba addresses.
    pub id: String,
    /// `spec.name`, kept only so the logs a restart emits read like the ones a
    /// deploy emits.
    pub workload: String,
    /// The helper's whole invocation, re-derived at arm time from nothing else.
    pub args: HydrateArgs,
}

/// The tails this node is running, one per workload, plus the on-disk record of
/// which workloads *should* have one.
pub struct TailSupervisor {
    running: Mutex<HashMap<WorkloadId, RunningTail>>,
    records_dir: PathBuf,
    /// Hands out a fresh token per arming so a superseded supervisor task can
    /// tell "my child died" from "I was replaced" — see [`RunningTail::token`].
    next_token: AtomicU64,
}

impl Default for TailSupervisor {
    fn default() -> Self {
        Self::with_records_dir(PathBuf::from(RECORDS_DIR))
    }
}

struct RunningTail {
    /// Diagnostic only — the kill goes through [`RunningTail::shutdown`], not
    /// through this. Logged because "which pid was that" is the first question
    /// anybody asks of a supervisor. Updated on every restart, so it always
    /// names the round that is actually running.
    pid: u32,
    /// Which arming owns this entry. A redeploy calls [`TailSupervisor::stop`]
    /// and then inserts a *new* entry under the same id; without this the old
    /// supervisor task, waking to find itself stopped, would clear the new
    /// tail's entry on its way out and leave a live helper nobody can stop.
    token: u64,
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
    /// Unix milliseconds of the last line this workload's tail printed — the stream
    /// tier's freshness signal (R932). Seeded at arm time rather than left at
    /// zero: a tail that has not finished its first round yet is young, not
    /// stale.
    last_output: Arc<AtomicU64>,
}

/// The handles one arming of one workload's tail shares between its
/// supervisor, its log drain and its freshness watchdog. Carried as a struct
/// rather than five parameters because all five have exactly the same lifetime
/// — they are born in [`arm`] and die when that arming does.
#[derive(Clone)]
struct Arming {
    token: u64,
    stopping: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    last_output: Arc<AtomicU64>,
}

impl TailSupervisor {
    /// Build a supervisor whose records live under `dir`. Tests point this at a
    /// temp dir; the production default is [`RECORDS_DIR`].
    pub fn with_records_dir(dir: PathBuf) -> Self {
        Self {
            running: Mutex::new(HashMap::new()),
            records_dir: dir,
            next_token: AtomicU64::new(1),
        }
    }

    /// Whether a tail is currently supervised for `id`. True across a restart
    /// round too: a supervisor waiting out its backoff still owns the workload.
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
    ///
    /// Leaves the on-disk record alone: a redeploy stops the old tail on its
    /// way to arming a new one, so forgetting here would drop the record of a
    /// workload that still has a tail. [`crate::server::stop_workload`] calls
    /// [`Self::forget`] explicitly, which is the only place a workload really
    /// stops having one.
    pub async fn stop(&self, id: &WorkloadId) {
        let Some(tail) = self.running.lock().await.remove(id) else {
            return;
        };
        tail.stopping.store(true, Ordering::SeqCst);
        // `notify_one`, not `notify_waiters`: a supervisor between rounds — in
        // its backoff, or mid-spawn — is registered on nothing, and
        // `notify_waiters` wakes only waiters that already exist. `notify_one`
        // leaves a permit, so the next `notified().await` returns at once and
        // the stop cannot be lost in that window.
        tail.shutdown.notify_one();
        info!(id = %id.0, pid = tail.pid, "stopped the durability tail");
    }

    /// Whether `id`'s entry still belongs to the arming that holds `token`.
    async fn owns(&self, id: &WorkloadId, token: u64) -> bool {
        self.running.lock().await.get(id).is_some_and(|t| t.token == token)
    }

    /// Unix milliseconds of the last line `id`'s tail printed, or `None` when this
    /// node is not tailing it. The last-write check R932 asks for: a stream
    /// tier otherwise carries no freshness signal at all, which is why an
    /// eight-day gap on us-east-001 looked exactly like a healthy workload.
    pub async fn last_output_at(&self, id: &WorkloadId) -> Option<u64> {
        self.running
            .lock()
            .await
            .get(id)
            .map(|t| t.last_output.load(Ordering::Relaxed))
    }

    /// Update the recorded pid for `id` after a restart. `false` means this
    /// arming was superseded (or stopped) while the new child was starting, and
    /// the caller must stand down.
    async fn claim_pid(&self, id: &WorkloadId, token: u64, pid: u32) -> bool {
        match self.running.lock().await.get_mut(id) {
            Some(tail) if tail.token == token => {
                tail.pid = pid;
                true
            }
            _ => false,
        }
    }

    /// Drop `id`'s entry, but only if it is still *this* arming's.
    async fn release(&self, id: &WorkloadId, token: u64) {
        let mut running = self.running.lock().await;
        if running.get(id).is_some_and(|t| t.token == token) {
            running.remove(id);
        }
    }

    /// The directory those records live in.
    pub fn records_dir(&self) -> &Path {
        &self.records_dir
    }

    /// Where `id`'s record lives. Public so a refusal can name the path an
    /// operator has to fix.
    pub fn record_path(&self, id: &WorkloadId) -> PathBuf {
        self.records_dir.join(format!("{}.json", id.0))
    }

    /// Persist `record`, owner-only, atomically (R932).
    ///
    /// Mode and staging discipline are [`crate::server::BundleBackend::record_deploy`]'s,
    /// for the reasons stated there: `.mode()` binds only when this call
    /// creates the file, the directory is chmodded on every write so an
    /// upgraded node self-heals, and the final path is never observable loose.
    /// This record holds no secret, but a bucket and key prefix are still not
    /// an unprivileged user's business.
    pub fn record(&self, record: &TailRecord) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::create_dir_all(&self.records_dir)?;
        std::fs::set_permissions(&self.records_dir, std::fs::Permissions::from_mode(0o700))?;
        let final_path = self.record_path(&WorkloadId::new(&record.id));
        let tmp = kamaji::atomic_file::staging_path(&final_path);
        let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(&bytes)?;
        }
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Drop `id`'s record. Idempotent — a Stop for a workload that never
    /// declared a tier is `Ok`.
    pub fn forget(&self, id: &WorkloadId) -> std::io::Result<()> {
        match std::fs::remove_file(self.record_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Every record on disk, in name order. An unreadable one is logged and
    /// skipped: one corrupt file must not keep every other workload on the node
    /// un-backed-up.
    pub fn recorded(&self) -> Vec<TailRecord> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.records_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
            Err(e) => {
                warn!(dir = %self.records_dir.display(), error = %e, "cannot read durability tail records");
                return out;
            }
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        for path in paths {
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<TailRecord>(&b).map_err(|e| e.to_string()))
            {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping unreadable durability tail record")
                }
            }
        }
        out
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
        HydratePlan::Declared(args) => ctx
            .durability_credentials
            .for_bucket(&args.bucket)
            .map(|_| ())
            .map_err(|e| format!("workload {}: {e}", spec.name)),
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

    // R932: write the record BEFORE the helper starts, and refuse the deploy if
    // it cannot be written. The same trade `BundleBackend::record_deploy` makes
    // and for a sharper reason: a tail that the next restart will not re-arm is
    // exactly the failure this ticket exists to remove, and it is invisible —
    // the workload stays healthy and serving for however long it takes someone
    // to notice the store stopped growing (eight days, on us-east-001).
    let record = TailRecord {
        id: id.0.clone(),
        workload: spec.name.clone(),
        args,
    };
    ctx.tail.record(&record).map_err(|e| {
        format!(
            "workload {}: its durability tail could not be recorded at {}: {e} — refusing rather \
             than arming a tail that would not survive the next kamaji restart",
            spec.name,
            ctx.tail.record_path(id).display()
        )
    })?;

    arm(ctx, id, &record, &helper).await?;
    Ok(true)
}

/// Start the helper and hand it to a supervisor task. Shared by [`spawn`] (a
/// fresh deploy) and [`resume`] (a restart), which is the whole point: the two
/// paths cannot drift, because there is one of them.
async fn arm(
    ctx: &Arc<ServerCtx>,
    id: &WorkloadId,
    record: &TailRecord,
    helper: &Path,
) -> Result<(), String> {
    let arming = Arming {
        token: ctx.tail.next_token.fetch_add(1, Ordering::Relaxed),
        stopping: Arc::new(AtomicBool::new(false)),
        shutdown: Arc::new(Notify::new()),
        last_output: Arc::new(AtomicU64::new(now_millis())),
    };

    let (mut child, pid) = launch(helper, &ctx.durability_credentials, record)?;
    let stdout = child.stdout.take();
    ctx.tail.running.lock().await.insert(
        id.clone(),
        RunningTail {
            pid,
            token: arming.token,
            stopping: arming.stopping.clone(),
            shutdown: arming.shutdown.clone(),
            last_output: arming.last_output.clone(),
        },
    );
    info!(id = %id.0, pid, tier = record.args.tier.as_str(), "durability tail started");
    drain_logs(id, stdout, &arming.last_output);
    watch_freshness(ctx, id.clone(), record.workload.clone(), arming.clone());

    let ctx = Arc::clone(ctx);
    let id = id.clone();
    let record = record.clone();
    let helper = helper.to_path_buf();
    tokio::spawn(async move {
        supervise(ctx, id, record, helper, child, arming).await;
    });
    Ok(())
}

/// Milliseconds since the epoch. The freshness stamp is a plain `u64` rather
/// than an `Instant` because it is read by anything holding the supervisor,
/// across tasks, and `AtomicU64` needs no lock to do it. Milliseconds rather
/// than seconds so that a stamp and the line that caused it are distinguishable
/// inside one second — otherwise the only test that can be written of this is
/// "it is roughly now", which passes against a stamp nothing ever updates.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How long a tail may say nothing before kamaji calls it stalled.
///
/// `turso-backup-tail` prints one line per round unconditionally — a round that
/// shipped nothing still prints its subjects — so silence is not idleness, it
/// is a tail that has stopped rounding. The threshold is the helper's own
/// convention: `TAIL_INTERVAL_SECS` (default 30) times four rounds of slack,
/// which is the same arithmetic the helper uses for its default RPO, with its
/// own comment giving the reason — "one missed round is a scheduler hiccup,
/// four in a row is a stopped tail". Read from kamaji's environment because
/// that is where the helper reads it from too: `command` passes the tail only
/// its subjects and store, and lets everything else be inherited.
fn stall_after() -> Duration {
    let interval = std::env::var("TAIL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    stall_after_for(interval)
}

/// The pure half of [`stall_after`], so the arithmetic can be asserted without
/// a process-global env var.
fn stall_after_for(interval_secs: Option<u64>) -> Duration {
    const DEFAULT_INTERVAL_SECS: u64 = 30;
    const RPO_ROUNDS: u64 = 4;
    let interval = interval_secs
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(interval.saturating_mul(RPO_ROUNDS))
}

/// Say out loud when a tail stops shipping — R932's other half.
///
/// The restart loop covers a tail that *dies*. This covers the one that lives
/// and goes quiet: a wedged round, a store that accepts a connection and never
/// answers, a claim renewal that hangs. Nothing else on this node would say so,
/// and that is the shape of the original failure — eight days of a healthy,
/// serving, un-shipping workload, found only because somebody eventually
/// listed the bucket. The workload is NOT stopped over it: silence is not the
/// fence verdict, and stopping a healthy workload because its backup is sick is
/// the trade this module's header already refuses.
fn watch_freshness(ctx: &Arc<ServerCtx>, id: WorkloadId, workload: String, arming: Arming) {
    let ctx = Arc::clone(ctx);
    let Arming { token, last_output, .. } = arming;
    let stall_after = stall_after();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(stall_after / 2).await;
            // Our arming is over — stopped, fenced, or replaced by a redeploy
            // whose own watcher is now on duty.
            if !ctx.tail.owns(&id, token).await {
                return;
            }
            let silent_for = now_millis().saturating_sub(last_output.load(Ordering::Relaxed));
            if silent_for >= stall_after.as_millis() as u64 {
                warn!(
                    id = %id.0, workload, silent_for_secs = silent_for / 1000,
                    threshold_secs = stall_after.as_secs(),
                    "durability tail has shipped nothing for longer than its round cadence — the \
                     workload is running and its state may not be reaching the store"
                );
            }
        }
    });
}

/// One round of the helper. `Err` is a refusal on the deploy path and a retry
/// on the restart path — the caller decides which, this only reports.
fn launch(
    helper: &Path,
    creds: &BucketCredentials,
    record: &TailRecord,
) -> Result<(Child, u32), String> {
    let child = command(helper, creds, &record.args)
        .map_err(|e| format!("workload {}: {e}", record.workload))?
        .spawn()
        .map_err(|e| {
            format!(
                "workload {}: could not run tail helper {}: {e}",
                record.workload,
                helper.display()
            )
        })?;
    let pid = child.id().ok_or_else(|| {
        format!(
            "workload {}: tail helper exited before it could be supervised",
            record.workload
        )
    })?;
    Ok((child, pid))
}

/// Forward the helper's stdout into the log.
///
/// Its own task rather than a step before the wait, so a chatty tail cannot
/// delay a `stop` and a silent one cannot hold the supervisor open. Each line
/// carries the round's frame counts and RPO, which is the only place an
/// operator sees that a workload's state is moving.
fn drain_logs(
    id: &WorkloadId,
    stdout: Option<tokio::process::ChildStdout>,
    last_output: &Arc<AtomicU64>,
) {
    let Some(stdout) = stdout else { return };
    let log_id = id.clone();
    let last_output = Arc::clone(last_output);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Stamped before the log, so the freshness signal survives a log
            // sink that is slow or full (R932).
            last_output.store(now_millis(), Ordering::Relaxed);
            info!(id = %log_id.0, outcome = %line, "durability tail");
        }
    });
}

/// Watch one workload's tail for as long as the workload has one.
///
/// Three ways out, and only three: we were asked to stop, the helper returned
/// the fence verdict, or the arming was superseded by a redeploy. **Anything
/// else is a restart**, on a backoff ladder — R932. What stood here before
/// logged "its state is no longer being shipped" and returned, which is an
/// accurate sentence about a node that then stays un-backed-up until somebody
/// redeploys it by hand. A crashed helper, an unreachable store and an expired
/// credential all land here, and all three are transient far more often than
/// they are permanent.
async fn supervise(
    ctx: Arc<ServerCtx>,
    id: WorkloadId,
    record: TailRecord,
    helper: PathBuf,
    first: Child,
    arming: Arming,
) {
    let Arming {
        token,
        stopping,
        shutdown,
        last_output,
    } = arming;
    let mut child = Some(first);
    let mut failures: u32 = 0;
    loop {
        let Some(mut running) = child.take() else {
            // No live child: wait out the backoff, then try another round.
            let delay = backoff_for(RESTART_BACKOFF_BASE, failures);
            warn!(
                id = %id.0, workload = record.workload, attempt = failures,
                delay_ms = delay.as_millis() as u64,
                "restarting the durability tail after a non-verdict exit; until it is back, this \
                 workload's state is not being shipped"
            );
            if !sleep_unless_stopped(delay, &shutdown, &stopping).await {
                ctx.tail.release(&id, token).await;
                return;
            }
            match launch(&helper, &ctx.durability_credentials, &record) {
                Ok((mut next, pid)) => {
                    let stdout = next.stdout.take();
                    if !ctx.tail.claim_pid(&id, token, pid).await {
                        // Superseded or stopped while we were spawning. Kill what
                        // we just started rather than leave a second tail on the
                        // prefix — that is the exact race `stop` exists to avoid.
                        let _ = next.start_kill();
                        return;
                    }
                    drain_logs(&id, stdout, &last_output);
                    info!(id = %id.0, pid, tier = record.args.tier.as_str(), "durability tail restarted");
                    child = Some(next);
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    error!(id = %id.0, error = %e, "durability tail could not be restarted");
                }
            }
            continue;
        };

        let started = Instant::now();
        let status = tokio::select! {
            status = running.wait() => status,
            _ = shutdown.notified() => {
                let _ = running.start_kill();
                running.wait().await
            }
        };
        if stopping.load(Ordering::SeqCst) {
            // `stop` already removed our entry; `release` is the belt for the
            // path where the child died on its own at the same moment.
            ctx.tail.release(&id, token).await;
            return;
        }

        let code = status.as_ref().ok().and_then(|s| s.code());
        if code == Some(EXIT_FENCED) {
            ctx.tail.release(&id, token).await;
            error!(
                id = %id.0, workload = record.workload,
                "durability tail was FENCED — another node owns this workload's state, so every \
                 write this instance accepts is unrecoverable; stopping it"
            );
            // Released above, so this cannot recurse: `stop_workload` calls
            // `tail.stop`, which now finds nothing.
            let reply =
                crate::server::stop_workload(&ctx, kamaji_proto::RequestId(0), id.clone()).await;
            info!(id = %id.0, reply = ?reply, "stopped a fenced workload");
            return;
        }

        if started.elapsed() >= HEALTHY_RUN {
            failures = 0;
        }
        failures = failures.saturating_add(1);
        warn!(
            id = %id.0, workload = record.workload, ?code, failures,
            "durability tail exited without a fence verdict"
        );
    }
}

/// Sleep, unless the tail is stopped first. `false` means stop won — the caller
/// must return rather than start another round.
async fn sleep_unless_stopped(
    delay: Duration,
    shutdown: &Notify,
    stopping: &AtomicBool,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = shutdown.notified() => {}
    }
    !stopping.load(Ordering::SeqCst)
}

/// Re-arm every recorded tail whose workload is still running — R932, and the
/// container-workload twin of [`ServerCtx::resume_bundle_workloads`]. Call once
/// at startup, before the UDS answers.
///
/// Without this, `tail::spawn`'s only caller was the Deploy handler, so a
/// kamaji restart left every container workload running with nothing shipping
/// its state and no log line saying so. Measured on us-east-001: the
/// noisetable-account workload shipped until 2026-09-13T19:30Z and then went
/// dark for eight days while serving healthily throughout.
///
/// # Why liveness is checked rather than assumed
///
/// A tail takes the ownership claim on the workload's prefix, and the claim is
/// a fence: the node that loses it **stops its workload**. So arming a tail for
/// a workload that is *not* running here would reach across and take down the
/// node that is running it. A record therefore only re-arms against a live
/// backend row, and a backend that cannot be listed re-arms nothing at all —
/// "I could not tell" must not be read as "it is mine".
///
/// Records for workloads that are not live are kept, not deleted: absence here
/// is a negative observation made seconds after boot, and a record is the only
/// evidence left that the workload ever had a tier.
pub async fn resume(ctx: &Arc<ServerCtx>) -> usize {
    let records = ctx.tail.recorded();
    if records.is_empty() {
        return 0;
    }
    let Some(helper) = ctx.tail_helper.clone() else {
        error!(
            records = records.len(),
            "this node has durability tail records but was started without --tail-helper; every \
             one of those workloads is running with nothing shipping its state"
        );
        return 0;
    };
    let live = match crate::server::live_workload_entries(ctx).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(
                error = %e, records = records.len(),
                "cannot list this node's workloads yet, so nothing was re-armed inline — a tail \
                 armed for a workload that is not running here would fence the node that is; \
                 retrying in the background"
            );
            resume_later(ctx, helper, e);
            return 0;
        }
    };
    rearm(ctx, &helper, records, &live).await
}

/// First retry delay when the backend could not be listed at startup; doubled
/// per attempt by [`backoff_for`], capped at [`RESTART_BACKOFF_CAP`].
const RESUME_RETRY_BASE: Duration = Duration::from_secs(5);

/// How many times [`resume_later`] tries before giving up — ~5 minutes across
/// the ladder, which covers a containerd that systemd started alongside kamaji
/// rather than before it.
const RESUME_RETRY_ATTEMPTS: u32 = 6;

/// Keep trying the resume in the background when the node could not be listed
/// at startup.
///
/// Without this, a containerd that is a few seconds behind kamaji on a reboot
/// costs every durable workload on the node its tail until somebody redeploys
/// it — which is R932's failure again, with a different first domino. Runs
/// detached so the UDS still comes up on time: a node that cannot answer
/// yubaba is a worse outage than one whose tails arm a minute late.
///
/// Re-reads the records each round rather than closing over the startup
/// snapshot: a Deploy admitted in the meantime has already armed its own tail,
/// and [`rearm`] skips whatever is running.
fn resume_later(ctx: &Arc<ServerCtx>, helper: PathBuf, first_error: String) {
    let ctx = Arc::clone(ctx);
    tokio::spawn(async move {
        let mut last = first_error;
        for attempt in 1..=RESUME_RETRY_ATTEMPTS {
            tokio::time::sleep(backoff_for(RESUME_RETRY_BASE, attempt)).await;
            match crate::server::live_workload_entries(&ctx).await {
                Ok(live) => {
                    let records = ctx.tail.recorded();
                    let armed = rearm(&ctx, &helper, records, &live).await;
                    info!(
                        armed, attempt,
                        "re-armed durability tails on a background retry (R932)"
                    );
                    return;
                }
                Err(e) => last = e,
            }
        }
        error!(
            error = %last, attempts = RESUME_RETRY_ATTEMPTS,
            "gave up re-arming this node's durability tails — every recorded workload is running \
             with nothing shipping its state until it is redeployed"
        );
    });
}

/// The decision half of [`resume`], with the live view passed in rather than
/// fetched. Split so the rule that governs it — arm against a live row, never
/// against a missing one — can be asserted without a backend.
async fn rearm(
    ctx: &Arc<ServerCtx>,
    helper: &Path,
    records: Vec<TailRecord>,
    live: &[kamaji_proto::WorkloadEntry],
) -> usize {
    let mut armed = 0;
    for record in records {
        let id = WorkloadId::new(&record.id);
        let state = live.iter().find(|e| e.id == id).map(|e| e.state);
        if !state.is_some_and(is_live) {
            warn!(
                id = %record.id, ?state,
                "a durability tail is recorded for a workload this node is not running; leaving it \
                 un-armed (arming it would fence whichever node is)"
            );
            continue;
        }
        if ctx.tail.is_running(&id).await {
            continue;
        }
        match arm(ctx, &id, &record, helper).await {
            Ok(()) => {
                armed += 1;
                info!(
                    id = %record.id, tier = record.args.tier.as_str(),
                    "re-armed a durability tail after restart (R932)"
                );
            }
            Err(e) => error!(id = %record.id, error = %e, "could not re-arm a durability tail"),
        }
    }
    armed
}

/// Whether a backend row means "this workload is running here *now*". Draining
/// counts: it is still accepting the writes the tail has to ship.
fn is_live(state: WorkloadState) -> bool {
    matches!(
        state,
        WorkloadState::Starting | WorkloadState::Running | WorkloadState::Draining
    )
}

/// The helper's invocation. Split out so a test can assert the environment
/// without spawning: a tail pointed at the wrong prefix writes a backup where no
/// restore will look, and that is invisible until the restore.
fn command(
    helper: &std::path::Path,
    creds: &BucketCredentials,
    args: &HydrateArgs,
) -> Result<tokio::process::Command, String> {
    let mut cmd = tokio::process::Command::new(helper);
    cmd.env("VOLUME_ROOT", &args.volume_root)
        .env("SUBJECTS", args.subjects.join(","))
        .env("TIER", args.tier.as_str())
        .env("OWNER", crate::hydrate::owner_label())
        .env("S3_BUCKET", &args.bucket)
        .env("BACKUP_PREFIX", &args.prefix)
        // Endpoint, region and the tail's own cadence are inherited from
        // kamaji's environment, as in `hydrate::run`. The key pair is selected
        // per bucket (R936-B13), so a node hosting two buckets' workloads
        // hands each tail its own.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    creds.apply(&mut cmd, &args.bucket)?;
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn fake_helper(tag: &str, script: &str) -> PathBuf {
        let dir = scratch(tag);
        let path = dir.join("turso-backup-tail");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A per-test directory. Named per test rather than shared, because R932
    /// put a *records* dir in here too and two tests sharing one would resume
    /// each other's workloads. Created, never cleared: a test calls this more
    /// than once (helper, counter, records) and a clearing version would delete
    /// the fake helper it had just written.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kamaji-tail-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A context whose tail records land in this test's own scratch dir.
    /// Every test needs one since R932: `spawn` refuses a deploy whose record
    /// cannot be written, and the production default is `/var/lib`.
    fn ctx_for(tag: &str, helper: Option<PathBuf>) -> Arc<ServerCtx> {
        let mut ctx = ServerCtx::new()
            .with_tail_records_dir(scratch(tag).join("records"))
            .with_durability_credentials(creds());
        if let Some(helper) = helper {
            ctx = ctx.with_tail_helper(helper);
        }
        Arc::new(ctx)
    }

    /// The pair for the test spec's bucket (`backups`) and one other bucket's,
    /// which must never reach the tail.
    fn creds() -> BucketCredentials {
        BucketCredentials::from_vars([
            ("S3_ACCESS_KEY__BACKUPS".to_string(), "ak-backups".to_string()),
            ("S3_SECRET_KEY__BACKUPS".to_string(), "sk-backups".to_string()),
            ("S3_ACCESS_KEY__YAH_HEADSCALE".to_string(), "ak-headscale".to_string()),
            ("S3_SECRET_KEY__YAH_HEADSCALE".to_string(), "sk-headscale".to_string()),
        ])
    }

    /// R936-B13: a tail is handed its own bucket's pair under the bare names
    /// the helper reads, every other bucket's scoped pair is stripped, and a
    /// bucket with no pair is refused naming the missing variable.
    #[test]
    fn the_tail_gets_only_its_own_buckets_pair() {
        let spec = spec_with_durability();
        let HydratePlan::Declared(args) = plan(&spec).unwrap() else {
            panic!("a declared spec must plan");
        };
        let cmd = command(std::path::Path::new("/bin/true"), &creds(), &args).unwrap();
        let envs: HashMap<String, Option<String>> = cmd
            .as_std()
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v.and_then(|v| v.to_str()).map(str::to_string))))
            .collect();
        assert_eq!(envs.get("S3_ACCESS_KEY"), Some(&Some("ak-backups".to_string())));
        assert_eq!(envs.get("S3_SECRET_KEY"), Some(&Some("sk-backups".to_string())));
        // `None` is an explicit removal from the inherited environment.
        assert_eq!(envs.get("S3_ACCESS_KEY__YAH_HEADSCALE"), Some(&None));
        assert_eq!(envs.get("S3_SECRET_KEY__BACKUPS"), Some(&None));

        let err = command(std::path::Path::new("/bin/true"), &BucketCredentials::default(), &args)
            .unwrap_err();
        assert!(err.contains("S3_ACCESS_KEY__BACKUPS"), "{err}");
    }

    #[test]
    fn tail_preflight_refuses_a_bucket_with_no_credential() {
        let ctx = ServerCtx::new().with_tail_helper(PathBuf::from("/bin/true"));
        let err = preflight(&ctx, &spec_with_durability()).unwrap_err();
        assert!(err.contains("S3_SECRET_KEY__BACKUPS"), "{err}");
        let ctx = ctx.with_durability_credentials(creds());
        assert!(preflight(&ctx, &spec_with_durability()).is_ok());
    }

    fn live_row(id: &str, state: WorkloadState) -> kamaji_proto::WorkloadEntry {
        kamaji_proto::WorkloadEntry {
            id: WorkloadId::new(id),
            state,
            pid: Some(1),
            mesh_ident: None,
            ports: Vec::new(),
            named_ports: Default::default(),
            spec_digest: None,
        }
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
            from_secret_mount: false,
        }];
        spec.durability = Some(workload_spec::Durability {
            tier: workload_spec::DurabilityTier::Stream,
            engine: Some(workload_spec::DurabilityEngine::Turso),
            store: Some("s3://backups/acct".into()),
            subjects: vec!["accounts.db".into(), "sessions.db".into()],
            rpo_seconds: None,
            state_mb: None,
        });
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
        let cmd = command(std::path::Path::new("/bin/true"), &creds(), &args).unwrap();
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
        let ctx = ctx_for("nohelper", None);
        let err = spawn(&ctx, &WorkloadId("acct".into()), &spec_with_durability())
            .await
            .expect_err("a declared tier with no helper must refuse");
        assert!(err.contains("--tail-helper"), "got: {err}");
    }

    /// Every spec in the tree declares nothing, and must stay untouched.
    #[tokio::test]
    async fn an_undeclared_workload_starts_no_tail_and_needs_no_helper() {
        let ctx = ctx_for("plain", None);
        let spec = plain_spec("plain");
        assert!(!spawn(&ctx, &WorkloadId("plain".into()), &spec).await.unwrap());
        assert!(!ctx.tail.is_running(&WorkloadId("plain".into())).await);
    }

    /// A tail that keeps running is supervised, and `stop` reaps it.
    #[tokio::test]
    async fn a_live_tail_is_tracked_and_stoppable() {
        let helper = fake_helper("live", "#!/bin/sh\nexec sleep 30\n");
        let ctx = ctx_for("live", Some(helper));
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
        let ctx = ctx_for("replace", Some(helper));
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
        let ctx = ctx_for("fenced", Some(helper));
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

    /// R932, the eight-day bug: arming a tail has to leave something behind
    /// that a restart can read, and it has to be owner-only — a bucket and key
    /// prefix are not an unprivileged user's business.
    #[tokio::test]
    async fn arming_a_tail_records_it_owner_only_and_stopping_forgets_it() {
        let helper = fake_helper("record", "#!/bin/sh\nexec sleep 30\n");
        let ctx = ctx_for("record", Some(helper));
        let id = WorkloadId("acct".into());
        assert!(spawn(&ctx, &id, &spec_with_durability()).await.unwrap());

        let path = ctx.tail.record_path(&id);
        let mode = |p: &std::path::Path| {
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&path), 0o600, "the record must not be world-readable");
        assert_eq!(mode(ctx.tail.records_dir()), 0o700);

        let recorded = ctx.tail.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].id, "acct");
        // The workload's own name, not its id — `for_forge` prefixes one and
        // not the other, and the logs a restart emits quote the name.
        assert_eq!(recorded[0].workload, spec_with_durability().name);
        assert_eq!(recorded[0].args.bucket, "backups");
        assert_eq!(recorded[0].args.prefix, "acct");
        assert_eq!(recorded[0].args.tier, workload_spec::DurabilityTier::Stream);

        ctx.tail.stop(&id).await;
        // `stop` alone must NOT forget: a redeploy stops the old tail on its
        // way to arming the new one, and a record dropped there would be a
        // workload the next restart silently leaves un-backed-up.
        assert_eq!(ctx.tail.recorded().len(), 1);
        ctx.tail.forget(&id).unwrap();
        assert!(ctx.tail.recorded().is_empty());
        // Idempotent, like every other teardown arm.
        ctx.tail.forget(&id).unwrap();
    }

    /// A node that cannot write the record must refuse the deploy rather than
    /// arm a tail the next restart will not know about. The unwritable dir is
    /// made by pointing the records dir at a path whose parent is a *file*.
    #[tokio::test]
    async fn a_tail_whose_record_cannot_be_written_refuses_the_deploy() {
        let helper = fake_helper("norecord", "#!/bin/sh\nexec sleep 30\n");
        let blocker = scratch("norecord").join("not-a-dir");
        std::fs::write(&blocker, b"").unwrap();
        let ctx = Arc::new(
            ServerCtx::new()
                .with_tail_helper(helper)
                .with_durability_credentials(creds())
                .with_tail_records_dir(blocker.join("records")),
        );
        let id = WorkloadId("acct".into());
        let err = spawn(&ctx, &id, &spec_with_durability())
            .await
            .expect_err("an unrecordable tail must refuse");
        assert!(err.contains("could not be recorded"), "got: {err}");
        assert!(
            !ctx.tail.is_running(&id).await,
            "the refusal must not leave a tail running"
        );
    }

    /// The ticket's first half: a recorded workload that is still running here
    /// gets its tail back on restart, with no Deploy.
    #[tokio::test]
    async fn a_recorded_tail_is_re_armed_for_a_workload_that_is_still_running() {
        let helper = fake_helper("resume", "#!/bin/sh\nexec sleep 30\n");
        let ctx = ctx_for("resume", Some(helper.clone()));
        let id = WorkloadId("acct".into());

        // What the previous kamaji left behind, written through the same API
        // the deploy path uses.
        let HydratePlan::Declared(args) = plan(&spec_with_durability()).unwrap() else {
            panic!("a declared spec must plan");
        };
        let record = TailRecord {
            id: "acct".into(),
            workload: "acct".into(),
            args,
        };
        ctx.tail.record(&record).unwrap();
        assert!(!ctx.tail.is_running(&id).await);

        let live = vec![live_row("acct", WorkloadState::Running)];
        assert_eq!(rearm(&ctx, &helper, ctx.tail.recorded(), &live).await, 1);
        assert!(ctx.tail.is_running(&id).await, "the tail was not re-armed");
        ctx.tail.stop(&id).await;
    }

    /// And the half that keeps the re-arm from being a weapon. A tail takes the
    /// ownership claim; taking it for a workload this node is NOT running
    /// fences the node that is, which stops a healthy workload elsewhere.
    #[tokio::test]
    async fn a_recorded_tail_is_not_re_armed_for_a_workload_this_node_is_not_running() {
        let helper = fake_helper("noresume", "#!/bin/sh\nexec sleep 30\n");
        let ctx = ctx_for("noresume", Some(helper.clone()));
        let HydratePlan::Declared(args) = plan(&spec_with_durability()).unwrap() else {
            panic!("a declared spec must plan");
        };
        ctx.tail
            .record(&TailRecord {
                id: "acct".into(),
                workload: "acct".into(),
                args,
            })
            .unwrap();

        for live in [
            vec![],
            vec![live_row("acct", WorkloadState::Exited)],
            vec![live_row("acct", WorkloadState::Pending)],
            vec![live_row("somebody-else", WorkloadState::Running)],
        ] {
            assert_eq!(rearm(&ctx, &helper, ctx.tail.recorded(), &live).await, 0);
            assert!(!ctx.tail.is_running(&WorkloadId("acct".into())).await);
        }
        // The record survives every one of those: absence is a negative
        // observation made seconds after boot, not a decision to un-declare the
        // workload's durability.
        assert_eq!(ctx.tail.recorded().len(), 1);
    }

    /// The ticket's second half. A helper that exits without the fence verdict
    /// used to be logged and abandoned; it must be restarted instead. Counted
    /// through the helper's own appends, so the assertion is "it ran again",
    /// not "the supervisor said it would".
    #[tokio::test]
    async fn a_tail_that_exits_without_a_verdict_is_restarted() {
        let dir = scratch("retry");
        let counter = dir.join("runs");
        let helper = fake_helper(
            "retry",
            &format!("#!/bin/sh\necho x >> {}\nexit 1\n", counter.display()),
        );
        let ctx = ctx_for("retry", Some(helper));
        let id = WorkloadId("acct".into());
        assert!(spawn(&ctx, &id, &spec_with_durability()).await.unwrap());

        let runs = || std::fs::read_to_string(&counter).map(|s| s.lines().count()).unwrap_or(0);
        // Generous for the same reason `a_fenced_tail_stops_the_workload` is:
        // a wrong implementation never restarts at all, so no deadline makes
        // this pass by luck.
        for _ in 0..1000 {
            if runs() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            runs() >= 3,
            "a non-verdict exit must be retried, not warned about once (ran {} times)",
            runs()
        );
        assert!(
            ctx.tail.is_running(&id).await,
            "a workload being retried still has a supervised tail"
        );

        // And the retry loop is stoppable — otherwise this fix trades a dead
        // tail for one nothing can turn off.
        ctx.tail.stop(&id).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let settled = runs();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(runs(), settled, "a stopped tail must stop restarting");
    }

    /// The stream tier's freshness signal (R932): every line the helper prints
    /// moves the workload's last-write stamp, so "when did this workload last
    /// ship anything" is answerable from kamaji rather than by listing a
    /// bucket eight days later.
    #[tokio::test]
    async fn a_tails_output_updates_its_last_write_stamp() {
        let helper = fake_helper(
            "fresh",
            "#!/bin/sh\nsleep 0.2\necho '{\"outcome\":\"round\"}'\nexec sleep 30\n",
        );
        let ctx = ctx_for("fresh", Some(helper));
        let id = WorkloadId("acct".into());
        assert!(spawn(&ctx, &id, &spec_with_durability()).await.unwrap());

        // Seeded at arm time: a tail that has not finished its first round is
        // young, not stale.
        let armed_at = ctx.tail.last_output_at(&id).await.expect("armed");
        assert!(armed_at > 0);

        for _ in 0..1000 {
            if ctx.tail.last_output_at(&id).await.is_some_and(|t| t > armed_at) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            ctx.tail.last_output_at(&id).await.is_some_and(|t| t > armed_at),
            "a printed round must move the last-write stamp"
        );

        ctx.tail.stop(&id).await;
        assert_eq!(
            ctx.tail.last_output_at(&id).await,
            None,
            "a workload this node is not tailing has no freshness to report"
        );
    }

    /// The stall threshold is the helper's own cadence, not a number picked
    /// here: `TAIL_INTERVAL_SECS` times the four rounds of slack
    /// `turso-backup-tail` uses for its default RPO.
    #[test]
    fn the_stall_threshold_follows_the_helpers_round_cadence() {
        assert_eq!(stall_after_for(None), Duration::from_secs(120));
        assert_eq!(stall_after_for(Some(30)), Duration::from_secs(120));
        assert_eq!(stall_after_for(Some(300)), Duration::from_secs(1200));
        // A zero or unparseable interval is the default, not an alarm that
        // fires on every check.
        assert_eq!(stall_after_for(Some(0)), Duration::from_secs(120));
    }

    /// The ladder the fleet actually runs, asserted against the production base
    /// that `cfg(test)` shortens away.
    #[test]
    fn the_restart_backoff_ladder_is_the_production_one() {
        let base = Duration::from_secs(2);
        assert_eq!(backoff_for(base, 1), Duration::from_secs(2));
        assert_eq!(backoff_for(base, 2), Duration::from_secs(4));
        assert_eq!(backoff_for(base, 3), Duration::from_secs(8));
        assert_eq!(backoff_for(base, 5), Duration::from_secs(32));
        // Capped, and it stays capped however long the store is down — the
        // shift is clamped, so a week of failures cannot overflow it into a
        // zero or a panic.
        assert_eq!(backoff_for(base, 6), RESTART_BACKOFF_CAP);
        assert_eq!(backoff_for(base, 1_000), RESTART_BACKOFF_CAP);
        assert_eq!(backoff_for(base, u32::MAX), RESTART_BACKOFF_CAP);
        // Attempt 0 is the first restart's own wait, not a zero delay.
        assert_eq!(backoff_for(base, 0), Duration::from_secs(2));
    }
}
