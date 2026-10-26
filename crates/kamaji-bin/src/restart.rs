//! Restart policy for containerd workloads (R971-B11).
//!
//! The native and microVM backends each run a per-workload supervisor
//! (`kamaji::supervise`) that owns the child and applies
//! [`RestartPolicy`] when it exits. The containerd backend had no equivalent:
//! containerd runs the task, kamaji only created it, and nothing watched it
//! afterwards. A task that died stayed `Failed` indefinitely whatever its
//! policy said — measured live by R971-F4, where a SIGKILLed fleet-git
//! (`on_failure`, exit 137) was restarted by neither kamaji nor yubaba and sat
//! down until an operator redeployed it.
//!
//! This module is that missing supervisor. It polls rather than holding a
//! containerd `Wait` stream per task, because a poll needs no per-task state
//! to survive a kamaji restart and is cheap at this cadence (one `List` per
//! tick). A dead task is put back **in place** through
//! [`crate::containerd::ContainerdBackend::restart_task`], from containerd's
//! own container record — same OCI spec, image, network namespace and volumes
//! — so a restart can never run something the deploy did not describe.
//!
//! ## What is restarted
//!
//! Only a workload kamaji still holds a deployed spec for. `Stop` removes that
//! spec, so a stopped workload — including one the durability tail fenced
//! (`tail.rs`) — is never brought back. The policy is the spec's, applied with
//! the same semantics as `kamaji::supervise`:
//!
//! - `Always`: any exit.
//! - `OnFailure`: a non-zero exit (`Failed` / `OomKilled`) only, up to
//!   `max_attempts` consecutive failures, with the declared backoff. **An exit
//!   0 is never restarted** — fleet-git exits 0 when it loses its writer claim
//!   (W363 s3) precisely so that it stays down.
//! - `Never`: nothing.
//!
//! A dead task must be seen on two consecutive ticks before it is restarted.
//! A `Stop` kills the task before it deletes the container, so a single
//! observation can land between the two; by the next tick the container is
//! gone and there is nothing to restart.
//!
//! @arch:layer(runtime)
//! @arch:role(supervisor)

use std::collections::HashMap;
use std::time::Duration;

use kamaji_proto::{WorkloadId, WorkloadState};
use workload_spec::{BackoffPolicy, RestartPolicy};

/// How often the containerd task census is taken.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Delay before an `Always` restart, matching `kamaji::supervise`.
const ALWAYS_RESTART_DELAY: Duration = Duration::from_secs(1);

/// A restarted task that stays `Running` this long has recovered: its
/// failure streak is reset, as `kamaji::supervise` resets it on a clean run.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

/// What the policy says about one observation of a workload's task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not dead, or dead in a way the policy leaves alone.
    Leave,
    /// Restart after this delay.
    Restart { after: Duration },
    /// `OnFailure` budget is spent; stay down.
    Exhausted,
}

/// Apply `policy` to a task observed in `state` after `streak` consecutive
/// failed restarts.
pub fn decide(policy: &RestartPolicy, state: WorkloadState, streak: u32) -> Verdict {
    let failed = matches!(state, WorkloadState::Failed | WorkloadState::OomKilled);
    let exited = state == WorkloadState::Exited;
    match policy {
        RestartPolicy::Always if failed || exited => Verdict::Restart {
            after: ALWAYS_RESTART_DELAY,
        },
        RestartPolicy::OnFailure {
            max_attempts,
            backoff,
        } if failed => {
            if streak < *max_attempts {
                Verdict::Restart {
                    after: backoff_delay(backoff, streak + 1),
                }
            } else {
                Verdict::Exhausted
            }
        }
        _ => Verdict::Leave,
    }
}

/// `initial_ms * multiplier^(attempt-1)`, capped at `max_ms` — the same curve
/// as `kamaji::supervise`.
fn backoff_delay(b: &BackoffPolicy, attempt: u32) -> Duration {
    let factor = (b.multiplier as f64).powi(attempt.saturating_sub(1) as i32);
    let ms = (b.initial_ms as f64 * factor).min(b.max_ms as f64);
    Duration::from_millis(ms as u64)
}

/// Per-workload bookkeeping across ticks.
#[derive(Debug, Default, Clone)]
struct Track {
    /// Consecutive failed restarts (for `OnFailure`).
    streak: u32,
    /// The task was seen dead on the previous tick.
    seen_dead: bool,
    /// Earliest instant the next restart may run.
    not_before: Option<std::time::Instant>,
    /// When the last restart started the task.
    restarted_at: Option<std::time::Instant>,
    /// The exhaustion warning was already logged.
    exhausted_logged: bool,
}

/// Pure state machine behind the poll loop, kept apart from containerd so the
/// policy can be tested without one.
#[derive(Debug, Default)]
pub struct Restarter {
    tracks: HashMap<WorkloadId, Track>,
}

impl Restarter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one census. `observed` pairs each containerd workload with its
    /// state and, when kamaji still holds its deployed spec, that spec's
    /// policy. Returns the workloads to restart now.
    pub fn tick(
        &mut self,
        now: std::time::Instant,
        observed: &[(WorkloadId, WorkloadState, Option<RestartPolicy>)],
    ) -> Vec<WorkloadId> {
        self.tracks
            .retain(|id, _| observed.iter().any(|(o, _, p)| o == id && p.is_some()));
        let mut due = Vec::new();
        for (id, state, policy) in observed {
            let Some(policy) = policy else { continue };
            let t = self.tracks.entry(id.clone()).or_default();
            if *state == WorkloadState::Running {
                t.seen_dead = false;
                t.not_before = None;
                t.exhausted_logged = false;
                if t.restarted_at.is_some_and(|at| now.duration_since(at) >= HEALTHY_RUN) {
                    t.streak = 0;
                    t.restarted_at = None;
                }
                continue;
            }
            match decide(policy, *state, t.streak) {
                Verdict::Leave => t.seen_dead = false,
                Verdict::Exhausted => {
                    if !t.exhausted_logged {
                        tracing::warn!(
                            id = %id.0, attempts = t.streak,
                            "containerd workload failed again with its on_failure budget spent; \
                             leaving it down (R971-B11)"
                        );
                        t.exhausted_logged = true;
                    }
                }
                Verdict::Restart { after } => {
                    // The backoff runs from the first sighting, the closest
                    // observation to the exit.
                    let not_before = *t.not_before.get_or_insert(now + after);
                    if !t.seen_dead {
                        t.seen_dead = true;
                        continue;
                    }
                    if now >= not_before {
                        due.push(id.clone());
                    }
                }
            }
        }
        due
    }

    /// Record that a restart of `id` was attempted at `now`. A failed exit is
    /// what drove it, unless the policy is `Always` on a clean exit; both
    /// count toward the streak, which `OnFailure` alone reads.
    pub fn restarted(&mut self, id: &WorkloadId, now: std::time::Instant) {
        let t = self.tracks.entry(id.clone()).or_default();
        t.streak = t.streak.saturating_add(1);
        t.seen_dead = false;
        t.not_before = None;
        t.restarted_at = Some(now);
    }
}

/// Run the restart loop for the containerd backend until the process exits.
#[cfg(feature = "containerd-integration")]
pub fn spawn(ctx: std::sync::Arc<crate::server::ServerCtx>) {
    let Some(backend) = ctx.containerd.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut restarter = Restarter::new();
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let entries = match backend.list().await {
                Ok(e) => e,
                // A failed census is not evidence that anything died.
                Err(e) => {
                    tracing::debug!(error = %e, "restart census skipped");
                    continue;
                }
            };
            let observed: Vec<_> = {
                let registry = ctx.registry.lock().await;
                entries
                    .into_iter()
                    .map(|e| {
                        let policy = registry
                            .deployed_spec(&e.id)
                            .and_then(|w| w.container_spec().map(|s| s.restart_policy.clone()));
                        (e.id, e.state, policy)
                    })
                    .collect()
            };
            let now = std::time::Instant::now();
            for id in restarter.tick(now, &observed) {
                // Re-check under the registry: a Stop that landed since the
                // census must win.
                if ctx.registry.lock().await.deployed_spec(&id).is_none() {
                    continue;
                }
                restarter.restarted(&id, now);
                match backend.restart_task(&id).await {
                    Ok(pid) => tracing::info!(
                        id = %id.0, pid,
                        "restarted a dead containerd task per its restart_policy (R971-B11)"
                    ),
                    Err(e) => tracing::warn!(
                        id = %id.0, error = %e,
                        "restart of a dead containerd task failed; retrying per policy"
                    ),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn on_failure(max_attempts: u32) -> RestartPolicy {
        RestartPolicy::OnFailure {
            max_attempts,
            backoff: BackoffPolicy {
                initial_ms: 2000,
                max_ms: 60000,
                multiplier: 2.0,
            },
        }
    }

    fn id() -> WorkloadId {
        WorkloadId::new("fleet-git")
    }

    #[test]
    fn on_failure_restarts_a_killed_task_with_backoff() {
        let p = on_failure(10);
        assert_eq!(
            decide(&p, WorkloadState::Failed, 0),
            Verdict::Restart { after: Duration::from_millis(2000) }
        );
        assert_eq!(
            decide(&p, WorkloadState::Failed, 2),
            Verdict::Restart { after: Duration::from_millis(8000) }
        );
        assert_eq!(
            decide(&p, WorkloadState::Failed, 9),
            Verdict::Restart { after: Duration::from_millis(60000) }
        );
        assert!(matches!(decide(&p, WorkloadState::OomKilled, 0), Verdict::Restart { .. }));
    }

    #[test]
    fn on_failure_never_restarts_a_clean_exit() {
        // fleet-git's fence-loss exit (W363 s3).
        assert_eq!(decide(&on_failure(10), WorkloadState::Exited, 0), Verdict::Leave);
    }

    #[test]
    fn on_failure_stops_when_the_budget_is_spent() {
        assert_eq!(decide(&on_failure(3), WorkloadState::Failed, 3), Verdict::Exhausted);
    }

    #[test]
    fn always_restarts_any_exit_and_never_restarts_nothing() {
        assert!(matches!(decide(&RestartPolicy::Always, WorkloadState::Exited, 0), Verdict::Restart { .. }));
        assert!(matches!(decide(&RestartPolicy::Always, WorkloadState::Failed, 99), Verdict::Restart { .. }));
        assert_eq!(decide(&RestartPolicy::Never, WorkloadState::Failed, 0), Verdict::Leave);
        assert_eq!(decide(&RestartPolicy::Always, WorkloadState::Running, 0), Verdict::Leave);
        assert_eq!(decide(&RestartPolicy::Always, WorkloadState::Pending, 0), Verdict::Leave);
    }

    #[test]
    fn a_dead_task_is_restarted_only_after_two_sightings_and_the_backoff() {
        let mut r = Restarter::new();
        let t0 = Instant::now();
        let dead = [(id(), WorkloadState::Failed, Some(on_failure(10)))];
        assert!(r.tick(t0, &dead).is_empty(), "first sighting only arms");
        assert!(
            r.tick(t0 + Duration::from_secs(1), &dead).is_empty(),
            "backoff (2 s from the first sighting) not elapsed"
        );
        assert_eq!(r.tick(t0 + Duration::from_secs(2), &dead), vec![id()]);
    }

    #[test]
    fn a_stopped_workload_is_never_restarted() {
        // Stop removed the deployed spec: no policy is known.
        let mut r = Restarter::new();
        let t0 = Instant::now();
        let dead = [(id(), WorkloadState::Failed, None)];
        for k in 0..10 {
            assert!(r.tick(t0 + POLL_INTERVAL * k, &dead).is_empty());
        }
    }

    #[test]
    fn a_fence_loss_exit_is_never_restarted() {
        let mut r = Restarter::new();
        let t0 = Instant::now();
        let exited = [(id(), WorkloadState::Exited, Some(on_failure(10)))];
        for k in 0..60 {
            assert!(r.tick(t0 + POLL_INTERVAL * k, &exited).is_empty());
        }
    }

    #[test]
    fn the_streak_spends_the_budget_and_a_healthy_run_resets_it() {
        let mut r = Restarter::new();
        let mut now = Instant::now();
        let dead = [(id(), WorkloadState::Failed, Some(on_failure(2)))];
        let up = [(id(), WorkloadState::Running, Some(on_failure(2)))];
        for _ in 0..2 {
            r.tick(now, &dead);
            now += Duration::from_secs(120);
            assert_eq!(r.tick(now, &dead), vec![id()]);
            r.restarted(&id(), now);
        }
        // Budget of 2 spent.
        r.tick(now, &dead);
        now += Duration::from_secs(120);
        assert!(r.tick(now, &dead).is_empty());
        // A run past HEALTHY_RUN resets it.
        r.tick(now, &up);
        now += HEALTHY_RUN;
        r.tick(now, &up);
        r.tick(now, &dead);
        now += Duration::from_secs(120);
        assert_eq!(r.tick(now, &dead), vec![id()]);
    }
}
