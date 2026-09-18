//! The restart loop, shared by every backend that supervises a host process
//! (R605-F31).
//!
//! # Why this is one module and not one per backend
//!
//! It used to be one, in [`crate::native`], and [`crate::microvm`]'s module
//! heading said in so many words that it "deliberately does not implement the
//! restart loop `crate::native` carries". That was true of a backend that could
//! only run jobs. The moment a microVM has to be able to be a *service* — a
//! long-lived guest that is restarted when it dies rather than reaped when it
//! exits — the choice is between a second restart loop and one shared one, and
//! a second one is the worse artifact: the two would agree on the day they were
//! written and drift on every day after it, and the bugs that produces are the
//! kind where a workload is restarted on one backend and not on another for
//! reasons nobody can name.
//!
//! So the state machine lives here, once, and a backend supplies the four
//! things that genuinely differ:
//!
//! | [`Supervised`] method | native | microVM |
//! |---|---|---|
//! | [`start`](Supervised::start) | fork+exec the binary | boot a guest from the VM config on disk |
//! | [`wait`](Supervised::wait) | wait on the child | wait on the VMM process |
//! | [`stop`](Supervised::stop) | SIGTERM → 5s → SIGKILL | SIGTERM (a guest power-off) → 10s → SIGKILL |
//! | [`settle`](Supervised::settle) | read the exit status | extract artifacts, free the TAP, read the guest's own status document |
//!
//! Everything else — the policy decision, the backoff, the `Restarting`
//! publication, the parked phase, the control-message handling — is identical
//! by construction rather than by inspection.
//!
//! # What the loop guarantees
//!
//! - **One owner of the instance.** The supervisor task holds it; every
//!   lifecycle operation that touches it arrives as a [`Ctrl`] message. There is
//!   no path where a trait method and the restart loop both act on the same
//!   process.
//! - **A terminal exit parks rather than ends.** The supervisor stays alive with
//!   no instance running, so a later `Restart` can revive the workload instead
//!   of finding a dead channel. This is what makes `RestartPolicy::Never` mean
//!   "the *supervisor* does not decide to restart" rather than "the workload can
//!   never run again".
//! - **Backoff is interruptible.** A teardown during a backoff wins immediately
//!   instead of waiting out the delay.
//!
//! Part of R605-F31; the board annotation lives on [`crate::microvm`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, watch};
use workload_spec::{BackoffPolicy, RestartPolicy};

use crate::WorkloadStatus;

/// Fixed delay before an unconditional ([`RestartPolicy::Always`]) respawn, so a
/// workload that exits immediately can't spin the supervisor into a hot loop.
const ALWAYS_RESTART_DELAY: Duration = Duration::from_secs(1);

/// How one supervised instance ended, as the OS reported it.
///
/// Both backends supervise a `tokio::process::Child` — a forked binary on one,
/// the VMM process on the other — so this is the same type on both, and the
/// *interpretation* of it is what [`Supervised::settle`] exists to vary.
pub(crate) type Exit = std::io::Result<std::process::ExitStatus>;

/// What a backend made of an instance's exit.
///
/// The split between `succeeded` and `terminal` is load-bearing. `succeeded`
/// answers the restart policy's question ("was this a failure?"); `terminal` is
/// the status published only if no restart follows. Keeping them apart is what
/// lets the microVM backend report *the job's* exit code — read out of the
/// guest's own status document — while the policy still sees a single boolean.
pub(crate) struct Completion {
    /// Whether this run counts as a success for [`RestartPolicy::OnFailure`].
    pub succeeded: bool,
    /// Exit code to publish in [`WorkloadStatus::Restarting`].
    pub exit_code: i32,
    /// Status to publish if the supervisor is not going to restart.
    pub terminal: WorkloadStatus,
}

/// Control messages from a backend's trait methods to a workload's supervisor
/// task.
///
/// Generic over the backend's instance type purely because of [`Self::Adopt`],
/// which hands the supervisor a *pre-spawned* replacement.
pub(crate) enum Ctrl<I> {
    /// Stop the instance and end supervision (no further restarts).
    Teardown(oneshot::Sender<()>),
    /// Stop the current instance and immediately start a fresh one. Acks with
    /// the new pid (or the start error).
    Restart(oneshot::Sender<Result<u32>>),
    /// Adopt a pre-started replacement as the supervised instance (graceful
    /// upgrade). The outgoing one is handed to [`Supervised::discard`].
    ///
    /// Only [`crate::native`] sends this — a graceful upgrade is a listener
    /// handoff between two host processes, and a microVM has no equivalent — so
    /// a build with the microVM backend and not the native one sees a variant
    /// nothing constructs. That is the truth about the build, not dead code.
    #[cfg_attr(not(feature = "native-integration"), allow(dead_code))]
    Adopt {
        replacement: I,
        ack: oneshot::Sender<()>,
    },
}

/// What a backend must provide for [`supervise`] to run its restart loop.
#[async_trait]
pub(crate) trait Supervised: Send + Sync + 'static {
    /// One running instance: a forked child, a booted guest.
    type Instance: Send + 'static;

    /// OS pid of the process that represents this instance.
    fn pid(&self, inst: &Self::Instance) -> u32;

    /// Wait for the instance to end.
    async fn wait(&self, inst: &mut Self::Instance) -> Exit;

    /// Start a fresh instance from the retained definition.
    ///
    /// Called for every restart, so whatever it reads must be the *current*
    /// definition — the supervisor retains it precisely so a respawn cannot run
    /// something the deploy did not describe.
    async fn start(&self) -> Result<Self::Instance>;

    /// Stop a running instance: signal, grace, kill. Each backend owns its own
    /// grace window because they are not the same duration or the same signal
    /// semantics (a SIGTERM to a VMM is a guest power-off, not a guest signal).
    async fn stop(&self, inst: &mut Self::Instance);

    /// Everything that must happen once an instance has ended, and the verdict
    /// on how it ended.
    ///
    /// This is the backend's whole post-exit hook, not just a classifier: the
    /// microVM backend copies artifacts back out of the scratch disk here,
    /// because that can only be done once the guest has released the block
    /// device.
    async fn settle(&self, exit: Exit) -> Completion;

    /// Dispose of an instance replaced by [`Ctrl::Adopt`]. Defaults to dropping
    /// it; a backend with a drain protocol overrides.
    fn discard(&self, _replaced: Self::Instance) {}
}

/// Outcome of the running-phase select: the instance ended, or a control
/// message arrived (`None` = the channel closed, i.e. the runtime was dropped).
enum Ev<I> {
    Exited(Exit),
    Ctrl(Option<Ctrl<I>>),
}

/// Exponential backoff delay for the `attempt`-th consecutive `OnFailure`
/// restart (1-based): `initial_ms * multiplier^(attempt-1)`, capped at `max_ms`.
fn backoff_delay(b: &BackoffPolicy, attempt: u32) -> Duration {
    let factor = (b.multiplier as f64).powi(attempt.saturating_sub(1) as i32);
    let ms = (b.initial_ms as f64 * factor).min(b.max_ms as f64);
    Duration::from_millis(ms as u64)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parked phase: no instance is running (a terminal exit, or a start that
/// failed). Wait for a control message that either revives the workload
/// (`Restart`/`Adopt`) or ends supervision (`Teardown` / channel closed).
async fn park<S: Supervised>(
    sup: &S,
    ctrl_rx: &mut mpsc::Receiver<Ctrl<S::Instance>>,
    pid: &Arc<AtomicU32>,
    status_tx: &watch::Sender<WorkloadStatus>,
) -> Option<S::Instance> {
    loop {
        match ctrl_rx.recv().await {
            None => return None,
            Some(Ctrl::Teardown(ack)) => {
                let _ = status_tx.send(WorkloadStatus::Stopped);
                let _ = ack.send(());
                return None;
            }
            Some(Ctrl::Adopt { replacement, ack }) => {
                pid.store(sup.pid(&replacement), Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Running);
                let _ = ack.send(());
                return Some(replacement);
            }
            Some(Ctrl::Restart(ack)) => match sup.start().await {
                Ok(new) => {
                    let p = sup.pid(&new);
                    pid.store(p, Ordering::SeqCst);
                    let _ = status_tx.send(WorkloadStatus::Running);
                    let _ = ack.send(Ok(p));
                    return Some(new);
                }
                Err(e) => {
                    let _ = status_tx.send(WorkloadStatus::Failed {
                        reason: format!("restart respawn failed: {e}"),
                        oom_killed: false,
                    });
                    let _ = ack.send(Err(e));
                    // stay parked, wait for the next control message
                }
            },
        }
    }
}

/// Per-workload supervisor: owns the live instance, restarts it per `policy`,
/// and serves control messages. Exits when torn down or when the control
/// channel closes.
pub(crate) async fn supervise<S: Supervised>(
    sup: S,
    policy: RestartPolicy,
    initial: S::Instance,
    pid: Arc<AtomicU32>,
    status_tx: watch::Sender<WorkloadStatus>,
    mut ctrl_rx: mpsc::Receiver<Ctrl<S::Instance>>,
) {
    let mut inst = initial;
    // Consecutive failed exits, for OnFailure's max_attempts/backoff. Reset on a
    // clean exit, an in-place restart, or an adopt.
    let mut failure_streak: u32 = 0;
    // Total restarts, for the Restarting status payload.
    let mut restart_count: u32 = 0;

    loop {
        // ── RUNNING: own `inst`; wait for it to end or a control message. Both
        //    futures are dropped before the handler runs, so the handler is free
        //    to move `inst`.
        let ev = tokio::select! {
            r = sup.wait(&mut inst) => Ev::Exited(r),
            c = ctrl_rx.recv() => Ev::Ctrl(c),
        };

        match ev {
            // Control channel closed — the runtime was dropped. Stop and exit.
            Ev::Ctrl(None) => {
                sup.stop(&mut inst).await;
                return;
            }
            Ev::Ctrl(Some(Ctrl::Teardown(ack))) => {
                sup.stop(&mut inst).await;
                pid.store(0, Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Stopped);
                let _ = ack.send(());
                return;
            }
            Ev::Ctrl(Some(Ctrl::Restart(ack))) => {
                sup.stop(&mut inst).await;
                pid.store(0, Ordering::SeqCst);
                match sup.start().await {
                    Ok(new) => {
                        restart_count += 1;
                        failure_streak = 0;
                        let p = sup.pid(&new);
                        pid.store(p, Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        inst = new;
                        let _ = ack.send(Ok(p));
                    }
                    Err(e) => {
                        let _ = status_tx.send(WorkloadStatus::Failed {
                            reason: format!("restart respawn failed: {e}"),
                            oom_killed: false,
                        });
                        let _ = ack.send(Err(e));
                        match park(&sup, &mut ctrl_rx, &pid, &status_tx).await {
                            Some(new) => {
                                restart_count += 1;
                                failure_streak = 0;
                                inst = new;
                            }
                            None => return,
                        }
                    }
                }
            }
            Ev::Ctrl(Some(Ctrl::Adopt { replacement, ack })) => {
                // Graceful upgrade: the caller already started + settled the
                // replacement. Dispose of the outgoing instance and adopt the
                // new one; the loop now supervises the replacement.
                sup.discard(inst);
                restart_count += 1;
                failure_streak = 0;
                pid.store(sup.pid(&replacement), Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Running);
                inst = replacement;
                let _ = ack.send(());
            }
            Ev::Exited(exit) => {
                pid.store(0, Ordering::SeqCst);
                let done = sup.settle(exit).await;

                let should_restart = match &policy {
                    RestartPolicy::Always => true,
                    RestartPolicy::Never => false,
                    RestartPolicy::OnFailure { max_attempts, .. } => {
                        !done.succeeded && failure_streak < *max_attempts
                    }
                };

                if !should_restart {
                    // Terminal: park until a control message arrives.
                    let _ = status_tx.send(done.terminal);
                    match park(&sup, &mut ctrl_rx, &pid, &status_tx).await {
                        Some(new) => {
                            restart_count += 1;
                            failure_streak = 0;
                            inst = new;
                            continue;
                        }
                        None => return,
                    }
                }

                // Restarting: publish the rich status, back off, start again.
                restart_count += 1;
                if !done.succeeded {
                    failure_streak += 1;
                }
                let _ = status_tx.send(WorkloadStatus::Restarting {
                    last_exit_code: done.exit_code,
                    restart_count,
                    last_finished_at_unix_ms: now_ms(),
                });

                let delay = match &policy {
                    RestartPolicy::Always => ALWAYS_RESTART_DELAY,
                    RestartPolicy::OnFailure { backoff, .. } => {
                        backoff_delay(backoff, failure_streak)
                    }
                    // Unreachable: should_restart is false for Never.
                    RestartPolicy::Never => Duration::ZERO,
                };

                // Interruptible backoff: a teardown (or a closed channel) during
                // the wait wins instead of blocking for the whole delay.
                let interrupted = tokio::select! {
                    _ = tokio::time::sleep(delay) => None,
                    c = ctrl_rx.recv() => Some(c),
                };
                match interrupted {
                    None => {} // backoff elapsed → fall through to start
                    Some(None) => return,
                    Some(Some(Ctrl::Teardown(ack))) => {
                        let _ = status_tx.send(WorkloadStatus::Stopped);
                        let _ = ack.send(());
                        return;
                    }
                    Some(Some(Ctrl::Adopt { replacement, ack })) => {
                        failure_streak = 0;
                        pid.store(sup.pid(&replacement), Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        inst = replacement;
                        let _ = ack.send(());
                        continue;
                    }
                    Some(Some(Ctrl::Restart(ack))) => match sup.start().await {
                        Ok(new) => {
                            failure_streak = 0;
                            let p = sup.pid(&new);
                            pid.store(p, Ordering::SeqCst);
                            let _ = status_tx.send(WorkloadStatus::Running);
                            inst = new;
                            let _ = ack.send(Ok(p));
                            continue;
                        }
                        Err(e) => {
                            let _ = status_tx.send(WorkloadStatus::Failed {
                                reason: format!("restart respawn failed: {e}"),
                                oom_killed: false,
                            });
                            let _ = ack.send(Err(e));
                            match park(&sup, &mut ctrl_rx, &pid, &status_tx).await {
                                Some(new) => {
                                    failure_streak = 0;
                                    inst = new;
                                    continue;
                                }
                                None => return,
                            }
                        }
                    },
                }

                // Backoff elapsed uninterrupted: start again.
                match sup.start().await {
                    Ok(new) => {
                        pid.store(sup.pid(&new), Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        inst = new;
                    }
                    Err(e) => {
                        let _ = status_tx.send(WorkloadStatus::Failed {
                            reason: format!("respawn failed: {e}"),
                            oom_killed: false,
                        });
                        match park(&sup, &mut ctrl_rx, &pid, &status_tx).await {
                            Some(new) => {
                                failure_streak = 0;
                                inst = new;
                            }
                            None => return,
                        }
                    }
                }
            }
        }
    }
}
