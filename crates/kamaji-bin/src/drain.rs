//! Kamaji's drain enforcement state machine (R406-T7).
//!
//! ## Protocol shape
//!
//! Drain is a Yubaba-issued request carrying a [`DrainBudget`]
//! (`{ flush_ms, checkpoint_ms }`). Kamaji runs a single combined timer of
//! `flush_ms + checkpoint_ms` and reports the workload's exit phase in the
//! returned [`DrainOutcome`]:
//!
//! - **`Flushed`** — workload exited within `flush_ms`.
//! - **`Checkpointed`** — workload exited between `flush_ms` and the total.
//! - **`ForceKilled`** — budget elapsed; Kamaji issued SIGKILL.
//!
//! Wire-level versioning rides the Yubaba↔Kamaji [`ProtocolVersion`]
//! handshake; the workload-side channel (signal-only floor here, structured
//! stdio/HTTP under R406-T11) is layered above this enforcer.
//!
//! [`ProtocolVersion`]: kamaji_proto::ProtocolVersion
//!
//! ## State machine
//!
//! ```text
//!     Idle
//!      │  Drain(budget) accepted
//!      ▼
//!   SigtermSent ─────exit-before-flush_ms─────────────▶  Reaped(Flushed)
//!      │
//!      │   flush_ms elapsed, child still alive
//!      ▼
//!   Checkpointing ──exit-before-flush+checkpoint_ms──▶  Reaped(Checkpointed)
//!      │
//!      │   total budget elapsed
//!      ▼
//!   SigkillSent ────exit (≤ 5s safety window)─────────▶  Reaped(ForceKilled)
//! ```
//!
//! The split between `SigtermSent` and `Checkpointing` is observational only:
//! Kamaji does not send a second signal at the `flush_ms` boundary. The
//! workload distinguishes phases by elapsed time in the SIGTERM-only floor;
//! once R406-T11 introduces the structured workload channel, Kamaji will
//! deliver the budget envelope so workload-side code can poll its phase
//! without consulting the clock.
//!
//! ## SIGTERM floor & race-freedom
//!
//! Signals are delivered via `pidfd_send_signal(2)` — Kamaji holds the
//! pidfd, so the kill targets that exact process even if its pid would
//! otherwise be eligible for reuse. Exit observation rides `epoll(7)` on the
//! same pidfd (via `tokio::io::unix::AsyncFd`); the kernel marks the pidfd
//! readable when the child exits, no SIGCHLD plumbing.
//!
//! ## Ownership
//!
//! [`enforce_drain`] **consumes** the [`OwnedFd`] for the workload's pidfd.
//! The caller (typically the server's Drain handler) must ensure the pidfd is
//! not concurrently registered with [`crate::pidfd::PidfdReaper`] — drain
//! reaps via `waitid(P_PIDFD, …)` itself, so a parallel reaper task would
//! either race or hit `ECHILD`. The full lifecycle wiring lands in R406-T8;
//! tests in this module take direct ownership of a freshly-opened pidfd.
//!
//! @yah:relay(R612, "kamaji-bin test hygiene: deflake drain SIGTERM-escalation timing tests")
//! @yah:at(2026-07-20T03:52:37Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//!
//! @yah:ticket(R612-B1, "Deflake sigterm_ignoring_workload_is_force_killed — SIGTERM-vs-budget race under host load")
//! @yah:status(review)
//! @yah:at(2026-07-20T04:14:22Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R612)
//! @yah:severity(low)
//! @yah:next("Tier: Thief — rote timing-tolerance fix in one test, no design work.")
//! @yah:next("Widen the drain budget in the test (e.g. flush_ms=500/checkpoint_ms=500) so the SIGKILL-escalation window is deterministic under CI load, OR make enforce_drain's outcome classification robust to a workload that is reaped by SIGTERM after the flush deadline has passed (treat post-deadline Signaled(15) exits as ForceKilled-equivalent since the SIGKILL is what unblocked the wait). Prefer the latter if the race is in classify logic, not just the timeout constant.")
//! @yah:next("Re-run 10x on a loaded Linux box (oss/kamaji: cargo test -p kamaji-bin --features containerd-integration drain::linux) to confirm 0 flakes before archiving.")
//! @yah:gotcha("Linux-only test (drain.rs:390, mod linux gated on target_os=linux) — not reproducible on darwin dev hosts. Fails ~2/5 re-runs under heavy host load: got DrainOutcome::Flushed{Signaled(15)} instead of ForceKilled. Budget is flush_ms=100/checkpoint_ms=100 (200ms total); under load the SIGKILL-escalation race is lost and the shell is reaped by an earlier signal path inside the flush window.")
//! @yah:handoff("Root cause was the trap-installation race, not a timeout constant or classify bug: `sh -c 'trap \"\" TERM; sleep 30'` has a window between exec(sh) and the `trap` builtin running where SIGTERM defaults to terminate. Under host load, slow shell startup widens that window, so drain's immediate SIGTERM kills the shell with Signaled(15) at ~0ms → classified Flushed. Neither next()-option applied: option 2 (post-deadline Signaled(15)→ForceKilled) was semantically wrong since the exit is pre-deadline and the workload genuinely responded.")
//! @yah:handoff("Fix (drain.rs tests): replaced the shell workload with `/bin/sleep 30` spawned via a new `spawn_configured` helper that sets SIGTERM→SIG_IGN in a pre_exec hook. SIG_IGN survives execve(2) (unlike caught handlers), so sleep ignores SIGTERM from its first instruction — zero race. Budget elapses → SIGKILL (unignorable) → deterministic ForceKilled. Budget left at 100/100; assertions unchanged.")
//! @yah:verify("cargo check --target aarch64-unknown-linux-musl -p kamaji-bin --tests — passes (done on darwin host).")
//! @yah:verify("SIGN-OFF (needs Linux host — cannot run on darwin): cd oss/kamaji && for i in $(seq 10); do cargo test -p kamaji-bin drain::linux::tests::sigterm_ignoring_workload_is_force_killed -- --exact --nocapture; done — expect 0 flakes under host load.")

use std::time::Duration;

use kamaji_proto::{DrainBudget, DrainOutcome, WorkloadId};
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

/// Wall-clock cap Kamaji waits for the kernel to publish the post-SIGKILL
/// exit on the pidfd. SIGKILL delivery is near-instant in practice; this is a
/// safety bound for pathological cases (D-state stuck in driver). The drain
/// outcome is reported as `ForceKilled` once SIGKILL is sent regardless of
/// whether the safety window elapses — the elapsed_ms field captures the
/// observation, not a re-escalation decision.
pub const SIGKILL_SAFETY_WINDOW: Duration = Duration::from_secs(5);

/// Errors from the drain enforcer that don't translate into a [`DrainOutcome`].
///
/// `Unsupported` (off-Linux build) is intentionally an outcome rather than an
/// error — it's a deployment-time fact the operator should see in the wire
/// reply, not a syscall failure.
#[derive(Debug, Error)]
pub enum DrainError {
    /// `pidfd_send_signal` failed. This is rare in practice — the kernel
    /// returns errors only for ESRCH (process gone), EPERM (capability
    /// missing), or EBADF (we mishandled the fd). All three indicate caller
    /// or environment bugs worth surfacing.
    #[error("pidfd_send_signal({signal}) failed: {source}")]
    Signal {
        signal: i32,
        #[source]
        source: std::io::Error,
    },
    /// Wrapping the pidfd in `AsyncFd` or driving its readability future
    /// failed. Either the runtime is not configured for IO (we use a
    /// current-thread runtime with `enable_io()`) or the fd was already
    /// invalid.
    #[error("async-register pidfd failed: {0}")]
    AsyncRegister(#[source] std::io::Error),
    /// `waitid(P_PIDFD, …)` failed after the pidfd reported readable. The
    /// kernel guarantees the child is reapable at that point, so this should
    /// not normally fire; surfacing it preserves the failure for debugging.
    #[error("waitid(P_PIDFD) failed: {0}")]
    Wait(#[source] std::io::Error),
}

/// Run the structured drain procedure for a single workload.
///
/// `pidfd` is the workload's process file descriptor; ownership transfers in.
/// `budget` is the (flush, checkpoint) window pair from Yubaba.
///
/// Returns:
///
/// - `Ok(DrainOutcome::Flushed)` if the child exited within `budget.flush_ms`.
/// - `Ok(DrainOutcome::Checkpointed)` if it exited between `flush_ms` and the
///   total budget.
/// - `Ok(DrainOutcome::ForceKilled)` if the combined window elapsed and
///   Kamaji issued SIGKILL.
/// - `Ok(DrainOutcome::Unsupported)` on non-Linux targets — the pidfd surface
///   is Linux-only.
/// - `Err(DrainError)` for unexpected syscall failures the caller may want to
///   surface to operators (logged, then translated into a `DrainAck` with
///   `accepted=false`).
///
/// `_workload_id` is currently informational (used for tracing); it will
/// become load-bearing once the server pushes structured
/// [`kamaji_proto::KamajiToYubaba::DrainCompleted`] events back to
/// Yubaba (R406-T8).
#[cfg(target_os = "linux")]
pub async fn enforce_drain(
    workload_id: WorkloadId,
    pidfd: OwnedFd,
    budget: DrainBudget,
) -> Result<DrainOutcome, DrainError> {
    linux::enforce(workload_id, pidfd, budget).await
}

/// Off-Linux stub — drain requires pidfd, which is Linux-only.
#[cfg(not(target_os = "linux"))]
pub async fn enforce_drain(
    workload_id: WorkloadId,
    pidfd: std::os::fd::OwnedFd,
    budget: DrainBudget,
) -> Result<DrainOutcome, DrainError> {
    let _ = (workload_id, pidfd, budget);
    Ok(DrainOutcome::Unsupported)
}

/// Classify a clean (non-forced) exit into a [`DrainOutcome`] phase variant by
/// comparing the wall-clock elapsed time against the budget's flush window.
///
/// Pure function — exposed for off-Linux unit testing of the boundary
/// arithmetic. The full integration tests live in `linux::tests` and on the
/// crate's `tests/` directory.
pub fn classify_clean_exit(
    exit: kamaji_proto::ExitStatus,
    elapsed_ms: u32,
    budget: DrainBudget,
) -> DrainOutcome {
    if elapsed_ms <= budget.flush_ms {
        DrainOutcome::Flushed { exit, elapsed_ms }
    } else {
        DrainOutcome::Checkpointed { exit, elapsed_ms }
    }
}

/// Saturating cast of `elapsed.as_millis()` into `u32`. Used by both Linux
/// and tests; the saturation matters because postcard encodes u32 but Rust's
/// `Duration::as_millis` is u128, and an unconverted overflow would panic.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn elapsed_ms_u32(elapsed: Duration) -> u32 {
    let ms = elapsed.as_millis();
    if ms > u32::MAX as u128 {
        u32::MAX
    } else {
        ms as u32
    }
}

/// Bound the budget at a sane upper limit when constructing the wait timer.
///
/// `DrainBudget` is u32 ms — up to ~49.7 days. Allowing that as a timeout is
/// fine but means a misconfigured budget effectively wedges the drain task
/// forever. Callers that want a hard cap layer it on top; this helper just
/// converts the bytes-on-the-wire shape into a `Duration`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn budget_to_duration(budget: DrainBudget) -> Duration {
    Duration::from_millis(budget.total_ms() as u64)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::time::Instant;

    use kamaji_proto::{DrainBudget, DrainOutcome, ExitStatus, WorkloadId};
    use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use tracing::{debug, warn};

    use super::{
        budget_to_duration, classify_clean_exit, elapsed_ms_u32, DrainError, SIGKILL_SAFETY_WINDOW,
    };

    pub(super) async fn enforce(
        workload_id: WorkloadId,
        pidfd: OwnedFd,
        budget: DrainBudget,
    ) -> Result<DrainOutcome, DrainError> {
        // Step 1: SIGTERM via pidfd_send_signal (race-free; targets this exact
        // process regardless of pid reuse). This is the floor — workloads that
        // catch SIGTERM and clean up exit before the budget; ones that ignore
        // it ride to the SIGKILL escalation below.
        send_signal(&pidfd, libc::SIGTERM).map_err(|e| DrainError::Signal {
            signal: libc::SIGTERM,
            source: e,
        })?;
        let started = Instant::now();
        debug!(
            workload = %workload_id.as_str(),
            flush_ms = budget.flush_ms,
            checkpoint_ms = budget.checkpoint_ms,
            "drain: SIGTERM sent",
        );

        let async_fd =
            AsyncFd::with_interest(pidfd, Interest::READABLE).map_err(DrainError::AsyncRegister)?;

        // Step 2: await child exit, bounded by the combined budget.
        let wait_window = budget_to_duration(budget);
        let readable = tokio::time::timeout(wait_window, async_fd.readable()).await;

        match readable {
            Ok(Ok(_guard)) => {
                // Clean exit within budget — reap and classify by phase.
                let pidfd = async_fd.into_inner();
                let exit = reap_now(&pidfd).map_err(DrainError::Wait)?;
                let elapsed_ms = elapsed_ms_u32(started.elapsed());
                let outcome = classify_clean_exit(exit, elapsed_ms, budget);
                debug!(
                    workload = %workload_id.as_str(),
                    elapsed_ms,
                    ?outcome,
                    "drain: workload exited within budget",
                );
                Ok(outcome)
            }
            Ok(Err(e)) => Err(DrainError::AsyncRegister(e)),
            Err(_elapsed) => {
                // Budget exhausted — escalate to SIGKILL.
                let pidfd = async_fd.into_inner();
                send_signal(&pidfd, libc::SIGKILL).map_err(|e| DrainError::Signal {
                    signal: libc::SIGKILL,
                    source: e,
                })?;
                warn!(
                    workload = %workload_id.as_str(),
                    budget_ms = budget.total_ms(),
                    "drain: budget elapsed; SIGKILL sent",
                );

                // SIGKILL is unblockable; we expect readability to land
                // promptly. The safety window protects against the pathological
                // D-state-in-driver case — we still report ForceKilled either way.
                let async_fd = AsyncFd::with_interest(pidfd, Interest::READABLE)
                    .map_err(DrainError::AsyncRegister)?;
                let _ = tokio::time::timeout(SIGKILL_SAFETY_WINDOW, async_fd.readable()).await;

                // Best-effort reap. If waitid fails after SIGKILL the child is
                // still gone from our supervision; we surface ForceKilled so
                // the outcome doesn't masquerade as a clean exit.
                let pidfd = async_fd.into_inner();
                if let Err(e) = reap_now(&pidfd) {
                    warn!(
                        workload = %workload_id.as_str(),
                        error = %e,
                        "drain: post-SIGKILL waitid failed; reporting ForceKilled anyway",
                    );
                }
                let elapsed_ms = elapsed_ms_u32(started.elapsed());
                Ok(DrainOutcome::ForceKilled { elapsed_ms })
            }
        }
    }

    fn send_signal(pidfd: &OwnedFd, signal: i32) -> Result<(), io::Error> {
        // SAFETY: pidfd is a valid OwnedFd; the syscall is the supported
        // race-free interface for delivering a signal to a specific process.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn reap_now(pidfd: &OwnedFd) -> Result<ExitStatus, io::Error> {
        let status = waitid(Id::PIDFd(pidfd.as_fd()), WaitPidFlag::WEXITED)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        match status {
            WaitStatus::Exited(_, code) => Ok(ExitStatus::Exited(code)),
            WaitStatus::Signaled(_, signal, _) => Ok(ExitStatus::Signaled(signal as i32)),
            other => Err(io::Error::other(format!(
                "unexpected WaitStatus from waitid(P_PIDFD): {other:?}",
            ))),
        }
    }

    #[cfg(test)]
    mod tests {
        //! End-to-end drain tests on Linux. Spawn a real child, hand its pidfd
        //! to [`super::super::enforce_drain`], assert the outcome.
        //!
        //! These tests run only on Linux (whole module is `cfg(target_os =
        //! "linux")`). Off-Linux callers exercise [`super::super::classify_clean_exit`]
        //! and the off-Linux Unsupported stub.

        use std::os::fd::OwnedFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        use kamaji_proto::{DrainBudget, DrainOutcome, ExitStatus, WorkloadId};

        use crate::drain::enforce_drain;
        use crate::pidfd::pidfd_open;

        fn spawn_with_pidfd(prog: &str, args: &[&str]) -> (u32, OwnedFd) {
            spawn_configured(prog, args, false)
        }

        /// Spawn a child and open a pidfd on it. When `ignore_sigterm` is set,
        /// the child has `SIGTERM` reset to `SIG_IGN` in a `pre_exec` hook,
        /// *before* `execve`. `SIG_IGN` dispositions survive `execve(2)` (only
        /// caught handlers reset to default), so the exec'd program ignores
        /// SIGTERM from its very first instruction — no trap-installation
        /// window for the drain's immediate SIGTERM to slip through. That race
        /// is exactly what made the shell-`trap`-based variant flake under host
        /// load (R612-B1): a slow shell startup let the SIGTERM land before
        /// `trap '' TERM` ran, killing the shell with `Signaled(15)` inside the
        /// flush window and mis-reporting `Flushed`.
        fn spawn_configured(prog: &str, args: &[&str], ignore_sigterm: bool) -> (u32, OwnedFd) {
            let mut cmd = Command::new(prog);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if ignore_sigterm {
                // SAFETY: `signal(2)` is async-signal-safe, which is the only
                // constraint on a post-fork/pre-exec hook. We touch no other
                // shared state.
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::signal(libc::SIGTERM, libc::SIG_IGN) == libc::SIG_ERR {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            let child = cmd
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {prog} failed: {e}"));
            let pid = child.id();
            // Drop std handle so it doesn't reap on Drop — drain owns the reap.
            std::mem::forget(child);
            let pidfd = pidfd_open(pid).expect("pidfd_open");
            (pid, pidfd)
        }

        #[tokio::test]
        async fn workload_exits_cleanly_on_sigterm_reports_flushed() {
            // `cat` with no input on a closed stdin exits on EOF — for our
            // purposes, a child that responds to SIGTERM by terminating
            // promptly. Use `sleep 30` which defaults SIGTERM to terminate
            // the process; it should exit within milliseconds of the signal.
            let (_pid, pidfd) = spawn_with_pidfd("/bin/sleep", &["30"]);
            let budget = DrainBudget {
                flush_ms: 2_000,
                checkpoint_ms: 2_000,
            };

            let outcome = tokio::time::timeout(
                Duration::from_secs(5),
                enforce_drain(WorkloadId::new("clean-sigterm"), pidfd, budget),
            )
            .await
            .expect("enforce_drain didn't return within 5s wall-clock");

            let outcome = outcome.expect("enforce_drain returned DrainError");
            match outcome {
                DrainOutcome::Flushed { exit, elapsed_ms } => {
                    // sleep dies on SIGTERM with a Signaled exit (signal 15).
                    assert!(
                        matches!(exit, ExitStatus::Signaled(15)),
                        "expected Signaled(15), got {exit:?}",
                    );
                    // Should be well under the flush window.
                    assert!(
                        elapsed_ms < 2_000,
                        "elapsed_ms={elapsed_ms} should be < flush_ms=2000",
                    );
                }
                other => panic!("expected Flushed, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn sigterm_ignoring_workload_is_force_killed() {
            // A workload that ignores SIGTERM from birth: `/bin/sleep 30`
            // spawned with `SIGTERM` set to `SIG_IGN` in a pre-exec hook.
            // Kamaji's budget elapses without effect; SIGKILL escalation reaps
            // it. We spawn sleep directly (not `sh -c 'trap …'`) so there is no
            // trap-installation window — the earlier shell variant flaked under
            // host load when the drain's immediate SIGTERM raced ahead of the
            // shell's `trap '' TERM`, killing the shell with Signaled(15)
            // inside the flush window and reporting Flushed (R612-B1).
            let (_pid, pidfd) = spawn_configured("/bin/sleep", &["30"], /* ignore_sigterm */ true);
            let budget = DrainBudget {
                flush_ms: 100,
                checkpoint_ms: 100,
            };

            let outcome = tokio::time::timeout(
                Duration::from_secs(10),
                enforce_drain(WorkloadId::new("sigterm-ignoring"), pidfd, budget),
            )
            .await
            .expect("enforce_drain didn't return within 10s wall-clock");

            let outcome = outcome.expect("enforce_drain returned DrainError");
            match outcome {
                DrainOutcome::ForceKilled { elapsed_ms } => {
                    // Should be just past the budget (200ms) plus SIGKILL
                    // reaction time. Generous upper bound to avoid CI flakes.
                    assert!(
                        elapsed_ms >= 200,
                        "elapsed_ms={elapsed_ms} should be >= total_budget=200",
                    );
                    assert!(
                        elapsed_ms < 3_000,
                        "elapsed_ms={elapsed_ms} took too long — SIGKILL should land fast",
                    );
                }
                other => panic!("expected ForceKilled, got {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Cross-platform unit tests for the pure-data helpers. The Linux-only
    //! end-to-end drain tests live in `linux::tests` above and only build
    //! on Linux targets.

    use super::*;
    use kamaji_proto::ExitStatus;

    #[test]
    fn classify_clean_exit_within_flush_window_is_flushed() {
        let budget = DrainBudget {
            flush_ms: 1_000,
            checkpoint_ms: 2_000,
        };
        let outcome = classify_clean_exit(ExitStatus::Exited(0), 500, budget);
        match outcome {
            DrainOutcome::Flushed { exit, elapsed_ms } => {
                assert_eq!(exit, ExitStatus::Exited(0));
                assert_eq!(elapsed_ms, 500);
            }
            other => panic!("expected Flushed, got {other:?}"),
        }
    }

    #[test]
    fn classify_clean_exit_at_flush_boundary_is_flushed() {
        // Boundary is inclusive on flush_ms (≤) so a workload exiting exactly
        // at the deadline still counts as flushed — operators tuning budgets
        // get monotonic semantics ("set flush_ms to 5000, anything ≤5000 is
        // flushed").
        let budget = DrainBudget {
            flush_ms: 1_000,
            checkpoint_ms: 2_000,
        };
        let outcome = classify_clean_exit(ExitStatus::Exited(0), 1_000, budget);
        assert!(matches!(outcome, DrainOutcome::Flushed { .. }));
    }

    #[test]
    fn classify_clean_exit_just_past_flush_is_checkpointed() {
        let budget = DrainBudget {
            flush_ms: 1_000,
            checkpoint_ms: 2_000,
        };
        let outcome = classify_clean_exit(ExitStatus::Exited(0), 1_001, budget);
        match outcome {
            DrainOutcome::Checkpointed { exit, elapsed_ms } => {
                assert_eq!(exit, ExitStatus::Exited(0));
                assert_eq!(elapsed_ms, 1_001);
            }
            other => panic!("expected Checkpointed, got {other:?}"),
        }
    }

    #[test]
    fn classify_clean_exit_carries_signaled_exit_through() {
        let budget = DrainBudget {
            flush_ms: 1_000,
            checkpoint_ms: 2_000,
        };
        let outcome = classify_clean_exit(ExitStatus::Signaled(15), 250, budget);
        match outcome {
            DrainOutcome::Flushed { exit, .. } => {
                assert_eq!(exit, ExitStatus::Signaled(15));
            }
            other => panic!("expected Flushed, got {other:?}"),
        }
    }

    #[test]
    fn elapsed_ms_u32_saturates_above_u32_max() {
        let huge = Duration::from_secs(u64::MAX / 1000);
        let ms = elapsed_ms_u32(huge);
        assert_eq!(ms, u32::MAX);
    }

    #[test]
    fn elapsed_ms_u32_passes_small_values_through() {
        let small = Duration::from_millis(250);
        assert_eq!(elapsed_ms_u32(small), 250);
    }

    #[test]
    fn budget_to_duration_sums_windows() {
        let budget = DrainBudget {
            flush_ms: 1_500,
            checkpoint_ms: 500,
        };
        assert_eq!(budget_to_duration(budget), Duration::from_millis(2_000));
    }

    #[test]
    fn budget_to_duration_saturates_overflow() {
        let budget = DrainBudget {
            flush_ms: u32::MAX,
            checkpoint_ms: 100,
        };
        // total_ms() saturates at u32::MAX; Duration accepts the max value.
        assert_eq!(
            budget_to_duration(budget),
            Duration::from_millis(u32::MAX as u64),
        );
    }
}
