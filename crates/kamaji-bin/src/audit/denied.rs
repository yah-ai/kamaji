//! Sampler for the `denied.jsonl` sink — bounds attacker traffic so a burst
//! of forged tokens can't drown the primary audit journal (W159
//! §Sampled `denied.jsonl`).
//!
//! Two levers combined:
//!
//! - **First-N-of-burst:** the first N rejections in a run are always kept
//!   so an operator sees the leading edge of a live incident without waiting
//!   for the sampler to open.
//! - **1-in-N thereafter:** past the burst, every Nth rejection is kept.
//!   The remaining `N-1` are dropped by the sampler and never touch disk.
//!
//! The burst counter resets after `burst_reset_after_secs` of quiet — so a
//! second wave of forged tokens hours later gets its own leading-edge sample
//! rather than being folded into the 1-in-N tail of the first wave.

use std::time::Duration;

/// Sampler policy — lives in kamaji config, NOT in the wire contract.
#[derive(Debug, Clone, Copy)]
pub struct SamplerConfig {
    /// How many rejections at the start of a burst to keep unsampled.
    /// Default: 16 (enough to characterize a live incident by hand).
    pub burst_head: u32,
    /// Sample rate after the burst head. Keep 1 in every `sample_every`
    /// subsequent rejections. Must be ≥ 1; 1 means keep everything (no
    /// sampling — useful in dev).
    pub sample_every: u32,
    /// Reset the burst counter after this much quiet. Default: 60s.
    pub burst_reset_after: Duration,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        Self {
            burst_head: 16,
            sample_every: 100,
            burst_reset_after: Duration::from_secs(60),
        }
    }
}

/// Sampler state. Not `Send`-agnostic on purpose — one sampler per kamaji
/// process, guarded by whatever lock the caller wraps it in.
#[derive(Debug)]
pub struct DeniedSampler {
    cfg: SamplerConfig,
    burst_seen: u32,
    since_last_kept: u32,
    last_rejection_unix_secs: Option<i64>,
}

impl DeniedSampler {
    pub fn new(cfg: SamplerConfig) -> Self {
        Self {
            cfg,
            burst_seen: 0,
            since_last_kept: 0,
            last_rejection_unix_secs: None,
        }
    }

    /// Ask "should this rejection be recorded?" Increments internal state
    /// regardless of the answer — the sampler advances one tick per
    /// call.
    ///
    /// `now_unix_secs` is the current time; the sampler uses it to detect
    /// burst-reset windows without owning a clock itself.
    pub fn should_keep(&mut self, now_unix_secs: i64) -> bool {
        if let Some(last) = self.last_rejection_unix_secs {
            let quiet = now_unix_secs.saturating_sub(last);
            if quiet >= self.cfg.burst_reset_after.as_secs() as i64 {
                self.burst_seen = 0;
                self.since_last_kept = 0;
            }
        }
        self.last_rejection_unix_secs = Some(now_unix_secs);

        if self.burst_seen < self.cfg.burst_head {
            self.burst_seen += 1;
            self.since_last_kept = 0;
            return true;
        }

        // Past the burst head — 1-in-N. `sample_every == 1` means keep-all.
        let every = self.cfg.sample_every.max(1);
        self.since_last_kept += 1;
        if self.since_last_kept >= every {
            self.since_last_kept = 0;
            return true;
        }
        false
    }

    /// Test / diagnostic hook — how many rejections have entered the burst
    /// window since the last reset.
    pub fn burst_seen(&self) -> u32 {
        self.burst_seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_head_keeps_leading_rejections() {
        let mut s = DeniedSampler::new(SamplerConfig {
            burst_head: 3,
            sample_every: 100,
            burst_reset_after: Duration::from_secs(60),
        });
        assert!(s.should_keep(100));
        assert!(s.should_keep(101));
        assert!(s.should_keep(102));
        // 4th is past the head → dropped (sample_every=100 → 1-in-100).
        assert!(!s.should_keep(103));
    }

    #[test]
    fn one_in_n_after_burst() {
        let mut s = DeniedSampler::new(SamplerConfig {
            burst_head: 0,
            sample_every: 5,
            burst_reset_after: Duration::from_secs(60),
        });
        let kept: Vec<bool> = (0..12).map(|i| s.should_keep(1000 + i)).collect();
        // With head=0 and every=5: after 5 drops we keep one — the 5th call
        // (index 4) is the first kept; then again at index 9.
        assert_eq!(
            kept,
            vec![false, false, false, false, true, false, false, false, false, true, false, false]
        );
    }

    #[test]
    fn sample_every_1_keeps_everything() {
        let mut s = DeniedSampler::new(SamplerConfig {
            burst_head: 0,
            sample_every: 1,
            burst_reset_after: Duration::from_secs(60),
        });
        for i in 0..10 {
            assert!(s.should_keep(1000 + i));
        }
    }

    #[test]
    fn quiet_window_resets_burst_head() {
        let mut s = DeniedSampler::new(SamplerConfig {
            burst_head: 2,
            sample_every: 100,
            burst_reset_after: Duration::from_secs(60),
        });
        // Wave 1: two kept, then a drop.
        assert!(s.should_keep(1000));
        assert!(s.should_keep(1001));
        assert!(!s.should_keep(1002));
        // Wait 60s of quiet → next rejection re-opens the head.
        assert!(s.should_keep(1062));
        assert!(s.should_keep(1063));
        assert!(!s.should_keep(1064));
    }

    #[test]
    fn sub_reset_gap_does_not_reset() {
        let mut s = DeniedSampler::new(SamplerConfig {
            burst_head: 2,
            sample_every: 100,
            burst_reset_after: Duration::from_secs(60),
        });
        assert!(s.should_keep(1000));
        assert!(s.should_keep(1001));
        // Under the 60s reset window — head does NOT re-open.
        assert!(!s.should_keep(1010));
        assert!(!s.should_keep(1059));
    }

    #[test]
    fn default_config_is_reasonable() {
        let d = SamplerConfig::default();
        assert_eq!(d.burst_head, 16);
        assert_eq!(d.sample_every, 100);
        assert_eq!(d.burst_reset_after, Duration::from_secs(60));
    }
}
