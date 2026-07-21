//! Batched HTTP forwarder — kamaji → cheers `/audit/ingest`.
//!
//! W159 §Audit journal:
//!
//! > Forwarded — cheers audit sink (`POST ${cheers_issuer}/audit/ingest`).
//! > Batched, bounded backoff on failure. The forwarded copy is for
//! > centralized querying — the local journal is durable and survives
//! > forwarding outages indefinitely.
//!
//! Shape:
//!
//! - `push` is non-blocking: records go onto a bounded mpsc; if the channel
//!   is full the record is *dropped by the forwarder* and a metric-shaped
//!   `tracing::warn!` fires. The primary journal already has it, so
//!   forwarder drops are recoverable via one-shot backfill (out of scope for
//!   R428-F2).
//! - Batch trigger: size (`max_batch`) OR age (`max_batch_age`), whichever
//!   comes first. Bounds the ingest RPS on cheers's side and gives operators
//!   a predictable batch-latency knob.
//! - Retries on network / 5xx use bounded exponential backoff. 4xx is
//!   terminal (the record shape rejected — logging and moving on beats
//!   pinning a task on a permanent failure). Batches survive kamaji restart
//!   only through the primary JSONL journal; the forwarder queue is
//!   deliberately in-memory (mirroring the "local is source of truth"
//!   contract — anything durable rides through the writer, not the
//!   forwarder).
//!
//! Testing: the forwarder is generic over an [`AuditHttp`] trait so tests
//! swap in an in-process capture and drive the batching + backoff behavior
//! deterministically. Production wire calls go through the `reqwest`-backed
//! [`HttpClient`] impl.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};

use super::record::AuditRecord;

/// Configuration knobs for the forwarder.
#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    /// Cheers ingest URL, e.g. `https://cheers.example/audit/ingest`.
    /// Trailing slashes are trimmed at construction time.
    pub ingest_url: String,
    /// Max records per batch. Cheers's ingest handler is bulk-shaped, so
    /// pushing 100–500 records at a time is cheaper than one-per-POST.
    pub max_batch: usize,
    /// Emit the current batch after this age even when it hasn't hit
    /// `max_batch`. Bounds the visibility lag on low-traffic camps.
    pub max_batch_age: Duration,
    /// Bounded queue depth. Older records are preserved (mpsc back-pressure
    /// on the writer side); pushes past capacity are dropped with a warn.
    pub queue_depth: usize,
    /// Initial retry delay for the exponential-backoff ladder.
    pub retry_initial: Duration,
    /// Cap on any single retry delay. `retry_initial * 2^n` is clamped to
    /// this value.
    pub retry_cap: Duration,
    /// Give up on a batch after this many attempts. Bounds pathological
    /// blocking on a persistently broken cheers endpoint — the record stays
    /// in the local journal regardless.
    pub max_attempts: u32,
}

impl ForwarderConfig {
    /// A production-shaped default.
    pub fn new(ingest_url: impl Into<String>) -> Self {
        let url = ingest_url.into().trim_end_matches('/').to_string();
        Self {
            ingest_url: url,
            max_batch: 128,
            max_batch_age: Duration::from_secs(5),
            queue_depth: 4096,
            retry_initial: Duration::from_millis(250),
            retry_cap: Duration::from_secs(30),
            max_attempts: 6,
        }
    }
}

/// The HTTP surface the forwarder uses. Concrete impl is
/// [`HttpClient`]; tests supply an in-process capture.
#[async_trait]
pub trait AuditHttp: Send + Sync + 'static {
    /// Send a batch of records as a JSON body to `url`. Return
    /// [`IngestOutcome::Retriable`] for network / 5xx errors,
    /// [`IngestOutcome::Terminal`] for 4xx (bad body / bad auth — no point
    /// retrying), and [`IngestOutcome::Accepted`] on 2xx.
    async fn post_batch(&self, url: &str, batch: &[AuditRecord]) -> IngestOutcome;
}

/// Outcome classification the forwarder acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    Accepted,
    /// Retriable failure — the forwarder backs off and re-sends the same
    /// batch. `reason` is logged; not carried on the wire.
    Retriable {
        reason: String,
    },
    /// Terminal failure — the forwarder logs and drops the batch. Records
    /// remain in the primary local journal, so this is recoverable through
    /// out-of-band backfill.
    Terminal {
        reason: String,
    },
}

/// The wire body cheers's `/audit/ingest` handler consumes.
///
/// Kept small on purpose — versioning happens by adding *optional* fields
/// per JSON's usual rules. Cheers's projection (W127 "who deployed what")
/// reads `on_behalf_of` = the record's `sub`; the projection schema itself
/// lives on cheers's side and is pinned in W159 §Audit journal.
#[derive(Debug, Clone, Serialize)]
pub struct IngestBody<'a> {
    /// Wire-schema version. Cheers's handler rejects unknown values so a
    /// forward-incompatible change surfaces as a `Terminal` bounce here.
    pub v: u32,
    /// The records in this batch. Order preserved (kamaji already writes
    /// them chronologically to the primary journal).
    pub records: &'a [AuditRecord],
}

/// Current wire-body schema version.
pub const INGEST_WIRE_VERSION: u32 = 1;

/// Handle to the running forwarder. Push records with [`push`]; call
/// [`shutdown`] to drain the queue and stop the task.
#[derive(Debug)]
pub struct ForwarderHandle {
    tx: mpsc::Sender<AuditRecord>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ForwarderHandle {
    /// Try to enqueue a record. Returns `false` if the queue is full —
    /// caller has already durably logged it to the primary journal, so a
    /// drop is recoverable.
    pub fn push(&self, record: AuditRecord) -> bool {
        match self.tx.try_send(record) {
            Ok(_) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("audit forwarder queue full — record dropped from forwarder (still in local journal)");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Signal shutdown and wait for the drain-and-exit path to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        drop(self.tx);
        let _ = self.task.await;
    }
}

/// Batched cheers forwarder. Spawn with [`spawn`] to get a handle.
pub struct CheersForwarder;

impl CheersForwarder {
    /// Spawn the forwarder task and return a handle.
    pub fn spawn<H>(cfg: ForwarderConfig, http: Arc<H>) -> ForwarderHandle
    where
        H: AuditHttp + 'static,
    {
        let (tx, rx) = mpsc::channel(cfg.queue_depth);
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run_forwarder(cfg, http, rx, stop_rx));
        ForwarderHandle {
            tx,
            stop_tx: Some(stop_tx),
            task,
        }
    }
}

async fn run_forwarder<H: AuditHttp>(
    cfg: ForwarderConfig,
    http: Arc<H>,
    mut rx: mpsc::Receiver<AuditRecord>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut buffer: Vec<AuditRecord> = Vec::with_capacity(cfg.max_batch);
    let mut buffer_opened_at: Option<Instant> = None;

    loop {
        let age_wait = match buffer_opened_at {
            Some(opened) => cfg.max_batch_age.saturating_sub(opened.elapsed()),
            None => cfg.max_batch_age,
        };

        tokio::select! {
            biased;
            _ = &mut stop_rx => {
                // Drain the queue into the buffer, flush what we have, then exit.
                while let Ok(rec) = rx.try_recv() {
                    buffer.push(rec);
                }
                if !buffer.is_empty() {
                    let _ = flush_batch(&*http, &cfg, &buffer).await;
                }
                return;
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(rec) => {
                        if buffer.is_empty() {
                            buffer_opened_at = Some(Instant::now());
                        }
                        buffer.push(rec);
                        if buffer.len() >= cfg.max_batch {
                            let _ = flush_batch(&*http, &cfg, &buffer).await;
                            buffer.clear();
                            buffer_opened_at = None;
                        }
                    }
                    None => {
                        // All senders dropped — final flush and exit.
                        if !buffer.is_empty() {
                            let _ = flush_batch(&*http, &cfg, &buffer).await;
                        }
                        return;
                    }
                }
            }
            _ = sleep(age_wait), if !buffer.is_empty() => {
                let _ = flush_batch(&*http, &cfg, &buffer).await;
                buffer.clear();
                buffer_opened_at = None;
            }
        }
    }
}

/// Attempt to send a batch, retrying with bounded exponential backoff.
/// Returns `Ok(())` for accepted or terminal outcomes (nothing more to do);
/// `Err(())` when the retry ladder is exhausted (bounded max_attempts) —
/// the caller logs and moves on.
async fn flush_batch<H: AuditHttp>(
    http: &H,
    cfg: &ForwarderConfig,
    batch: &[AuditRecord],
) -> Result<(), ()> {
    let mut attempt = 0;
    loop {
        match http.post_batch(&cfg.ingest_url, batch).await {
            IngestOutcome::Accepted => return Ok(()),
            IngestOutcome::Terminal { reason } => {
                tracing::warn!(reason = %reason, batch_size = batch.len(), "audit forwarder: terminal ingest failure — dropping batch");
                return Ok(());
            }
            IngestOutcome::Retriable { reason } => {
                attempt += 1;
                if attempt >= cfg.max_attempts {
                    tracing::warn!(reason = %reason, batch_size = batch.len(), attempts = attempt, "audit forwarder: retry ladder exhausted — dropping batch");
                    return Err(());
                }
                let delay = backoff_delay(cfg.retry_initial, cfg.retry_cap, attempt);
                tracing::debug!(reason = %reason, attempt, backoff_ms = delay.as_millis() as u64, "audit forwarder: retriable ingest failure");
                sleep(delay).await;
            }
        }
    }
}

/// `initial * 2^(attempt-1)`, clamped to `cap`. Deterministic — no jitter
/// (this is a single-tenant per-camp forwarder, not a thundering-herd risk).
fn backoff_delay(initial: Duration, cap: Duration, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(20); // avoid overflow for pathological configs
    let scaled = initial.saturating_mul(1u32 << shift);
    if scaled > cap {
        cap
    } else {
        scaled
    }
}

/// Production HTTP client backed by `reqwest`. Kept separate so the
/// forwarder logic tests can bypass network I/O entirely.
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client build with default config never fails"),
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditHttp for HttpClient {
    async fn post_batch(&self, url: &str, batch: &[AuditRecord]) -> IngestOutcome {
        let body = IngestBody {
            v: INGEST_WIRE_VERSION,
            records: batch,
        };
        match self.client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    IngestOutcome::Accepted
                } else if status.is_client_error() {
                    IngestOutcome::Terminal {
                        reason: format!("cheers rejected batch: HTTP {}", status.as_u16()),
                    }
                } else {
                    IngestOutcome::Retriable {
                        reason: format!("cheers ingest returned HTTP {}", status.as_u16()),
                    }
                }
            }
            Err(e) => IngestOutcome::Retriable {
                reason: format!("network error posting to cheers: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::{AuditRecord, Outcome};
    use std::sync::Mutex;

    fn rec(req: &str) -> AuditRecord {
        AuditRecord {
            at: 1_700_000_500,
            sub: Some("user:abc".into()),
            act: None,
            camp_id: Some("C1".into()),
            aud: Some("https://kamaji.example".into()),
            method: "cloud.deploy".into(),
            scope: Some("cloud:deploy".into()),
            result: Outcome::Ok,
            request_id: req.into(),
        }
    }

    #[derive(Debug, Default)]
    struct CaptureHttp {
        batches: Mutex<Vec<Vec<AuditRecord>>>,
        script: Mutex<Vec<IngestOutcome>>,
    }

    impl CaptureHttp {
        fn always_accept() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn scripted(outcomes: Vec<IngestOutcome>) -> Arc<Self> {
            Arc::new(Self {
                batches: Mutex::new(Vec::new()),
                script: Mutex::new(outcomes),
            })
        }
        fn batches(&self) -> Vec<Vec<AuditRecord>> {
            self.batches.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AuditHttp for CaptureHttp {
        async fn post_batch(&self, _url: &str, batch: &[AuditRecord]) -> IngestOutcome {
            self.batches.lock().unwrap().push(batch.to_vec());
            let next = self.script.lock().unwrap().pop();
            next.unwrap_or(IngestOutcome::Accepted)
        }
    }

    #[test]
    fn backoff_ladder_is_bounded() {
        let initial = Duration::from_millis(100);
        let cap = Duration::from_secs(2);
        assert_eq!(backoff_delay(initial, cap, 1), Duration::from_millis(100));
        assert_eq!(backoff_delay(initial, cap, 2), Duration::from_millis(200));
        assert_eq!(backoff_delay(initial, cap, 3), Duration::from_millis(400));
        assert_eq!(backoff_delay(initial, cap, 4), Duration::from_millis(800));
        assert_eq!(backoff_delay(initial, cap, 5), Duration::from_millis(1_600));
        // Past cap → clamped.
        assert_eq!(backoff_delay(initial, cap, 6), Duration::from_secs(2));
        assert_eq!(backoff_delay(initial, cap, 20), Duration::from_secs(2));
        // Absurd attempt number doesn't panic on shift overflow.
        assert_eq!(backoff_delay(initial, cap, 40), Duration::from_secs(2));
    }

    #[test]
    fn config_new_trims_trailing_slash() {
        let cfg = ForwarderConfig::new("https://cheers.example/audit/ingest/");
        assert_eq!(cfg.ingest_url, "https://cheers.example/audit/ingest");
    }

    #[test]
    fn ingest_body_shape() {
        let batch = vec![rec("req-1")];
        let body = IngestBody {
            v: INGEST_WIRE_VERSION,
            records: &batch,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["v"], INGEST_WIRE_VERSION);
        assert!(v["records"].is_array());
        assert_eq!(v["records"][0]["request_id"], "req-1");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn batch_flushes_at_size_trigger() {
        let http = CaptureHttp::always_accept();
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 3;
        cfg.max_batch_age = Duration::from_secs(60);
        let h = CheersForwarder::spawn(cfg, http.clone());
        for i in 0..3 {
            assert!(h.push(rec(&format!("r-{i}"))));
        }
        // Yield so the forwarder task drains — start_paused=true means we
        // control the clock, but the mpsc recv still runs on the next poll.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        h.shutdown().await;
        let batches = http.batches();
        assert_eq!(batches.len(), 1, "one size-triggered flush");
        assert_eq!(batches[0].len(), 3);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn batch_flushes_at_age_trigger() {
        let http = CaptureHttp::always_accept();
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 100;
        cfg.max_batch_age = Duration::from_secs(2);
        let h = CheersForwarder::spawn(cfg, http.clone());
        assert!(h.push(rec("only")));
        tokio::task::yield_now().await;
        // Age past max_batch_age → the sleep arm fires.
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        h.shutdown().await;
        let batches = http.batches();
        assert!(!batches.is_empty(), "age-triggered flush landed a batch");
        assert_eq!(batches[0].len(), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn retriable_then_accepted_reflushes_same_batch() {
        // Script pops LIFO — the last-pushed is returned first.
        let http = CaptureHttp::scripted(vec![
            IngestOutcome::Accepted,
            IngestOutcome::Retriable {
                reason: "5xx".into(),
            },
        ]);
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 1;
        cfg.max_batch_age = Duration::from_secs(60);
        cfg.retry_initial = Duration::from_millis(10);
        cfg.retry_cap = Duration::from_millis(10);
        cfg.max_attempts = 3;
        let h = CheersForwarder::spawn(cfg, http.clone());
        assert!(h.push(rec("req-1")));
        tokio::task::yield_now().await;
        // Let the retry sleep elapse.
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
        h.shutdown().await;
        let batches = http.batches();
        // Two POST attempts observed for the same batch content.
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0][0].request_id, "req-1");
        assert_eq!(batches[1][0].request_id, "req-1");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn terminal_outcome_drops_batch_without_retry() {
        let http = CaptureHttp::scripted(vec![IngestOutcome::Terminal {
            reason: "bad body".into(),
        }]);
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 1;
        cfg.max_batch_age = Duration::from_secs(60);
        let h = CheersForwarder::spawn(cfg, http.clone());
        assert!(h.push(rec("req-1")));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        h.shutdown().await;
        let batches = http.batches();
        assert_eq!(batches.len(), 1, "no retry on terminal");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn retry_ladder_exhausts_and_drops() {
        // All attempts retriable → ladder exhausts at max_attempts.
        let script = vec![
            IngestOutcome::Retriable { reason: "x".into() },
            IngestOutcome::Retriable { reason: "x".into() },
            IngestOutcome::Retriable { reason: "x".into() },
        ];
        let http = CaptureHttp::scripted(script);
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 1;
        cfg.max_batch_age = Duration::from_secs(60);
        cfg.retry_initial = Duration::from_millis(1);
        cfg.retry_cap = Duration::from_millis(1);
        cfg.max_attempts = 3;
        let h = CheersForwarder::spawn(cfg, http.clone());
        assert!(h.push(rec("req-1")));
        for _ in 0..10 {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(5)).await;
        }
        h.shutdown().await;
        let batches = http.batches();
        assert_eq!(
            batches.len(),
            3,
            "exactly max_attempts POSTs before giving up"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queue_full_returns_false() {
        let http = CaptureHttp::always_accept();
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.queue_depth = 1;
        cfg.max_batch = 100;
        cfg.max_batch_age = Duration::from_secs(60);
        let h = CheersForwarder::spawn(cfg, http);
        // First push fits; second may or may not race the reader.
        assert!(h.push(rec("a")));
        // With queue_depth=1 and the forwarder not yet flushing, subsequent
        // pushes eventually see Full. Push aggressively enough that at least
        // one lands after the buffer is saturated.
        let mut any_dropped = false;
        for i in 0..1000 {
            if !h.push(rec(&format!("q-{i}"))) {
                any_dropped = true;
                break;
            }
        }
        assert!(any_dropped, "expected at least one drop with queue_depth=1");
        h.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_drains_remaining_records() {
        let http = CaptureHttp::always_accept();
        let mut cfg = ForwarderConfig::new("https://ignored/ingest");
        cfg.max_batch = 100;
        cfg.max_batch_age = Duration::from_secs(60);
        let h = CheersForwarder::spawn(cfg, http.clone());
        assert!(h.push(rec("last")));
        tokio::task::yield_now().await;
        // No age trigger fires before shutdown; the drain path must flush.
        h.shutdown().await;
        let batches = http.batches();
        assert_eq!(batches.len(), 1, "shutdown flushed the queued record");
        assert_eq!(batches[0][0].request_id, "last");
    }
}
