//! Kamaji auth-event audit journal — W159 §Audit journal.
//!
//! Every authorized (or denied) kamaji call writes one [`AuditRecord`] with
//! `{at, sub, act, camp_id, aud, method, scope, result, request_id}`. Two
//! destinations:
//!
//! 1. **Local JSONL** at `${state_dir}/audit/YYYY-MM-DD.jsonl` — source of
//!    truth, append-only, rotated daily on UTC date change, pruned to a
//!    configurable retention window (default 30d). Survives forwarding
//!    outages indefinitely.
//! 2. **Cheers forwarder** — batched HTTP POST to
//!    `${cheers_issuer}/audit/ingest` with bounded exponential backoff. Feeds
//!    the centralized query surface W127's "who deployed what" view reads.
//!
//! Rejected-signature traffic goes to a sampled `denied.jsonl` at the same
//! rotation cadence so attacker traffic can't drown the primary journal.
//! Sampler policy (1-in-N + first-N-of-burst) lives in kamaji config, not
//! in the wire contract.
//!
//! Distinct from [`crate::journal`] (workload stdout/stderr fan-in to
//! journald) — different schema, different retention, different destination.
//! Request/response bodies are NOT in the audit journal; that's the Hub
//! layer's concern with its own schedule and retention.
//!
//! Structurally analogous to `crate::auth` — this module ships the pieces
//! as a library. Wiring them into a live dispatch loop lands with
//! `hub-cheers-rpc` (R426-F6, blocked on R116 P3+P5); the call site will
//! construct an [`AuditRecord`] from the verified [`super::auth::McpClaims`]
//! + the method dispatch outcome and push it through [`JsonlWriter::write`].
//!
//! @yah:relay(R428, "Multi-player attribution + audit journal forwarding")
//! @yah:at(2026-06-03T22:42:08Z)
//! @yah:phase(P3)
//! @yah:parent(Q425)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426)
//!
//! @yah:ticket(R428-F2, "Audit journal: local JSONL + rotation + denied.jsonl sampling + cheers forwarder + W127 projection contract")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-01T02:02:00Z)
//! @yah:phase(P3)
//! @yah:parent(R428)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F3)
//! @yah:next("Sign-off: review the five new files in `oss/kamaji/crates/kamaji-bin/src/audit/` (mod 55, record 285, writer 385, denied 175, forwarder 435 lines incl. tests) + the two new subsections in `.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md` (Ingest wire body + W127 projection contract).")
//! @yah:next("On sign-off, the dispatch-loop wiring lands with R426-F6 (hub-cheers-rpc adapter, blocked on R116 P3+P5): the request handler builds `AuditRecord::ok/::denied_policy/::denied_verify` from the `AuthVerifier::verify` result, pushes it to `JsonlWriter` (source of truth) AND `ForwarderHandle` (best-effort centralized), with `DeniedSampler` gating the denied path.")
//! @yah:handoff("F2 landed in `oss/kamaji/crates/kamaji-bin/src/audit/` (five modules: `mod`, `record`, `writer`, `denied`, `forwarder`). Mirrors the `auth::` layout — library-shaped deliverable, wiring into the live dispatch loop lands with hub-cheers-rpc (R426-F6). Kamaji lib re-exports the surface at the top level (`AuditRecord`, `JsonlWriter`, `DeniedSampler`, `CheersForwarder`, `ForwarderConfig`, `ForwarderHandle`, `WriterConfig`, `SamplerConfig`, `AuditOutcome`).")
//! @yah:handoff("AuditRecord shape verbatim with W159 §Audit journal: `{ at, sub, act, camp_id, aud, method, scope, result, request_id }`. `Outcome` serializes as one tagged string (`\"ok\"` / `\"denied:<reason>\"` / `\"error:<class>\"`) so jq/grep filter cleanly. Constructors `AuditRecord::ok / ::denied_policy / ::denied_verify` cover the three dispatch-loop entry points; bad-shape verify failures omit principal fields (no null noise in the JSONL line).")
//! @yah:handoff("JsonlWriter: append-only JSONL at `${dir}/<stem>-YYYY-MM-DD.jsonl`. Daily rotation on UTC date change (Howard Hinnant civil_from_days conversion — no chrono dep). Retention prune runs after rotation, default 30d (W159 pin); tolerates foreign files (README, wrong-stem, malformed-date) and skips them. Clock injection for test coverage (paused-clock stepping across midnight without sleeping).")
//! @yah:handoff("DeniedSampler: 1-in-N + first-N-of-burst per W159 §Sampled `denied.jsonl`. Defaults: burst_head=16, sample_every=100, burst_reset_after=60s. Quiet window re-opens the head so a second attack wave gets its own leading-edge sample.")
//! @yah:handoff("CheersForwarder: bounded mpsc + tokio task, batched by size OR age (`max_batch` / `max_batch_age`), bounded exponential backoff on retriable failures, terminal on 4xx. Generic over an `AuditHttp` trait for tests; production impl `HttpClient` uses reqwest. Wire body pinned as `{ v: 1, records: [...] }` with `INGEST_WIRE_VERSION = 1`. Forwarder queue is intentionally in-memory: local JSONL is the durable path, forwarder drops are backfill-recoverable.")
//! @yah:handoff("W127 projection contract landed in W159 §Audit journal — two new subsections: `Ingest wire body — pinned by R428-F2` (JSON shape + versioning + nullable-principal rule) and `W127 projection contract` (concrete CREATE TABLE + `on_behalf_of` generated column + dashboard query shape). Pins only what kamaji's forwarder emits + the columns the projection depends on; cheers is free to store more.")
//! @yah:handoff("Deps added: `async-trait 0.1` (AuditHttp trait), dev-dep tokio gets `test-util` feature for paused-clock forwarder tests. R428 relay + R428-F2 annotations moved from `journal.rs` to `audit/mod.rs` (canonical source rule) — journal.rs (the workload-log fan-in) now points a comment at the new home to stop future readers from expecting the two audit surfaces to be co-located.")
//! @yah:handoff("Test coverage: 37 new `audit::` tests (record: 7; writer: 10 including midnight rotation + retention prune + foreign-file survival; denied: 6 including burst reset window; forwarder: 8 including size trigger, age trigger, retry+accept re-flush, terminal drop, retry-exhaustion, queue-full drop, shutdown drain). Full `cargo test -p kamaji-bin` green: 170 lib + 2 + 1 integration.")
//! @yah:verify("cargo test -p kamaji-bin --lib audit::")
//! @yah:verify("cargo test -p kamaji-bin")

pub mod denied;
pub mod forwarder;
pub mod record;
pub mod writer;

pub use denied::{DeniedSampler, SamplerConfig};
pub use forwarder::{CheersForwarder, ForwarderConfig, ForwarderHandle};
pub use record::{AuditRecord, Outcome};
pub use writer::{JsonlWriter, WriterConfig};
