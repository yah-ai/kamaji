//! `kamaji-proto` — Yubaba ↔ Kamaji wire protocol.
//!
//! Wire shape:
//!
//! ```text
//! [u32 LE length][postcard-encoded payload]
//! ```
//!
//! The crate has no I/O. Callers (yubaba, kamaji) own the
//! [`tokio::net::UnixStream`](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html)
//! and push/pull framed bytes through [`encode_frame`] / [`decode_frame`].
//!
//! Payload fields carrying a structure that *accretes* — the workload spec, the
//! workload entries, the node capabilities — are encoded as a length-prefixed
//! JSON blob inside that frame rather than inline (R896-F2). A peer one field
//! behind skips a field it does not know instead of misreading every byte after
//! it. See [`tolerant`] for the bound on which fields get this and why the frame
//! and the greeting deliberately do not.
//!
//! Both directions are versioned via [`ProtocolVersion`]; peers exchange
//! [`YubabaToKamaji::Hello`] / [`KamajiToYubaba::Welcome`] at connection start.
//! The handshake is **exact equality, not negotiation**: kamaji refuses any
//! version that is not its own `CURRENT` (`kamaji-bin/src/server.rs`). This
//! paragraph used to claim the receiver "picks the highest version it supports
//! that the sender also offers" — it never did, and every operational note in
//! the tree (`scripts/hotship.sh`, R876) describes the refusal instead. Corrected
//! under R896-S1, because roll-safety reasoning was being done from the wrong
//! sentence.
//!
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//!
//! @yah:relay(R896, "Evolvable kamaji wire envelope: stop the schema migrating into annotations")
//! @yah:at(2026-09-11T22:26:53Z)
//! @yah:status(handoff)
//! @yah:assignee(agent:user-custom-char-gul2)
//! @yah:next("From the 2026-09-11 yubaba/kamaji architecture review (chat session:d6fc1d54): the positional-postcard wire makes every WorkloadSpec field change a fleet-wide coordinated roll (R885-T6's three-node bump), so new schema-shaped facts now land in annotations instead of fields — yah.limits.*, yah.durability.*, yah.placement.* — a stringly second WorkloadSpec that bypasses the JSON schema, TS export and serde validation, with R885-T6's handoff naming the cost driver outright (\"annotation not field, because a field costs exactly the wire bump\"). Substrate MARKERS (yah.exec, yah.sandbox) are correct as annotations and stay. This track exists to make single-node hotships able to cross a field change, which is what keeps the chaos-survivability property cheap permanently.")
//! @arch:see(oss/yah-base/crates/workload-spec/src/lib.rs)

pub mod codec;
pub mod digest;
pub mod messages;
pub mod tolerant;
pub mod version;

pub use codec::{decode_frame, encode_frame, Error, MAX_FRAME_BYTES};
pub use digest::{spec_digest, SpecDigest};
pub use messages::{
    AckKind, DrainBudget, DrainOutcome, DrainPhase, ErrorCode, ExitStatus, KamajiToYubaba,
    MeshAssignment, MicroVmHealth, NodeCapabilities, ProbeStatus, RequestId, WireguardPeer,
    WorkloadEntry, WorkloadId, WorkloadState, YubabaToKamaji,
};
pub use version::ProtocolVersion;
