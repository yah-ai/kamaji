use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on any backward-incompatible change to the
/// message enums.
///
/// Both peers exchange [`crate::YubabaToKamaji::Hello`] /
/// [`crate::KamajiToYubaba::Welcome`] at connection start so a rolling
/// cluster can decode multiple versions during upgrades — the receiver picks
/// the highest version it supports that the sender also offers.
///
/// V1 is the initial scaffolding shape. Add a new variant when a breaking
/// rename or removal lands; additive variant introductions (new request kinds,
/// new ack kinds) ride on the `#[non_exhaustive]` enums without a version bump.
///
/// V2 (R599-F12) added `mesh` to [`crate::YubabaToKamaji::Deploy`]. Postcard is
/// positional, so a *field* added to an existing variant is breaking in both
/// directions even though a new *variant* would not be: an old kamaji decoding
/// a V2 `Deploy` trips on the trailing bytes, and a new kamaji decoding a V1
/// one runs off the end. The bump is what turns that into an explicit
/// handshake refusal naming the version, instead of a postcard error mid-frame.
/// Variants are appended, so `V1` keeps postcard discriminant 0 and the
/// `Hello`/`Welcome` exchange itself still decodes across the skew — which is
/// the whole point of doing version negotiation in the first frame.
///
/// V3 (R330-F33) made a bundle [`crate::YubabaToKamaji::Deploy`]
/// **asynchronous**: the `Ack` now means *admitted*, not *running*, and the
/// outcome is polled with [`crate::YubabaToKamaji::DeployStatus`]. Note what
/// kind of break this is — the message shapes are untouched, and the two new
/// variants are appended, so every frame still decodes across the skew. What
/// changed is what an existing frame *means*. That is more dangerous than a
/// decode error, not less: an old yubaba against a new kamaji would decode the
/// admission ack perfectly and report a workload deployed that had not yet
/// materialized, turning a deploy failure into a silent success. The bump is
/// what turns that into a handshake refusal instead.
///
/// V4 (R844-F2) added `ports` to [`crate::WorkloadEntry`] — the resolved
/// listen port(s) kamaji actually bound, which is the return path automatic
/// port allocation needs. Same postcard positionality as V2: a field appended
/// to an existing *struct* shifts every byte after it, so an old yubaba
/// decoding a V4 `WorkloadList` runs off into the next entry and a new yubaba
/// decoding a V3 one runs off the end. `#[serde(default)]` does not help —
/// postcard has no field names to notice are missing. The bump turns that into
/// a handshake refusal naming the version.
///
/// V5 (R852-B4) added `spec_digest` to [`crate::WorkloadEntry`] — the digest of
/// the spec kamaji was handed, which is what lets a reconciler tell an unchanged
/// declaration from a changed one instead of re-deploying (and, on the JIT tier,
/// re-binding) every workload on every sweep. Exactly the V4 situation: a field
/// appended to an existing *struct* shifts every byte after it, `#[serde(default)]`
/// cannot help because postcard has no field names to notice are missing, and the
/// bump is what turns a mid-frame decode error into a handshake refusal naming the
/// version.
///
/// V6 (R844-F15) added `named_ports` to [`crate::WorkloadEntry`] — the same
/// resolved ports keyed by port name, so a consumer can ask for `wss` instead
/// of guessing which of three numbers it is. Third instance of the identical
/// V2/V4/V5 situation, and it cost a debugging cycle to re-learn: the field was
/// first written with `#[serde(default, skip_serializing_if = ...)]` on the
/// theory that an optional field is compatible. On a *self-describing* format
/// it would be. Here it broke the wire against a peer of its OWN version —
/// `skip_serializing_if` omits bytes the positional decoder still reads,
/// so `List` came back `PeerClosed` — which is a nastier failure than the skew
/// this enum guards, because it needs no version mismatch at all. Rule, stated
/// once for whoever adds V7: **every field on a postcard message is mandatory
/// and always encoded; the only compatibility mechanism here is this bump.**
///
/// V7 (R844-F17) changed `expose.mesh.ports` on [`workload_spec::MeshExpose`]
/// from `Vec<u16>` to `Vec<MeshPort>`, so a manifest can *name* the ports every
/// tier below already spoke by name. Unlike V2/V4/V5/V6 this is not a field
/// appended to a struct — it is a field whose element type changed, inside
/// `Workload::Container(WorkloadSpec)`, which the `Deploy` frame carries. On
/// postcard a `Vec<u16>` is `len` followed by `len` varints; a `Vec<MeshPort>`
/// is `len` followed by `len` two-`Option` structs. An unbumped peer decoding
/// the wrong one does not fail cleanly at the port list — it consumes the wrong
/// number of bytes and then misreads *every field after it* in the spec, which
/// is how a wrong image or a wrong volume mount gets deployed instead of an
/// error. The V6 rule applies unchanged and is the reason: **every field on a
/// postcard message is mandatory and always encoded; the only compatibility
/// mechanism here is this bump.**
///
/// V8 (R870-F23) appends `files: Vec<InlineFile>` to
/// [`workload_spec::WorkloadSpec`] — config a workload reads at startup,
/// carried in the spec so the file and the process that reads it are one
/// deploy rather than two. Fourth instance of the V2/V4/V5/V6 shape, and it
/// nearly shipped unbumped on the same reasoning V6's stanza already refutes:
/// the field has `#[serde(default)]`, so an *old* spec decodes fine and the
/// JSON leg is genuinely unaffected. That is not the direction that breaks.
/// `default` only affects DEserialization; a V8 yubaba still *encodes* the
/// field — a length varint at minimum — and a V7 kamaji then reads it as
/// whatever the next field is and misparses from there. Caught in review by
/// @Ashguard:eclipse (session:e188ccc2) before it left the working tree, which
/// is why this paragraph names the wrong reasoning rather than only the rule:
/// **every field on a postcard message is mandatory and always encoded; the
/// only compatibility mechanism here is this bump.**
///
/// V9 (R605-T27) appends `microvm: MicroVmHealth` to
/// [`crate::NodeCapabilities`] — whether this node attached the microVM
/// backend and, if it did, a live re-probe of `/dev/kvm`. Fifth instance of
/// the V2/V4/V5/V6/V8 shape (a field appended to a struct carried inside an
/// existing message), same rule applies unchanged: every field on a postcard
/// message is mandatory and always encoded, so an unbumped peer on either
/// side misreads every byte after this one. Before this field the only
/// honest remote answer to "did this node attach the microVM backend" was
/// the kamaji startup journal line — `GET /health` returns a fixed body with
/// nothing per-backend, and the sibling wire had no capability query for this
/// backend at all (unlike `native_exec`, already covered by
/// [`crate::YubabaToKamaji::Capabilities`] / [`crate::NodeCapabilities`]).
///
/// The blast radius is one node: this protocol runs over a node-local UDS, and
/// yubaba and kamaji self-install as a pair, so the skew window is a restart
/// rather than a rolling fleet upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
    V9,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl ProtocolVersion {
    /// The version this build of `kamaji-proto` produces by default.
    pub const CURRENT: Self = Self::V9;
}
