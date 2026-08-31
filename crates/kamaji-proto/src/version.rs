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
/// The blast radius is one node: this protocol runs over a node-local UDS, and
/// yubaba and kamaji self-install as a pair, so the skew window is a restart
/// rather than a rolling fleet upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolVersion {
    V1,
    V2,
    V3,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl ProtocolVersion {
    /// The version this build of `kamaji-proto` produces by default.
    pub const CURRENT: Self = Self::V3;
}
