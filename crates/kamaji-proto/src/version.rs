//! @yah:ticket(R880-B1, "hotship's proto-skew guard compares the tree against the last RELEASE, not against what the node runs — so it passes on a hotshipped node and breaks the kamaji/yubaba pair")
//! @yah:status(review)
//! @yah:at(2026-10-07T16:30:28Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R880)
//! @yah:severity(high)
//! @yah:next("The guard reads proto_max() of the tree against proto_max() of the last `release v*` commit, on the stated assumption that \"the node's other half is on the released wire\". That assumption is false on any node carrying a hotship — the normal state of this fleet. us-west-002/003 ran kamaji 0.8.40-h4 (unreleased) while v0.8.40 had just been cut, so tree-proto == release-proto, the guard saw no bump and said nothing, and the node's h4 wire was older than both. Compare against the NODE: the script already probes each one and /health reports the other half's version.</next>\n<parameter name=\"assumes\">Recovery used here was to ship the other half (--binaries kamaji) and then restart yubaba by hand on each node. yubaba's KamajiClient connects ONCE at boot with a 30s budget and falls back permanently, so shipping kamaji alone does not re-pair. Whether `hotship --binaries kamaji` should also restart yubaba is undecided.</parameter>\n<parameter name=\"verify\">Point a tree whose kamaji_proto has moved past a node's hotshipped half at that node with --binaries yubaba; today the guard is silent. After the fix it must refuse and name the node.")
//! @yah:gotcha("Hit for real 2026-09-18. `scripts/hotship.sh --nodes us-west-002,us-west-003 --binaries yubaba` passed the guard and broke the kamaji UDS on both nodes: kamaji logged `decode failed: postcard error: Serde Deserialization Error` once per retry, and yubaba fell back to its in-process containerd runtime with a single WARN. The only external symptom is that GET /health then OMITS kamaji_version entirely — easy to read as transient. This is the exact failure the guard's own R881-B7 comment predicts; the guard simply could not see it.")
//! @arch:see(scripts/hotship.sh)
//! @yah:verify("Point a tree whose kamaji_proto has moved past a node's hotshipped half at that node with --binaries yubaba; today the guard is silent. After the fix it must refuse and name the node.")
//! @yah:handoff("Guard now compares against each NODE. yubaba GET /health gains `kamaji_protocol: u32` (ProtocolVersion::CURRENT.number(), new const fn in oss/kamaji/crates/kamaji-proto/src/version.rs). scripts/hotship.sh `node_pair_proto` probes every --nodes target (mesh then LAN): kamaji_protocol + kamaji_version present = pair proven on V<n>; else UNPROVEN (old yubaba without the field, unreachable, or no kamaji handshaken — the 2026-09-18 symptom). Any mismatch or unproven node refuses a single-half restart ship and names the node; --no-restart warns; --allow-proto-skew overrides. Release-commit comparison removed. --allow-proto-skew help text updated.")
//! @yah:verify("cd oss/kamaji && cargo test -p kamaji-proto --lib number_tests (1/1); cd oss/yubaba && cargo test -p yubaba --lib health (52/52); node_pair_proto exercised against stubbed /health bodies: proven→13, no kamaji_version→unproven, pre-field yubaba→unproven; bash -n clean. Not run against a live node.")
//! @yah:gotcha("Rollout: no live node carries kamaji_protocol yet, so EVERY single-half hotship (--binaries yubaba or kamaji alone) refuses as unproven until a yubaba with this change is on that node — ship both halves once (--binaries kamaji,yubaba) per node, or --allow-proto-skew deliberately. Intended: unproven is never a match.")
//! @yah:handoff("Operator call A (2026-10-07): a kamaji restart-ship without yubaba in --binaries now also restarts the node's existing yubaba unit, so KamajiClient re-handshakes (scripts/hotship.sh unit:* activation arm). Uses the per-node raft floor already checked before the node; no sovereign-flag retire since yubaba bytes are unchanged. bash -n clean; not run against a live node.")

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
/// V10 (R850-T4) replaces the deploy ack. `AckKind::Deploy` is **removed** and
/// [`crate::KamajiToYubaba::DeployAck`] answers
/// [`crate::YubabaToKamaji::Deploy`] instead, carrying `hydrate:
/// Option<String>` — the JSON line `turso-backup-hydrate` printed when
/// hydrate-on-place restored the workload's volume, so a measured restore time
/// reaches the recovery journal without an operator copying it out of a log.
///
/// This is the first bump in the list that is NOT a field appended to a struct,
/// and it breaks the wire twice over, in two different ways worth naming
/// separately. (a) The new reply is an appended *variant*, which would normally
/// ride `#[non_exhaustive]` unbumped — but the rule that makes appended
/// variants safe only covers a new peer sending an old one something it can
/// still decode, and this replaces a reply an old peer expects: a V9 yubaba
/// receiving `DeployAck` fails the frame *mid-deploy*, on the reply, after
/// kamaji has already started the workload. (b) Deleting `AckKind::Deploy`
/// renumbers every remaining [`crate::AckKind`] discriminant, so a V9 `Stop`
/// ack decodes as `Probe` on a V10 peer and vice versa — a silent misread, not
/// an error. Either alone earns the bump; (b) is the one that would have been
/// easy to miss, because removing a variant looks like subtraction and postcard
/// makes it renumbering.
///
/// V11 (R885-T6) carries **two** changes that had to ride one bump, which is
/// the only reason this ticket waited on a sibling.
///
/// (a) `ResourceLimits::ephemeral_storage_mb` is **deleted** from
/// [`workload_spec::WorkloadSpec`], which the `Deploy` frame carries. A field
/// *removed* from a struct is the V2/V4/V5/V6/V8 situation run backwards and it
/// is no safer for being subtraction: postcard is positional, so every byte
/// after the hole shifts, and a V10 peer decoding a V11 spec misreads every
/// field following `resources` — a wrong image or a wrong volume mount
/// deployed, not an error. The field was deleted rather than kept because it
/// **lied**: it documented itself as a cap on the writable layer, no backend
/// ever enforced it as one, and its single live consumer read it as a floor.
/// Its replacement is an annotation (`yah.limits.scratch-floor-mb`,
/// [`workload_spec::WorkloadSpec::scratch_floor_mb`]), which costs no wire at
/// all — the same trade [`workload_spec::WorkloadSpec::cpu_limit_millis`] made.
///
/// (b) [`crate::WorkloadState::OomKilled`] is **appended**, so kamaji can tell
/// yubaba that a workload hit its `memory.max` rather than merely crashing.
/// R885-F3 built that classification node-local and deliberately stopped at the
/// UDS, leaving the upward report to this bump rather than spending a second
/// one. On its own this half would be the *benign* kind of change — an appended
/// variant on a `#[non_exhaustive]` enum, which only breaks a peer that is sent
/// the new discriminant — but (a) is not benign, and once a bump is being spent
/// the appended variant is free.
///
/// The blast radius is one node: this protocol runs over a node-local UDS, and
/// yubaba and kamaji self-install as a pair, so the skew window is a restart
/// rather than a rolling fleet upgrade.
///
/// V12 (R895-F1) **deletes** `netns_name` from [`crate::MeshAssignment`], which
/// the `Deploy` frame carries. Same positional break as V11(a) run on a nested
/// struct: postcard encodes every field, so a V11 peer decoding a V12
/// `MeshAssignment` runs off the end of the assignment and into the frame's
/// remaining bytes — and because the deleted field was the *last* one in the
/// struct and typed `Option<String>`, the byte a V11 decoder reads as the
/// option tag is whatever follows the assignment, which is a misread rather
/// than a reliable error.
///
/// The field was deleted rather than repointed because **nothing ever set it**:
/// both constructors ([`crate::MeshAssignment`]'s runtime twin `inlined`/`stub`)
/// hardcoded `None`, no allocator, flag or config produced a name, and its two
/// consumers — socket custody in `kamaji::containerd` and
/// `kamaji::jit::JitRuntime::deploy_on_demand` — therefore always bound in the
/// host namespace. It named a *yubaba-assigned per-workload WireGuard netns*,
/// a thing W343's adopted data plane does not have: WireGuard stays strictly
/// node-to-node and a workload's namespace is created node-locally by
/// `kamaji::container_net`, which now names it. Socket custody takes that name
/// from the site that created the namespace rather than deriving a second one.
///
/// Blast radius is the same one node as V11, for the same reason.
///
/// V13 (R896-F2) is **the bump that exists to stop most of the bumps above**,
/// and it is the last one a field change should ever cost. The payload fields
/// carrying a structure that accretes — `Workload` and `Option<MeshAssignment>`
/// on [`crate::YubabaToKamaji::Deploy`], `Workload` on
/// [`crate::YubabaToKamaji::GracefulUpgrade`]
/// / [`crate::KamajiToYubaba::WorkloadDescription`], `Vec<WorkloadEntry>` on
/// [`crate::KamajiToYubaba::WorkloadList`], `NodeCapabilities` on
/// [`crate::KamajiToYubaba::CapabilitiesReport`] — now ride a length-prefixed
/// JSON blob inside the frame rather than inline positional bytes
/// ([`crate::tolerant`]). A peer one field behind matches by NAME and skips what
/// it does not know, instead of consuming the wrong byte count and misreading
/// every field after it.
///
/// R896-S1 classified every bump in this list: **seven of the last ten**
/// (V2, V4, V5, V6, V8, V9, V11a) were byte-layout accidents this would have
/// absorbed; V7, a retype, would have failed cleanly at the field instead of
/// silently misdeploying; only V3 and V10 are semantic — a change in what an
/// existing frame MEANS — where a handshake refusal is the right and only
/// answer.
///
/// V12, landing beside this one, is an eighth of the same kind. It was not
/// absorbed — V12 deleted a field from the positional `mesh` before anything
/// wrapped it, so V12's own analysis stands. `Deploy.mesh` was wrapped
/// afterwards, still inside V13 (no V13 binary had been released, and hotship's
/// pairing guard means any node running one received it as a matched pair), so
/// the next [`crate::MeshAssignment`] field change is free where V12's was not.
///
/// **The rule the V6 and V8 stanzas state is now scoped, not repealed.** It
/// still holds verbatim for every field NOT wrapped: the frame header, the
/// message enums, and the small control types. Those stay positional
/// deliberately, and `Hello`/`Welcome` above all — a greeting a skewed peer
/// cannot parse fails with a frame error instead of naming the two versions,
/// which is the unreadable failure this enum exists to prevent. Leaving the
/// greeting's bytes untouched is what keeps the refusal legible across V13.
///
/// So: **adding a field to a wrapped payload no longer needs a bump; adding one
/// anywhere else still does.** What does still need a bump either way is a field
/// whose absence would mean something the older peer does not already do —
/// tolerance turns a loud break into a silent semantic skew, and only a default
/// equal to the pre-field behaviour makes that safe. A deletion additionally
/// needs the OLD peer's field to have carried `#[serde(default)]`, which is a
/// property you cannot add retroactively.
///
/// Two consequences at the roll. `scripts/hotship.sh`'s pairing guard refuses a
/// lone `--binaries yubaba` or `--binaries kamaji` across this bump, correctly —
/// it is a paired ship. And [`crate::spec_digest`]'s basis moved with the
/// encoding (domain prefix `v1` → `v2`), so every node reads its recorded
/// digests as stale and redeploys everything once.
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
    V10,
    V11,
    V12,
    V13,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl ProtocolVersion {
    /// The version this build of `kamaji-proto` produces by default.
    pub const CURRENT: Self = Self::V13;

    /// The `n` of `Vn`. Surfaced on yubaba's `GET /health` as
    /// `kamaji_protocol` so `scripts/hotship.sh` can compare a tree against the
    /// wire a NODE actually speaks, not against the last release (R880-B1).
    pub const fn number(self) -> u32 {
        self as u32 + 1
    }
}

#[cfg(test)]
mod number_tests {
    use super::ProtocolVersion;

    #[test]
    fn number_matches_the_variant_name() {
        assert_eq!(ProtocolVersion::V1.number(), 1);
        assert_eq!(ProtocolVersion::V13.number(), 13);
    }
}
