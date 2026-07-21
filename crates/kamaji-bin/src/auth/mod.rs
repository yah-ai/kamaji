//! Cheers JWT verifier surface — local-only, no per-call AS round-trip.
//!
//! See `.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md`
//! §Canonical claim schema and §Kamaji startup and JWKS lifecycle. The
//! envelope is PASETO v4.public (W159 pinned 2026-06-03); `kid` rides in the
//! PASETO footer so the cache lookup is O(1) before signature verification.
//!
//! F2 scope: JWKS fetch + on-disk cache + atomic refresh + kid-miss refresh +
//! signature verification. Scope check, `owns:[...]` check, and the 401/403
//! response shapes are F3. The HTTPS server / JSON-RPC dispatch loop is later.
//!
//! @yah:ticket(R593-F6, "Token binding in kamaji-bin auth: presenting NodeId must be enrolled to the token subject where policy demands")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-07-17T17:47:15Z)
//! @yah:phase(P4)
//! @yah:parent(R593)
//! @yah:verify("cargo test -p kamaji-bin auth; unit: same valid PASETO from an unenrolled NodeId is denied; enrolled NodeId passes; UDS caller without NodeId unaffected when policy does not demand binding")
//! @yah:gotcha("TRUST-BOUNDARY code: adversarial second review required before this moves to review. Sequenced behind Wave-1 kamaji-lane tickets R592-T1 (backend-core extraction) + R592-T4 (wire rename) — same workspace lane, and T4 renames the very enums/sockets around auth.")
//! @yah:gotcha("Transport caveat from R593-F3 review (2026-07-02): the mshr acceptor hook gates Endpoint::accept_dispatch ONLY — raw Endpoint::accept() is deliberately hook-free. Whatever accept loop the kamaji-bin mshr listener uses MUST either go through accept_dispatch or manually consult Endpoint::acceptor(); an ungated raw-accept loop silently bypasses token binding.")
//! @yah:tier(Wizard)
//! @yah:depends_on(R593-F3)
//! @yah:depends_on(R593-F4)
//! @yah:depends_on(R593-F8)
//! @yah:depends_on(R593-F9)
//! @yah:depends_on(R592-T1)
//! @yah:depends_on(R592-T4)
//! @yah:handoff("LANDED + adversarially reviewed (clean). Token-binding gate in auth/policy.rs: new CallerNode{Local, Mshr(hex)} + Requirement.bind_node/require_node_binding() + enforce(claims, req, caller). Binding is checked FIRST (before scope/owns) so an off-device token yields NO scope oracle. Pure-local compare of owns['node'] (the enrollment row, embedded in the PASETO at mint) against the acceptor-provided NodeId hex — zero mshr/cheers dep, so the W268 DAG rule holds (enforced by the service, not the transport). Deny::token_binding() wires as 401 invalid_token, byte-identical to other 401s in status/error_code/body (no attacker oracle), but a distinct DenyKind::TokenBinding rides in-process so the audit journal records reason 'token_binding' (audit/record.rs). No-ops for CallerNode::Local (UDS/in-process trusted by SO_PEERCRED per server::peer_is_authorized). Tests: 8 new policy + 1 deny; 67 auth / 192 crate green; clippy clean. Files: auth/policy.rs, auth/deny.rs, audit/record.rs, auth/mod.rs (re-exports).")
//! @yah:handoff("ADVERSARIAL REVIEW (Miravel/Cleric, 2026-07-17): no bypass, no fail-open, no canonicalization issue (all mismatches fail safe=deny), DAG clean. Two findings — (1) FIXED: dropped CallerNode's Default(=Local) derive; a future dispatch loop can no longer silently no-op binding for an mshr caller by forgetting to classify it (now a compile error). (2) ACCEPTED-Low: error_description 'invalid token' distinguishes a binding-fail from expired/bad-sig 401s — a weak oracle only for an attacker who already holds the token; full 401 description-uniformity is out of scope per W159.")
//! @yah:next("END-TO-END TRUST still gated on F8 (authenticated admission ceremony — currently handoff, endpoint unwired) + F9 (server-mediated LAN-pair enrollment writer — review): F6 enforces binding correctly, but the owns['node'] rows it trusts only become a TRUSTWORTHY authorization signal once those authenticated enrollment writers land. Binding is a strict safety improvement in the meantime (never weakens the current posture).")
//! @yah:next("DISPATCH-LOOP / R593-T7 wiring (future, transport not adopted in kamaji-bin yet): build CallerNode::Mshr(node_hex) ONLY from the acceptor-authenticated id (Endpoint::accept_dispatch / acceptor()) — never a self-reported PairOffer/wire value or a raw accept() loop; source hex from mshr::NodeId's Display (HEXLOWER) so it matches the enrollment row's resource_id (case/format mismatch fails safe=deny but denies a legit node). Add a call-site unit test that enforce() receives CallerNode::Mshr for an mshr connection; consider a NodeId newtype only that acceptor path can mint (stronger than the Default removal already done here).")

pub mod claims;
pub mod config;
pub mod deny;
pub mod error;
pub mod jwks;
pub mod metadata;
pub mod policy;
pub mod verifier;

pub use claims::{ActorClaim, AuthStrength, McpClaims, OwnsClaim};
pub use config::AuthConfig;
pub use deny::{Deny, DenyKind, DEFAULT_REALM};
pub use error::{AuthError, VerifyError};
pub use jwks::{JwkKey, JwksCache, JwksDoc};
pub use metadata::{ProtectedResourceMetadata, SCOPE_VOCABULARY};
pub use policy::{enforce, CallerNode, Requirement, NODE_RESOURCE_KIND};
pub use verifier::AuthVerifier;
