//! Scope + ownership-list policy check — W159 §The wire Layer 2 — plus the
//! W268 §token-binding gate.
//!
//! Pure-function check against a verified [`McpClaims`] bag. Input is the
//! parsed token claims, a per-method [`Requirement`] (scopes required,
//! optionally a `(kind, id)` resource the call targets, optionally a
//! node-binding demand), and the [`CallerNode`] the request arrived over.
//! Output is `Ok(())` or a [`Deny`] ready for serialization onto the wire.
//!
//! No network calls. No state. Layer 1 (signature + standard claims) ran in
//! [`super::AuthVerifier::verify`] already; this is the second-pass policy
//! gate run by the dispatch loop (a later ticket) once it knows which Hub
//! method is being invoked and which resource id the params name.
//!
//! ## Token binding (W268)
//!
//! W268 makes enrollment "user U owns node:<NodeId>" a row in cheers's
//! ownership ledger; at mint time that row rides on the token as
//! `owns["node"] = [<NodeId-hex>, …]`. So checking that the *presenting
//! connection's* NodeId is enrolled to the token subject is a purely local
//! comparison here — no cheers dependency, no round-trip. This honours the
//! W268 DAG rule: the binding is **data in cheers, enforced by the service
//! (kamaji), never by the transport (mshr)**. Kamaji-bin deliberately does
//! not depend on mshr; the acceptor-authenticated NodeId is threaded in as its
//! canonical lower-hex string ([`CallerNode::Mshr`]), the same form the `node`
//! ownership row's `resource_id` carries.
//!
//! Binding is **where-policy-demands, not unconditional** ([`Requirement::
//! require_node_binding`]). It no-ops for [`CallerNode::Local`] — a UDS /
//! in-process caller has no machine identity to bind and is already gated at
//! the transport layer by `SO_PEERCRED` + the 0600 socket (see
//! `server::peer_is_authorized`); the mshr QUIC surface is where a remotely
//! exfiltrated token needs the gate.

use super::claims::McpClaims;
use super::deny::Deny;

/// The `owns[...]` resource-kind key under which enrolled machines live.
/// Verbatim with the fleet-admission (R593-F4) and LAN-pair (R593-F5/F9)
/// enrollment writers and yubaba's `NODE_RESOURCE_KIND` — an enrollment row is
/// `principal owns node:<NodeId-hex>`.
pub const NODE_RESOURCE_KIND: &str = "node";

/// The transport-authenticated machine identity of the calling connection.
///
/// This is the *acceptor's* view of who is on the other end of the wire, not
/// anything the token or the peer self-reports. For an mshr QUIC connection it
/// is the NodeId the handshake mutually authenticated; for a UDS / loopback /
/// in-process caller there is no machine identity at all.
///
/// SECURITY: a `Mshr` value MUST be sourced from the acceptor-authenticated id
/// (`Endpoint::accept_dispatch` / `Endpoint::acceptor()` — never a raw
/// `accept()` loop, which is hook-free and would let a self-reported id slip
/// past; see the module note on the auth mod). Passing a token-supplied or
/// otherwise-unauthenticated NodeId here would defeat the binding entirely.
///
/// Deliberately **not** `Default`: the dispatch loop must *consciously* decide
/// which transport a request arrived over. A `Default`-ing to `Local` would let
/// a caller that forgot to set the transport silently no-op binding for an mshr
/// connection — the footgun R593-F6's adversarial review flagged. With no
/// `Default`, "forgot to classify the caller" is a compile error, not a silent
/// bypass. (A stronger form — a NodeId newtype only the mshr acceptor path can
/// mint — is left to the dispatch-loop / transport-adoption ticket that owns
/// `accept_dispatch`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerNode {
    /// No machine identity on the wire — UDS, loopback, in-process. Local trust
    /// is established by `SO_PEERCRED`; token binding no-ops.
    Local,
    /// mshr QUIC connection. Carries the acceptor-authenticated NodeId in its
    /// canonical lower-hex form (matches `mshr::NodeId`'s `Display` and the
    /// `node` ownership row's `resource_id`).
    Mshr(String),
}

/// What a specific request requires of the caller's token.
///
/// Built per-call by the dispatch loop based on the Hub method being invoked.
/// `cloud.deploy(svc-xyz)` → `Requirement::scope("cloud:deploy").owns("service", "svc-xyz")`.
/// `cloud.list_services()` → `Requirement::scope("cloud:read")`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirement {
    /// All scopes that must be present on the token. Exact-match — W159
    /// §Scope vocabulary composition rules forbid wildcards and forbid
    /// implication trees (`camp:admin` does NOT imply `camp:read`).
    pub scopes: Vec<String>,
    /// Resource the call targets — `(resource_kind, resource_id)`. When
    /// present, the token's `owns[resource_kind]` must contain `resource_id`.
    pub owns: Option<(String, String)>,
    /// When set, the call demands **token binding** (W268 §token binding): the
    /// presenting connection's NodeId must be enrolled to the token subject —
    /// i.e. `owns["node"]` must contain the [`CallerNode::Mshr`] id. No-ops for
    /// [`CallerNode::Local`] (no NodeId to bind; local trust is peer-cred). Set
    /// via [`Self::require_node_binding`].
    pub bind_node: bool,
}

impl Requirement {
    /// Single-scope shorthand. Chain with [`Self::and_scope`] for multi.
    pub fn scope(scope: impl Into<String>) -> Self {
        Self {
            scopes: vec![scope.into()],
            owns: None,
            bind_node: false,
        }
    }

    /// Add an additional required scope. Idempotent — a duplicate is just
    /// checked twice, which is cheap.
    pub fn and_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Require ownership of `(kind, id)` in addition to the scope set.
    /// Convention: `kind` matches the resource-kind key in `owns:` —
    /// `"service"`, `"arch_doc"`, etc.
    pub fn owns(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.owns = Some((kind.into(), id.into()));
        self
    }

    /// Demand token binding for this call: an mshr-transport caller's NodeId
    /// must be enrolled to the token subject (W268 §token binding). Additive —
    /// compose with a scope requirement (`Requirement::scope(...).
    /// require_node_binding()`); a binding-only requirement is legal but leaves
    /// local UDS callers ungated by scope, so it should be the exception.
    pub fn require_node_binding(mut self) -> Self {
        self.bind_node = true;
        self
    }
}

/// Layer 2: enforce a [`Requirement`] against verified claims and the
/// [`CallerNode`] the request arrived over. Returns the first failure.
///
/// Order: **token binding** first, then scopes, then ownership. Binding runs
/// first on purpose — when a method demands it, an mshr caller whose NodeId is
/// not enrolled to the token subject is rejected with a uniform 401
/// ([`Deny::token_binding`]) *before* any scope is evaluated, so an
/// off-device (exfiltrated) token yields no scope oracle at all: it is simply
/// "useless off-device" (W268 §token binding). Among the remaining checks,
/// scopes are reported before ownership so a missing scope surfaces even when
/// the token also lacks the resource.
pub fn enforce(
    claims: &McpClaims,
    requirement: &Requirement,
    caller: &CallerNode,
) -> Result<(), Deny> {
    // Fail closed on an empty/defaulted requirement. A method that reaches
    // Layer 2 with no required scope, no ownership predicate, AND no binding
    // demand has no authorization gate at all — treating that as "allow" would
    // authorize *every* caller for it. An unset requirement is a wiring bug,
    // not a deliberately public method, so deny rather than wave it through.
    if requirement.scopes.is_empty() && requirement.owns.is_none() && !requirement.bind_node {
        return Err(Deny::insufficient_scope(
            Option::<&str>::None,
            Option::<&str>::None,
        ));
    }
    // Token binding (W268). Only enforced where the method demands it, and only
    // for a caller that actually presents a machine identity: a Local (UDS /
    // in-process) caller has no NodeId to bind and is already trusted via
    // peer-cred, so binding no-ops for it — "where-policy-demands, not
    // unconditional". An mshr caller must have the presenting NodeId in the
    // token's `owns["node"]` list, i.e. be enrolled to the subject.
    if requirement.bind_node {
        if let CallerNode::Mshr(node_hex) = caller {
            let enrolled = claims
                .owns
                .as_ref()
                .map(|o| o.contains(NODE_RESOURCE_KIND, node_hex))
                .unwrap_or(false);
            if !enrolled {
                return Err(Deny::token_binding());
            }
        }
    }
    for required in &requirement.scopes {
        if !claims.scope.iter().any(|s| s == required) {
            return Err(Deny::insufficient_scope(
                Some(required.clone()),
                requirement.owns.as_ref().map(|(_, id)| id.clone()),
            ));
        }
    }
    if let Some((kind, id)) = &requirement.owns {
        let owned = claims
            .owns
            .as_ref()
            .map(|o| o.contains(kind, id))
            .unwrap_or(false);
        if !owned {
            // No specific scope to surface — all scopes present — so the
            // `WWW-Authenticate` `scope=` parameter stays None. The body's
            // `resource` field reports which resource the request targeted.
            return Err(Deny::insufficient_scope(
                Option::<&str>::None,
                Some(id.clone()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::claims::{AuthStrength, McpClaims, OwnsClaim};
    use std::collections::BTreeMap;

    fn claims_with(scopes: &[&str], owns: Option<BTreeMap<String, Vec<String>>>) -> McpClaims {
        McpClaims {
            iss: "https://cheers.test".into(),
            aud: "https://kamaji.test".into(),
            exp: 2_000_000_000,
            iat: 1_700_000_000,
            jti: "01HTEST".into(),
            sub: "user:abc".into(),
            scope: scopes.iter().map(|s| s.to_string()).collect(),
            act: None,
            camp_id: Some("C1".into()),
            owns: owns.map(|by_kind| OwnsClaim { by_kind }),
            auth_strength: Some(AuthStrength::Bootstrap),
        }
    }

    #[test]
    fn passes_when_scope_present_no_owns_required() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:read");
        assert!(enforce(&claims, &req, &CallerNode::Local).is_ok());
    }

    #[test]
    fn empty_requirement_is_denied_fail_closed() {
        // A defaulted/empty Requirement carries no scope and no ownership
        // predicate. Layer 2 must DENY it (fail-closed) rather than authorize
        // every caller — a method with no explicit requirement is an unwired
        // bug, not a public endpoint. Holds even for a richly-scoped token.
        let claims = claims_with(&["cloud:read", "cloud:deploy"], None);
        let deny = enforce(&claims, &Requirement::default(), &CallerNode::Local).unwrap_err();
        assert_eq!(deny.status_code(), 403);
        assert!(deny.scope.is_none());
        assert!(deny.resource.is_none());

        // An explicitly-constructed empty requirement denies the same way.
        let empty = Requirement {
            scopes: vec![],
            owns: None,
            bind_node: false,
        };
        assert!(enforce(&claims, &empty, &CallerNode::Local).is_err());
    }

    #[test]
    fn fails_when_scope_missing() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:deploy");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.status_code(), 403);
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
        assert!(deny.resource.is_none());
    }

    #[test]
    fn requires_all_scopes_present() {
        let claims = claims_with(&["cloud:read"], None);
        let req = Requirement::scope("cloud:read").and_scope("cloud:deploy");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
    }

    #[test]
    fn owns_check_passes_when_resource_in_list() {
        let mut owns = BTreeMap::new();
        owns.insert("service".into(), vec!["svc-abc".into(), "svc-xyz".into()]);
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        assert!(enforce(&claims, &req, &CallerNode::Local).is_ok());
    }

    #[test]
    fn owns_check_fails_when_resource_missing() {
        let mut owns = BTreeMap::new();
        owns.insert("service".into(), vec!["svc-abc".into()]);
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.status_code(), 403);
        // No missing scope to report — only the resource id.
        assert!(deny.scope.is_none());
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn owns_check_fails_when_no_owns_claim_at_all() {
        let claims = claims_with(&["cloud:deploy"], None);
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn owns_check_fails_when_kind_missing_even_if_other_kinds_present() {
        let mut owns = BTreeMap::new();
        owns.insert("arch_doc".into(), vec!["doc-1".into()]);
        let claims = claims_with(&["cloud:deploy"], Some(owns));
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn scope_check_runs_before_owns_check() {
        // Token lacks BOTH the scope and the resource. The reported failure
        // must be the scope — Layer 2 fails on scopes first so the operator
        // grants scope before worrying about ownership.
        let claims = claims_with(&[], None);
        let req = Requirement::scope("cloud:deploy").owns("service", "svc-xyz");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("cloud:deploy"));
        // The scope-failure path also reports the targeted resource — F3's
        // contract: when both fail, surface scope first but include resource
        // context so the operator sees the full intent.
        assert_eq!(deny.resource.as_deref(), Some("svc-xyz"));
    }

    #[test]
    fn no_admin_implication_tree() {
        // `camp:admin` does NOT imply `camp:read` — W159 §Scope composition
        // rule 3. Kamaji does exact-match only.
        let claims = claims_with(&["camp:admin"], None);
        let req = Requirement::scope("camp:read");
        let deny = enforce(&claims, &req, &CallerNode::Local).unwrap_err();
        assert_eq!(deny.scope.as_deref(), Some("camp:read"));
    }

    // ── W268 token binding ──────────────────────────────────────────────────

    /// Representative NodeId hex — the string form the acceptor authenticates
    /// and the `node` ownership row's `resource_id` carries. Content is opaque
    /// to the check (pure equality), so a short stand-in is faithful.
    const ENROLLED_NODE: &str = "aaaa0000bbbb1111cccc2222dddd3333";
    const OTHER_NODE: &str = "9999888877776666555544443333222";

    fn node_owns(hex: &str) -> BTreeMap<String, Vec<String>> {
        let mut owns = BTreeMap::new();
        owns.insert("node".into(), vec![hex.into()]);
        owns
    }

    #[test]
    fn binding_passes_when_mshr_node_is_enrolled_to_subject() {
        let claims = claims_with(&["cloud:deploy"], Some(node_owns(ENROLLED_NODE)));
        let req = Requirement::scope("cloud:deploy").require_node_binding();
        assert!(enforce(&claims, &req, &CallerNode::Mshr(ENROLLED_NODE.into())).is_ok());
    }

    #[test]
    fn binding_denies_valid_token_from_unenrolled_mshr_node() {
        // THE property under test: an exfiltrated-but-signature-valid token is
        // useless off-device. The token subject owns ENROLLED_NODE, but the
        // connection presents from OTHER_NODE → denied, and the denial is a
        // 401 `invalid_token` (no scope oracle, no "you hold a valid token"
        // confirmation).
        let claims = claims_with(&["cloud:deploy"], Some(node_owns(ENROLLED_NODE)));
        let req = Requirement::scope("cloud:deploy").require_node_binding();
        let deny = enforce(&claims, &req, &CallerNode::Mshr(OTHER_NODE.into())).unwrap_err();
        assert_eq!(deny.kind, crate::auth::deny::DenyKind::TokenBinding);
        assert_eq!(deny.status_code(), 401);
        assert_eq!(deny.error_code(), "invalid_token");
        assert!(deny.scope.is_none());
    }

    #[test]
    fn binding_denies_when_token_has_no_node_owns_at_all() {
        let claims = claims_with(&["cloud:deploy"], None);
        let req = Requirement::scope("cloud:deploy").require_node_binding();
        let deny = enforce(&claims, &req, &CallerNode::Mshr(ENROLLED_NODE.into())).unwrap_err();
        assert_eq!(deny.kind, crate::auth::deny::DenyKind::TokenBinding);
    }

    #[test]
    fn binding_noops_for_local_caller_even_when_demanded() {
        // A UDS / in-process caller has no NodeId to bind and is trusted by
        // peer-cred; binding is where-policy-demands, and Local has nothing to
        // bind → the scope requirement still governs, binding waves through.
        let claims = claims_with(&["cloud:deploy"], None);
        let req = Requirement::scope("cloud:deploy").require_node_binding();
        assert!(enforce(&claims, &req, &CallerNode::Local).is_ok());
    }

    #[test]
    fn unenrolled_mshr_node_passes_when_binding_not_demanded() {
        // Where policy does NOT demand binding, the presenting NodeId is
        // irrelevant — even an mshr caller absent from owns["node"] passes.
        let claims = claims_with(&["cloud:read"], Some(node_owns(ENROLLED_NODE)));
        let req = Requirement::scope("cloud:read"); // no require_node_binding()
        assert!(enforce(&claims, &req, &CallerNode::Mshr(OTHER_NODE.into())).is_ok());
    }

    #[test]
    fn binding_is_checked_before_scope_so_off_device_token_leaks_no_scope() {
        // Token lacks BOTH the required scope AND enrollment for the presenting
        // node. Binding runs first, so the caller sees a uniform 401 binding
        // denial — never the 403 `insufficient_scope` that would confirm which
        // scope a stolen token is missing.
        let claims = claims_with(&[], Some(node_owns(ENROLLED_NODE)));
        let req = Requirement::scope("cloud:deploy").require_node_binding();
        let deny = enforce(&claims, &req, &CallerNode::Mshr(OTHER_NODE.into())).unwrap_err();
        assert_eq!(deny.kind, crate::auth::deny::DenyKind::TokenBinding);
        assert_eq!(deny.status_code(), 401);
        assert!(deny.scope.is_none(), "off-device token must leak no scope");
    }

    #[test]
    fn binding_only_requirement_is_a_gate_for_mshr_callers() {
        // A binding-only Requirement (no scope, no owns) is NOT fail-closed —
        // it is a real gate for mshr callers.
        let req = Requirement::default().require_node_binding();

        // Enrolled mshr caller passes.
        let enrolled = claims_with(&[], Some(node_owns(ENROLLED_NODE)));
        assert!(enforce(&enrolled, &req, &CallerNode::Mshr(ENROLLED_NODE.into())).is_ok());

        // Unenrolled mshr caller is denied (a gate exists — not waved through
        // as an empty requirement would be).
        let deny = enforce(&enrolled, &req, &CallerNode::Mshr(OTHER_NODE.into())).unwrap_err();
        assert_eq!(deny.kind, crate::auth::deny::DenyKind::TokenBinding);
    }
}
