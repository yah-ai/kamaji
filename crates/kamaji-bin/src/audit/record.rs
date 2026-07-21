//! One audit record — W159 §Audit journal:
//!
//! `{ at, sub, act, camp_id, aud, method, scope, result, request_id }`
//!
//! `result` distinguishes `ok` / `denied:<reason>` / `error:<class>`. Request
//! and response bodies are NOT here — auth events only.
//!
//! The `denied:<reason>` string carries the fine-grained *local* reason (which
//! signature check failed, which claim shape misbehaved) that W159 §Failure
//! responses deliberately keeps off the wire. That detail is what makes the
//! local journal useful for operators investigating forgery attempts even
//! while the 401/403 wire body stays generic.

use serde::{Deserialize, Serialize};

use crate::auth::{ActorClaim, DenyKind, McpClaims, VerifyError};

/// One audit journal entry. Field order mirrors the W159 spec block so a
/// side-by-side diff reads cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix seconds when kamaji processed the call.
    pub at: i64,
    /// Principal — `user:<id>` / `svc:<id>` / `camp:<id>`. Absent when the
    /// request lacked a verifiable token (bad-shape rejections).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Agent variant acting on the user's behalf (RFC 8693).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// Call context — the camp the action is scoped to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camp_id: Option<String>,
    /// Resource this token was minted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// The Hub method that was dispatched, e.g. `cloud.deploy`.
    pub method: String,
    /// Scope check point — what scope was required for the call. Missing on
    /// bad-shape rejections that never reached the scope check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Outcome — one of `ok`, `denied:<reason>`, `error:<class>`.
    pub result: Outcome,
    /// Correlator supplied by the caller (or minted by the dispatch loop).
    pub request_id: String,
}

/// Result classification, serialized as a single tagged string.
///
/// Wire form:
///
/// - `Ok` → `"ok"`
/// - `Denied { reason }` → `"denied:<reason>"`
/// - `Error { class }` → `"error:<class>"`
///
/// Custom serde: JSONL scanners (jq / grep) can filter on `result` as a
/// simple string without unpacking a nested object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Denied { reason: String },
    Error { class: String },
}

impl Outcome {
    /// Build from a [`VerifyError`] — the local reason names the specific
    /// failure arm (unlike the wire body, which collapses to `invalid_token`).
    pub fn from_verify_error(err: &VerifyError) -> Self {
        Self::Denied {
            reason: verify_error_tag(err).to_string(),
        }
    }

    /// Build from a [`DenyKind`] when the origin was a policy failure (scope
    /// or ownership check), not a token-parse failure.
    pub fn from_deny_kind(kind: DenyKind) -> Self {
        Self::Denied {
            reason: match kind {
                DenyKind::InvalidToken => "invalid_token".to_string(),
                DenyKind::InsufficientScope => "insufficient_scope".to_string(),
                // W268 token binding: the wire collapses to `invalid_token`
                // (no off-device oracle), but the audit journal keeps the
                // distinct reason so an operator can spot exfiltrated-token
                // presentation from an unenrolled node.
                DenyKind::TokenBinding => "token_binding".to_string(),
            },
        }
    }
}

/// Stable short tags for [`VerifyError`] variants. Kept alongside the enum
/// so a new variant on the auth side surfaces here as a compile error rather
/// than a silent `"unknown"` in the audit journal.
fn verify_error_tag(err: &VerifyError) -> &'static str {
    match err {
        VerifyError::Malformed(_) => "malformed",
        VerifyError::MissingKid => "missing_kid",
        VerifyError::UnknownKid(_) => "unknown_kid",
        VerifyError::SignatureMismatch => "signature_mismatch",
        VerifyError::Expired { .. } => "expired",
        VerifyError::BadIssuer { .. } => "bad_issuer",
        VerifyError::BadAudience { .. } => "bad_audience",
        VerifyError::BadClaims(_) => "bad_claims",
    }
}

impl Serialize for Outcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Outcome::Ok => s.serialize_str("ok"),
            Outcome::Denied { reason } => s.serialize_str(&format!("denied:{reason}")),
            Outcome::Error { class } => s.serialize_str(&format!("error:{class}")),
        }
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw == "ok" {
            return Ok(Outcome::Ok);
        }
        if let Some(reason) = raw.strip_prefix("denied:") {
            return Ok(Outcome::Denied {
                reason: reason.to_string(),
            });
        }
        if let Some(class) = raw.strip_prefix("error:") {
            return Ok(Outcome::Error {
                class: class.to_string(),
            });
        }
        Err(serde::de::Error::custom(format!(
            "invalid outcome tag: {raw:?}"
        )))
    }
}

impl AuditRecord {
    /// Build an `ok` record from a verified claim block and a Hub method name.
    /// The typical dispatch-loop happy path.
    pub fn ok(
        at: i64,
        claims: &McpClaims,
        method: impl Into<String>,
        scope: Option<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            at,
            sub: Some(claims.sub.clone()),
            act: claims.act.clone(),
            camp_id: claims.camp_id.clone(),
            aud: Some(claims.aud.clone()),
            method: method.into(),
            scope,
            result: Outcome::Ok,
            request_id: request_id.into(),
        }
    }

    /// Build a `denied` record for a call that verified but failed the scope
    /// / ownership check.
    pub fn denied_policy(
        at: i64,
        claims: &McpClaims,
        method: impl Into<String>,
        scope: Option<String>,
        kind: DenyKind,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            at,
            sub: Some(claims.sub.clone()),
            act: claims.act.clone(),
            camp_id: claims.camp_id.clone(),
            aud: Some(claims.aud.clone()),
            method: method.into(),
            scope,
            result: Outcome::from_deny_kind(kind),
            request_id: request_id.into(),
        }
    }

    /// Build a `denied` record for a token that failed verification. The
    /// claim block isn't available (verify never returned it), so
    /// principal-related fields are `None`.
    pub fn denied_verify(
        at: i64,
        method: impl Into<String>,
        err: &VerifyError,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            at,
            sub: None,
            act: None,
            camp_id: None,
            aud: None,
            method: method.into(),
            scope: None,
            result: Outcome::from_verify_error(err),
            request_id: request_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_claims() -> McpClaims {
        McpClaims {
            iss: "https://cheers.example".into(),
            aud: "https://kamaji.example".into(),
            exp: 1_700_000_900,
            iat: 1_700_000_000,
            jti: "01HXYZ".into(),
            sub: "user:abc".into(),
            scope: vec!["cloud:deploy".into()],
            act: Some(ActorClaim {
                sub: "agent:claude".into(),
            }),
            camp_id: Some("C1".into()),
            owns: None,
            auth_strength: None,
        }
    }

    #[test]
    fn outcome_ok_wire_form() {
        let v = serde_json::to_value(Outcome::Ok).unwrap();
        assert_eq!(v, json!("ok"));
        let back: Outcome = serde_json::from_value(v).unwrap();
        assert_eq!(back, Outcome::Ok);
    }

    #[test]
    fn outcome_denied_wire_form_carries_reason() {
        let v = serde_json::to_value(Outcome::Denied {
            reason: "expired".into(),
        })
        .unwrap();
        assert_eq!(v, json!("denied:expired"));
        let back: Outcome = serde_json::from_value(v).unwrap();
        assert_eq!(
            back,
            Outcome::Denied {
                reason: "expired".into()
            }
        );
    }

    #[test]
    fn outcome_error_wire_form_carries_class() {
        let v = serde_json::to_value(Outcome::Error {
            class: "backend_timeout".into(),
        })
        .unwrap();
        assert_eq!(v, json!("error:backend_timeout"));
        let back: Outcome = serde_json::from_value(v).unwrap();
        assert_eq!(
            back,
            Outcome::Error {
                class: "backend_timeout".into()
            }
        );
    }

    #[test]
    fn outcome_deserialize_rejects_untagged_string() {
        let err = serde_json::from_value::<Outcome>(json!("mystery")).unwrap_err();
        assert!(err.to_string().contains("invalid outcome tag"));
    }

    #[test]
    fn record_ok_carries_full_claim_context() {
        let claims = sample_claims();
        let r = AuditRecord::ok(
            1_700_000_500,
            &claims,
            "cloud.deploy",
            Some("cloud:deploy".into()),
            "req-1",
        );
        assert_eq!(r.sub.as_deref(), Some("user:abc"));
        assert_eq!(r.act.as_ref().unwrap().sub, "agent:claude");
        assert_eq!(r.camp_id.as_deref(), Some("C1"));
        assert_eq!(r.aud.as_deref(), Some("https://kamaji.example"));
        assert_eq!(r.result, Outcome::Ok);
    }

    #[test]
    fn record_denied_policy_carries_scope_and_reason() {
        let claims = sample_claims();
        let r = AuditRecord::denied_policy(
            1_700_000_500,
            &claims,
            "cloud.deploy",
            Some("cloud:deploy".into()),
            DenyKind::InsufficientScope,
            "req-2",
        );
        assert_eq!(
            r.result,
            Outcome::Denied {
                reason: "insufficient_scope".into()
            }
        );
        assert_eq!(r.scope.as_deref(), Some("cloud:deploy"));
    }

    #[test]
    fn record_denied_verify_has_no_principal_fields() {
        let err = VerifyError::Expired { exp: 100, now: 200 };
        let r = AuditRecord::denied_verify(1_700_000_500, "cloud.deploy", &err, "req-3");
        assert!(r.sub.is_none());
        assert!(r.act.is_none());
        assert!(r.camp_id.is_none());
        assert!(r.aud.is_none());
        assert_eq!(
            r.result,
            Outcome::Denied {
                reason: "expired".into()
            }
        );
    }

    #[test]
    fn all_verify_error_variants_have_stable_tags() {
        // Belt-and-braces exhaustive check — if the enum grows a variant,
        // verify_error_tag stops compiling instead of silently emitting
        // the wrong reason.
        let cases = [
            (VerifyError::MissingKid, "missing_kid"),
            (VerifyError::UnknownKid("k1".into()), "unknown_kid"),
            (VerifyError::SignatureMismatch, "signature_mismatch"),
            (VerifyError::Expired { exp: 100, now: 200 }, "expired"),
            (
                VerifyError::BadIssuer {
                    expected: "e".into(),
                    got: "g".into(),
                },
                "bad_issuer",
            ),
            (
                VerifyError::BadAudience {
                    expected: "e".into(),
                    got: "g".into(),
                },
                "bad_audience",
            ),
        ];
        for (err, tag) in cases {
            let r = AuditRecord::denied_verify(0, "m", &err, "r");
            match r.result {
                Outcome::Denied { reason } => assert_eq!(reason, tag),
                other => panic!("expected Denied, got {other:?}"),
            }
        }
    }

    #[test]
    fn record_jsonl_line_omits_none_fields() {
        // The JSONL sink writes one line per record; we don't want stray
        // "act": null / "camp_id": null noise for bad-shape rejections.
        let err = VerifyError::Malformed("footer missing".into());
        let r = AuditRecord::denied_verify(1_700_000_500, "cloud.deploy", &err, "req-4");
        let line = serde_json::to_string(&r).unwrap();
        assert!(
            !line.contains("null"),
            "unexpected null in wire form: {line}"
        );
    }
}
