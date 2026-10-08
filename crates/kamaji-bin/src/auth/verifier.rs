//! Token verifier — the load-bearing public surface of the auth module.
//!
//! Binds cheers-verify's JWKS cache + [`KeySetVerifier`] (R731-F6) to kamaji's
//! config and claim shape in one async `verify` call. Matches
//! W159 §The wire — Layer 1 line-for-line:
//!
//! - Signature verifies against an issuer-role JWKS key (or a self-signer key
//!   within its ceiling; assertion keys never verify here).
//! - `iss` is the expected cheers AS.
//! - `aud` matches this kamaji's resource URI.
//! - `exp` is in the future.
//!
//! Layer 2 (scope + `owns:[...]` membership) is F3 — this module exposes the
//! parsed [`McpClaims`] and stops there.
//!
//! @yah:ticket(R592-F3, "Golden-token vectors: one PASETO v4.public envelope, shared fixtures every minter and verifier must pass")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-02T20:26:03Z)
//! @yah:phase(P2)
//! @yah:parent(R592)
//! @yah:next("Minters: cheers-server (SessionAuthority secret minter), cheers-mock (oss/kamaji/crates/cheers-mock), yubaba local service-principal minter (oss/yubaba/crates/yubaba/src/cheers_client.rs — READ ONLY, lane is peer-active: replicate its envelope in the fixtures, add a next-line on R592 for its in-crate test later). Verifiers: kamaji-bin auth/verifier.rs (+jwks.rs), cloud-admin (crates/yah/cloud-admin).")
//! @yah:next("Shape: deterministic fixture set (pinned test seed) of golden tokens + JWKS JSON — valid cases plus invalid: expired, wrong aud, wrong iss, tampered sig, unknown kid, footer/kid games. Home fixtures in oss/cheers/crates/cheers-test-support (exists for exactly this). Tests in cheers-server, cheers-verify, cheers-mock, kamaji-bin all consume the SAME files by path or include_str.")
//! @yah:next("Envelope to pin: sub/iss/aud/scope/exp/kid/jti shapes + the 64-byte secret layout (32 seed + 32 pub) + iss==aud self-scoping rule — see R427 handoff/gotcha notes in oss/yubaba/crates/yubaba/src/identity.rs header.")
//! @yah:verify("cd oss/cheers && cargo test -p cheers-test-support -p cheers-server -p cheers-verify; cd ../kamaji && cargo test -p kamaji-bin && cargo test -p cheers-mock")
//! @yah:tier(Warrior)
//! @yah:handoff("Delivered: golden-token fixture suite in oss/cheers/crates/cheers-test-support (15 committed files: valid_user + valid_svc + 6 invalid-envelope cases + JWKS; pinned seed 01..20, FIXTURE_NOW=1.7e9, no wall clock anywhere; regeneration test re-mints byte-identical from seed). Consumer tests: cheers-server, cheers-verify, cheers-mock, kamaji-bin (9 new). ALL GREEN both workspaces. HEADLINE FINDING -> R592-B7 (blocker): two non-interoperable PASETO conventions in production; cheers-server mint_mcp tokens fail kamaji-bin with MissingKid; cheers-mock diverges from the real minter it mocks. Secondary -> R592-B8: cloud-admin has no iss/aud validation at all. Both resolved under R592-B7 (2026-07-02).")
//!

use std::sync::Arc;

use cheers_verify::{HttpJwksSource, JwksCache, JwksCacheConfig, KeySet, KeySetVerifier};

use super::claims::McpClaims;
use super::config::AuthConfig;
use super::error::{JwksError, VerifyError};

/// The verifier. Construct once via [`AuthVerifier::boot`]; share via `Arc`.
///
/// Since R731-F6 the W159 cache (first fetch, atomic refresh, rate-limited
/// kid-miss refetch, restart from disk) and the key-role rules live in
/// cheers-verify; this type binds them to kamaji's [`AuthConfig`] and claim
/// shape. Role enforcement: issuer keys sign any `sub`, assertion keys are
/// always refused, self-signer keys only for their own `sub` within a
/// cheers-issued ceiling.
#[derive(Debug)]
pub struct AuthVerifier {
    config: AuthConfig,
    cache: Arc<JwksCache>,
    verifier: KeySetVerifier,
}

impl AuthVerifier {
    /// Boot per W159 §Restart resilience (see `cheers_verify::JwksCache::boot`):
    /// no cache + AS unreachable is [`JwksError::BootFetchFatal`].
    pub async fn boot(config: AuthConfig) -> Result<Self, JwksError> {
        // Fail closed BEFORE any network fetch: a plaintext (`http://`,
        // non-loopback) issuer means the JWKS would be fetched over a channel
        // an on-path attacker can rewrite — a key-substitution → token-forgery
        // vector. Every later refresh reuses this source, so gating boot
        // covers every fetch path.
        config.validate_issuer()?;
        let source = HttpJwksSource::new(config.jwks_url())?;
        let cache_config = JwksCacheConfig {
            cache_path: config.cache_path.clone(),
            refresh_interval: config.refresh_interval,
            kid_miss_rate_limit: config.kid_miss_rate_limit,
            serve_stale_on_failure: config.serve_stale_on_failure,
        };
        let cache = Arc::new(JwksCache::boot(Box::new(source), cache_config).await?);
        Ok(Self {
            config,
            verifier: KeySetVerifier::from_cache(cache.clone()),
            cache,
        })
    }

    /// Verify a PASETO v4.public token: kid lookup (one rate-limited refetch
    /// on miss), key role, signature, `iss`, `aud`, `exp`. Per-failure error
    /// variants map 1:1 to the W159 §Failure responses table.
    pub async fn verify(&self, token: &str, now: i64) -> Result<McpClaims, VerifyError> {
        self.verifier
            .verify(
                token,
                now,
                &self.config.cheers_issuer,
                Some(&self.config.expected_aud),
            )
            .await
    }

    /// Refresh JWKS from the AS. Used by the background refresh task and
    /// directly available for a manual refresh after a known rotation.
    pub async fn refresh(&self) -> Result<(), JwksError> {
        self.cache.refresh().await
    }

    /// Spawn the background refresh task. Returns the join handle so the
    /// caller can abort on shutdown. The task ticks at
    /// `config.refresh_interval`; AS failures are logged but do not cancel
    /// the loop (W159: rotation is overlap-windowed, so missing one tick
    /// rarely loses verifiability).
    pub fn spawn_refresh_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.refresh_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate fire — boot already populated the cache.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!(error = ?e, "background JWKS refresh failed; continuing");
                }
            }
        })
    }

    /// The key set verifies currently read — for operator surfaces and tests.
    pub fn jwks(&self) -> Arc<KeySet> {
        self.cache.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::KeyRole;
    use cheers_verify::{JwkKey, JwksDoc};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version4::{PublicToken, V4};

    /// Persist `doc` as a fresh on-disk cache so `boot` serves it without an
    /// HTTP fetch.
    fn seed_cache(path: &std::path::Path, doc: JwksDoc) {
        let set = KeySet::from_doc(doc).unwrap();
        cheers_verify::jwks::write_atomic(path, &set, std::time::SystemTime::now()).unwrap();
    }

    fn keypair() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().expect("keypair gen")
    }

    fn pubkey_bytes(kp: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        let bytes = kp.public.as_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    }

    fn jwks_doc_for(kid: &str, kp: &AsymmetricKeyPair<V4>) -> JwksDoc {
        jwks_doc_with_role(kid, kp, "https://cheers.test", KeyRole::Issuer)
    }

    fn jwks_doc_with_role(
        kid: &str,
        kp: &AsymmetricKeyPair<V4>,
        principal: &str,
        role: KeyRole,
    ) -> JwksDoc {
        JwksDoc {
            keys: vec![JwkKey::ed25519(kid, &pubkey_bytes(kp), principal, role)],
        }
    }

    fn mint_token(
        secret: &AsymmetricSecretKey<V4>,
        kid: &str,
        payload: serde_json::Value,
    ) -> String {
        // Mint via the low-level v4 PublicToken API. Mirrors the verifier's
        // path: raw JSON bytes in, raw JSON bytes out — sidestepping
        // pasetors's high-level Claims wrapper that constrains registered
        // claims to be strings (W159 wants i64 `exp`/`iat`).
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let footer_bytes = format!(r#"{{"kid":"{kid}"}}"#).into_bytes();
        PublicToken::sign(secret, &payload_bytes, Some(&footer_bytes), None).expect("sign succeeds")
    }

    fn good_payload(
        iss: &str,
        aud: &str,
        exp: i64,
        iat: i64,
        sub: &str,
        scope: &[&str],
    ) -> serde_json::Value {
        serde_json::json!({
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "iat": iat,
            "jti": "01HTEST",
            "sub": sub,
            "scope": scope,
        })
    }

    async fn build_verifier_with_doc(doc: JwksDoc) -> AuthVerifier {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("jwks.json");
        // Persist a synthetic cache so `boot` takes the cache-present arm
        // without making a real HTTP fetch.
        seed_cache(&cache_path, doc);
        let config = AuthConfig::new("https://cheers.test", "https://kamaji.test")
            .with_cache_path(cache_path);
        // Keep the temp dir alive via leak — tests exit before it matters.
        std::mem::forget(tmp);
        AuthVerifier::boot(config).await.unwrap()
    }

    /// R731-B1: a service principal's assertion key is in the published set,
    /// but a token it signs claiming `sub=user:x` must not verify. The
    /// platform (issuer) key in the same set still does.
    #[tokio::test]
    async fn rejects_token_signed_by_service_principal_assertion_key() {
        let platform = keypair();
        let svc = keypair();
        let mut doc = jwks_doc_for("platform-1", &platform);
        doc.keys.extend(
            jwks_doc_with_role("svc-key-1", &svc, "svc:robot", KeyRole::Assertion).keys,
        );
        let verifier = build_verifier_with_doc(doc).await;
        let payload = || {
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "user:x",
                &["cloud:deploy"],
            )
        };

        let forged = mint_token(&svc.secret, "svc-key-1", payload());
        match verifier.verify(&forged, 1_800_000_000).await {
            Err(VerifyError::KeyRoleRejected { kid, role, .. }) => {
                assert_eq!(kid, "svc-key-1");
                assert_eq!(role, KeyRole::Assertion);
            }
            other => panic!("expected KeyRoleRejected, got {other:?}"),
        }

        let legit = mint_token(&platform.secret, "platform-1", payload());
        let claims = verifier.verify(&legit, 1_800_000_000).await.expect("platform key verifies");
        assert_eq!(claims.sub, "user:x");
    }

    #[tokio::test]
    async fn rejects_token_signed_by_self_signer_key() {
        let kp = keypair();
        let doc = jwks_doc_with_role("ss-1", &kp, "svc:robot", KeyRole::SelfSigner);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "ss-1",
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "svc:robot",
                &["cloud:deploy"],
            ),
        );
        assert!(matches!(
            verifier.verify(&token, 1_800_000_000).await,
            Err(VerifyError::KeyRoleRejected { role: KeyRole::SelfSigner, .. })
        ));
    }

    #[tokio::test]
    async fn verifies_well_formed_token() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );

        let claims = verifier.verify(&token, 1_800_000_000).await.unwrap();
        assert_eq!(claims.sub, "user:abc");
        assert_eq!(claims.scope, vec!["cloud:deploy"]);
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &kp.secret,
            "k-unknown",
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        // Cheers is unreachable in tests, so the kid-miss refresh path is a
        // no-op and we get UnknownKid back.
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKid(kid) if kid == "k-unknown"));
    }

    #[tokio::test]
    async fn rejects_signature_mismatch() {
        let signing_kp = keypair();
        let other_kp = keypair();
        // JWKS publishes the WRONG key for kid k1.
        let doc = jwks_doc_for("k1", &other_kp);
        let verifier = build_verifier_with_doc(doc).await;

        let token = mint_token(
            &signing_kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::SignatureMismatch));
    }

    #[tokio::test]
    async fn rejects_expired() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://kamaji.test",
                1_500_000_000,
                1_400_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::Expired { .. }));
    }

    #[tokio::test]
    async fn rejects_bad_issuer() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://wrong.example",
                "https://kamaji.test",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::BadIssuer { .. }));
    }

    #[tokio::test]
    async fn rejects_bad_audience() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let token = mint_token(
            &kp.secret,
            "k1",
            good_payload(
                "https://cheers.test",
                "https://wrong-kamaji.example",
                2_000_000_000,
                1_700_000_000,
                "user:abc",
                &["cloud:deploy"],
            ),
        );
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::BadAudience { .. }));
    }

    #[tokio::test]
    async fn rejects_token_without_footer() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        // Mint a token with no footer at all (signature still valid against
        // the JWKS key — what fails is the lookup, because we cannot know
        // which key to verify against without a kid).
        let payload = good_payload(
            "https://cheers.test",
            "https://kamaji.test",
            2_000_000_000,
            1_700_000_000,
            "user:abc",
            &["cloud:read"],
        );
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let token = PublicToken::sign(&kp.secret, &payload_bytes, None, None).unwrap();
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(matches!(err, VerifyError::MissingKid), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_token_with_footer_missing_kid() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        // Footer is present but the kid field is missing — Deserialize fails
        // at the Footer struct, surfaced as Malformed("footer: ...").
        let payload = good_payload(
            "https://cheers.test",
            "https://kamaji.test",
            2_000_000_000,
            1_700_000_000,
            "user:abc",
            &["cloud:read"],
        );
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let token =
            PublicToken::sign(&kp.secret, &payload_bytes, Some(br#"{"other":"x"}"#), None).unwrap();
        let err = verifier.verify(&token, 1_800_000_000).await.unwrap_err();
        assert!(
            matches!(err, VerifyError::Malformed(ref m) if m.starts_with("footer:")),
            "got {err:?}"
        );
    }

    // The kid-miss rate-limit test moved with the cache to cheers-verify
    // (`jwks::tests::kid_miss_refresh_is_rate_limited`, R731-F6).

    #[tokio::test]
    async fn boot_no_cache_no_as_is_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("jwks.json");
        let config = AuthConfig::new("http://127.0.0.1:1/", "https://kamaji.test")
            .with_cache_path(cache_path);
        let result = AuthVerifier::boot(config).await;
        // `Result::unwrap_err` requires `T: Debug`; avoid that bound on
        // `AuthVerifier` by matching the result form directly.
        match result {
            Err(JwksError::BootFetchFatal { .. }) => {}
            Err(other) => panic!("expected BootFetchFatal, got {other:?}"),
            Ok(_) => panic!("expected boot failure with no cache + unreachable AS"),
        }
    }

    // ── R592-F3 golden-token fixtures ───────────────────────────────────────
    //
    // Shared with cheers-server / cheers-verify / cheers-mock / yubaba's
    // minter. Committed under
    // oss/cheers/crates/cheers-test-support/fixtures/ — see that crate's
    // src/fixtures.rs for the pinned Ed25519 seed, the `FIXTURE_NOW` clock
    // strategy, and the regeneration test that keeps these bytes honest.
    // Path-referenced via `include_str!` rather than a Cargo dependency:
    // kamaji-bin lives in a separate Cargo workspace, and cheers-test-support
    // pulls cheers-core/-server/-verify + turso — too heavy for kamaji-bin's
    // dev profile just to read nine token strings and a JWKS doc.
    //
    // These fixtures are pre-signed (not minted in this test) — this module
    // proves kamaji-bin's PRODUCTION verifier accepts/rejects the exact same
    // bytes cheers-mock and yubaba's minter agree on, independent of whatever
    // local keypair `keypair()` generates for the tests above.
    mod golden_fixtures {
        use super::*;
        use crate::auth::claims::AuthStrength;

        const GOLDEN_JWKS_JSON: &str =
            include_str!("../../../../../cheers/crates/cheers-test-support/fixtures/jwks.json");
        const GOLDEN_VALID_USER_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/valid_user.token"
        );
        const GOLDEN_VALID_SVC_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/valid_svc.token"
        );
        const GOLDEN_EXPIRED_TOKEN: &str =
            include_str!("../../../../../cheers/crates/cheers-test-support/fixtures/expired.token");
        const GOLDEN_WRONG_AUD_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/wrong_aud.token"
        );
        const GOLDEN_WRONG_ISS_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/wrong_iss.token"
        );
        const GOLDEN_TAMPERED_SIG_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/tampered_sig.token"
        );
        const GOLDEN_UNKNOWN_KID_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/unknown_kid.token"
        );
        const GOLDEN_NO_FOOTER_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/no_footer.token"
        );
        const GOLDEN_FOOTER_MISSING_KID_TOKEN: &str = include_str!(
            "../../../../../cheers/crates/cheers-test-support/fixtures/footer_missing_kid.token"
        );

        const GOLDEN_ISS: &str = "https://cheers.fixture.test";
        const GOLDEN_AUD: &str = "https://kamaji.fixture.test";
        const GOLDEN_NOW: i64 = 1_700_000_000;

        /// Boot an `AuthVerifier` from the golden JWKS fixture. Mirrors
        /// `build_verifier_with_doc` above, parameterized on `expected_aud`
        /// since the golden fixtures carry their own `fixture://`-style
        /// issuer/audience rather than this file's `cheers.test`/`kamaji.test`.
        async fn build_golden_verifier(expected_aud: &str) -> AuthVerifier {
            let doc: JwksDoc =
                serde_json::from_str(GOLDEN_JWKS_JSON).expect("golden jwks.json parses");
            let tmp = tempfile::tempdir().unwrap();
            let cache_path = tmp.path().join("jwks.json");
            seed_cache(&cache_path, doc);
            let config = AuthConfig::new(GOLDEN_ISS, expected_aud).with_cache_path(cache_path);
            std::mem::forget(tmp);
            AuthVerifier::boot(config).await.unwrap()
        }

        #[tokio::test]
        async fn golden_valid_user_token_verifies() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let claims = verifier
                .verify(GOLDEN_VALID_USER_TOKEN.trim(), GOLDEN_NOW)
                .await
                .expect("golden valid_user fixture must verify");
            assert_eq!(claims.sub, "user:alice-fixture");
            assert_eq!(claims.scope, vec!["cloud:read", "cloud:deploy"]);
            assert_eq!(claims.camp_id.as_deref(), Some("camp-fixture-1"));
            assert_eq!(
                claims.act.as_ref().expect("act present").sub,
                "svc:agent-claude-fixture"
            );
            assert!(claims
                .owns
                .as_ref()
                .expect("owns present")
                .contains("service", "svc-fixture-a"));
            assert_eq!(claims.auth_strength, Some(AuthStrength::UserFresh));
        }

        #[tokio::test]
        async fn golden_valid_svc_token_verifies_self_scoped() {
            // yubaba's ownership-write pattern: `aud == iss` (cheers verifying
            // its own routes), so the verifier here is configured with
            // expected_aud == the issuer, not a kamaji resource URI.
            let verifier = build_golden_verifier(GOLDEN_ISS).await;
            let claims = verifier
                .verify(GOLDEN_VALID_SVC_TOKEN.trim(), GOLDEN_NOW)
                .await
                .expect("golden valid_svc fixture must verify");
            assert_eq!(claims.sub, "svc:yubaba-fixture-1");
            assert_eq!(claims.scope, vec!["ownership:write"]);
            assert!(claims.owns.is_none());
            assert!(claims.camp_id.is_none());
        }

        #[tokio::test]
        async fn golden_expired_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_EXPIRED_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(matches!(err, VerifyError::Expired { .. }), "got {err:?}");
        }

        #[tokio::test]
        async fn golden_wrong_aud_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_WRONG_AUD_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(
                matches!(err, VerifyError::BadAudience { .. }),
                "got {err:?}"
            );
        }

        #[tokio::test]
        async fn golden_wrong_iss_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_WRONG_ISS_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(matches!(err, VerifyError::BadIssuer { .. }), "got {err:?}");
        }

        #[tokio::test]
        async fn golden_tampered_sig_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_TAMPERED_SIG_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(matches!(err, VerifyError::SignatureMismatch), "got {err:?}");
        }

        #[tokio::test]
        async fn golden_unknown_kid_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_UNKNOWN_KID_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(
                matches!(err, VerifyError::UnknownKid(ref kid) if kid == "ghost-kid-not-in-jwks"),
                "got {err:?}"
            );
        }

        #[tokio::test]
        async fn golden_no_footer_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_NO_FOOTER_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(matches!(err, VerifyError::MissingKid), "got {err:?}");
        }

        #[tokio::test]
        async fn golden_footer_missing_kid_token_is_rejected() {
            let verifier = build_golden_verifier(GOLDEN_AUD).await;
            let err = verifier
                .verify(GOLDEN_FOOTER_MISSING_KID_TOKEN.trim(), GOLDEN_NOW)
                .await
                .unwrap_err();
            assert!(
                matches!(err, VerifyError::Malformed(ref m) if m.starts_with("footer:")),
                "got {err:?}"
            );
        }
    }
}
