//! Token verifier — the load-bearing public surface of the auth module.
//!
//! Composes the JWKS cache, the rate-limited kid-miss refresh, and pasetors'
//! PASETO v4.public signature check into one async `verify` call. Matches
//! W159 §The wire — Layer 1 line-for-line:
//!
//! - Signature verifies against the JWKS (cheers key *or* a service-principal
//!   pubkey published in the same JWKS).
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
use std::time::Duration;

use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use super::claims::McpClaims;
use super::config::AuthConfig;
use super::error::{AuthError, VerifyError};
use super::jwks::{JwksCache, JwksDoc};

/// Footer payload — we only care about `kid`. Other footer fields (alg, etc.)
/// are accepted-and-ignored so a future minter can carry hints without
/// breaking the verifier.
#[derive(Debug, Deserialize)]
struct Footer {
    kid: String,
}

/// The verifier. Construct once via [`AuthVerifier::boot`]; share via `Arc`.
/// `verify` is `&self`-callable concurrently — JWKS reads are RwLock'd.
#[derive(Debug)]
pub struct AuthVerifier {
    config: AuthConfig,
    jwks: Arc<RwLock<JwksCache>>,
    http: reqwest::Client,
    /// Last out-of-band refresh time (kid-miss path). `None` until first
    /// kid-miss. Rate-limited by `config.kid_miss_rate_limit`.
    kid_miss_last: Arc<Mutex<Option<Instant>>>,
}

impl AuthVerifier {
    /// Boot the verifier. Implements W159 §Restart resilience verbatim:
    ///
    /// - Cache present + fresh → start from cache, refresh in background.
    /// - Cache present + stale → synchronous refresh before serving (best-effort;
    ///   falls through to cache+warn on AS failure if `serve_stale_on_failure`).
    /// - Cache present + AS unreachable → serve from stale cache with a warn.
    /// - No cache + AS unreachable → [`AuthError::BootFetchFatal`].
    pub async fn boot(config: AuthConfig) -> Result<Self, AuthError> {
        // Fail closed BEFORE any network fetch: a plaintext (`http://`,
        // non-loopback) issuer means the JWKS would be fetched over a channel
        // an on-path attacker can rewrite — a key-substitution → token-forgery
        // vector. `refresh()` reuses this same validated config, so gating boot
        // covers every fetch path.
        config.validate_issuer()?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(AuthError::Fetch)?;

        let on_disk = JwksCache::load_from_disk(&config.cache_path).await?;

        let cache = match on_disk {
            Some(cached) => {
                let stale = cached
                    .last_refresh()
                    .elapsed()
                    .map(|age| age > config.refresh_interval)
                    .unwrap_or(true);
                if stale {
                    // Try a sync refresh; if AS unreachable, fall through to
                    // cache with a warn (serve-stale arm).
                    match fetch_jwks(&http, &config).await {
                        Ok(doc) => {
                            let next = JwksCache::from_doc(doc)?;
                            if let Err(e) = next.write_atomic(&config.cache_path).await {
                                tracing::warn!(error = ?e, "JWKS cache persist failed at boot");
                            }
                            next
                        }
                        Err(e) if config.serve_stale_on_failure => {
                            tracing::warn!(
                                error = ?e,
                                "cheers AS unreachable at boot; serving from stale JWKS cache"
                            );
                            cached
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    cached
                }
            }
            None => {
                // No cache. First-start fetch is fatal if it fails.
                let doc =
                    fetch_jwks(&http, &config)
                        .await
                        .map_err(|e| AuthError::BootFetchFatal {
                            cache_path: config.cache_path.clone(),
                            source: Box::new(e),
                        })?;
                let next = JwksCache::from_doc(doc)?;
                next.write_atomic(&config.cache_path).await?;
                next
            }
        };

        Ok(Self {
            config,
            jwks: Arc::new(RwLock::new(cache)),
            http,
            kid_miss_last: Arc::new(Mutex::new(None)),
        })
    }

    /// Verify a PASETO v4.public token. Returns parsed [`McpClaims`] on
    /// success. Per-failure error variants map 1:1 to the W159 §Failure
    /// responses table (F3 turns these into HTTP shapes).
    pub async fn verify(&self, token: &str, now: i64) -> Result<McpClaims, VerifyError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|e| VerifyError::Malformed(format!("{e:?}")))?;

        // Parse footer to get kid BEFORE signature verification — the footer
        // is bound into the signature so a forged footer fails verify anyway.
        let footer_bytes = untrusted.untrusted_footer();
        if footer_bytes.is_empty() {
            return Err(VerifyError::MissingKid);
        }
        let footer: Footer = serde_json::from_slice(footer_bytes)
            .map_err(|e| VerifyError::Malformed(format!("footer: {e}")))?;

        // Cache lookup with a single rate-limited refresh retry on miss.
        let pubkey_bytes = {
            let cache = self.jwks.read().await;
            cache.get(&footer.kid).copied()
        };
        let pubkey_bytes = match pubkey_bytes {
            Some(b) => b,
            None => {
                self.try_kid_miss_refresh().await;
                let cache = self.jwks.read().await;
                cache
                    .get(&footer.kid)
                    .copied()
                    .ok_or_else(|| VerifyError::UnknownKid(footer.kid.clone()))?
            }
        };

        let pubkey = AsymmetricPublicKey::<V4>::from(&pubkey_bytes)
            .map_err(|e| VerifyError::Malformed(format!("pubkey: {e:?}")))?;

        // Use the low-level v4 PublicToken API directly. The high-level
        // `pasetors::public::verify` would route the payload through
        // `Claims::from_string`, which rejects any registered claim
        // (`iss`/`sub`/`aud`/`exp`/`iat`/`jti`/`nbf`) that isn't a string —
        // incompatible with W159 §Canonical claim schema's i64 `exp`/`iat`.
        // The signature + footer-binding check is identical between the two
        // entry points (the high level wraps this one).
        let trusted =
            PublicToken::verify(&pubkey, &untrusted, None, None).map_err(|e| match e {
                pasetors::errors::Error::TokenValidation => VerifyError::SignatureMismatch,
                other => VerifyError::Malformed(format!("{other:?}")),
            })?;

        let claims: McpClaims = serde_json::from_str(trusted.payload())
            .map_err(|e| VerifyError::BadClaims(e.to_string()))?;

        // Standard-claim checks (W159 Layer 1).
        if claims.iss != self.config.cheers_issuer {
            return Err(VerifyError::BadIssuer {
                expected: self.config.cheers_issuer.clone(),
                got: claims.iss.clone(),
            });
        }
        if claims.aud != self.config.expected_aud {
            return Err(VerifyError::BadAudience {
                expected: self.config.expected_aud.clone(),
                got: claims.aud.clone(),
            });
        }
        if claims.exp <= now {
            return Err(VerifyError::Expired {
                exp: claims.exp,
                now,
            });
        }

        Ok(claims)
    }

    /// Refresh JWKS from the AS. Used by the background refresh task and
    /// directly available so an operator surface can trigger a manual
    /// refresh (e.g. after a known-good key rotation).
    pub async fn refresh(&self) -> Result<(), AuthError> {
        let doc = fetch_jwks(&self.http, &self.config).await?;
        let next = JwksCache::from_doc(doc)?;
        next.write_atomic(&self.config.cache_path).await?;
        let mut guard = self.jwks.write().await;
        *guard = next;
        Ok(())
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

    /// Read-only access to the cached JWKS — for operator surfaces and
    /// tests. Holds a read lock for the duration of the closure.
    pub async fn with_jwks<R>(&self, f: impl FnOnce(&JwksCache) -> R) -> R {
        let guard = self.jwks.read().await;
        f(&guard)
    }

    async fn try_kid_miss_refresh(&self) {
        let mut last = self.kid_miss_last.lock().await;
        let now = Instant::now();
        if let Some(prev) = *last {
            if now.duration_since(prev) < self.config.kid_miss_rate_limit {
                tracing::debug!("kid-miss refresh suppressed by rate limit");
                return;
            }
        }
        *last = Some(now);
        drop(last);
        if let Err(e) = self.refresh().await {
            tracing::warn!(error = ?e, "kid-miss JWKS refresh failed");
        }
    }
}

async fn fetch_jwks(http: &reqwest::Client, config: &AuthConfig) -> Result<JwksDoc, AuthError> {
    let resp = http.get(config.jwks_url()).send().await?;
    let resp = resp.error_for_status()?;
    let doc: JwksDoc = resp.json().await?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwks::{JwkKey, JwksDoc};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};

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
        JwksDoc {
            keys: vec![JwkKey {
                kty: "OKP".into(),
                crv: Some("Ed25519".into()),
                x: Some(Base64UrlUnpadded::encode_string(&pubkey_bytes(kp))),
                kid: Some(kid.into()),
                use_: Some("sig".into()),
                alg: Some("EdDSA".into()),
            }],
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
        let cache = JwksCache::from_doc(doc).unwrap();
        cache.write_atomic(&cache_path).await.unwrap();
        let config = AuthConfig::new("https://cheers.test", "https://kamaji.test")
            .with_cache_path(cache_path);
        // Keep the temp dir alive via leak — tests exit before it matters.
        std::mem::forget(tmp);
        AuthVerifier::boot(config).await.unwrap()
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

    /// W159: out-of-band refresh on kid miss is rate-limited to ≤1 per
    /// `kid_miss_rate_limit` so attacker-controlled kid choices can't drive
    /// the AS into the ground. With AS unreachable in tests, both calls
    /// surface `UnknownKid`; what we verify is that the gate is set on the
    /// first attempt — observable by introspecting `kid_miss_last`.
    #[tokio::test]
    async fn kid_miss_refresh_is_rate_limited() {
        let kp = keypair();
        let doc = jwks_doc_for("k1", &kp);
        let verifier = build_verifier_with_doc(doc).await;
        let bad = |kid: &str| {
            mint_token(
                &kp.secret,
                kid,
                good_payload(
                    "https://cheers.test",
                    "https://kamaji.test",
                    2_000_000_000,
                    1_700_000_000,
                    "user:abc",
                    &["cloud:read"],
                ),
            )
        };
        // First miss spends the gate.
        let t1 = bad("k-miss-1");
        let _ = verifier.verify(&t1, 1_800_000_000).await;
        let gate_after_first = *verifier.kid_miss_last.lock().await;
        assert!(gate_after_first.is_some(), "gate must arm after first miss");

        // Second miss within the cooldown does not advance the gate (the
        // verifier returns early without calling refresh).
        let t2 = bad("k-miss-2");
        let _ = verifier.verify(&t2, 1_800_000_000).await;
        let gate_after_second = *verifier.kid_miss_last.lock().await;
        assert_eq!(
            gate_after_first, gate_after_second,
            "second kid-miss within cooldown must not re-arm the gate"
        );
    }

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
            Err(AuthError::BootFetchFatal { .. }) => {}
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
            let cache = JwksCache::from_doc(doc).unwrap();
            cache.write_atomic(&cache_path).await.unwrap();
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
