//! Content digest of a deployed workload spec (R852-B4).
//!
//! ## Why the wire needs one
//!
//! `Deploy` is idempotent *by tearing down*: kamaji's JIT tier stops the
//! supervisor and **releases the held listen socket** before it binds fresh
//! (`kamaji::jit::JitRuntime::deploy_on_demand`), and the container backends
//! replace the running task. That makes a redeploy correct but never free.
//!
//! A reconciler that re-sends every declaration on every sweep therefore
//! re-binds every socket on every sweep — for `yubaba::tenant_passway` that is
//! one unbind/rebind per enrolled custom domain per sweep, and any JIT child
//! that happened to be warm inside its idle TTL is killed mid-life. Nothing in
//! a log looks wrong: the sweep reports it armed everything, and it did.
//!
//! [`WorkloadEntry::spec_digest`] closes that loop. kamaji records the digest of
//! the spec it was handed and returns it on `List`; a caller digests the spec it
//! *would* send and skips the deploy when the two agree. The comparison is over
//! the same [`Workload`] value on both sides — kamaji digests what it received,
//! not a reconstruction — so there is no second copy of the truth to drift.
//!
//! [`WorkloadEntry::spec_digest`]: crate::WorkloadEntry::spec_digest
//!
//! ## What equality does and does not promise
//!
//! The digest is SHA-256 over the postcard encoding of the `Workload`, under a
//! domain-separation prefix. Postcard is positional, so the encoding is a pure
//! function of the value for every spec whose maps are *ordered* — which is the
//! case for [`workload_spec::TenantPasswayWorkload`], whose only map is a
//! `BTreeMap`.
//!
//! It is **not** the case for a `Workload::Container`: [`workload_spec::WorkloadSpec`]
//! carries `labels` and `annotations` as `HashMap`s, whose iteration order is
//! randomized per process. Two processes holding an identical container spec can
//! therefore compute different digests.
//!
//! That asymmetry is safe, and it is why the digest is usable anyway. The two
//! failure directions are not equal:
//!
//! - a spurious **mismatch** costs one redeploy — exactly the behaviour a caller
//!   without digests has on every sweep, so it can only ever be an improvement;
//! - a spurious **match** would leave a changed spec undeployed, and that is the
//!   one this cannot produce: equal digests mean equal encodings up to a SHA-256
//!   collision.
//!
//! So `Some(d) == Some(d)` is a sound "nothing changed" for an ordered-map spec,
//! and merely a best-effort optimisation for a `HashMap`-carrying one. Callers
//! that need the guarantee should say which specs they rely on it for, as
//! `yubaba::tenant_passway` does.
//!
//! `None` — an unencodable spec, or an entry from a kamaji that never recorded
//! one (a restart, another backend, a pre-V5 peer) — compares unequal to
//! everything including itself, so the caller falls back to redeploying. Unknown
//! is never mistaken for unchanged.

use sha2::{Digest, Sha256};
use workload_spec::Workload;

/// A workload spec's content digest — SHA-256, 32 bytes.
pub type SpecDigest = [u8; 32];

/// Domain-separation prefix. Keeps this digest from ever colliding with a bare
/// SHA-256 of the same postcard bytes computed for some other purpose, and gives
/// the scheme a version to bump if the basis (postcard-of-`Workload`) is ever
/// replaced — a changed prefix invalidates every recorded digest, which reads on
/// a node as "redeploy everything once", the safe direction.
const DIGEST_DOMAIN: &[u8] = b"kamaji-proto/spec-digest/v1\0";

/// Digest `spec` for [`WorkloadEntry::spec_digest`] comparison.
///
/// `None` when the spec cannot be postcard-encoded — the shape that reaches this
/// today is a `Workload::Container` holding a local build *recipe*, which names
/// no digest and which the serializer refuses precisely so it cannot cross this
/// wire. A caller treats `None` as "no opinion", i.e. deploy.
///
/// Read the module doc before relying on equality: it is sound for ordered-map
/// specs and best-effort for `HashMap`-carrying ones.
///
/// [`WorkloadEntry::spec_digest`]: crate::WorkloadEntry::spec_digest
pub fn spec_digest(spec: &Workload) -> Option<SpecDigest> {
    let encoded = postcard::to_stdvec(spec).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(&encoded);
    Some(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use workload_spec::{TenantPasswayTls, TenantPasswayWorkload};

    fn passway(domain: &str, listen: &str) -> Workload {
        Workload::TenantPassway(TenantPasswayWorkload {
            schema_version: Default::default(),
            domain: domain.to_string(),
            listen: listen.to_string(),
            upstreams: vec!["127.0.0.1:8080".to_string()],
            tls: TenantPasswayTls::for_domain(domain),
            idle_ttl: None,
            command: None,
            env: BTreeMap::new(),
        })
    }

    #[test]
    fn the_same_declaration_digests_to_the_same_bytes() {
        let a = spec_digest(&passway("a.example", "127.0.0.1:8443")).unwrap();
        let b = spec_digest(&passway("a.example", "127.0.0.1:8443")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn the_bind_string_is_part_of_the_digest() {
        // The field a changed enrollment moves, and the one whose staleness is
        // an outage rather than a cosmetic drift: the listen string is the
        // fd-table key passway's socket activation matches on.
        let a = spec_digest(&passway("a.example", "127.0.0.1:8443")).unwrap();
        let b = spec_digest(&passway("a.example", "127.0.0.1:9443")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_domain_digests_differently() {
        let a = spec_digest(&passway("a.example", "127.0.0.1:8443")).unwrap();
        let b = spec_digest(&passway("b.example", "127.0.0.1:8443")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_env_escape_hatch_is_covered_too() {
        // The env map is a BTreeMap, so this is exactly the property the
        // module doc promises for ordered-map specs: the encoding is a pure
        // function of the value, and a changed value changes the digest.
        let mut with_env = passway("a.example", "127.0.0.1:8443");
        if let Workload::TenantPassway(w) = &mut with_env {
            w.env
                .insert("PASSWAY_ACME_CONTACT".into(), "ops@example".into());
        }
        assert_ne!(
            spec_digest(&passway("a.example", "127.0.0.1:8443")).unwrap(),
            spec_digest(&with_env).unwrap()
        );
    }

    #[test]
    fn the_domain_prefix_is_actually_mixed_in() {
        // Guards against the prefix being dropped in a refactor: a bare
        // SHA-256 of the postcard bytes must NOT equal what we return, or the
        // version half of the prefix buys nothing.
        let spec = passway("a.example", "127.0.0.1:8443");
        let bare: SpecDigest = Sha256::digest(postcard::to_stdvec(&spec).unwrap()).into();
        assert_ne!(bare, spec_digest(&spec).unwrap());
    }
}
