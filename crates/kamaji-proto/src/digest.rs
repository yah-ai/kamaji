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
//! The digest is SHA-256 over the **canonical JSON** encoding of the `Workload`
//! ([`crate::tolerant::canonical_json`]), under a domain-separation prefix. Every
//! object key is sorted at every depth, so the encoding is a pure function of the
//! value — including for a `Workload::Container`, whose
//! [`workload_spec::WorkloadSpec`] carries `labels` and `annotations` as
//! `HashMap`s.
//!
//! **That is a change, and it strengthens the promise.** The basis used to be the
//! postcard encoding, which is positional and therefore canonical only for a spec
//! whose maps are *ordered* — true of [`workload_spec::TenantPasswayWorkload`]
//! (a `BTreeMap`), false of a container spec, whose `HashMap` iteration order is
//! randomized per process. Two processes holding an identical container spec
//! could compute different digests, and this doc used to argue that away as a
//! safe asymmetry:
//!
//! - a spurious **mismatch** costs one redeploy — exactly the behaviour a caller
//!   without digests has on every sweep, so it could only ever be an improvement;
//! - a spurious **match** would leave a changed spec undeployed, and that is the
//!   one it could not produce.
//!
//! The argument was sound; it is now moot. `Some(d) == Some(d)` is a sound
//! "nothing changed" for every spec shape, not just the ordered-map ones, so a
//! caller no longer has to say which specs it relies on it for.
//!
//! R896-F2 moved the basis because the wire moved (see [`crate::tolerant`]), and
//! sorting was free once the encoding went through `serde_json::Value`. The
//! domain prefix went `v1` → `v2` with it: every recorded digest is invalidated,
//! which reads on a node as **redeploy everything once**, the safe direction, and
//! is exactly the bump this prefix exists to make possible.
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
const DIGEST_DOMAIN: &[u8] = b"kamaji-proto/spec-digest/v2\0";

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
    let mut value = serde_json::to_value(spec).ok()?;
    // R960-F6: `WorkloadSpec::db` is always serialized (postcard is positional),
    // so an empty one would put `"db": []` into every spec's digest and read as
    // "changed" on every node recorded before the field existed. An empty `db`
    // means what an absent one meant; hash it as absent. A non-empty `db`
    // does change the digest, which is right: the spec did change.
    // R960-F8: `capabilities` is always serialized for the same reason.
    if let Some(obj) = value.as_object_mut() {
        for key in ["db", "capabilities"] {
            if obj.get(key).is_some_and(|v| v.as_array().is_some_and(Vec::is_empty)) {
                obj.remove(key);
            }
        }
    }
    let encoded = serde_json::to_vec(&value).ok()?;
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
            domain: domain.to_string(),
            listen: listen.to_string(),
            upstreams: vec!["127.0.0.1:8080".to_string()],
            tls: TenantPasswayTls::for_domain(domain),
            idle_ttl: None,
            command: None,
            env: BTreeMap::new(),
            discover: None,
        })
    }

    fn container(db: Vec<workload_spec::WorkloadDb>) -> Workload {
        let mut spec = workload_spec::WorkloadSpec::for_forge(
            "b3",
            workload_spec::ImageRef {
                registry: "ghcr.io".into(),
                repository: "yah/forge".into(),
                tag: "v1".into(),
                digest: "sha256:abc123".into(),
            },
            workload_spec::TierTag("private".into()),
            vec![8080],
        );
        spec.db = db;
        Workload::container(spec)
    }

    /// R960-F6: a spec with no `[[db]]` rows must digest exactly as it did
    /// before the field existed (the bytes a pre-field node recorded), or the
    /// first sweep after a yubaba roll redeploys the whole fleet.
    #[test]
    fn an_empty_db_digests_as_if_the_field_did_not_exist() {
        let w = container(vec![]);
        let mut value = serde_json::to_value(&w).unwrap();
        assert!(value.as_object_mut().unwrap().remove("db").is_some(), "db is always serialized");
        assert!(
            value.as_object_mut().unwrap().remove("capabilities").is_some(),
            "capabilities is always serialized"
        );
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(serde_json::to_vec(&value).unwrap());
        let pre_field: SpecDigest = hasher.finalize().into();
        assert_eq!(spec_digest(&w), Some(pre_field));

        let with_row = container(vec![workload_spec::WorkloadDb {
            name: "a".into(),
            subject: "a.db".into(),
            workbench: workload_spec::WorkbenchKind::None,
        }]);
        assert_ne!(spec_digest(&with_row), Some(pre_field), "a real db row is a real change");
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
        let bare: SpecDigest =
            Sha256::digest(crate::tolerant::canonical_json(&spec).unwrap()).into();
        assert_ne!(bare, spec_digest(&spec).unwrap());
    }

    /// The property the basis change bought: a container spec's digest no longer
    /// depends on `HashMap` iteration order. Building the same annotations in two
    /// different insertion orders must land on the same bytes.
    #[test]
    fn a_container_spec_digests_independently_of_map_order() {
        use workload_spec::{ImageRef, TierTag, WorkloadSpec};

        let base = || {
            WorkloadSpec::for_forge(
                "b3",
                ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "yah/forge".into(),
                    tag: "v1".into(),
                    digest: "sha256:abc123".into(),
                },
                TierTag("private".into()),
                vec![8080],
            )
        };

        let keys = ["yah.exec", "yah.sandbox", "yah.forge", "zulu"];
        let mut forward = base();
        for key in keys {
            forward.annotations.insert(key.into(), "v".into());
        }
        let mut reverse = base();
        for key in keys.iter().rev() {
            reverse.annotations.insert((*key).into(), "v".into());
        }

        assert_eq!(
            spec_digest(&Workload::container(forward)).unwrap(),
            spec_digest(&Workload::container(reverse)).unwrap(),
            "canonical encoding must sort map keys — this is the guarantee the \
             postcard basis could not make for a HashMap-carrying spec"
        );
    }
}
