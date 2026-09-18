//! Name-keyed payloads inside the postcard frame (R896-F2, W349).
//!
//! Postcard is positional and carries no field names, so every field added to,
//! removed from or retyped inside a struct the wire carries is a break in both
//! directions — and not a clean one. A peer one field behind consumes the wrong
//! number of bytes and misreads *every field after* the change, "which is how a
//! wrong image or a wrong volume mount gets deployed instead of an error"
//! ([`crate::ProtocolVersion`]'s V7 stanza). [`ProtocolVersion`] exists to turn
//! that into a handshake refusal, and the refusal is the cost: a bumped tree
//! cannot hot-ship one half of the yubaba/kamaji pair, so a one-line fix becomes
//! a two-binary ship on every node it touches.
//!
//! R896-S1 classified all eleven bumps: **seven of the last ten** were byte
//! layout accidents, not semantics. This module is what stops those.
//!
//! ## The mechanism
//!
//! `#[serde(with = "crate::tolerant")]` on a field encodes that field as a
//! **length-prefixed blob of JSON** rather than inline positional bytes. Two
//! properties follow, and they are the whole point:
//!
//! - the decoder matches **by field name**, so an unknown field is skipped
//!   instead of shifting every byte after it;
//! - the blob is length-prefixed, so even a decoder that understands none of
//!   its contents knows exactly where it ends.
//!
//! ## What deliberately stays positional
//!
//! Only the structs that actually accrete fields are wrapped — `Workload`,
//! `MeshAssignment`, `WorkloadEntry`, `NodeCapabilities`. The frame header, the message enums and
//! the small control types ([`crate::RequestId`], [`crate::AckKind`],
//! [`crate::WorkloadState`]) stay plain postcard.
//!
//! That bound is not just frugality. **`Hello`/`Welcome` must keep decoding
//! across a skew or version negotiation cannot report a version mismatch** — a
//! peer that cannot parse the greeting fails with a frame error instead of
//! naming the two versions, which is precisely the unreadable failure
//! [`ProtocolVersion`] was introduced to prevent. Wrapping payload fields leaves
//! the greeting's bytes untouched, so an older peer still decodes it and still
//! refuses by name.
//!
//! ## What this does *not* buy
//!
//! A **deletion** crosses only if the peer that still knows the field can
//! deserialize without it — i.e. only if that peer's field carries
//! `#[serde(default)]`. Tolerance is a codec property; survivable absence is a
//! per-field one. And a default must equal the **pre-field behaviour**, or a
//! tolerated frame is a silent *semantic* skew rather than a loud break. When a
//! new field's absence would mean something the older peer does not already do,
//! bump [`ProtocolVersion`] — that is its residual and still-necessary job.
//!
//! That per-field decision is enforced, not just documented:
//! `tests/tolerant_field_policy.rs` freezes, for every wrapped struct, the set
//! of fields whose absence fails the decode, so a field added without making
//! the call fails a test instead of a roll.
//!
//! [`ProtocolVersion`]: crate::ProtocolVersion

use serde::de::{DeserializeOwned, Error as DeError, Visitor};
use serde::ser::Error as SerError;
use serde::{Deserializer, Serialize, Serializer};
use std::fmt;

/// Encode `value` as a length-prefixed JSON blob.
///
/// On a human-readable format (a JSON dump of a message, a test fixture) the
/// value is written inline instead — nesting an escaped JSON string inside JSON
/// would make the debugging surface worse for no compatibility gain, since a
/// named format is already tolerant.
pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    if serializer.is_human_readable() {
        return value.serialize(serializer);
    }
    let bytes = serde_json::to_vec(value).map_err(S::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

/// Decode a field written by [`serialize`].
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        return T::deserialize(deserializer);
    }
    let bytes = deserializer.deserialize_byte_buf(BlobVisitor)?;
    serde_json::from_slice(&bytes).map_err(D::Error::custom)
}

struct BlobVisitor;

impl<'de> Visitor<'de> for BlobVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a length-prefixed payload blob")
    }

    fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or_default());
        while let Some(byte) = seq.next_element()? {
            out.push(byte);
        }
        Ok(out)
    }
}

/// Canonical JSON encoding of `value` — object keys in sorted order.
///
/// `serde_json::Value` holds objects in a `BTreeMap` (the `preserve_order`
/// feature is off; `canonical_encoding_sorts_object_keys` guards that, because
/// cargo feature unification means some other crate in the graph could turn it
/// on and silently make this function non-canonical). Round-tripping through
/// `Value` therefore sorts every object key at every depth.
///
/// [`crate::spec_digest`] needs this: [`workload_spec::WorkloadSpec`] carries
/// `labels` and `annotations` as `HashMap`s, whose iteration order is randomized
/// per process, so a digest over an unsorted encoding is only best-effort. See
/// `digest.rs` for what that changes.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Old {
        name: String,
        #[serde(default)]
        tail: Vec<String>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct New {
        name: String,
        #[serde(default)]
        added: Option<u32>,
        #[serde(default)]
        tail: Vec<String>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct OldFrame {
        lead: u8,
        #[serde(with = "super")]
        payload: Old,
        trail: u8,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct NewFrame {
        lead: u8,
        #[serde(with = "super")]
        payload: New,
        trail: u8,
    }

    #[test]
    fn a_field_added_inside_the_blob_does_not_shift_the_frame() {
        let new = NewFrame {
            lead: 1,
            payload: New {
                name: "forge-b3".into(),
                added: Some(7),
                tail: vec!["sentinel".into()],
            },
            trail: 9,
        };
        let bytes = postcard::to_stdvec(&new).expect("encode");
        let old: OldFrame = postcard::from_bytes(&bytes).expect("older peer decodes");

        assert_eq!(old.payload.name, "forge-b3");
        // The property positionality cannot offer: a field *after* the addition,
        // both inside the blob and outside it, is still itself.
        assert_eq!(old.payload.tail, vec!["sentinel".to_string()]);
        assert_eq!(old.trail, 9, "the frame past the blob is untouched");
    }

    #[test]
    fn a_field_absent_from_an_older_blob_defaults() {
        let old = OldFrame {
            lead: 1,
            payload: Old {
                name: "forge-b3".into(),
                tail: vec!["sentinel".into()],
            },
            trail: 9,
        };
        let bytes = postcard::to_stdvec(&old).expect("encode");
        let new: NewFrame = postcard::from_bytes(&bytes).expect("newer peer decodes");

        assert_eq!(new.payload.added, None, "absence means the pre-field behaviour");
        assert_eq!(new.payload.tail, vec!["sentinel".to_string()]);
        assert_eq!(new.trail, 9);
    }

    #[test]
    fn human_readable_formats_keep_the_payload_inline() {
        let frame = OldFrame {
            lead: 1,
            payload: Old {
                name: "forge-b3".into(),
                tail: vec![],
            },
            trail: 9,
        };
        let json = serde_json::to_string(&frame).expect("encode");
        assert!(
            json.contains(r#""payload":{"name":"forge-b3""#),
            "payload must not be a nested escaped string, got {json}"
        );
        assert_eq!(
            serde_json::from_str::<OldFrame>(&json).expect("decode"),
            frame
        );
    }

    #[test]
    fn canonical_encoding_sorts_object_keys() {
        // Guards the `preserve_order` assumption `canonical_json`'s doc names:
        // if some crate in the graph enables that serde_json feature, insertion
        // order wins and the spec digest silently stops being canonical.
        let mut map = HashMap::new();
        for key in ["zulu", "alpha", "mike", "bravo"] {
            map.insert(key.to_string(), 1u8);
        }
        let encoded = String::from_utf8(canonical_json(&map).expect("encode")).expect("utf8");
        assert_eq!(encoded, r#"{"alpha":1,"bravo":1,"mike":1,"zulu":1}"#);
    }
}
