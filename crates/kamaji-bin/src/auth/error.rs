//! Error types for the auth surface.
//!
//! Both live in cheers-verify since R731-F6 moved the W159 cache there:
//! [`JwksError`] (lifecycle: boot, fetch, persist) and [`VerifyError`]
//! (per-request: kid, key role, signature, claims). The split matches W159
//! §Failure responses — "kamaji cannot serve" vs "this token isn't good for
//! this call"; [`super::deny`] owns the response-shape mapping.

pub use cheers_verify::{JwksError, VerifyError};
