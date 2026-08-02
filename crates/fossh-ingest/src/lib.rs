#![forbid(unsafe_code)]
//! foSSH request → `Event` pipeline (M3): salt lifecycle (P2), HMAC/bearer
//! auth (§8), per-site rate limiting (S10), and the spool writer +
//! compactor (§7.1).
//!
//! §8 and S10 describe the nonce-replay cache and rate-limit bucket as
//! living in an mmap'd file. This crate uses plain positioned file I/O
//! instead — see `DECISIONS.md`. S1 forbids `unsafe` in every crate
//! except `fossh-ffi`, and every `mmap` API is `unsafe fn` by construction
//! (the kernel can change the mapped bytes out from under Rust's aliasing
//! model at any time); a hard security invariant beats an implementation
//! suggestion. The spec's own tolerance for slop ("no lock, tolerate ±1
//! slop") is exactly what a read-then-write-back on a plain file gives
//! under concurrent CGI processes, without needing `unsafe` anywhere here.

pub mod auth;
pub mod compact;
pub mod crypto;
pub mod pipeline;
pub mod random;
pub mod ratelimit;
pub mod salt;
pub mod site_cache;
pub mod spool;

use std::fmt;

#[derive(Debug)]
pub enum IngestError {
    Io(std::io::Error),
    Random(std::io::Error),
    Store(fossh_store::StoreError),
    Validation(fossh_core::validate::ValidationError),
    Json(serde_json::Error),
    /// A spool frame's CRC didn't match its payload — corrupt or
    /// truncated (e.g. a torn write from a crash mid-append).
    CorruptFrame,
    /// A stored sketch/state blob wasn't the size this crate wrote.
    CorruptState,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::Io(e) => write!(f, "io: {e}"),
            IngestError::Random(e) => write!(f, "reading /dev/urandom: {e}"),
            IngestError::Store(e) => write!(f, "store: {e}"),
            IngestError::Validation(e) => write!(f, "validation: {e}"),
            IngestError::Json(e) => write!(f, "json: {e}"),
            IngestError::CorruptFrame => write!(f, "spool frame CRC mismatch"),
            IngestError::CorruptState => write!(f, "persisted state blob has an unexpected shape"),
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngestError::Io(e) | IngestError::Random(e) => Some(e),
            IngestError::Store(e) => Some(e),
            IngestError::Validation(e) => Some(e),
            IngestError::Json(e) => Some(e),
            IngestError::CorruptFrame | IngestError::CorruptState => None,
        }
    }
}

impl From<std::io::Error> for IngestError {
    fn from(e: std::io::Error) -> Self {
        IngestError::Io(e)
    }
}

impl From<fossh_store::StoreError> for IngestError {
    fn from(e: fossh_store::StoreError) -> Self {
        IngestError::Store(e)
    }
}

impl From<serde_json::Error> for IngestError {
    fn from(e: serde_json::Error) -> Self {
        IngestError::Json(e)
    }
}
