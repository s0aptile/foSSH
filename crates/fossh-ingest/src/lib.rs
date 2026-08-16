#![forbid(unsafe_code)]

pub mod auth;
pub mod compact;
pub mod crypto;
pub mod forwarded;
pub mod geoip;
pub mod ingest;
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

    CorruptFrame,

    CorruptState,

    InvalidSlug,
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
            IngestError::InvalidSlug => write!(f, "slug is not safe to use as a path component"),
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
            IngestError::CorruptFrame | IngestError::CorruptState | IngestError::InvalidSlug => {
                None
            }
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
