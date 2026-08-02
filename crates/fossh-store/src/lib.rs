#![forbid(unsafe_code)]
//! foSSH SQLite storage (§6, M2): schema + migrations, interning, hourly
//! rollups (with mergeable HLL/histogram sketches so `uniques`/`p50`/`p95`
//! survive raw-row deletion), retention/vacuum, and a k-anonymity-enforcing
//! grouped query engine.
//!
//! `rusqlite`'s `bundled` feature vendors and compiles SQLite itself, so
//! the only unsafe code anywhere near this crate is inside that C library
//! and the `libsqlite3-sys` bindings — none of it in `fossh-store`
//! (`#![forbid(unsafe_code)]`, S1).

mod events;
mod intern;
mod retention;
mod rollup;
mod schema;
mod sites;

use std::fmt;
use std::path::Path;

pub use rollup::{GroupByField, GroupRow};
pub use sites::Site;

/// Owns the SQLite connection. All storage operations are methods on this
/// type, split across sibling modules (`events`, `rollup`, `retention`,
/// `sites`) via separate `impl Store` blocks.
pub struct Store {
    conn: rusqlite::Connection,
}

impl Store {
    /// Opens (creating if needed) a database file, sets the required
    /// pragmas (§6: `journal_mode=WAL, synchronous=NORMAL,
    /// busy_timeout=3000, foreign_keys=ON, trusted_schema=OFF`), and runs
    /// any pending migration.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// An in-process, non-persistent store — used by tests and by any
    /// caller that wants the schema/query logic without a file on disk.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: rusqlite::Connection) -> Result<Self, StoreError> {
        conn.execute_batch(schema::PRAGMAS)?;
        schema::migrate(&conn)?;
        Ok(Self { conn })
    }
}

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Validation(fossh_core::validate::ValidationError),
    Json(serde_json::Error),
    /// A blob in `uniques` or `value_hist` didn't deserialize to a
    /// sketch of the expected fixed size — the schema invariant that
    /// should prevent this is exactly what `schema::tests` checks.
    CorruptSketch,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "sqlite: {e}"),
            StoreError::Validation(e) => write!(f, "validation: {e}"),
            StoreError::Json(e) => write!(f, "json: {e}"),
            StoreError::CorruptSketch => write!(f, "stored sketch blob has an unexpected length"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Sqlite(e) => Some(e),
            StoreError::Validation(e) => Some(e),
            StoreError::Json(e) => Some(e),
            StoreError::CorruptSketch => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e)
    }
}
