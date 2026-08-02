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
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub use rollup::{GroupByField, GroupRow};
pub use sites::Site;

const REQUIRED_MODE: u32 = 0o600;

/// Owns the SQLite connection. All storage operations are methods on this
/// type, split across sibling modules (`events`, `rollup`, `retention`,
/// `sites`) via separate `impl Store` blocks.
#[derive(Debug)]
pub struct Store {
    conn: rusqlite::Connection,
}

impl Store {
    /// Opens (creating if needed) a database file, sets the required
    /// pragmas (§6: `journal_mode=WAL, synchronous=NORMAL,
    /// busy_timeout=3000, foreign_keys=ON, trusted_schema=OFF`), and runs
    /// any pending migration.
    ///
    /// S8: "DB and spool files `0600`... Refuse to start if permissions
    /// are wider; print the exact `chmod` to run." A brand-new file is
    /// created with `0600` from the start — before SQLite ever opens it,
    /// closing the window where a default-umask create (typically `644`)
    /// would otherwise briefly exist. An *existing* file with wider
    /// permissions is refused outright, not silently tightened: silently
    /// rewriting permissions on a file that already violated the
    /// invariant could paper over a real misconfiguration (or tampering)
    /// instead of surfacing it.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode != REQUIRED_MODE {
                    return Err(StoreError::PermissionsTooOpen {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(StoreError::Io)?;
                }
                let file = fs::File::create(path).map_err(StoreError::Io)?;
                file.set_permissions(fs::Permissions::from_mode(REQUIRED_MODE))
                    .map_err(StoreError::Io)?;
            }
            Err(e) => return Err(StoreError::Io(e)),
        }

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
    Io(std::io::Error),
    Validation(fossh_core::validate::ValidationError),
    Json(serde_json::Error),
    /// A blob in `uniques` or `value_hist` didn't deserialize to a
    /// sketch of the expected fixed size — the schema invariant that
    /// should prevent this is exactly what `schema::tests` checks.
    CorruptSketch,
    /// S8: an existing DB file's permissions are wider than `0600`.
    PermissionsTooOpen {
        path: PathBuf,
        mode: u32,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "sqlite: {e}"),
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Validation(e) => write!(f, "validation: {e}"),
            StoreError::Json(e) => write!(f, "json: {e}"),
            StoreError::CorruptSketch => write!(f, "stored sketch blob has an unexpected length"),
            StoreError::PermissionsTooOpen { path, mode } => write!(
                f,
                "{} has mode {mode:o}, which is wider than the required 0600 (S8); refusing to start. Run: chmod 600 {}",
                path.display(),
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Sqlite(e) => Some(e),
            StoreError::Io(e) => Some(e),
            StoreError::Validation(e) => Some(e),
            StoreError::Json(e) => Some(e),
            StoreError::CorruptSketch | StoreError::PermissionsTooOpen { .. } => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-store-open-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("{name}.db"))
    }

    #[test]
    fn fresh_db_is_created_with_0600() {
        let path = scratch_path("fresh");
        let _ = fs::remove_file(&path);
        Store::open(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn reopening_a_0600_db_succeeds() {
        let path = scratch_path("reopen");
        let _ = fs::remove_file(&path);
        Store::open(&path).unwrap();
        Store::open(&path).unwrap(); // must not error the second time
        fs::remove_file(&path).ok();
    }

    #[test]
    fn existing_db_with_wide_permissions_is_refused() {
        let path = scratch_path("wide-perms");
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = Store::open(&path);
        assert!(matches!(result, Err(StoreError::PermissionsTooOpen { .. })));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn error_message_names_the_exact_chmod_command() {
        let path = scratch_path("chmod-message");
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = Store::open(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("chmod 600"));
        assert!(message.contains(&path.display().to_string()));
        fs::remove_file(&path).ok();
    }
}
