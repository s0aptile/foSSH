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
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

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
    /// S8: "DB and spool files `0600`... Refuse to start if permissions
    /// are wider; print the exact `chmod` to run." An *existing* file
    /// with wider permissions is refused outright, not silently
    /// tightened: silently rewriting permissions on a file that already
    /// violated the invariant could paper over a real misconfiguration
    /// (or tampering) instead of surfacing it.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        ensure_file_ready(path)?;
        let conn = rusqlite::Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_encrypted(path: &Path, key: &[u8; 32]) -> Result<Self, StoreError> {
        let is_fresh = ensure_file_ready(path)?;
        let key_hex = Zeroizing::new(hex_encode(key));

        if is_fresh {
            let conn = rusqlite::Connection::open(path)?;
            set_key(&conn, &key_hex)?;
            return Self::from_connection(conn);
        }

        let conn = rusqlite::Connection::open(path)?;
        set_key(&conn, &key_hex)?;
        match probe(&conn) {
            Ok(()) => return Self::from_connection(conn),
            Err(e) if is_not_a_database(&e) => {}
            Err(e) => return Err(e.into()),
        }
        drop(conn); // release the file before the plaintext probe reopens it

        let plain_conn = rusqlite::Connection::open(path)?;
        if probe(&plain_conn).is_err() {
            return Err(StoreError::EncryptionKeyMismatchOrCorrupt {
                path: path.to_path_buf(),
            });
        }

        migrate_plaintext_to_encrypted(plain_conn, path, &key_hex)?;

        let conn = rusqlite::Connection::open(path)?;
        set_key(&conn, &key_hex)?;
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

fn ensure_file_ready(path: &Path) -> Result<bool, StoreError> {
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode != REQUIRED_MODE {
                return Err(StoreError::PermissionsTooOpen {
                    path: path.to_path_buf(),
                    mode,
                });
            }
            Ok(false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(StoreError::Io)?;
            }
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(REQUIRED_MODE)
                .open(path)
            {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let meta = fs::metadata(path).map_err(StoreError::Io)?;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != REQUIRED_MODE {
                        return Err(StoreError::PermissionsTooOpen {
                            path: path.to_path_buf(),
                            mode,
                        });
                    }
                    Ok(false)
                }
                Err(e) => Err(StoreError::Io(e)),
            }
        }
        Err(e) => Err(StoreError::Io(e)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn set_key(conn: &rusqlite::Connection, key_hex: &str) -> rusqlite::Result<()> {
    conn.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))
}

fn probe(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|_| ())
}

fn is_not_a_database(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(ffi_err, _)
            if ffi_err.code == rusqlite::ErrorCode::NotADatabase
    )
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn temp_migration_path(path: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fossh")
        .to_string();
    name.push_str(&format!(".reencrypt-{}-{nanos}.tmp", std::process::id()));
    path.with_file_name(name)
}

fn migrate_plaintext_to_encrypted(
    plain_conn: rusqlite::Connection,
    path: &Path,
    key_hex: &str,
) -> Result<(), StoreError> {
    let _ = plain_conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

    let source_version: i64 = plain_conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0);

    let tmp_path = temp_migration_path(path);
    let _ = fs::remove_file(&tmp_path); // clear out any dead attempt from a previous crashed run
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(REQUIRED_MODE)
        .open(&tmp_path)
        .map_err(StoreError::Io)?;

    let tmp_str = tmp_path.to_str().ok_or_else(|| {
        StoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database path is not valid UTF-8",
        ))
    })?;
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS reenc KEY \"x'{key_hex}'\";\n\
         SELECT sqlcipher_export('reenc');\n\
         PRAGMA reenc.user_version = {source_version};\n\
         DETACH DATABASE reenc;",
        tmp_str.replace('\'', "''"),
    );
    let result = plain_conn.execute_batch(&attach_sql);
    drop(plain_conn);

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp_path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(sibling_with_suffix(&tmp_path, suffix));
        }
        return Err(e.into());
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = fs::remove_file(sibling_with_suffix(&tmp_path, suffix));
    }

    fs::rename(&tmp_path, path).map_err(StoreError::Io)?;

    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = fs::remove_file(sibling_with_suffix(path, suffix));
    }
    Ok(())
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
    EncryptionKeyMismatchOrCorrupt {
        path: PathBuf,
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
            StoreError::EncryptionKeyMismatchOrCorrupt { path } => write!(
                f,
                "{} could not be opened with the current per-install data-encryption key, \
                 and is not a readable plaintext SQLite file either. This usually means the \
                 per-install key file (fossh's `.data_key`, alongside the data directory) was \
                 lost, replaced, or regenerated after this database was encrypted under a \
                 different key. Do not delete {}: restore the correct `.data_key` from backup \
                 if you have one. If the data genuinely cannot be recovered, move {} aside \
                 (e.g. `mv {} {}.bak`) and let foSSH create a fresh, empty database at the same path.",
                path.display(),
                path.display(),
                path.display(),
                path.display(),
                path.display(),
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
            StoreError::CorruptSketch
            | StoreError::PermissionsTooOpen { .. }
            | StoreError::EncryptionKeyMismatchOrCorrupt { .. } => None,
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

    mod encryption {
        use super::*;
        use fossh_core::types::{Country, Event, EventKind, SiteId};
        use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
        use fossh_core::validate::{Key, Name, Val};

        const KEY_A: [u8; 32] = [0x11; 32];
        const KEY_B: [u8; 32] = [0x22; 32];
        const MARKER: &str = "fossh-marker-quick-brown-fox-verify-me";

        fn scratch_path(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "fossh-store-encryption-test-{}",
                std::process::id()
            ));
            let _ = fs::create_dir_all(&dir);
            dir.join(format!("{name}.db"))
        }

        fn cleanup(path: &Path) {
            let _ = fs::remove_file(path);
            for suffix in ["-wal", "-shm", "-journal"] {
                let _ = fs::remove_file(sibling_with_suffix(path, suffix));
            }
        }

        fn marker_event(marker: &str) -> Event {
            Event {
                site_id: SiteId::new(1),
                ts: 1_700_000_000,
                kind: EventKind::Pageview,
                name: Name::parse("pageview").unwrap(),
                path: None,
                referrer: None,
                country: Country::parse("TR").unwrap(),
                browser: BrowserFamily::Chrome,
                os: OsFamily::Linux,
                device: DeviceClass::Desktop,
                visitor: Some(42),
                value: None,
                props: vec![(Key::parse("marker").unwrap(), Val::parse(marker).unwrap())],
            }
        }

        fn all_bytes_on_disk(path: &Path) -> Vec<u8> {
            let mut out = fs::read(path).unwrap_or_default();
            for suffix in ["-wal", "-journal"] {
                if let Ok(bytes) = fs::read(sibling_with_suffix(path, suffix)) {
                    out.extend(bytes);
                }
            }
            out
        }

        fn contains_marker(haystack: &[u8], marker: &str) -> bool {
            haystack
                .windows(marker.len())
                .any(|w| w == marker.as_bytes())
        }

        #[test]
        fn round_trips_a_marker_through_an_encrypted_database() {
            let path = scratch_path("roundtrip");
            cleanup(&path);

            {
                let mut store = Store::open_encrypted(&path, &KEY_A).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let store = Store::open_encrypted(&path, &KEY_A).unwrap();
            let stored: String = store
                .conn
                .query_row("SELECT v FROM props LIMIT 1", [], |r| r.get(0))
                .unwrap();
            assert_eq!(stored, MARKER, "the real API must still read back the exact marker");
            drop(store);
            cleanup(&path);
        }

        #[test]
        fn a_written_marker_is_not_recoverable_in_cleartext_from_disk() {
            let path = scratch_path("no-cleartext");
            cleanup(&path);

            {
                let mut store = Store::open_encrypted(&path, &KEY_A).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let raw = all_bytes_on_disk(&path);
            assert!(
                !raw.is_empty(),
                "sanity: the encrypted file(s) must actually contain bytes"
            );
            assert!(
                !contains_marker(&raw, MARKER),
                "marker string must not appear in cleartext anywhere on disk (main file or -wal)"
            );
            cleanup(&path);
        }

        #[test]
        fn wrong_key_is_rejected_cleanly_not_silently() {
            let path = scratch_path("wrong-key");
            cleanup(&path);

            {
                let mut store = Store::open_encrypted(&path, &KEY_A).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let result = Store::open_encrypted(&path, &KEY_B);
            assert!(
                matches!(result, Err(StoreError::EncryptionKeyMismatchOrCorrupt { .. })),
                "opening with the wrong key must fail cleanly, not return a usable Store: got {result:?}"
            );
            cleanup(&path);
        }

        #[test]
        fn no_key_cannot_open_an_already_encrypted_database() {
            let path = scratch_path("no-key");
            cleanup(&path);

            {
                let mut store = Store::open_encrypted(&path, &KEY_A).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let result = Store::open(&path);
            assert!(
                result.is_err(),
                "an unkeyed open of an encrypted database must fail, not return garbage"
            );
            cleanup(&path);
        }

        #[test]
        fn a_preexisting_plaintext_database_is_migrated_in_place_transparently() {
            let path = scratch_path("migrate");
            cleanup(&path);

            {
                let mut store = Store::open(&path).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let raw_before = fs::read(&path).unwrap();
            assert!(
                contains_marker(&raw_before, MARKER),
                "sanity: the pre-migration file really is plaintext"
            );

            let store = Store::open_encrypted(&path, &KEY_A).unwrap();
            let recovered: String = store
                .conn
                .query_row("SELECT v FROM props LIMIT 1", [], |r| r.get(0))
                .unwrap();
            assert_eq!(recovered, MARKER, "migration must preserve existing data, not discard it");
            drop(store);

            let raw_after = all_bytes_on_disk(&path);
            assert!(
                !contains_marker(&raw_after, MARKER),
                "after migration the marker must no longer be recoverable in cleartext"
            );

            assert!(
                matches!(
                    Store::open_encrypted(&path, &KEY_B),
                    Err(StoreError::EncryptionKeyMismatchOrCorrupt { .. })
                ),
                "the migrated database must now be a real SQLCipher database, not a no-op"
            );

            cleanup(&path);
        }

        #[test]
        fn migration_cleans_up_stale_wal_and_journal_siblings_of_the_original_plaintext_file() {
            let path = scratch_path("migrate-wal-cleanup");
            cleanup(&path);

            {
                let mut store = Store::open(&path).unwrap();
                store.record_event(&marker_event(MARKER)).unwrap();
            }

            let wal_path = sibling_with_suffix(&path, "-wal");
            let journal_path = sibling_with_suffix(&path, "-journal");
            fs::write(&wal_path, format!("stale plaintext wal: {MARKER}")).unwrap();
            fs::write(&journal_path, format!("stale plaintext journal: {MARKER}")).unwrap();

            Store::open_encrypted(&path, &KEY_A).unwrap();

            assert!(
                !wal_path.exists(),
                "a stale plaintext -wal sibling of the original file must not survive migration"
            );
            assert!(
                !journal_path.exists(),
                "a stale plaintext -journal sibling of the original file must not survive migration"
            );

            cleanup(&path);
        }

        #[test]
        fn fresh_encrypted_db_is_created_with_0600() {
            let path = scratch_path("fresh-encrypted-perms");
            cleanup(&path);
            Store::open_encrypted(&path, &KEY_A).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            cleanup(&path);
        }

        #[test]
        fn reopening_an_encrypted_db_with_the_same_key_is_idempotent() {
            let path = scratch_path("reopen-encrypted");
            cleanup(&path);
            Store::open_encrypted(&path, &KEY_A).unwrap();
            Store::open_encrypted(&path, &KEY_A).unwrap(); // must not error the second time
            cleanup(&path);
        }
    }
}
