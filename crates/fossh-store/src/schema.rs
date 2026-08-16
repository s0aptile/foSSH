pub const PRAGMAS: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 3000;
PRAGMA foreign_keys = ON;
PRAGMA trusted_schema = OFF;
";

const SCHEMA_V1: &str = "
CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  name_id INTEGER NOT NULL REFERENCES names(id),
  path_id INTEGER REFERENCES paths(id),
  ref_id INTEGER REFERENCES refs(id),
  country TEXT NOT NULL,
  browser INTEGER NOT NULL,
  os INTEGER NOT NULL,
  device INTEGER NOT NULL,
  value INTEGER
) STRICT;

CREATE INDEX idx_events_site_ts ON events(site_id, ts);

CREATE TABLE props (
  event_id INTEGER NOT NULL REFERENCES events(id),
  k INTEGER NOT NULL REFERENCES names(id),
  v TEXT NOT NULL
) STRICT;

CREATE INDEX idx_props_event_id ON props(event_id);

CREATE TABLE names (id INTEGER PRIMARY KEY, s TEXT UNIQUE NOT NULL) STRICT;
CREATE TABLE paths (id INTEGER PRIMARY KEY, s TEXT UNIQUE NOT NULL) STRICT;
CREATE TABLE refs  (id INTEGER PRIMARY KEY, s TEXT UNIQUE NOT NULL) STRICT;

CREATE TABLE rollup_hourly (
  site_id INTEGER NOT NULL,
  bucket INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  name_id INTEGER NOT NULL,
  path_id INTEGER NOT NULL,
  country TEXT NOT NULL,
  browser INTEGER NOT NULL,
  os INTEGER NOT NULL,
  device INTEGER NOT NULL,
  hits INTEGER NOT NULL,
  uniques BLOB NOT NULL,
  value_sum INTEGER,
  value_count INTEGER,
  value_hist BLOB,
  p50 INTEGER,
  p95 INTEGER,
  PRIMARY KEY (site_id, bucket, kind, name_id, path_id, country, browser, os, device)
) STRICT, WITHOUT ROWID;

CREATE TABLE sites (
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  key_hash BLOB NOT NULL,
  allowlist TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  public INTEGER NOT NULL DEFAULT 0
) STRICT;
";

const SCHEMA_V2: &str = "
ALTER TABLE sites ADD COLUMN sign_pubkey BLOB;
";

pub fn migrate(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.execute_batch("PRAGMA user_version = 1;")?;
    }
    if version < 2 {
        conn.execute_batch(SCHEMA_V2)?;
        conn.execute_batch("PRAGMA user_version = 2;")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PRAGMAS, SCHEMA_V1};
    use crate::Store;

    fn columns_of(conn: &rusqlite::Connection, table: &str) -> Vec<(String, String, bool)> {
        let mut stmt = conn
            .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info(?1) ORDER BY cid")
            .unwrap();
        stmt.query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    #[test]
    fn events_table_has_exactly_the_expected_columns() {
        let store = Store::open_in_memory().unwrap();
        let cols = columns_of(&store.conn, "events");
        let expected = vec![
            ("id".to_string(), "INTEGER".to_string(), false),
            ("site_id".to_string(), "INTEGER".to_string(), true),
            ("ts".to_string(), "INTEGER".to_string(), true),
            ("kind".to_string(), "INTEGER".to_string(), true),
            ("name_id".to_string(), "INTEGER".to_string(), true),
            ("path_id".to_string(), "INTEGER".to_string(), false),
            ("ref_id".to_string(), "INTEGER".to_string(), false),
            ("country".to_string(), "TEXT".to_string(), true),
            ("browser".to_string(), "INTEGER".to_string(), true),
            ("os".to_string(), "INTEGER".to_string(), true),
            ("device".to_string(), "INTEGER".to_string(), true),
            ("value".to_string(), "INTEGER".to_string(), false),
        ];
        assert_eq!(
            cols, expected,
            "events column set changed — re-review P1 before updating this test"
        );
    }

    #[test]
    fn rollup_hourly_table_has_exactly_the_expected_columns() {
        let store = Store::open_in_memory().unwrap();
        let cols = columns_of(&store.conn, "rollup_hourly");
        let names: Vec<&str> = cols.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "site_id",
                "bucket",
                "kind",
                "name_id",
                "path_id",
                "country",
                "browser",
                "os",
                "device",
                "hits",
                "uniques",
                "value_sum",
                "value_count",
                "value_hist",
                "p50",
                "p95",
            ],
            "rollup_hourly column set changed — see the ADR on uniques/value_hist before updating this test"
        );
    }

    #[test]
    fn sites_table_has_exactly_the_expected_columns() {
        let store = Store::open_in_memory().unwrap();
        let cols = columns_of(&store.conn, "sites");
        let names: Vec<&str> = cols.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "id",
                "slug",
                "key_hash",
                "allowlist",
                "created_at",
                "disabled",
                "public",
                "sign_pubkey"
            ]
        );
    }

    #[test]
    fn no_pii_shaped_column_names_anywhere_in_the_schema() {
        let store = Store::open_in_memory().unwrap();
        let mut stmt = store
            .conn
            .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let banned = [
            "ip",
            "email",
            "username",
            "query_string",
            "user_agent",
            "ua_raw",
        ];
        for table in tables {
            for (col, _, _) in columns_of(&store.conn, &table) {
                let lower = col.to_lowercase();
                assert!(
                    !banned.iter().any(|b| lower.contains(b)),
                    "column {table}.{col} looks PII-shaped"
                );
            }
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let store = Store::open_in_memory().unwrap();

        super::migrate(&store.conn).unwrap();
        super::migrate(&store.conn).unwrap();
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }

    #[test]
    fn v1_to_v2_migration_adds_sign_pubkey_without_disturbing_existing_sites() {

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(PRAGMAS).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
        conn.execute(
            "INSERT INTO sites (slug, key_hash, allowlist, created_at, disabled, public) VALUES ('blog', X'42', '[]', 1700000000, 0, 0)",
            [],
        )
        .unwrap();

        super::migrate(&conn).unwrap();

        let (key_hash, sign_pubkey): (Vec<u8>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT key_hash, sign_pubkey FROM sites WHERE slug = 'blog'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(key_hash, vec![0x42]);
        assert_eq!(
            sign_pubkey, None,
            "a site migrated from v1 has no signing key yet — opt-in via rotate-signing-key"
        );
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let store = Store::open_in_memory().unwrap();
        let result = store.conn.execute(
            "INSERT INTO events (site_id, ts, kind, name_id, country, browser, os, device) VALUES (1, 0, 0, 999, 'ZZ', 0, 0, 0)",
            [],
        );
        assert!(
            result.is_err(),
            "inserting an event with a non-existent name_id must fail (foreign_keys=ON)"
        );
    }
}
