//! Interning helpers shared by `events` and `rollup`. Each function's SQL
//! is a complete, hardcoded literal — no `format!`/`push_str` building a
//! query string anywhere near these, which is what S3's CI grep gate
//! (added in M8) actually greps for. Take `&rusqlite::Connection` so
//! callers can pass a `&rusqlite::Transaction` too (it derefs to
//! `Connection`), keeping interning and the row insert it precedes in one
//! atomic unit.
//!
//! Prop *keys* intern into the same `names` table as event names (§6 has
//! no separate keys table, and both are short allowlisted identifiers
//! under the same grammar — see DECISIONS.md).

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

pub(crate) fn intern_name(conn: &Connection, s: &str) -> Result<i64, StoreError> {
    conn.query_row(
        "INSERT INTO names(s) VALUES (?1) ON CONFLICT(s) DO UPDATE SET s = excluded.s RETURNING id",
        params![s],
        |row| row.get(0),
    )
    .map_err(StoreError::from)
}

pub(crate) fn intern_path(conn: &Connection, s: &str) -> Result<i64, StoreError> {
    conn.query_row(
        "INSERT INTO paths(s) VALUES (?1) ON CONFLICT(s) DO UPDATE SET s = excluded.s RETURNING id",
        params![s],
        |row| row.get(0),
    )
    .map_err(StoreError::from)
}

pub(crate) fn intern_ref(conn: &Connection, s: &str) -> Result<i64, StoreError> {
    conn.query_row(
        "INSERT INTO refs(s) VALUES (?1) ON CONFLICT(s) DO UPDATE SET s = excluded.s RETURNING id",
        params![s],
        |row| row.get(0),
    )
    .map_err(StoreError::from)
}

/// Looks up an interned id without inserting — used for read paths
/// (queries never need to *create* a name/path row).
#[allow(dead_code)] // used once query-side lookups grow past the join-based approach in rollup.rs
pub(crate) fn lookup_name_id(conn: &Connection, s: &str) -> Result<Option<i64>, StoreError> {
    conn.query_row("SELECT id FROM names WHERE s = ?1", params![s], |row| {
        row.get(0)
    })
    .optional()
    .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn interning_the_same_string_twice_returns_the_same_id() {
        let store = Store::open_in_memory().unwrap();
        let a = intern_name(&store.conn, "signup.completed").unwrap();
        let b = intern_name(&store.conn, "signup.completed").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn interning_different_strings_returns_different_ids() {
        let store = Store::open_in_memory().unwrap();
        let a = intern_name(&store.conn, "signup.completed").unwrap();
        let b = intern_name(&store.conn, "signup.started").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn three_tables_are_independent_namespaces() {
        let store = Store::open_in_memory().unwrap();
        let name_id = intern_name(&store.conn, "shared-string").unwrap();
        let path_id = intern_path(&store.conn, "shared-string").unwrap();
        let ref_id = intern_ref(&store.conn, "shared-string").unwrap();
        // All three are free to reuse the same underlying id space (each
        // table has its own autoincrement) — nothing should crash or
        // collide across tables.
        assert!(name_id >= 1 && path_id >= 1 && ref_id >= 1);
    }

    #[test]
    fn lookup_missing_name_is_none() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(lookup_name_id(&store.conn, "never-interned").unwrap(), None);
    }

    #[test]
    fn lookup_finds_interned_name() {
        let store = Store::open_in_memory().unwrap();
        let id = intern_name(&store.conn, "signup.completed").unwrap();
        assert_eq!(
            lookup_name_id(&store.conn, "signup.completed").unwrap(),
            Some(id)
        );
    }
}
