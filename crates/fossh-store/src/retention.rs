//! P7: raw event rows are hard-deleted after `retention_days`; rollups are
//! untouched (they hold aggregates/sketches, never visitor-level rows, so
//! there's nothing in them retention needs to remove).

use rusqlite::params;

use crate::{Store, StoreError};

impl Store {
    /// Hard-deletes `events` (and their `props`) with `ts` older than
    /// `now_ts - retention_days`. Returns the number of event rows removed.
    pub fn enforce_retention(
        &mut self,
        retention_days: u32,
        now_ts: i64,
    ) -> Result<u64, StoreError> {
        let cutoff = now_ts - i64::from(retention_days) * 86_400;
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM props WHERE event_id IN (SELECT id FROM events WHERE ts < ?1)",
            params![cutoff],
        )?;
        let deleted = tx.execute("DELETE FROM events WHERE ts < ?1", params![cutoff])?;
        tx.commit()?;
        Ok(deleted as u64)
    }

    /// `VACUUM`s the database file. §7.1/P7 describe this running "on
    /// ingest with probability 1/1000, and on `fossh maintain`" — the
    /// probability roll needs a source of randomness that has no business
    /// living in the storage layer, so that decision is the caller's job
    /// (`fossh-ingest`/`fossh-cli`, M3/M4); this method just does the work
    /// unconditionally when called.
    pub fn vacuum(&self) -> Result<(), StoreError> {
        self.conn.execute_batch("VACUUM;")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::types::{Country, Event, EventKind, SiteId};
    use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
    use fossh_core::validate::Name;

    fn event_at(ts: i64) -> Event {
        Event {
            site_id: SiteId::new(1),
            ts,
            kind: EventKind::Pageview,
            name: Name::parse("pageview").unwrap(),
            path: None,
            referrer: None,
            country: Country::parse("TR").unwrap(),
            browser: BrowserFamily::Chrome,
            os: OsFamily::Linux,
            device: DeviceClass::Desktop,
            visitor: Some(1),
            value: None,
            props: vec![],
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn deletes_only_events_older_than_the_cutoff() {
        let mut store = Store::open_in_memory().unwrap();
        let now = 1_700_000_000i64;
        store.record_event(&event_at(now - 100 * DAY)).unwrap(); // old, must go
        store.record_event(&event_at(now - DAY)).unwrap(); // recent, must stay

        let deleted = store.enforce_retention(90, now).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count_events(SiteId::new(1)).unwrap(), 1);
    }

    #[test]
    fn deletes_orphaned_props_too() {
        let mut store = Store::open_in_memory().unwrap();
        let now = 1_700_000_000i64;
        let mut ev = event_at(now - 100 * DAY);
        ev.props = vec![(
            fossh_core::validate::Key::parse("k").unwrap(),
            fossh_core::validate::Val::parse("v").unwrap(),
        )];
        store.record_event(&ev).unwrap();

        store.enforce_retention(90, now).unwrap();
        let props: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM props", [], |r| r.get(0))
            .unwrap();
        assert_eq!(props, 0, "props for a deleted event must not be orphaned");
    }

    #[test]
    fn rollups_survive_retention() {
        let mut store = Store::open_in_memory().unwrap();
        let now = 1_700_000_000i64;
        store.record_event(&event_at(now - 100 * DAY)).unwrap();

        store.enforce_retention(90, now).unwrap();

        let rollups: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM rollup_hourly", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rollups, 1, "P7: rollups survive raw-row deletion");
    }

    #[test]
    fn nothing_to_delete_is_not_an_error() {
        let mut store = Store::open_in_memory().unwrap();
        let deleted = store.enforce_retention(90, 1_700_000_000).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn vacuum_runs_without_error() {
        let store = Store::open_in_memory().unwrap();
        store.vacuum().unwrap();
    }
}
