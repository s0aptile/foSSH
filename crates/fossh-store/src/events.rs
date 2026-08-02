//! Raw event storage. `Store::record_event` is the only way in: it
//! interns name/path/referrer, inserts the raw row + its props, and folds
//! the event into its hourly rollup bucket, all inside one transaction —
//! matching the compactor's job of turning one drained spool frame into
//! both a durable raw row and an up-to-date aggregate.

use rusqlite::params;

use fossh_core::types::{Event, SiteId};
#[cfg(test)]
use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};

use crate::intern::{intern_name, intern_path, intern_ref};
use crate::rollup::upsert_rollup;
use crate::{Store, StoreError};

/// `rollup_hourly.path_id` is part of a `WITHOUT ROWID` primary key, so
/// SQLite implicitly forbids `NULL` there (unlike `events.path_id`, an
/// ordinary nullable column). `0` is reserved as "no path" — `paths.id` is
/// an `INTEGER PRIMARY KEY` (rowid alias) that SQLite starts allocating
/// from `1`, so `0` is never assigned to a real interned path.
pub(crate) const NO_PATH_SENTINEL: i64 = 0;

impl Store {
    /// Records one event: interns name/path/referrer, inserts the raw row
    /// and its properties, and folds it into the matching hourly rollup —
    /// all atomically. Returns the new `events.id`.
    pub fn record_event(&mut self, event: &Event) -> Result<i64, StoreError> {
        event.validate().map_err(StoreError::Validation)?;

        let tx = self.conn.transaction()?;

        let name_id = intern_name(&tx, event.name.as_str())?;
        let path_id = match &event.path {
            Some(p) => Some(intern_path(&tx, p.as_str())?),
            None => None,
        };
        let ref_id = match &event.referrer {
            Some(h) => Some(intern_ref(&tx, h.as_str())?),
            None => None,
        };

        tx.execute(
            "INSERT INTO events (site_id, ts, kind, name_id, path_id, ref_id, country, browser, os, device, visitor, value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.site_id.get(),
                event.ts,
                event.kind.as_i64(),
                name_id,
                path_id,
                ref_id,
                event.country.as_str(),
                event.browser.as_u8(),
                event.os.as_u8(),
                event.device.as_u8(),
                event.visitor.map(|v| v as i64),
                event.value,
            ],
        )?;
        let event_id = tx.last_insert_rowid();

        for (k, v) in &event.props {
            let key_id = intern_name(&tx, k.as_str())?;
            tx.execute(
                "INSERT INTO props (event_id, k, v) VALUES (?1, ?2, ?3)",
                params![event_id, key_id, v.as_str()],
            )?;
        }

        let rollup_path_id = path_id.unwrap_or(NO_PATH_SENTINEL);
        let bucket = event.ts.div_euclid(3600) * 3600;
        upsert_rollup(&tx, event, bucket, name_id, rollup_path_id)?;

        tx.commit()?;
        Ok(event_id)
    }

    /// Raw row count for a site — test/debug helper, also handy for
    /// `fossh doctor`-style sanity checks later.
    pub fn count_events(&self, site_id: SiteId) -> Result<u64, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE site_id = ?1",
            params![site_id.get()],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::types::{Country, EventKind, Host, Path};
    use fossh_core::validate::{Key, Name, Val};

    fn sample_event(site: u32, ts: i64, name: &str) -> Event {
        Event {
            site_id: SiteId::new(site),
            ts,
            kind: EventKind::Pageview,
            name: Name::parse(name).unwrap(),
            path: Some(Path::from_raw("/blog/hello-world")),
            referrer: Host::from_referrer_url("https://www.google.com/search?q=x"),
            country: Country::parse("TR").unwrap(),
            browser: BrowserFamily::Chrome,
            os: OsFamily::Linux,
            device: DeviceClass::Desktop,
            visitor: Some(0xABCD_EF01_2345_6789),
            value: None,
            props: vec![(Key::parse("plan").unwrap(), Val::parse("pro").unwrap())],
        }
    }

    #[test]
    fn record_event_round_trips() {
        let mut store = Store::open_in_memory().unwrap();
        let id = store
            .record_event(&sample_event(1, 1_700_000_000, "pageview"))
            .unwrap();
        assert!(id > 0);
        assert_eq!(store.count_events(SiteId::new(1)).unwrap(), 1);
    }

    #[test]
    fn record_event_rejects_too_many_props() {
        let mut store = Store::open_in_memory().unwrap();
        let mut ev = sample_event(1, 1_700_000_000, "pageview");
        ev.props = (0..17)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v").unwrap(),
                )
            })
            .collect();
        let result = store.record_event(&ev);
        assert!(matches!(result, Err(StoreError::Validation(_))));
        assert_eq!(
            store.count_events(SiteId::new(1)).unwrap(),
            0,
            "a rejected event must not be partially written"
        );
    }

    #[test]
    fn events_without_path_or_referrer_are_fine() {
        let mut store = Store::open_in_memory().unwrap();
        let mut ev = sample_event(1, 1_700_000_000, "signup.completed");
        ev.path = None;
        ev.referrer = None;
        ev.kind = EventKind::Action;
        ev.value = Some(1);
        let id = store.record_event(&ev).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn multiple_events_same_bucket_share_interned_ids() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_event(&sample_event(1, 1_700_000_000, "pageview"))
            .unwrap();
        store
            .record_event(&sample_event(1, 1_700_000_100, "pageview"))
            .unwrap();
        let names: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM names", [], |r| r.get(0))
            .unwrap();
        // `sample_event` uses the event name "pageview" and the prop key
        // "plan" (props keys intern into the same `names` table) — two
        // distinct strings, each interned twice, must still leave exactly
        // two rows, not four.
        assert_eq!(
            names, 2,
            "each distinct interned string (name + prop key) must reuse one row across both events"
        );
    }

    #[test]
    fn stored_browser_os_device_codes_match_fossh_core_encoding() {
        // The u8/from_u8 roundtrip itself is covered in fossh-core's own
        // tests; this just checks the stored integer actually is what
        // `as_u8()` produces, i.e. that `record_event` didn't invent its
        // own encoding somewhere along the way.
        let mut store = Store::open_in_memory().unwrap();
        let mut ev = sample_event(1, 1_700_000_000, "pageview");
        ev.browser = BrowserFamily::Edge;
        ev.os = OsFamily::Ios;
        ev.device = DeviceClass::Tablet;
        store.record_event(&ev).unwrap();

        let (browser, os, device): (i64, i64, i64) = store
            .conn
            .query_row("SELECT browser, os, device FROM events LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(browser, BrowserFamily::Edge.as_u8() as i64);
        assert_eq!(os, OsFamily::Ios.as_u8() as i64);
        assert_eq!(device, DeviceClass::Tablet.as_u8() as i64);
    }

    #[test]
    fn props_are_stored_and_countable() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_event(&sample_event(1, 1_700_000_000, "pageview"))
            .unwrap();
        let n: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM props", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}
