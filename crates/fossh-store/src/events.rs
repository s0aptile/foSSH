use rusqlite::{Connection, params};

use fossh_core::types::{Event, SiteId};
#[cfg(test)]
use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};

use crate::intern::{intern_name, intern_path, intern_ref};
use crate::rollup::upsert_rollup;
use crate::{Store, StoreError};

pub(crate) const NO_PATH_SENTINEL: i64 = 0;

fn insert_one(conn: &Connection, event: &Event) -> Result<i64, StoreError> {
    event.validate().map_err(StoreError::Validation)?;

    let name_id = intern_name(conn, event.name.as_str())?;
    let path_id = match &event.path {
        Some(p) => Some(intern_path(conn, p.as_str())?),
        None => None,
    };
    let ref_id = match &event.referrer {
        Some(h) => Some(intern_ref(conn, h.as_str())?),
        None => None,
    };

    conn.execute(
        "INSERT INTO events (site_id, ts, kind, name_id, path_id, ref_id, country, browser, os, device, value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
            event.value,
        ],
    )?;
    let event_id = conn.last_insert_rowid();

    for (k, v) in &event.props {
        let key_id = intern_name(conn, k.as_str())?;
        conn.execute(
            "INSERT INTO props (event_id, k, v) VALUES (?1, ?2, ?3)",
            params![event_id, key_id, v.as_str()],
        )?;
    }

    let rollup_path_id = path_id.unwrap_or(NO_PATH_SENTINEL);
    let bucket = event.ts.div_euclid(3600) * 3600;
    upsert_rollup(conn, event, bucket, name_id, rollup_path_id)?;

    Ok(event_id)
}

impl Store {

    pub fn record_event(&mut self, event: &Event) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        let event_id = insert_one(&tx, event)?;
        tx.commit()?;
        Ok(event_id)
    }

    pub fn record_events_batch(&mut self, events: &[Event]) -> Result<u64, StoreError> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut tx = self.conn.transaction()?;
        let mut recorded = 0u64;
        for event in events {
            let sp = tx.savepoint()?;
            if insert_one(&sp, event).is_ok() {
                sp.commit()?;
                recorded += 1;
            }

        }
        tx.commit()?;
        Ok(recorded)
    }

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

        assert_eq!(
            names, 2,
            "each distinct interned string (name + prop key) must reuse one row across both events"
        );
    }

    #[test]
    fn stored_browser_os_device_codes_match_fossh_core_encoding() {

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
    fn events_table_has_no_visitor_column_to_query_at_all() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_event(&sample_event(1, 1_700_000_000, "pageview"))
            .unwrap();
        let result = store
            .conn
            .query_row("SELECT visitor FROM events LIMIT 1", [], |r| {
                r.get::<_, i64>(0)
            });
        assert!(
            result.is_err(),
            "events.visitor must not exist as a column at all"
        );
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

    #[test]
    fn record_events_batch_records_all_of_them_in_one_shared_transaction() {
        let mut store = Store::open_in_memory().unwrap();
        let events = vec![
            sample_event(1, 1_700_000_000, "pageview"),
            sample_event(1, 1_700_000_100, "pageview"),
            sample_event(2, 1_700_000_200, "pageview"),
        ];
        let recorded = store.record_events_batch(&events).unwrap();
        assert_eq!(recorded, 3);
        assert_eq!(store.count_events(SiteId::new(1)).unwrap(), 2);
        assert_eq!(store.count_events(SiteId::new(2)).unwrap(), 1);
    }

    #[test]
    fn record_events_batch_empty_slice_is_a_no_op_not_an_error() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.record_events_batch(&[]).unwrap(), 0);
    }

    #[test]
    fn record_events_batch_one_invalid_event_is_skipped_without_affecting_the_others() {

        let mut store = Store::open_in_memory().unwrap();
        let mut invalid = sample_event(1, 1_700_000_100, "pageview");
        invalid.props = (0..17)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v").unwrap(),
                )
            })
            .collect();
        let events = vec![
            sample_event(1, 1_700_000_000, "pageview"),
            invalid,
            sample_event(1, 1_700_000_200, "pageview"),
        ];

        let recorded = store.record_events_batch(&events).unwrap();
        assert_eq!(recorded, 2, "only the two valid events");
        assert_eq!(
            store.count_events(SiteId::new(1)).unwrap(),
            2,
            "the invalid event's savepoint must have rolled back cleanly, \
             leaving the two valid events (before and after it) committed"
        );
    }
}
