use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};

use fossh_core::hist::Histogram;
use fossh_core::hll::Hll;
use fossh_core::types::{Event, SiteId};
use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};

use crate::{Store, StoreError};

type ExistingRollup = (Vec<u8>, i64, i64, Option<Vec<u8>>, i64);

pub(crate) fn upsert_rollup(
    conn: &Connection,
    event: &Event,
    bucket: i64,
    name_id: i64,
    path_id: i64,
) -> Result<(), StoreError> {
    let browser = event.browser.as_u8();
    let os = event.os.as_u8();
    let device = event.device.as_u8();
    let kind = event.kind.as_i64();
    let country = event.country.as_str();
    let site_id = event.site_id.get();

    let existing: Option<ExistingRollup> = conn
        .query_row(
            "SELECT uniques, hits, COALESCE(value_sum, 0), value_hist, COALESCE(value_count, 0)
             FROM rollup_hourly
             WHERE site_id = ?1 AND bucket = ?2 AND kind = ?3 AND name_id = ?4 AND path_id = ?5
               AND country = ?6 AND browser = ?7 AND os = ?8 AND device = ?9",
            params![
                site_id, bucket, kind, name_id, path_id, country, browser, os, device
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    let (mut hll, mut hits, mut value_sum, mut hist, mut value_count) = match existing {
        Some((u, h, vs, vh, vc)) => {
            let hll = Hll::from_bytes(&u).ok_or(StoreError::CorruptSketch)?;
            let hist = match vh {
                Some(b) => Histogram::from_bytes(&b).ok_or(StoreError::CorruptSketch)?,
                None => Histogram::new(),
            };
            (hll, h, vs, hist, vc)
        }
        None => (Hll::new(), 0i64, 0i64, Histogram::new(), 0i64),
    };

    hits += 1;
    if let Some(v) = event.visitor {
        hll.add(v);
    }
    if let Some(val) = event.value {
        hist.add(val);
        value_sum += val;
        value_count += 1;
    }

    let p50 = hist.percentile(0.5);
    let p95 = hist.percentile(0.95);

    conn.execute(
        "INSERT INTO rollup_hourly
            (site_id, bucket, kind, name_id, path_id, country, browser, os, device,
             hits, uniques, value_sum, value_count, value_hist, p50, p95)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
         ON CONFLICT(site_id, bucket, kind, name_id, path_id, country, browser, os, device)
         DO UPDATE SET
            hits = excluded.hits,
            uniques = excluded.uniques,
            value_sum = excluded.value_sum,
            value_count = excluded.value_count,
            value_hist = excluded.value_hist,
            p50 = excluded.p50,
            p95 = excluded.p95",
        params![
            site_id,
            bucket,
            kind,
            name_id,
            path_id,
            country,
            browser,
            os,
            device,
            hits,
            hll.to_bytes(),
            value_sum,
            value_count,
            hist.to_bytes(),
            p50,
            p95,
        ],
    )?;

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupByField {
    Kind,
    Name,
    Path,
    Country,
    Browser,
    Os,
    Device,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupRow {

    pub dims: Vec<(GroupByField, String)>,
    pub hits: i64,
    pub uniques: u64,
    pub p50: i64,
    pub p95: i64,
}

struct Accumulator {
    hits: i64,
    hll: Hll,
    hist: Histogram,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            hits: 0,
            hll: Hll::new(),
            hist: Histogram::new(),
        }
    }

    fn absorb(&mut self, hits: i64, hll: &Hll, hist: &Histogram) {
        self.hits += hits;
        self.hll.merge(hll);
        self.hist.merge(hist);
    }

    fn into_row(self, dims: Vec<(GroupByField, String)>) -> GroupRow {
        GroupRow {
            dims,
            hits: self.hits,
            uniques: self.hll.estimate().round() as u64,
            p50: self.hist.percentile(0.5),
            p95: self.hist.percentile(0.95),
        }
    }
}

impl Store {

    pub fn query_rollup(
        &self,
        site_id: SiteId,
        from_ts: i64,
        to_ts: i64,
        group_by: &[GroupByField],
        k_anonymity: u32,
    ) -> Result<Vec<GroupRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT r.kind, n.s, p.s, r.country, r.browser, r.os, r.device, r.hits, r.uniques, r.value_hist
             FROM rollup_hourly r
             JOIN names n ON n.id = r.name_id
             LEFT JOIN paths p ON p.id = r.path_id
             WHERE r.site_id = ?1 AND r.bucket >= ?2 AND r.bucket < ?3",
        )?;

        let rows = stmt.query_map(params![site_id.get(), from_ts, to_ts], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        })?;

        let mut groups: HashMap<Vec<String>, Accumulator> = HashMap::new();

        for row in rows {
            let (kind, name, path, country, browser, os, device, hits, uniques_bytes, hist_bytes) =
                row?;
            let hll = Hll::from_bytes(&uniques_bytes).ok_or(StoreError::CorruptSketch)?;
            let hist = match hist_bytes {
                Some(b) => Histogram::from_bytes(&b).ok_or(StoreError::CorruptSketch)?,
                None => Histogram::new(),
            };

            let dim_value = |f: GroupByField| -> String {
                match f {
                    GroupByField::Kind => kind.to_string(),
                    GroupByField::Name => name.clone(),
                    GroupByField::Path => path.clone().unwrap_or_default(),
                    GroupByField::Country => country.clone(),
                    GroupByField::Browser => format!("{:?}", BrowserFamily::from_u8(browser as u8)),
                    GroupByField::Os => format!("{:?}", OsFamily::from_u8(os as u8)),
                    GroupByField::Device => format!("{:?}", DeviceClass::from_u8(device as u8)),
                }
            };
            let key: Vec<String> = group_by.iter().map(|&f| dim_value(f)).collect();

            groups
                .entry(key)
                .or_insert_with(Accumulator::new)
                .absorb(hits, &hll, &hist);
        }

        let k = k_anonymity as u64;
        let mut kept: Vec<(Vec<String>, Accumulator)> = Vec::new();
        let mut other = Accumulator::new();
        let mut other_present = false;

        for (key, acc) in groups {
            if acc.hll.estimate().round() as u64 >= k {
                kept.push((key, acc));
            } else {
                other.absorb(acc.hits, &acc.hll, &acc.hist);
                other_present = true;
            }
        }

        if other_present && (other.hll.estimate().round() as u64) < k {

            kept.sort_by(|(_, a), (_, b)| {
                b.hll
                    .estimate()
                    .partial_cmp(&a.hll.estimate())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            while (other.hll.estimate().round() as u64) < k {
                match kept.pop() {
                    Some((_, acc)) => other.absorb(acc.hits, &acc.hll, &acc.hist),

                    None => return Ok(Vec::new()),
                }
            }
        }

        let mut result: Vec<GroupRow> = kept
            .into_iter()
            .map(|(key, acc)| acc.into_row(group_by.iter().copied().zip(key).collect()))
            .collect();

        if other_present {
            let dims = group_by
                .iter()
                .map(|&f| (f, "(other)".to_string()))
                .collect();
            result.push(other.into_row(dims));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::types::{Country, EventKind, Path};
    use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
    use fossh_core::validate::Name;

    fn event(site: u32, ts: i64, name: &str, path: &str, visitor_seed: u64) -> Event {
        let visitor_hash = fossh_core::visitor::hash_visitor(
            &[0x42; 32],
            &format!("203.0.113.{visitor_seed}"),
            "test-agent",
            SiteId::new(site),
        );
        Event {
            site_id: SiteId::new(site),
            ts,
            kind: EventKind::Pageview,
            name: Name::parse(name).unwrap(),
            path: Some(Path::from_raw(path)),
            referrer: None,
            country: Country::parse("TR").unwrap(),
            browser: BrowserFamily::Chrome,
            os: OsFamily::Linux,
            device: DeviceClass::Desktop,
            visitor: Some(visitor_hash),
            value: Some(120),
            props: vec![],
        }
    }

    #[test]
    fn repeated_events_in_the_same_bucket_accumulate_hits() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..5 {
            store
                .record_event(&event(1, 1_700_000_000 + i, "pageview", "/a", 1))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[], 1)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hits, 5);
    }

    #[test]
    fn uniques_reflect_distinct_visitors_not_hit_count() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..10 {

            store
                .record_event(&event(1, 1_700_000_000 + i, "pageview", "/a", i as u64 % 3))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[], 1)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hits, 10);
        assert_eq!(rows[0].uniques, 3);
    }

    #[test]
    fn group_by_path_splits_rows() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..10 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/a",
                    10 + i as u64,
                ))
                .unwrap();
        }
        for i in 0..10 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/b",
                    20 + i as u64,
                ))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 1)
            .unwrap();
        assert_eq!(rows.len(), 2);
        for r in &rows {
            assert_eq!(r.hits, 10);
            assert_eq!(r.uniques, 10);
        }
    }

    #[test]
    fn k_anonymity_folds_small_groups_into_other() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..20 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/popular",
                    100 + i as u64,
                ))
                .unwrap();
        }
        for i in 0..2 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/rare",
                    200 + i as u64,
                ))
                .unwrap();
        }
        for i in 0..3 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/rare2",
                    300 + i as u64,
                ))
                .unwrap();
        }

        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert_eq!(rows.len(), 2, "one real group + one (other) fold");

        let popular = rows
            .iter()
            .find(|r| r.dims[0].1 == "/popular")
            .expect("popular survives k-anon");
        assert_eq!(popular.uniques, 20);

        let other = rows
            .iter()
            .find(|r| r.dims[0].1 == "(other)")
            .expect("rare groups merge into a (other) that itself meets k");
        assert_eq!(other.hits, 5);
        assert_eq!(other.uniques, 5);
        assert!(
            other.uniques >= 5,
            "no reported group, including (other), may show uniques < k"
        );
    }

    #[test]
    fn the_hidden_remainder_cannot_be_recovered_by_subtracting_from_the_total() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..6 {
            store
                .record_event(&event(1, 1_700_000_000 + i, "pageview", "/a", i as u64))
                .unwrap();
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/b",
                    100 + i as u64,
                ))
                .unwrap();
        }

        store
            .record_event(&event(1, 1_700_000_000, "pageview", "/c", 999))
            .unwrap();

        let grouped = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        let total = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[], 5)
            .unwrap();
        assert_eq!(total.len(), 1, "no grouping is one row");

        assert!(
            !grouped.iter().any(|r| r.dims[0].1 == "/c"),
            "the single-visitor group must not be reported on its own"
        );

        let residual = total[0].hits - grouped.iter().map(|r| r.hits).sum::<i64>();
        assert_eq!(
            residual, 0,
            "the total minus the published groups must leave nothing: {grouped:#?}"
        );

        let other = grouped
            .iter()
            .find(|r| r.dims[0].1 == "(other)")
            .expect("a fold happened, so (other) must be published");
        assert!(
            other.uniques >= 5,
            "(other) with {} uniques would isolate what it is hiding",
            other.uniques
        );
        assert!(
            other.hits > 1,
            "(other) holding exactly the hidden group's hits discloses it verbatim"
        );
    }

    #[test]
    fn a_dataset_too_small_to_publish_at_all_returns_no_rows() {
        let mut store = Store::open_in_memory().unwrap();
        for (i, path) in ["/a", "/b", "/c"].iter().enumerate() {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i as i64,
                    "pageview",
                    path,
                    i as u64,
                ))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert!(
            rows.is_empty(),
            "three groups of one visitor each is three visitors, still under k=5: {rows:#?}"
        );
    }

    #[test]
    fn k_anonymity_default_five_matches_spec() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..4 {
            store
                .record_event(&event(1, 1_700_000_000 + i, "pageview", "/a", i as u64))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert!(
            rows.is_empty(),
            "4 uniques < k=5, and the lone (other) fold's own uniques are also 4 < 5 — not reportable at all"
        );
    }

    #[test]
    fn other_bucket_below_k_after_merge_is_suppressed_entirely() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..2 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/a",
                    100 + i as u64,
                ))
                .unwrap();
        }
        for i in 0..2 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/b",
                    200 + i as u64,
                ))
                .unwrap();
        }

        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert!(
            rows.is_empty(),
            "both groups fold into (other), whose own merged uniques (4) is still < k=5"
        );
    }

    #[test]
    fn other_bucket_at_or_above_k_after_merge_is_reported() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..2 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/a",
                    100 + i as u64,
                ))
                .unwrap();
        }
        for i in 0..3 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/b",
                    200 + i as u64,
                ))
                .unwrap();
        }

        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "the merged (other) bucket meets k=5 and is reportable"
        );
        assert_eq!(rows[0].dims[0].1, "(other)");
        assert_eq!(rows[0].uniques, 5);
        assert!(
            rows[0].uniques >= 5,
            "no reported group may show uniques < k"
        );
    }

    #[test]
    fn suppressed_other_bucket_leaks_no_row_at_all_not_even_via_hits() {
        let mut store = Store::open_in_memory().unwrap();
        for i in 0..2 {
            store
                .record_event(&event(
                    1,
                    1_700_000_000 + i,
                    "pageview",
                    "/rare",
                    300 + i as u64,
                ))
                .unwrap();
        }
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 5)
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn time_range_filters_buckets() {
        let mut store = Store::open_in_memory().unwrap();

        let bucket_a = 36_000i64;
        let bucket_b = bucket_a + 7_200;
        store
            .record_event(&event(1, bucket_a, "pageview", "/a", 1))
            .unwrap();
        store
            .record_event(&event(1, bucket_b, "pageview", "/a", 2))
            .unwrap();
        let rows = store
            .query_rollup(SiteId::new(1), bucket_a, bucket_a + 3600, &[], 1)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hits, 1);
    }

    #[test]
    fn different_sites_never_mix() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .record_event(&event(1, 1_700_000_000, "pageview", "/a", 1))
            .unwrap();
        store
            .record_event(&event(2, 1_700_000_000, "pageview", "/a", 1))
            .unwrap();
        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[], 1)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hits, 1);
    }

    #[test]
    fn events_without_a_path_use_the_sentinel_and_do_not_collide_with_a_real_path() {
        let mut store = Store::open_in_memory().unwrap();
        let mut no_path = event(1, 1_700_000_000, "signup", "/x", 1);
        no_path.path = None;
        store.record_event(&no_path).unwrap();
        store
            .record_event(&event(1, 1_700_000_001, "signup", "/x", 2))
            .unwrap();

        let rows = store
            .query_rollup(SiteId::new(1), 0, i64::MAX, &[GroupByField::Path], 1)
            .unwrap();
        assert_eq!(rows.len(), 2, "no-path and /x must be distinct rollup rows");
    }
}
