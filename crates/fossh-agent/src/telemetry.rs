//! Everything the console reads out of `fossh-store`, independent of
//! the watchdog (whose live status is `watchdog_status.rs`'s job).
//!
//! The k-anonymity fold (P6) is not reimplemented here and must never
//! be: it is enforced once, inside `fossh-store`'s query engine, so no
//! read path can bypass it — see `THREAT_MODEL.md`'s "curious
//! operator" entry. This module passes `k_anonymity` through and
//! reports whether the result came back entirely folded, so the
//! console can say so plainly instead of drawing an empty chart.

use std::path::{Path, PathBuf};

use fossh_core::types::SiteId;
use fossh_store::{GroupByField, Store};

pub struct SiteSummary {
    pub slug: String,
    pub public: bool,
    pub disabled: bool,
    pub allowlist: Vec<String>,
    pub created_at: i64,
    pub hits_today: i64,
    pub uniques_today: u64,
}

#[derive(Debug)]
pub struct QueryRow {
    pub dims: Vec<(String, String)>,
    pub hits: i64,
    pub uniques: u64,
    pub p50: i64,
    pub p95: i64,
}

#[derive(Debug)]
pub struct QueryResult {
    pub rows: Vec<QueryRow>,
    /// True when every row that came back is the synthetic `(other)`
    /// fold — the normal case for a low-traffic site, and something the
    /// console has to distinguish from "no data" so it can explain
    /// rather than look broken.
    pub entirely_folded: bool,
}

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("fossh.db")
}

/// One day back from `now` — matches how "today" is defined for a quick
/// glance; not a replacement for an explicit range. `rem_euclid`, not
/// `%`: Rust's `%` takes the sign of the dividend, so a negative `now`
/// would overshoot past the day start instead of rounding down to it.
fn start_of_today(now: i64) -> i64 {
    now - now.rem_euclid(86_400)
}

pub fn field_name(f: GroupByField) -> &'static str {
    match f {
        GroupByField::Kind => "kind",
        GroupByField::Name => "name",
        GroupByField::Path => "path",
        GroupByField::Country => "country",
        GroupByField::Browser => "browser",
        GroupByField::Os => "os",
        GroupByField::Device => "device",
    }
}

/// The console sends field names as strings; this is the only place
/// they are turned back into the enum, so an unknown one is rejected
/// once rather than silently ignored somewhere downstream.
pub fn parse_field(name: &str) -> Option<GroupByField> {
    match name {
        "kind" => Some(GroupByField::Kind),
        "name" => Some(GroupByField::Name),
        "path" => Some(GroupByField::Path),
        "country" => Some(GroupByField::Country),
        "browser" => Some(GroupByField::Browser),
        "os" => Some(GroupByField::Os),
        "device" => Some(GroupByField::Device),
        _ => None,
    }
}

fn open(data_dir: &Path) -> Result<Store, String> {
    let key = fossh_admin::data_key::load_or_generate(&data_dir.join(".data_key"))
        .map_err(|e| e.to_string())?;
    Store::open_encrypted(&db_path(data_dir), &key).map_err(|e| e.to_string())
}

pub fn load_summary(
    data_dir: &Path,
    now: i64,
    k_anonymity: u32,
) -> Result<Vec<SiteSummary>, String> {
    let store = open(data_dir)?;
    let sites = store.list_sites().map_err(|e| e.to_string())?;
    let from = start_of_today(now);

    let mut out = Vec::with_capacity(sites.len());
    for site in sites {
        let rows = store
            .query_rollup(
                SiteId::new(site.id.get()),
                from,
                now,
                &[GroupByField::Kind],
                k_anonymity,
            )
            .map_err(|e| e.to_string())?;
        let hits_today: i64 = rows.iter().map(|r| r.hits).sum();
        // Uniques don't sum across HyperLogLog buckets the way hits do
        // — this is a display approximation (a sum of already-estimated
        // per-kind counts), good enough for a glance, not a substitute
        // for a real merged-sketch estimate.
        let uniques_today: u64 = rows.iter().map(|r| r.uniques).sum();
        out.push(SiteSummary {
            slug: site.slug,
            public: site.public,
            disabled: site.disabled,
            allowlist: site.allowlist,
            created_at: site.created_at,
            hits_today,
            uniques_today,
        });
    }
    Ok(out)
}

pub fn query(
    data_dir: &Path,
    slug: &str,
    from: i64,
    to: i64,
    group_by: &[GroupByField],
    k_anonymity: u32,
) -> Result<QueryResult, String> {
    let store = open(data_dir)?;
    let site = store
        .find_site_by_slug(slug)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no site named \"{slug}\""))?;

    let rows = store
        .query_rollup(site.id, from, to, group_by, k_anonymity)
        .map_err(|e| e.to_string())?;

    let entirely_folded = !rows.is_empty()
        && rows
            .iter()
            .all(|r| r.dims.iter().all(|(_, v)| v == "(other)"));

    let rows = rows
        .into_iter()
        .map(|r| QueryRow {
            dims: r
                .dims
                .into_iter()
                .map(|(f, v)| (field_name(f).to_string(), v))
                .collect(),
            hits: r.hits,
            uniques: r.uniques,
            p50: r.p50,
            p95: r.p95,
        })
        .collect();

    Ok(QueryResult {
        rows,
        entirely_folded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_of_today_rounds_down_to_the_day_boundary() {
        assert_eq!(start_of_today(1_700_000_000), 1_699_920_000);
        assert_eq!(start_of_today(86_400), 86_400);
        assert_eq!(start_of_today(86_399), 0);
    }

    #[test]
    fn start_of_today_handles_a_negative_timestamp_without_overshooting() {
        assert_eq!(start_of_today(-1), -86_400);
        assert_eq!(start_of_today(-86_400), -86_400);
    }

    #[test]
    fn every_group_by_field_round_trips_through_its_wire_name() {
        // A field that serialises to a name `parse_field` doesn't know
        // would be a console request that silently can't be made.
        for f in [
            GroupByField::Kind,
            GroupByField::Name,
            GroupByField::Path,
            GroupByField::Country,
            GroupByField::Browser,
            GroupByField::Os,
            GroupByField::Device,
        ] {
            assert_eq!(
                parse_field(field_name(f)),
                Some(f),
                "{f:?} did not round-trip"
            );
        }
        assert_eq!(parse_field("visitor_ip"), None);
        assert_eq!(parse_field(""), None);
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-agent-telemetry-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fresh_data_dir_has_no_sites() {
        let dir = scratch_dir("fresh");
        assert!(load_summary(&dir, 1_700_000_000, 5).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_created_site_shows_up_with_its_real_metadata_and_zero_activity() {
        let dir = scratch_dir("one-site");
        {
            let key = fossh_admin::data_key::load_or_generate(&dir.join(".data_key")).unwrap();
            let store = Store::open_encrypted(&db_path(&dir), &key).unwrap();
            store
                .create_site(
                    "blog",
                    &[7u8; 32],
                    None,
                    &["pageview".to_string(), "signup".to_string()],
                    1_700_000_000,
                    false,
                )
                .unwrap();
        }
        let summary = load_summary(&dir, 1_700_000_000, 5).unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].slug, "blog");
        assert_eq!(summary[0].hits_today, 0);
        assert_eq!(summary[0].uniques_today, 0);
        assert_eq!(summary[0].allowlist, vec!["pageview", "signup"]);
        assert_eq!(summary[0].created_at, 1_700_000_000);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn querying_a_site_that_does_not_exist_says_so_instead_of_returning_nothing() {
        // An empty result and a typo in the slug look identical in the
        // console unless they are distinguished here.
        let dir = scratch_dir("missing-site");
        let err = query(&dir, "nope", 0, 1_700_000_000, &[GroupByField::Path], 5).unwrap_err();
        assert!(err.contains("nope"), "unhelpful error: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_result_is_not_reported_as_entirely_folded() {
        // `entirely_folded` drives a specific explanation in the
        // console ("your traffic is below k"); showing it for a site
        // with genuinely no events would be a lie.
        let dir = scratch_dir("empty-not-folded");
        {
            let key = fossh_admin::data_key::load_or_generate(&dir.join(".data_key")).unwrap();
            let store = Store::open_encrypted(&db_path(&dir), &key).unwrap();
            store
                .create_site(
                    "blog",
                    &[7u8; 32],
                    None,
                    &["pageview".to_string()],
                    0,
                    false,
                )
                .unwrap();
        }
        let result = query(&dir, "blog", 0, 1_700_000_000, &[GroupByField::Path], 5).unwrap();
        assert!(result.rows.is_empty());
        assert!(!result.entirely_folded);
        std::fs::remove_dir_all(&dir).ok();
    }
}
