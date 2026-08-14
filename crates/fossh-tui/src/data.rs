//! Real data for the telemetry screen, independent of the watchdog
//! (whose own live status is `watchdog_status.rs`'s job instead): a
//! per-site telemetry summary read straight from the same
//! `fossh-store` database `fossh-cli query` reads.

use std::path::{Path, PathBuf};

use fossh_core::types::SiteId;
use fossh_store::{GroupByField, Store};

pub struct SiteSummary {
    pub slug: String,
    pub public: bool,
    pub disabled: bool,
    pub hits_today: i64,
    pub uniques_today: u64,
}

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("fossh.db")
}

/// One day back from `now` — matches how "today" is defined for a
/// quick dashboard glance; not meant to replace `fossh query`'s
/// explicit `--from`/`--to` for real reporting. `rem_euclid`, not `%`:
/// Rust's `%` takes the sign of the dividend, so a negative `now`
/// (unreachable today — `unix_now()`'s only fallback is exactly `0`,
/// never negative — but not `pub`, so nothing enforces that at this
/// function's own boundary) would overshoot past the day start instead
/// of rounding down to it.
fn start_of_today(now: i64) -> i64 {
    now - now.rem_euclid(86_400)
}

pub fn load_summary(
    data_dir: &Path,
    now: i64,
    k_anonymity: u32,
) -> Result<Vec<SiteSummary>, String> {
    let key = fossh_admin::data_key::load_or_generate(&data_dir.join(".data_key"))
        .map_err(|e| e.to_string())?;
    let store = Store::open_encrypted(&db_path(data_dir), &key).map_err(|e| e.to_string())?;
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
        // Uniques don't sum across HyperLogLog buckets the way hits do —
        // this is a display approximation (sum of already-estimated
        // per-kind counts), good enough for a glance, not a substitute
        // for `fossh query`'s actual merged-sketch estimate.
        let uniques_today: u64 = rows.iter().map(|r| r.uniques).sum();
        out.push(SiteSummary {
            slug: site.slug,
            public: site.public,
            disabled: site.disabled,
            hits_today,
            uniques_today,
        });
    }
    Ok(out)
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
        // Unreachable via `unix_now()` today (its only fallback is
        // exactly `0`), but `start_of_today` isn't `pub` specifically
        // so nothing outside this module can rely on that — this
        // function's own contract must hold regardless.
        assert_eq!(start_of_today(-1), -86_400);
        assert_eq!(start_of_today(-86_400), -86_400);
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-tui-data-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fresh_data_dir_has_no_sites() {
        let dir = scratch_dir("fresh");
        let summary = load_summary(&dir, 1_700_000_000, 5).unwrap();
        assert!(summary.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_created_site_shows_up_with_zero_activity() {
        let dir = scratch_dir("one-site");
        {
            // Same key `load_summary` will derive below: `load_or_generate`
            // is idempotent on the same `.data_key` path, so seeding the
            // store here through the real encrypted API (not plain
            // `Store::open`) exercises exactly the path a real caller
            // takes, rather than relying on `open_encrypted`'s plaintext-
            // migration fallback to paper over a mismatched test setup.
            let key = fossh_admin::data_key::load_or_generate(&dir.join(".data_key")).unwrap();
            let store = Store::open_encrypted(&db_path(&dir), &key).unwrap();
            store
                .create_site(
                    "blog",
                    &[7u8; 32],
                    None,
                    &["pageview".to_string()],
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
        std::fs::remove_dir_all(&dir).ok();
    }
}
