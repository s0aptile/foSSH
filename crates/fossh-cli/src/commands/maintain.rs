//! `fossh maintain` (§9, §7.1): drain every site's spool, enforce
//! retention, vacuum. This is the "or cron every minute" compactor §7.1
//! mentions as an alternative to `fossh-fcgi`'s background thread (M7).

use fossh_core::types::SiteId;

use crate::common::{load_config, open_store, unix_now};

fn site_spool_dir(data_dir: &std::path::Path, site_id: SiteId) -> std::path::PathBuf {
    data_dir
        .join("sites")
        .join(site_id.get().to_string())
        .join("spool")
}

pub fn run(_args: &[String]) -> i32 {
    let config = load_config();
    let mut store = open_store(&config.data_dir);
    let now = unix_now();

    let sites = match store.list_sites() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fossh maintain: listing sites: {e}");
            return 1;
        }
    };

    let mut total_recorded = 0u64;
    let mut total_corrupt = 0u64;
    for site in &sites {
        let dir = site_spool_dir(&config.data_dir, site.id);
        match fossh_ingest::compact::drain_site_spool(&mut store, &dir) {
            Ok(stats) => {
                total_recorded += stats.events_recorded;
                total_corrupt += stats.frames_corrupt;
                if stats.events_recorded > 0 || stats.frames_corrupt > 0 {
                    println!(
                        "{}: recorded {} event(s), {} corrupt frame(s) dropped",
                        site.slug, stats.events_recorded, stats.frames_corrupt
                    );
                }
            }
            Err(e) => eprintln!("fossh maintain: draining spool for '{}': {e}", site.slug),
        }
    }

    let deleted = match store.enforce_retention(config.retention_days, now) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("fossh maintain: enforcing retention: {e}");
            return 1;
        }
    };

    // §7.1/P7: "a vacuum job runs ... on `fossh maintain`" — unconditional
    // here, unlike the ingest hot path's separate 1/1000 probabilistic
    // trigger (a decision that needs a source of randomness that has no
    // business in the storage layer — see `fossh-store`'s
    // `retention::vacuum` doc comment).
    if let Err(e) = store.vacuum() {
        eprintln!("fossh maintain: vacuum: {e}");
        return 1;
    }

    println!(
        "Maintenance complete: {total_recorded} event(s) recorded, {total_corrupt} corrupt frame(s) dropped, \
         {deleted} expired row(s) deleted, database vacuumed."
    );
    0
}
