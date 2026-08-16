use fossh_core::types::SiteId;

use crate::args::wants_help;
use crate::common::{load_config, open_store, unix_now};

const HELP: &str = "usage: fossh maintain\n\n\
Drain every site's spool into the database, enforce retention, vacuum.";

fn site_spool_dir(data_dir: &std::path::Path, site_id: SiteId) -> std::path::PathBuf {
    data_dir
        .join("sites")
        .join(site_id.get().to_string())
        .join("spool")
}

pub fn run(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{HELP}");
        return 0;
    }
    let config = load_config();
    let mut store = open_store(&config.data_dir);
    let now = unix_now();

    let data_key = crate::common::load_data_key(&config.data_dir);

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
        match fossh_ingest::compact::drain_site_spool(&mut store, &dir, &data_key) {
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
