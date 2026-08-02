//! `fossh export --site <slug> --format ndjson` (§9): aggregates only,
//! never raw rows — trivially true here, since the rollup table this
//! reads from structurally cannot hold a raw per-visitor row (P1/ADR-0009).

use fossh_store::GroupByField;

use crate::args::flag_value;
use crate::common::load_config;
use crate::date::parse_date;

const USAGE: &str =
    "usage: fossh export --site <slug> --format ndjson [--from YYYY-MM-DD] [--to YYYY-MM-DD]";

/// Full granularity — every dimension the rollup table has — since export
/// has no `--group-by` of its own; k-anonymity (P6) still applies at
/// this, the finest, level.
const ALL_DIMS: &[GroupByField] = &[
    GroupByField::Kind,
    GroupByField::Name,
    GroupByField::Path,
    GroupByField::Country,
    GroupByField::Browser,
    GroupByField::Os,
    GroupByField::Device,
];

fn field_name(f: GroupByField) -> &'static str {
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

pub fn run(args: &[String]) -> i32 {
    let Some(slug) = flag_value(args, "--site") else {
        eprintln!("{USAGE}");
        return 2;
    };
    let format = flag_value(args, "--format").unwrap_or("ndjson");
    if format != "ndjson" {
        eprintln!("fossh export: only --format ndjson is supported");
        return 2;
    }
    let from = flag_value(args, "--from")
        .map(|s| parse_date(s).unwrap_or(0))
        .unwrap_or(0);
    let to = flag_value(args, "--to")
        .map(|s| parse_date(s).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX);

    let config = load_config();
    let store = crate::common::open_store(&config.data_dir);
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("fossh export: no such site '{slug}'");
            return 1;
        }
        Err(e) => {
            eprintln!("fossh export: {e}");
            return 1;
        }
    };

    let rows = match store.query_rollup(site.id, from, to, ALL_DIMS, config.k_anonymity) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fossh export: {e}");
            return 1;
        }
    };

    for row in &rows {
        let mut obj = serde_json::Map::new();
        for (field, value) in &row.dims {
            obj.insert(
                field_name(*field).to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
        obj.insert("hits".to_string(), serde_json::Value::from(row.hits));
        obj.insert("uniques".to_string(), serde_json::Value::from(row.uniques));
        obj.insert("p50".to_string(), serde_json::Value::from(row.p50));
        obj.insert("p95".to_string(), serde_json::Value::from(row.p95));
        match serde_json::to_string(&serde_json::Value::Object(obj)) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("fossh export: serializing a row: {e}"),
        }
    }
    0
}
