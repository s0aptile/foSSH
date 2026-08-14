//! `fossh query --site <slug> --from DATE --to DATE --group-by ... --metric ... --format ...` (§9).

use fossh_store::GroupByField;

use crate::args::{comma_list, flag_value, wants_help};
use crate::common::load_config;
use crate::date::parse_date;

const USAGE: &str = "usage: fossh query --site <slug> --from YYYY-MM-DD --to YYYY-MM-DD \
[--group-by path,country,...] [--metric hits,uniques,p50,p95] [--format table|json|csv]";

fn parse_group_by(s: &str) -> Result<Vec<GroupByField>, String> {
    comma_list(s)
        .into_iter()
        .map(|field| match field.as_str() {
            "kind" => Ok(GroupByField::Kind),
            "name" => Ok(GroupByField::Name),
            "path" => Ok(GroupByField::Path),
            "country" => Ok(GroupByField::Country),
            "browser" => Ok(GroupByField::Browser),
            "os" => Ok(GroupByField::Os),
            "device" => Ok(GroupByField::Device),
            other => Err(format!("unknown --group-by field '{other}'")),
        })
        .collect()
}

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
    if wants_help(args) {
        println!("{USAGE}");
        return 0;
    }
    let Some(slug) = flag_value(args, "--site") else {
        eprintln!("{USAGE}");
        return 2;
    };
    let Some(from) = flag_value(args, "--from").and_then(|s| parse_date(s).ok()) else {
        eprintln!("fossh query: --from must be YYYY-MM-DD\n{USAGE}");
        return 2;
    };
    let Some(to) = flag_value(args, "--to").and_then(|s| parse_date(s).ok()) else {
        eprintln!("fossh query: --to must be YYYY-MM-DD\n{USAGE}");
        return 2;
    };
    let group_by = match flag_value(args, "--group-by") {
        Some(s) => match parse_group_by(s) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("fossh query: {e}");
                return 2;
            }
        },
        None => Vec::new(),
    };
    let metrics: Vec<String> = flag_value(args, "--metric")
        .map(comma_list)
        .unwrap_or_else(|| comma_list("hits,uniques,p50,p95"));
    let format = flag_value(args, "--format").unwrap_or("table");

    let config = load_config();
    let store = crate::common::open_store(&config.data_dir);
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("fossh query: no such site '{slug}'");
            return 1;
        }
        Err(e) => {
            eprintln!("fossh query: {e}");
            return 1;
        }
    };

    let rows = match store.query_rollup(site.id, from, to, &group_by, config.k_anonymity) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fossh query: {e}");
            return 1;
        }
    };

    if folded_entirely_into_other(&rows, &group_by) {
        eprintln!(
            "note: every group in this result had fewer than {} unique visitor(s) and was \
folded into a single '(other)' row — this is k-anonymity (P6), not a bug or an empty result. \
Widen --from/--to, drop a --group-by dimension, or see PRIVACY.md's \"Numbers, not individuals\" \
section for what this means for a low-traffic site.",
            config.k_anonymity
        );
    }

    match format {
        "json" => print_json(&rows, &metrics),
        "csv" => print_csv(&rows, &group_by, &metrics),
        _ => print_table(&rows, &group_by, &metrics), // "table", and the default for anything unrecognized
    }
    0
}

/// True when the whole result is the single k-anonymity "(other)" fold —
/// i.e. every real group the query would otherwise have shown was below
/// the k-anonymity threshold, and there's nothing left to break down by.
/// Only meaningful with a non-empty `group_by`: with none, a single row's
/// dims are always empty regardless of whether it was folded, since a
/// bare total's value doesn't change from folding (P6, `fossh-store`'s
/// `rollup.rs`).
fn folded_entirely_into_other(rows: &[fossh_store::GroupRow], group_by: &[GroupByField]) -> bool {
    !group_by.is_empty() && rows.len() == 1 && rows[0].dims.iter().all(|(_, v)| v == "(other)")
}

fn metric_value(row: &fossh_store::GroupRow, metric: &str) -> String {
    match metric {
        "hits" => row.hits.to_string(),
        "uniques" => row.uniques.to_string(),
        "p50" => row.p50.to_string(),
        "p95" => row.p95.to_string(),
        other => format!("?{other}"),
    }
}

fn print_table(rows: &[fossh_store::GroupRow], group_by: &[GroupByField], metrics: &[String]) {
    let mut header: Vec<String> = group_by
        .iter()
        .map(|f| field_name(*f).to_string())
        .collect();
    header.extend(metrics.iter().cloned());
    println!("{}", header.join("\t"));
    for row in rows {
        let mut cols: Vec<String> = row.dims.iter().map(|(_, v)| v.clone()).collect();
        cols.extend(metrics.iter().map(|m| metric_value(row, m)));
        println!("{}", cols.join("\t"));
    }
}

fn print_csv(rows: &[fossh_store::GroupRow], group_by: &[GroupByField], metrics: &[String]) {
    fn csv_field(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut header: Vec<String> = group_by
        .iter()
        .map(|f| field_name(*f).to_string())
        .collect();
    header.extend(metrics.iter().cloned());
    println!("{}", header.join(","));
    for row in rows {
        let mut cols: Vec<String> = row.dims.iter().map(|(_, v)| csv_field(v)).collect();
        cols.extend(metrics.iter().map(|m| csv_field(&metric_value(row, m))));
        println!("{}", cols.join(","));
    }
}

fn print_json(rows: &[fossh_store::GroupRow], metrics: &[String]) {
    // Unlike the table/CSV formatters, JSON needs no separate header row
    // built from `group_by` — each object's keys (from `row.dims`) are
    // already self-describing.
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut obj = serde_json::Map::new();
        for (field, value) in &row.dims {
            obj.insert(
                field_name(*field).to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
        for m in metrics {
            let v = metric_value(row, m);
            let json_v = v
                .parse::<i64>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| serde_json::Value::String(v));
            obj.insert(m.clone(), json_v);
        }
        out.push(serde_json::Value::Object(obj));
    }
    match serde_json::to_string_pretty(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("fossh query: serializing JSON output: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn other_row(group_by: &[GroupByField]) -> fossh_store::GroupRow {
        fossh_store::GroupRow {
            dims: group_by
                .iter()
                .map(|&f| (f, "(other)".to_string()))
                .collect(),
            hits: 3,
            uniques: 2,
            p50: 0,
            p95: 0,
        }
    }

    fn real_row(group_by: &[GroupByField], value: &str) -> fossh_store::GroupRow {
        fossh_store::GroupRow {
            dims: group_by.iter().map(|&f| (f, value.to_string())).collect(),
            hits: 347,
            uniques: 12,
            p50: 120,
            p95: 450,
        }
    }

    #[test]
    fn low_traffic_site_folded_wholly_into_other_is_detected() {
        let group_by = [GroupByField::Path];
        let rows = vec![other_row(&group_by)];
        assert!(folded_entirely_into_other(&rows, &group_by));
    }

    #[test]
    fn a_real_row_among_others_is_not_flagged_as_wholly_folded() {
        let group_by = [GroupByField::Path];
        let rows = vec![real_row(&group_by, "/blog"), other_row(&group_by)];
        assert!(!folded_entirely_into_other(&rows, &group_by));
    }

    #[test]
    fn only_real_rows_are_not_flagged() {
        let group_by = [GroupByField::Path];
        let rows = vec![real_row(&group_by, "/blog")];
        assert!(!folded_entirely_into_other(&rows, &group_by));
    }

    #[test]
    fn empty_group_by_is_never_flagged() {
        // With no --group-by, a single total row's dims are always empty
        // whether or not it was folded (folding a bare total doesn't
        // change its hits/uniques) — nothing to warn about here.
        let rows = vec![fossh_store::GroupRow {
            dims: vec![],
            hits: 3,
            uniques: 2,
            p50: 0,
            p95: 0,
        }];
        assert!(!folded_entirely_into_other(&rows, &[]));
    }

    #[test]
    fn no_rows_at_all_is_not_flagged() {
        assert!(!folded_entirely_into_other(&[], &[GroupByField::Path]));
    }
}
