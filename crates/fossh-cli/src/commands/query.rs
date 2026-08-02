//! `fossh query --site <slug> --from DATE --to DATE --group-by ... --metric ... --format ...` (§9).

use fossh_store::GroupByField;

use crate::args::{comma_list, flag_value};
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

    match format {
        "json" => print_json(&rows, &metrics),
        "csv" => print_csv(&rows, &group_by, &metrics),
        _ => print_table(&rows, &group_by, &metrics), // "table", and the default for anything unrecognized
    }
    0
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
