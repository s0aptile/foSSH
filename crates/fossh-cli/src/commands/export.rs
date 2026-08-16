use fossh_store::GroupByField;

use crate::args::{flag_value, wants_help};
use crate::common::load_config;
use crate::date::parse_date;

const USAGE: &str = "usage: fossh export --site <slug> --format ndjson|csv \
[--from YYYY-MM-DD] [--to YYYY-MM-DD]";

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
    if wants_help(args) {
        println!("{USAGE}");
        return 0;
    }
    let Some(slug) = flag_value(args, "--site") else {
        eprintln!("{USAGE}");
        return 2;
    };
    let format = flag_value(args, "--format").unwrap_or("ndjson");
    if format != "ndjson" && format != "csv" {
        eprintln!("fossh export: --format must be ndjson or csv");
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

    if format == "csv" {
        print_csv(&rows);
    } else {
        print_ndjson(&rows);
    }
    0
}

fn print_ndjson(rows: &[fossh_store::GroupRow]) {
    for row in rows {
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
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_row(rows: &[fossh_store::GroupRow]) -> Vec<String> {
    let mut header: Vec<String> = ALL_DIMS
        .iter()
        .map(|&f| field_name(f).to_string())
        .collect();
    header.extend(["hits", "uniques", "p50", "p95"].map(String::from));
    let mut lines = vec![header.join(",")];
    for row in rows {
        let mut cols: Vec<String> = row.dims.iter().map(|(_, v)| csv_field(v)).collect();
        cols.push(row.hits.to_string());
        cols.push(row.uniques.to_string());
        cols.push(row.p50.to_string());
        cols.push(row.p95.to_string());
        lines.push(cols.join(","));
    }
    lines
}

fn print_csv(rows: &[fossh_store::GroupRow]) {
    for line in csv_row(rows) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_store::GroupByField;

    fn row(
        dims: &[(GroupByField, &str)],
        hits: i64,
        uniques: u64,
        p50: i64,
        p95: i64,
    ) -> fossh_store::GroupRow {
        fossh_store::GroupRow {
            dims: dims.iter().map(|&(f, v)| (f, v.to_string())).collect(),
            hits,
            uniques,
            p50,
            p95,
        }
    }

    #[test]
    fn csv_header_matches_all_dims_plus_metrics() {
        let lines = csv_row(&[]);
        assert_eq!(
            lines[0],
            "kind,name,path,country,browser,os,device,hits,uniques,p50,p95"
        );
    }

    #[test]
    fn csv_row_renders_dims_then_metrics_in_order() {
        let rows = vec![row(
            &[
                (GroupByField::Kind, "pageview"),
                (GroupByField::Name, "pageview"),
                (GroupByField::Path, "/blog"),
                (GroupByField::Country, "TR"),
                (GroupByField::Browser, "Firefox"),
                (GroupByField::Os, "Linux"),
                (GroupByField::Device, "Desktop"),
            ],
            347,
            12,
            120,
            450,
        )];
        let lines = csv_row(&rows);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[1],
            "pageview,pageview,/blog,TR,Firefox,Linux,Desktop,347,12,120,450"
        );
    }

    #[test]
    fn csv_field_quotes_values_containing_commas() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("has \"quote\""), "\"has \"\"quote\"\"\"");
    }

    #[test]
    fn csv_row_folds_other_bucket_the_same_as_any_other_row() {

        let rows = vec![row(
            &[
                (GroupByField::Kind, "(other)"),
                (GroupByField::Name, "(other)"),
                (GroupByField::Path, "(other)"),
                (GroupByField::Country, "(other)"),
                (GroupByField::Browser, "(other)"),
                (GroupByField::Os, "(other)"),
                (GroupByField::Device, "(other)"),
            ],
            3,
            2,
            0,
            0,
        )];
        let lines = csv_row(&rows);
        assert_eq!(
            lines[1],
            "(other),(other),(other),(other),(other),(other),(other),3,2,0,0"
        );
    }
}
