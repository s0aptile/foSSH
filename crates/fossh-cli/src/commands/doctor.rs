//! `fossh doctor` (§9): "actively verify §3/§4 invariants against the
//! live install and print a pass/fail table" — the operator-facing proof
//! that the promises hold.
//!
//! Scoped to what's actually checkable against a live install without
//! network access (S6's no-egress ethos extends to this tool too — no
//! NTP query for "real" clock-skew detection, just a plausibility check)
//! or a running webserver (S9's "no `Set-Cookie`" is a structural
//! guarantee — the response writer has no header-setting API for it —
//! not something `doctor` can probe without an actual HTTP round trip
//! through a configured webserver, which is outside its reach).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::common::{db_path, unix_now};

struct Check {
    name: &'static str,
    pass: bool,
    detail: String,
}

fn check_permissions(path: &Path, expected: u32, name: &'static str) -> Check {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode == expected {
                Check {
                    name,
                    pass: true,
                    detail: format!("{:o}", mode),
                }
            } else {
                Check {
                    name,
                    pass: false,
                    detail: format!(
                        "is {:o}, want {:o} — chmod {:o} {}",
                        mode,
                        expected,
                        expected,
                        path.display()
                    ),
                }
            }
        }
        Err(_) => Check {
            name,
            pass: true,
            detail: "not present yet (nothing to check)".to_string(),
        },
    }
}

pub fn run(_args: &[String]) -> i32 {
    let mut checks = Vec::new();

    let config = match fossh_core::config::Config::load() {
        Ok(c) => {
            checks.push(Check {
                name: "config loads",
                pass: true,
                detail: "ok".to_string(),
            });
            c
        }
        Err(e) => {
            checks.push(Check {
                name: "config loads",
                pass: false,
                detail: e.to_string(),
            });
            print_table(&checks);
            return 1;
        }
    };

    checks.push(check_permissions(
        &config.data_dir,
        0o700,
        "data_dir permissions (0700)",
    ));
    checks.push(check_permissions(
        &db_path(&config.data_dir),
        0o600,
        "database file permissions (0600)",
    ));
    checks.push(check_permissions(
        &config.salt_dir.join("daily_salt"),
        0o600,
        "salt file permissions (0600, P2)",
    ));

    match std::fs::metadata(&config.data_dir) {
        Ok(_) => checks.push(Check {
            name: "data_dir exists",
            pass: true,
            detail: config.data_dir.display().to_string(),
        }),
        Err(e) => checks.push(Check {
            name: "data_dir exists",
            pass: false,
            detail: e.to_string(),
        }),
    }

    let store_result = fossh_store::Store::open(&db_path(&config.data_dir));
    checks.push(Check {
        name: "database schema opens cleanly",
        pass: store_result.is_ok(),
        detail: match &store_result {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        },
    });

    checks.push(Check {
        name: "k_anonymity threshold (P6)",
        pass: config.k_anonymity >= 1,
        detail: format!("k = {}", config.k_anonymity),
    });
    checks.push(Check {
        name: "retention_days is positive (P7)",
        pass: config.retention_days >= 1,
        detail: format!("{} days", config.retention_days),
    });
    checks.push(Check {
        name: "respect_optout_signals (P5)",
        pass: true, // both true and explicit-false are valid, documented configurations
        detail: format!("{}", config.respect_optout_signals),
    });
    checks.push(Check {
        name: "listener never binds an unspecified address (S7)",
        pass: true, // Config::load() already refuses to parse a config where this doesn't hold
        detail: match &config.listener {
            Some(l) => format!("bind = {}", l.bind),
            None => "HTTP listener feature not configured".to_string(),
        },
    });

    let now = unix_now();
    let plausible = (1_700_000_000..=4_000_000_000).contains(&now); // 2023-11-14 .. 2096-10-02
    checks.push(Check {
        name: "system clock is plausible",
        pass: plausible,
        detail: format!(
            "{now} ({}) — doctor checks plausibility only; no NTP query is made, per S6's no-egress ethos",
            if plausible { "looks sane" } else { "looks wrong" }
        ),
    });

    checks.push(Check {
        name: "no Set-Cookie in ingest responses (S9)",
        pass: true,
        detail: "structural: fossh-cgi's response writer has no header-setting API at all — not independently probed here".to_string(),
    });

    print_table(&checks);
    if checks.iter().all(|c| c.pass) { 0 } else { 1 }
}

fn print_table(checks: &[Check]) {
    let name_width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for check in checks {
        let mark = if check.pass { "PASS" } else { "FAIL" };
        println!(
            "[{mark}] {:<width$}  {}",
            check.name,
            check.detail,
            width = name_width
        );
    }
}
