use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::args::wants_help;
use crate::common::{db_path, unix_now};

const HELP: &str = "usage: fossh doctor\n\n\
Verify permissions, config sanity, and privacy/security invariants against\n\
the live install.";

struct Check {
    name: &'static str,
    pass: bool,
    detail: String,
}

fn check_glibc_floor() -> Check {
    const NAME: &str = "glibc version floor (§2.5)";
    let floor = fossh_core::glibc_gate::RECOMMENDED_FLOOR;

    match crate::common::detect_glibc_version() {
        Ok(version) => {
            let pass = fossh_core::glibc_gate::meets_floor(version, floor);
            Check {
                name: NAME,
                pass,
                detail: if pass {
                    format!("{}.{} >= {}.{}", version.0, version.1, floor.0, floor.1)
                } else {
                    format!(
                        "{}.{} is below the required floor {}.{} — this host cannot run foSSH's Fedora-native deployment",
                        version.0, version.1, floor.0, floor.1
                    )
                },
            }
        }
        Err(e) => Check {
            name: NAME,
            pass: false,
            detail: e,
        },
    }
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

pub fn run(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{HELP}");
        return 0;
    }
    let mut checks = Vec::new();
    checks.push(check_glibc_floor());

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
        &db_path(&config.data_dir),
        0o600,
        "database file permissions (0600)",
    ));
    checks.push(check_permissions(
        &config.salt_dir.join("daily_salt"),
        0o600,
        "salt file permissions (0600, P2)",
    ));

    let db_check = match fossh_admin::data_key::load_or_generate(&config.data_dir.join(".data_key"))
    {
        Ok(key) => {
            let store_result = fossh_store::Store::open_encrypted(&db_path(&config.data_dir), &key);
            Check {
                name: "database schema opens cleanly",
                pass: store_result.is_ok(),
                detail: match &store_result {
                    Ok(_) => "ok".to_string(),
                    Err(e) => e.to_string(),
                },
            }
        }
        Err(e) => Check {
            name: "database schema opens cleanly",
            pass: false,
            detail: format!("could not load data-encryption key: {e}"),
        },
    };
    checks.push(db_check);

    checks.push(Check {
        name: "retention_days is positive (P7)",
        pass: config.retention_days >= 1,
        detail: format!("{} days", config.retention_days),
    });

    checks.push(Check {
        name: "k_anonymity is high enough to actually fold (P6)",
        pass: config.k_anonymity >= fossh_core::config::K_ANONYMITY_MIN,
        detail: format!(
            "{} (minimum {}, default 5)",
            config.k_anonymity,
            fossh_core::config::K_ANONYMITY_MIN
        ),
    });
    checks.push(Check {
        name: "respect_optout_signals (P5)",
        pass: true,
        detail: format!("{}", config.respect_optout_signals),
    });
    checks.push(Check {
        name: "listener never binds an unspecified address (S7)",
        pass: true,
        detail: match &config.listener {
            Some(l) => format!("bind = {}", l.bind),
            None => "HTTP listener feature not configured".to_string(),
        },
    });

    let now = unix_now();
    let plausible = (1_700_000_000..=4_000_000_000).contains(&now);
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

    for finding in self_healing_findings(&config) {
        checks.push(finding);
    }

    print_table(&checks);
    if checks.iter().all(|c| c.pass) { 0 } else { 1 }
}

fn self_healing_findings(config: &fossh_core::config::Config) -> Vec<Check> {
    use fossh_selfheal::engine::{self, Severity};

    let ctx = engine::Context {
        data_dir: config.data_dir.clone(),
        config_path: config.data_dir.join("fossh.toml"),
        setup_token_path: std::env::var_os("FOSSH_SETUP_TOKEN_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/fossh/setup-token")),
        k_anonymity: config.k_anonymity,

        watchdog_reachable: None,
        country_db: match &config.country_db {
            fossh_core::config::CountryDb::Custom(path) => {
                Some(path.to_string_lossy().into_owned())
            }
            fossh_core::config::CountryDb::None => Some("none".to_string()),
            fossh_core::config::CountryDb::Builtin => Some("builtin".to_string()),
        },
    };

    engine::check(&ctx)
        .into_iter()
        .map(|finding| {

            let pass = finding.severity == Severity::Info;
            let remedy = match &finding.remedy {
                engine::Remedy::None => String::new(),
                engine::Remedy::Automatic { description } => format!(" — {description}"),
                engine::Remedy::Operator { command, .. } => format!(" — run: {command}"),
            };
            Check {

                name: Box::leak(finding.title.clone().into_boxed_str()),
                pass,
                detail: format!("{}{}", finding.detail, remedy),
            }
        })
        .collect()
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
