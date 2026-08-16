use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {

    Info,

    Warning,

    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Remedy {

    None,

    Automatic { description: String },

    Operator {
        description: String,
        command: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {

    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub remedy: Remedy,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
}

impl Finding {
    fn new(
        id: &str,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        remedy: Remedy,
    ) -> Self {
        Self {
            id: id.to_string(),
            severity,
            title: title.into(),
            detail: detail.into(),
            remedy,
            advice: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Context {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub setup_token_path: PathBuf,
    pub k_anonymity: u32,

    pub watchdog_reachable: Option<bool>,

    pub country_db: Option<String>,
}

pub fn check(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_data_dir(ctx, &mut findings);
    check_data_key(ctx, &mut findings);
    check_k_anonymity(ctx, &mut findings);
    check_setup_token(ctx, &mut findings);
    check_country_db(ctx, &mut findings);
    check_watchdog(ctx, &mut findings);

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    findings
}

fn check_data_dir(ctx: &Context, out: &mut Vec<Finding>) {
    if !ctx.data_dir.exists() {
        out.push(Finding::new(
            "data_dir_missing",
            Severity::Critical,
            "The data directory does not exist",
            format!(
                "{} is where this install keeps its database, spool and keys. Nothing can be \
                 recorded or read until it exists.",
                ctx.data_dir.display()
            ),
            Remedy::Operator {
                description: "Create it with the right ownership".to_string(),
                command: format!("sudo fossh init --dir {}", ctx.data_dir.display()),
            },
        ));
        return;
    }

    if let Some(mode) = mode_of(&ctx.data_dir) {

        if mode & 0o007 != 0 {
            out.push(Finding::new(
                "data_dir_world_accessible",
                Severity::Critical,
                "The data directory is readable by every local user",
                format!(
                    "{} is mode {:o}. It holds the spool and this install's data key.",
                    ctx.data_dir.display(),
                    mode & 0o777
                ),
                Remedy::Automatic {
                    description: "Remove all access for other users (chmod o-rwx)".to_string(),
                },
            ));
        }
    }
}

fn check_data_key(ctx: &Context, out: &mut Vec<Finding>) {
    let key_path = ctx.data_dir.join(".data_key");
    if !key_path.exists() {

        return;
    }
    if let Some(mode) = mode_of(&key_path)
        && mode & 0o077 != 0
    {
        {
            out.push(Finding::new(
                "data_key_permissions",
                Severity::Critical,
                "The data key is readable beyond its owner",
                format!(
                    "{} is mode {:o}. This key decrypts the spool and the stored integration \
                     credentials; anyone who can read it can read both.",
                    key_path.display(),
                    mode & 0o777
                ),
                Remedy::Automatic {
                    description: "Restrict it to its owner (chmod 600)".to_string(),
                },
            ));
        }
    }
}

fn check_k_anonymity(ctx: &Context, out: &mut Vec<Finding>) {
    if ctx.k_anonymity < 1 {
        out.push(Finding::new(
            "k_anonymity_disabled",
            Severity::Critical,
            "k-anonymity is switched off",
            "k_anonymity is 0, so no group is ever folded into (other) and every breakdown is \
             reported exactly as recorded. This is the invariant foSSH exists to hold (P6); a \
             value below 1 does not weaken it, it removes it."
                .to_string(),
            Remedy::Operator {
                description: "Set it back to a real threshold".to_string(),
                command: "fossh config set k_anonymity 5".to_string(),
            },
        ));
    } else if ctx.k_anonymity < 5 {
        out.push(Finding::new(
            "k_anonymity_low",
            Severity::Warning,
            "k-anonymity is below the default",
            format!(
                "k_anonymity is {}, against a default of 5. This is a legitimate choice — \
                 smaller groups survive into breakdowns — but it is a real privacy trade and \
                 worth having made deliberately rather than inherited.",
                ctx.k_anonymity
            ),
            Remedy::None,
        ));
    }
}

fn check_setup_token(ctx: &Context, out: &mut Vec<Finding>) {
    if ctx.setup_token_path.exists() {
        out.push(Finding::new(
            "setup_token_present",
            Severity::Warning,
            "A setup token is still on disk",
            format!(
                "{} exists, which means first-run enrollment has not been completed. Until it \
                 is, anyone who can read that file can enroll themselves as the operator.",
                ctx.setup_token_path.display()
            ),
            Remedy::Operator {
                description: "Finish setup in the console, which burns the token".to_string(),
                command: "fossh-console".to_string(),
            },
        ));
    }
}

fn check_country_db(ctx: &Context, out: &mut Vec<Finding>) {
    let Some(configured) = ctx.country_db.as_deref() else {
        return;
    };

    if configured.is_empty() || configured == "none" || configured == "builtin" {
        return;
    }
    if !Path::new(configured).exists() {
        out.push(Finding::new(
            "country_db_missing",
            Severity::Warning,
            "The configured GeoIP database is not there",
            format!(
                "country_db points at {configured}, which does not exist. Country resolution is \
                 additive and fails silently to \"ZZ\", so this costs you country breakdowns \
                 without ever failing a request — which is why it is easy to miss."
            ),
            Remedy::Operator {
                description: "Point country_db at the real file, or set it to \"none\"".to_string(),
                command: "fossh config set country_db none".to_string(),
            },
        ));
    }
}

fn check_watchdog(ctx: &Context, out: &mut Vec<Finding>) {
    if ctx.watchdog_reachable == Some(false) {
        out.push(Finding::new(
            "watchdog_unreachable",
            Severity::Warning,
            "The watchdog is not answering",
            "Without it there is no supervised restart, no tamper detection, and no operator \
             auth gate. On EPEL and RHEL this is expected — the subpackage cannot be built \
             there — but on Fedora it usually means the service is not running."
                .to_string(),
            Remedy::Operator {
                description: "Check whether the service is running".to_string(),
                command: "systemctl status fossh-watchdog".to_string(),
            },
        ));
    }
}

fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

pub fn apply_automatic(ctx: &Context, findings: &[Finding]) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;

    let mut applied = Vec::new();
    for finding in findings {
        if !matches!(finding.remedy, Remedy::Automatic { .. }) {
            continue;
        }
        let target = match finding.id.as_str() {
            "data_dir_world_accessible" => ctx.data_dir.clone(),
            "data_key_permissions" => ctx.data_dir.join(".data_key"),

            _ => continue,
        };
        let Ok(meta) = std::fs::metadata(&target) else {
            continue;
        };
        let current = meta.permissions().mode();
        let wanted = if finding.id == "data_key_permissions" {
            0o600
        } else {
            current & !0o007
        };
        if std::fs::set_permissions(&target, std::fs::Permissions::from_mode(wanted)).is_ok() {
            applied.push(finding.id.clone());
        }
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-selfheal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ctx_for(dir: &Path) -> Context {
        Context {
            data_dir: dir.to_path_buf(),
            config_path: dir.join("fossh.toml"),
            setup_token_path: dir.join("setup-token"),
            k_anonymity: 5,
            watchdog_reachable: None,
            country_db: None,
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn a_healthy_install_produces_no_findings() {
        let dir = scratch("healthy");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check(&ctx_for(&dir)).is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_data_directory_is_critical_and_says_how_to_make_it() {
        let dir = scratch("missing");
        fs::remove_dir_all(&dir).unwrap();
        let findings = check(&ctx_for(&dir));
        assert_eq!(ids(&findings), vec!["data_dir_missing"]);
        assert_eq!(findings[0].severity, Severity::Critical);
        match &findings[0].remedy {
            Remedy::Operator { command, .. } => assert!(command.contains("fossh init")),
            other => panic!("expected an operator remedy, got {other:?}"),
        }
    }

    #[test]
    fn a_world_readable_data_directory_is_caught_and_can_be_fixed_automatically() {
        let dir = scratch("world-readable");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let ctx = ctx_for(&dir);
        let findings = check(&ctx);
        assert!(ids(&findings).contains(&"data_dir_world_accessible"));

        let applied = apply_automatic(&ctx, &findings);
        assert!(applied.contains(&"data_dir_world_accessible".to_string()));

        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o007, 0, "other-access should be gone, got {mode:o}");

        assert!(!ids(&check(&ctx)).contains(&"data_dir_world_accessible"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_loose_data_key_is_critical_and_gets_tightened_to_exactly_600() {
        let dir = scratch("loose-key");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let key = dir.join(".data_key");
        fs::write(&key, b"x").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        let ctx = ctx_for(&dir);
        let findings = check(&ctx);
        assert!(ids(&findings).contains(&"data_key_permissions"));
        assert_eq!(findings[0].severity, Severity::Critical);

        apply_automatic(&ctx, &findings);
        let mode = fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_absent_data_key_is_not_a_finding() {

        let dir = scratch("no-key");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!ids(&check(&ctx_for(&dir))).contains(&"data_key_permissions"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn k_anonymity_of_zero_is_critical_not_a_warning() {

        let dir = scratch("k-zero");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ctx = ctx_for(&dir);
        ctx.k_anonymity = 0;
        let findings = check(&ctx);
        let f = findings
            .iter()
            .find(|f| f.id == "k_anonymity_disabled")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_low_but_nonzero_k_anonymity_is_only_a_warning_with_no_automatic_change() {

        let dir = scratch("k-low");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ctx = ctx_for(&dir);
        ctx.k_anonymity = 2;
        let findings = check(&ctx);
        let f = findings.iter().find(|f| f.id == "k_anonymity_low").unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.remedy, Remedy::None);
        assert!(apply_automatic(&ctx, &findings).is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_leftover_setup_token_is_reported() {
        let dir = scratch("token");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let ctx = ctx_for(&dir);
        fs::write(&ctx.setup_token_path, b"tok").unwrap();
        assert!(ids(&check(&ctx)).contains(&"setup_token_present"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_geoip_sentinels_are_not_mistaken_for_paths() {
        let dir = scratch("geoip");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        for sentinel in ["none", "builtin", ""] {
            let mut ctx = ctx_for(&dir);
            ctx.country_db = Some(sentinel.to_string());
            assert!(
                !ids(&check(&ctx)).contains(&"country_db_missing"),
                "{sentinel:?} is a sentinel, not a filename"
            );
        }
        let mut ctx = ctx_for(&dir);
        ctx.country_db = Some("/nonexistent/ip-to-country.mmdb".to_string());
        assert!(ids(&check(&ctx)).contains(&"country_db_missing"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unknown_watchdog_state_is_not_reported_as_a_failure() {

        let dir = scratch("watchdog-unknown");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ctx = ctx_for(&dir);
        ctx.watchdog_reachable = None;
        assert!(!ids(&check(&ctx)).contains(&"watchdog_unreachable"));

        ctx.watchdog_reachable = Some(false);
        assert!(ids(&check(&ctx)).contains(&"watchdog_unreachable"));

        ctx.watchdog_reachable = Some(true);
        assert!(!ids(&check(&ctx)).contains(&"watchdog_unreachable"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn findings_come_back_most_severe_first() {
        let dir = scratch("ordering");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let mut ctx = ctx_for(&dir);
        ctx.k_anonymity = 2;
        fs::write(&ctx.setup_token_path, b"tok").unwrap();

        let findings = check(&ctx);
        assert!(findings.len() >= 3);
        for pair in findings.windows(2) {
            assert!(
                pair[0].severity >= pair[1].severity,
                "out of order: {:?} before {:?}",
                pair[0].id,
                pair[1].id
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_automatic_never_touches_an_operator_remedy() {

        let dir = scratch("no-operator-actions");
        fs::remove_dir_all(&dir).unwrap();
        let ctx = ctx_for(&dir);
        let findings = check(&ctx);
        assert!(matches!(findings[0].remedy, Remedy::Operator { .. }));
        assert!(apply_automatic(&ctx, &findings).is_empty());
        assert!(!dir.exists(), "an operator remedy was carried out");
    }

    #[test]
    fn every_finding_carries_a_stable_id_and_real_prose() {
        let dir = scratch("shape");
        fs::remove_dir_all(&dir).unwrap();
        let mut ctx = ctx_for(&dir);
        ctx.k_anonymity = 0;
        ctx.watchdog_reachable = Some(false);
        ctx.country_db = Some("/nope.mmdb".to_string());

        for finding in check(&ctx) {
            assert!(!finding.id.is_empty());
            assert!(
                finding
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_')
            );
            assert!(finding.title.len() > 10, "{}", finding.id);
            assert!(finding.detail.len() > 30, "{}", finding.id);
            assert!(finding.advice.is_none(), "the engine never writes advice");
        }
    }
}
