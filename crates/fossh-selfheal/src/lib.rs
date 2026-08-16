#![forbid(unsafe_code)]

pub mod advisor;
pub mod capability;
pub mod engine;
pub mod keylock;
pub mod memory;
pub mod persona;

pub use advisor::{Availability, MODEL};
pub use capability::{Capability, Tier};
pub use engine::{Finding, Remedy, Severity, check};

pub fn diagnose(ctx: &engine::Context) -> (Vec<Finding>, Availability) {
    let findings = engine::check(ctx);
    let capability = Capability::detect();
    let availability = match advisor::assess_hardware(&capability) {

        Ok(_tier) => Availability::NotInstalled {
            reason: "not probed yet".to_string(),
        },
        Err(unavailable) => unavailable,
    };
    (findings, availability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn diagnose_returns_real_findings_whatever_the_model_situation_is() {

        let dir: PathBuf =
            std::env::temp_dir().join(format!("fossh-selfheal-diagnose-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let ctx = engine::Context {
            data_dir: dir.clone(),
            config_path: dir.join("fossh.toml"),
            setup_token_path: dir.join("setup-token"),
            k_anonymity: 0,
            watchdog_reachable: Some(false),
            country_db: None,
        };

        let (findings, _availability) = diagnose(&ctx);
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"k_anonymity_disabled"));
        assert!(ids.contains(&"watchdog_unreachable"));
        assert!(ids.contains(&"data_dir_world_accessible"));
        assert!(
            findings.iter().all(|f| f.advice.is_none()),
            "no advice without a model"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
