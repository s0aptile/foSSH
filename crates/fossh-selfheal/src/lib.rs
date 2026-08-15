#![forbid(unsafe_code)]
//! foSSH self-healing.
//!
//! Two layers, and the relationship between them is the design:
//!
//! * [`engine`] — deterministic rules over real state. Always runs,
//!   always produces the findings and the remedies, and is the entire
//!   feature on its own. Nothing in foSSH's behaviour depends on the
//!   layer below existing.
//!
//! * [`advisor`] — an optional local model
//!   (`lfm2.5-thinking:1.2b` under Ollama) that may write one string
//!   onto a finding the engine already produced. It cannot create a
//!   finding, change a severity, alter a remedy, or cause anything to
//!   run.
//!
//! * [`capability`] — decides whether the second layer is allowed to
//!   exist on this machine at all: AVX2 required, AVX-512 preferred,
//!   Vulkan as the fail-switch, six physical cores and 8 GiB as the
//!   floor, and then a real timed probe on top of that.
//!
//! ## Why it is built this way round
//!
//! "Self-healing" and "language model" in the same subsystem is a
//! combination that usually means the model decides what to repair.
//! Here it explicitly does not, and the reason is what foSSH is for:
//! an operator installs it for a set of privacy invariants, and a
//! component that could author remedies would be able to argue them
//! out of one. A 1.2B model will produce "your k-anonymity threshold
//! looks high, try lowering it" fluently and confidently. Keeping it
//! on the explaining side of the line makes its worst failure
//! unhelpful prose rather than a changed setting.
//!
//! ## Where this runs, and where it does not
//!
//! Admin path only. No ingest component depends on this crate — the
//! same structural rule that keeps `integrations_net` out of
//! `fossh-cgi`/`fossh-fcgi` — so the "zero outbound network access
//! from the ingest path" property is unaffected by anything here.
//! Check it the same way: `cargo tree -p fossh-cgi | grep
//! fossh-selfheal` finds nothing.

pub mod advisor;
pub mod capability;
pub mod engine;
pub mod keylock;
pub mod memory;
pub mod persona;

pub use advisor::{Availability, MODEL};
pub use capability::{Capability, Tier};
pub use engine::{Finding, Remedy, Severity, check};

/// One call: run the rules, and say whether the optional layer is
/// available to annotate them.
///
/// Returns the findings regardless. A caller that ignores the
/// `Availability` gets a complete, correct result — which is the
/// intended relationship between the two halves, expressed in the
/// signature rather than only in prose.
pub fn diagnose(ctx: &engine::Context) -> (Vec<Finding>, Availability) {
    let findings = engine::check(ctx);
    let capability = Capability::detect();
    let availability = match advisor::assess_hardware(&capability) {
        // The static gate passed; whether the model is actually there
        // and fast enough is the caller's next step, because it costs
        // a real generation to find out and not every caller wants to
        // pay that.
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
        // The contract that matters: a machine with no model, no
        // Ollama and no AVX2 still gets the full diagnosis.
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
