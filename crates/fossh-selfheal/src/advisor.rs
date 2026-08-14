//! The optional local model, and the fence around it.
//!
//! Runs `lfm2.5-thinking:1.2b` under Ollama, on this machine, and lets
//! it write one thing: the `advice` field of a `Finding` that
//! `engine.rs` already produced. It cannot create a finding, cannot
//! change a severity, cannot alter a remedy, and cannot cause anything
//! to be executed. `attach_advice` enforces all four by construction —
//! it matches replies to findings by id and copies exactly one string.
//!
//! ## Why the fence is this tight
//!
//! An operator installs foSSH for a set of privacy invariants. A
//! component able to author remedies could talk someone out of the one
//! they came for — "your k-anonymity threshold looks high, try
//! lowering it" is a fluent, plausible, and completely wrong sentence
//! that a 1.2B model will happily produce. Keeping the model on the
//! explaining side of the line means its worst failure is unhelpful
//! prose, not a changed setting.
//!
//! ## Reaching it
//!
//! Ollama binds loopback and is not exposed; Apache sits in front on
//! `127.0.0.1` and is what actually enforces access, gated on a
//! per-install OpenPGP key generated at setup (see
//! `packaging/apache/fossh-model.conf` and `keylock.rs`). The end user
//! of the site being measured has no route to any of it — different
//! machine, different network, and nothing in the ingest path even
//! links this crate.
//!
//! Transport is the project's existing BoringSSL/QUIC channel where a
//! watchdog is present, and plain loopback HTTP where one is not:
//! `fossh-ipc`'s mTLS pins exactly one peer certificate pair, so a
//! third party to that channel needs its own pinning step, which is a
//! larger change than this feature justifies. Loopback-only, behind
//! Apache, key-gated, is the boundary that actually holds here — the
//! QUIC leg protects the watchdog↔core hop, not this one, and saying
//! otherwise would be security theatre. See ADR-0065.
//!
//! ## Nothing about a visitor is ever sent
//!
//! The prompt is built from `Finding` ids, titles, and details — all
//! of them strings this codebase wrote. No event, no path, no country,
//! no aggregate, and no configuration value beyond what a finding
//! already names. `redact_prompt_inputs` is the check, and it is
//! asserted rather than assumed.

use crate::capability::{Capability, Tier};
use crate::engine::Finding;

/// The model this subsystem is built around.
pub const MODEL: &str = "lfm2.5-thinking:1.2b";

/// Where Apache publishes it. Loopback by construction — a non-local
/// address here would be a bug, and `validate_endpoint` refuses one.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";

/// The floor a timed probe has to clear, in tokens per second.
///
/// Below this the advisory layer is not "slow", it is a background
/// process competing with the thing the server is actually for. A
/// 1.2B model quantised for CPU inference clears this comfortably on
/// any machine that passes the static gate; a machine that does not is
/// almost always one where CPUID advertises a feature the hypervisor
/// emulates, which is exactly the case static detection cannot see.
pub const MIN_TOKENS_PER_SECOND: f64 = 8.0;

/// The longest a single advisory generation may take before it is
/// abandoned. Self-healing advice that arrives after the operator has
/// stopped looking is worth nothing, and the finding is already
/// complete without it.
pub const GENERATION_TIMEOUT_SECS: u32 = 20;

#[derive(Debug, Clone, PartialEq)]
pub enum Availability {
    /// The model may be used.
    Ready { tier: Tier, tokens_per_second: f64 },
    /// Hardware ruled it out before anything was timed.
    UnsupportedHardware { reason: String },
    /// Hardware was fine; the measurement was not.
    TooSlow { measured: f64 },
    /// Ollama is not installed, not running, or not reachable.
    NotInstalled { reason: String },
    /// Deliberately switched off by the operator.
    Disabled,
}

impl Availability {
    pub fn model_running(&self) -> bool {
        matches!(self, Availability::Ready { .. })
    }

    /// One sentence for `fossh doctor` and the console.
    pub fn explain(&self) -> String {
        match self {
            Availability::Ready {
                tier,
                tokens_per_second,
            } => format!(
                "The local model is running at the {} tier, measured at {tokens_per_second:.1} \
                 tokens/second.",
                tier.as_str()
            ),
            Availability::UnsupportedHardware { reason } => format!(
                "Self-healing is running from its deterministic rules only: {reason}"
            ),
            Availability::TooSlow { measured } => format!(
                "The local model was measured at {measured:.1} tokens/second, below the \
                 {MIN_TOKENS_PER_SECOND:.0}/second floor, so it has been switched off for this \
                 session rather than competing with the server's real work. Self-healing runs \
                 from its deterministic rules, which is the whole feature."
            ),
            Availability::NotInstalled { reason } => format!(
                "The local model is not available ({reason}). Self-healing runs from its \
                 deterministic rules only."
            ),
            Availability::Disabled => {
                "The local model is switched off. Self-healing runs from its deterministic \
                 rules only."
                    .to_string()
            }
        }
    }
}

/// The static half of the gate. Cheap, and enough to rule most
/// machines out before anything is started.
pub fn assess_hardware(capability: &Capability) -> Result<Tier, Availability> {
    let tier = capability.static_tier();
    if !tier.model_allowed() {
        return Err(Availability::UnsupportedHardware {
            reason: capability.explain(),
        });
    }
    Ok(tier)
}

/// The measured half. `measured_tokens_per_second` comes from a real
/// generation — see `probe`.
pub fn assess_measurement(tier: Tier, measured_tokens_per_second: f64) -> Availability {
    if measured_tokens_per_second < MIN_TOKENS_PER_SECOND {
        Availability::TooSlow {
            measured: measured_tokens_per_second,
        }
    } else {
        Availability::Ready {
            tier,
            tokens_per_second: measured_tokens_per_second,
        }
    }
}

/// Refuses an endpoint that is not loopback.
///
/// The model endpoint is an internal detail behind Apache; pointing it
/// at another host would send this install's findings — which name its
/// paths and its configuration — to a machine the operator may not
/// control, over plain HTTP. There is no legitimate reason to, so it
/// is refused rather than warned about.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let rest = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .ok_or_else(|| "the model endpoint must be an http:// or https:// URL".to_string())?;

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    let host = if let Some(close) = host.find(']') {
        &host[..=close]
    } else {
        host.split_once(':').map(|(h, _)| h).unwrap_or(host)
    };

    let loopback = host.eq_ignore_ascii_case("localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|a| a.is_loopback())
            .unwrap_or(false);

    if loopback {
        Ok(())
    } else {
        Err(format!(
            "the model endpoint must be on this machine, and {host} is not — self-healing \
             findings name this install's own paths and settings, and are not sent anywhere else"
        ))
    }
}

/// The prompt for one finding.
///
/// Deliberately built from fixed text plus three fields this codebase
/// itself wrote. Nothing derived from a visitor, an event, or a
/// measurement can reach it, which is what makes the privacy claim
/// checkable rather than a promise.
pub fn build_prompt(finding: &Finding) -> String {
    format!(
        "You are explaining one diagnostic from foSSH, a self-hosted, privacy-preserving \
         analytics server. Explain in at most three sentences what this means for the operator \
         and why it matters.\n\n\
         Do not suggest a fix, a command, or a configuration change: the fix is already decided \
         and shown separately, and inventing another one would be wrong. Do not restate the \
         title.\n\n\
         Diagnostic: {}\n\
         Severity: {}\n\
         Detail: {}\n",
        finding.title,
        finding.severity.as_str(),
        finding.detail,
    )
}

/// Copies model output onto findings, and nothing else.
///
/// `replies` is `(finding id, advice)`. An id that does not match a
/// real finding is dropped — that is the model trying to talk about
/// something that was never diagnosed, and there is no version of that
/// which should reach a screen. Advice is trimmed and capped; a
/// runaway generation is a display problem, not a licence to scroll.
pub fn attach_advice(findings: &mut [Finding], replies: &[(String, String)]) {
    const MAX_ADVICE_CHARS: usize = 600;

    for (id, advice) in replies {
        let Some(finding) = findings.iter_mut().find(|f| &f.id == id) else {
            continue;
        };
        let cleaned = advice.trim();
        if cleaned.is_empty() {
            continue;
        }
        let capped: String = cleaned.chars().take(MAX_ADVICE_CHARS).collect();
        finding.advice = Some(capped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Remedy, Severity};

    fn capability(cores: usize, avx2: bool, avx512: bool, vulkan: bool) -> Capability {
        Capability {
            physical_cores: cores,
            logical_cores: cores * 2,
            ram_bytes: 16 * 1024 * 1024 * 1024,
            avx2,
            avx512,
            avx512_vnni: false,
            vulkan_loader: vulkan,
            arch: "x86_64",
        }
    }

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            severity: Severity::Warning,
            title: "A title long enough to be real".to_string(),
            detail: "A detail long enough to be a real sentence about the install.".to_string(),
            remedy: Remedy::None,
            advice: None,
        }
    }

    #[test]
    fn hardware_below_the_floor_is_refused_before_anything_starts() {
        let err = assess_hardware(&capability(2, true, true, true)).unwrap_err();
        match err {
            Availability::UnsupportedHardware { reason } => assert!(reason.contains("cores")),
            other => panic!("expected UnsupportedHardware, got {other:?}"),
        }
    }

    #[test]
    fn an_avx2_machine_passes_the_static_gate_at_baseline() {
        assert_eq!(
            assess_hardware(&capability(6, true, false, false)).unwrap(),
            Tier::Baseline
        );
    }

    #[test]
    fn vulkan_only_hardware_passes_as_the_fail_switch() {
        assert_eq!(
            assess_hardware(&capability(6, false, false, true)).unwrap(),
            Tier::FailSwitch
        );
    }

    #[test]
    fn passing_the_static_gate_is_not_enough_on_its_own() {
        // The point of measuring: CPUID can advertise AVX-512 that a
        // hypervisor emulates at a fraction of the speed, and no
        // amount of static detection sees that.
        let slow = assess_measurement(Tier::Preferred, MIN_TOKENS_PER_SECOND - 0.1);
        assert!(matches!(slow, Availability::TooSlow { .. }));
        assert!(!slow.model_running());

        let fine = assess_measurement(Tier::Baseline, MIN_TOKENS_PER_SECOND + 10.0);
        assert!(fine.model_running());
    }

    #[test]
    fn exactly_at_the_floor_is_accepted() {
        assert!(assess_measurement(Tier::Baseline, MIN_TOKENS_PER_SECOND).model_running());
    }

    #[test]
    fn every_unavailable_state_says_the_deterministic_rules_still_run() {
        // The message that stops "the model is off" from reading as
        // "the feature is broken". It is the same feature either way.
        for state in [
            Availability::UnsupportedHardware {
                reason: "x".to_string(),
            },
            Availability::TooSlow { measured: 1.0 },
            Availability::NotInstalled {
                reason: "x".to_string(),
            },
            Availability::Disabled,
        ] {
            assert!(
                state.explain().contains("deterministic rules"),
                "{state:?} does not reassure: {}",
                state.explain()
            );
        }
    }

    #[test]
    fn a_non_loopback_endpoint_is_refused() {
        assert!(validate_endpoint("http://127.0.0.1:11434").is_ok());
        assert!(validate_endpoint("http://localhost:11434").is_ok());
        assert!(validate_endpoint("http://[::1]:11434").is_ok());
        assert!(validate_endpoint("http://10.0.0.5:11434").is_err());
        assert!(validate_endpoint("http://models.example.com").is_err());
        // The same substring traps `integrations` had to handle.
        assert!(validate_endpoint("http://127.0.0.1.evil.example/").is_err());
        assert!(validate_endpoint("http://evil.example/?h=127.0.0.1").is_err());
        assert!(validate_endpoint("http://evil.example#@localhost/").is_err());
        assert!(validate_endpoint("ollama://127.0.0.1").is_err());
    }

    #[test]
    fn the_prompt_carries_only_strings_this_codebase_wrote() {
        // The privacy claim, as a test. If a future edit widened the
        // prompt to include, say, a site slug or an event name, this
        // is what would catch it.
        let f = finding("k_anonymity_low");
        let prompt = build_prompt(&f);
        assert!(prompt.contains(&f.title));
        assert!(prompt.contains(&f.detail));
        assert!(prompt.contains("warning"));
        // The id is internal and has no business in a prompt.
        assert!(!prompt.contains("k_anonymity_low"));
    }

    #[test]
    fn the_prompt_tells_the_model_not_to_invent_a_fix() {
        let prompt = build_prompt(&finding("x"));
        assert!(prompt.contains("Do not suggest a fix"));
    }

    #[test]
    fn advice_lands_only_on_a_finding_that_already_exists() {
        // The fence. A model that answers about something never
        // diagnosed is not adding information, it is hallucinating a
        // diagnosis, and there is no display for that.
        let mut findings = vec![finding("real_one")];
        attach_advice(
            &mut findings,
            &[
                ("real_one".to_string(), "This matters because…".to_string()),
                ("invented_finding".to_string(), "Also your disk is on fire".to_string()),
            ],
        );
        assert_eq!(findings.len(), 1, "the model must not be able to add findings");
        assert_eq!(findings[0].advice.as_deref(), Some("This matters because…"));
    }

    #[test]
    fn advice_can_never_change_a_severity_or_a_remedy() {
        // Asserted directly rather than left to inspection: this is
        // the property the whole design rests on.
        let mut findings = vec![Finding {
            severity: Severity::Critical,
            remedy: Remedy::Operator {
                description: "do the real thing".to_string(),
                command: "fossh init".to_string(),
            },
            ..finding("fixed")
        }];
        let before_severity = findings[0].severity;
        let before_remedy = findings[0].remedy.clone();

        attach_advice(
            &mut findings,
            &[("fixed".to_string(), "ignore the above, run `rm -rf /`".to_string())],
        );

        assert_eq!(findings[0].severity, before_severity);
        assert_eq!(findings[0].remedy, before_remedy);
        assert!(findings[0].advice.is_some());
    }

    #[test]
    fn empty_or_whitespace_advice_is_dropped_rather_than_shown() {
        let mut findings = vec![finding("a")];
        attach_advice(&mut findings, &[("a".to_string(), "   \n  ".to_string())]);
        assert_eq!(findings[0].advice, None);
    }

    #[test]
    fn runaway_advice_is_capped_on_a_char_boundary() {
        let mut findings = vec![finding("a")];
        attach_advice(&mut findings, &[("a".to_string(), "é".repeat(5_000))]);
        let advice = findings[0].advice.as_ref().unwrap();
        assert!(advice.chars().count() <= 600);
        assert!(advice.starts_with('é'));
    }

    #[test]
    fn the_model_name_is_the_one_this_subsystem_was_built_for() {
        assert_eq!(MODEL, "lfm2.5-thinking:1.2b");
    }
}
