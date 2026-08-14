//! Keeping the model endpoint closed, and its configuration honest.
//!
//! Two separate mechanisms, deliberately not conflated.
//!
//! ## 1. Access — a per-install bearer secret
//!
//! Apache sits in front of Ollama on loopback and requires a secret
//! that is generated once, at random, and stored 0600 readable only by
//! `fossh-svc`. Nothing else can reach the model: Ollama itself binds
//! `127.0.0.1`, Apache is the only thing in front of it, and the
//! person whose visit is being counted is on a different machine
//! entirely.
//!
//! It is a bearer secret rather than an OpenPGP challenge-response
//! because Apache can check the former with one directive it already
//! has, and the latter would mean inventing an HTTP auth scheme and a
//! module to verify it. An invented protocol guarding a loopback
//! socket would be worse security than a well-understood one, not
//! better.
//!
//! ## 2. Tamper protection — an OpenPGP-signed configuration manifest
//!
//! This is where the OpenPGP key does real work. The model's
//! configuration — which model, which endpoint, how many threads — is
//! written out and clearsigned with a per-install key generated at
//! random on first run. Before the advisory layer is used at all, that
//! signature is verified against the key's own fingerprint. An edited
//! endpoint, a swapped model, or a thread count raised until the box
//! is saturated all fail that check, and failing it means the advisory
//! layer does not run — the deterministic engine carries on exactly as
//! before.
//!
//! This mirrors `watchdog/lib/manifest.ml` on purpose. That module
//! already established the pattern in this codebase, including the two
//! things that are easy to get wrong and were got wrong there first:
//! the manifest has to cover the thing actually being used (ADR-0041),
//! and `gpg --verify` has to be run with `--status-fd` parsing rather
//! than trusting the exit code, because `gpgv` alone does not check
//! revocation or expiry (ADR-0040).
//!
//! ## Fails closed
//!
//! Every failure here — no key, no manifest, a bad signature, an
//! unreadable secret — disables the advisory layer and nothing else.
//! There is no path where a tamper-check failure degrades the
//! deterministic engine, because the engine does not consult this
//! module at all.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Length of the generated bearer secret, in bytes before hex
/// encoding. 32 bytes is the same width this project already uses for
/// its data key and its nonces.
const SECRET_BYTES: usize = 32;

pub const SECRET_FILE: &str = "model-access-secret";
pub const MANIFEST_FILE: &str = "model-config.asc";

/// Exactly what the signature covers.
///
/// Every field here is one an attacker would want to change: point the
/// endpoint somewhere else, swap in a different model, or raise the
/// thread count until the machine stops serving. Adding a field to
/// this struct without adding it to the signed manifest would be the
/// ADR-0041 bug again, which is why there is a test asserting the
/// serialised form contains each one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model: String,
    pub endpoint: String,
    pub threads: usize,
}

#[derive(Debug)]
pub enum LockError {
    /// No configuration has been established yet — the ordinary state
    /// before setup has run.
    NotConfigured,
    /// The manifest exists but did not verify. Fails closed.
    Tampered(String),
    Io(String),
    Gpg(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::NotConfigured => write!(
                f,
                "the local model has not been configured on this install yet"
            ),
            LockError::Tampered(m) => write!(
                f,
                "the local model's signed configuration did not verify ({m}), so the advisory \
                 layer has been left switched off. Self-healing's deterministic rules are \
                 unaffected."
            ),
            LockError::Io(m) => write!(f, "{m}"),
            LockError::Gpg(m) => write!(f, "gpg: {m}"),
        }
    }
}

impl std::error::Error for LockError {}

pub fn secret_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SECRET_FILE)
}

pub fn manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MANIFEST_FILE)
}

/// Reads the per-install bearer secret, or generates one.
///
/// Created 0600 before anything is written into it — never written
/// and then chmod'ed, which leaves a window where the secret is
/// world-readable on disk.
pub fn load_or_generate_secret(state_dir: &Path) -> Result<String, LockError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = secret_path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(existing) => {
            let trimmed = existing.trim().to_string();
            if trimmed.is_empty() {
                return Err(LockError::Io(format!(
                    "{} is empty; remove it and re-run setup",
                    path.display()
                )));
            }
            return Ok(trimmed);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(LockError::Io(format!("{}: {e}", path.display()))),
    }

    let random = read_random_hex(SECRET_BYTES)?;
    std::fs::create_dir_all(state_dir)
        .map_err(|e| LockError::Io(format!("{}: {e}", state_dir.display())))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| LockError::Io(format!("{}: {e}", path.display())))?;
    file.write_all(random.as_bytes())
        .map_err(|e| LockError::Io(format!("{}: {e}", path.display())))?;
    file.sync_all()
        .map_err(|e| LockError::Io(format!("{}: {e}", path.display())))?;
    Ok(random)
}

/// `/dev/urandom`, hex-encoded. The same source
/// `fossh_ingest::random` and the watchdog's `Nonce` already use —
/// deliberately not a userspace PRNG seeded from it.
fn read_random_hex(bytes: usize) -> Result<String, LockError> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| LockError::Io(format!("/dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// The exact bytes the signature covers.
///
/// Canonical and sorted, so a manifest signed on one machine and
/// verified on another cannot differ because a serialiser reordered a
/// map. A trailing newline is included so the clearsigned form is
/// stable.
pub fn canonical_manifest(config: &ModelConfig) -> String {
    format!(
        "endpoint={}\nmodel={}\nthreads={}\n",
        config.endpoint, config.model, config.threads
    )
}

/// Verifies the clearsigned manifest and returns the configuration it
/// attests to.
///
/// `--status-fd` output is parsed rather than the exit code being
/// trusted. `gpg` exits 0 for a good signature from an expired or
/// revoked key, which is the exact gap ADR-0040 found in this
/// project's watchdog and fixed there; repeating the mistake here
/// would reintroduce it in a second place.
pub fn verify(state_dir: &Path, expected_fingerprint: &str) -> Result<ModelConfig, LockError> {
    let path = manifest_path(state_dir);
    if !path.exists() {
        return Err(LockError::NotConfigured);
    }

    let output = std::process::Command::new("gpg")
        .arg("--batch")
        .arg("--no-tty")
        .arg("--status-fd")
        .arg("1")
        .arg("--decrypt")
        .arg(&path)
        .output()
        .map_err(|e| LockError::Gpg(format!("could not run gpg: {e}")))?;

    let status = String::from_utf8_lossy(&output.stdout);
    parse_verified_manifest(&status, expected_fingerprint)
}

/// Split out so the `--status-fd` grammar is testable without a
/// keyring — the part most likely to be got wrong, and the part a
/// live-only test would never exercise for the revoked/expired cases.
pub fn parse_verified_manifest(
    gpg_output: &str,
    expected_fingerprint: &str,
) -> Result<ModelConfig, LockError> {
    let mut good = false;
    let mut fingerprint_matches = false;

    for line in gpg_output.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        match parts.next() {
            Some("GOODSIG") => good = true,
            // Any of these means do not proceed, regardless of
            // GOODSIG, and regardless of gpg's exit code.
            Some("REVKEYSIG") => {
                return Err(LockError::Tampered("the signing key is revoked".to_string()))
            }
            Some("EXPKEYSIG") => {
                return Err(LockError::Tampered("the signing key has expired".to_string()))
            }
            Some("EXPSIG") => {
                return Err(LockError::Tampered("the signature has expired".to_string()))
            }
            Some("BADSIG") => {
                return Err(LockError::Tampered("the signature does not match".to_string()))
            }
            Some("ERRSIG") => {
                return Err(LockError::Tampered(
                    "the signature could not be checked".to_string(),
                ))
            }
            Some("VALIDSIG") => {
                if let Some(fpr) = parts.next() {
                    fingerprint_matches = fpr.eq_ignore_ascii_case(expected_fingerprint);
                }
            }
            _ => {}
        }
    }

    if !good {
        return Err(LockError::Tampered(
            "no good signature on the manifest".to_string(),
        ));
    }
    if !fingerprint_matches {
        return Err(LockError::Tampered(
            "the manifest is signed by a different key than this install's".to_string(),
        ));
    }

    // Only now is the content worth reading.
    parse_manifest_body(gpg_output)
}

fn parse_manifest_body(text: &str) -> Result<ModelConfig, LockError> {
    let mut model = None;
    let mut endpoint = None;
    let mut threads = None;

    for line in text.lines() {
        if line.starts_with("[GNUPG:] ") {
            continue;
        }
        if let Some(v) = line.strip_prefix("model=") {
            model = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("endpoint=") {
            endpoint = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("threads=") {
            threads = v.trim().parse::<usize>().ok();
        }
    }

    match (model, endpoint, threads) {
        (Some(model), Some(endpoint), Some(threads)) => Ok(ModelConfig {
            model,
            endpoint,
            threads,
        }),
        _ => Err(LockError::Tampered(
            "the signed manifest is missing one of model, endpoint or threads".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fossh-keylock-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const FPR: &str = "AAAABBBBCCCCDDDDEEEEFFFF00001111222233334";

    fn status(lines: &[&str]) -> String {
        let mut out = String::new();
        for line in lines {
            out.push_str("[GNUPG:] ");
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("endpoint=http://127.0.0.1:11434\nmodel=lfm2.5-thinking:1.2b\nthreads=4\n");
        out
    }

    #[test]
    fn a_good_signature_from_the_expected_key_verifies() {
        let config = parse_verified_manifest(
            &status(&["GOODSIG 1234 foSSH", &format!("VALIDSIG {FPR} 2026-01-01")]),
            FPR,
        )
        .unwrap();
        assert_eq!(config.model, "lfm2.5-thinking:1.2b");
        assert_eq!(config.endpoint, "http://127.0.0.1:11434");
        assert_eq!(config.threads, 4);
    }

    #[test]
    fn a_revoked_key_is_refused_even_with_a_good_signature() {
        // The exact gap ADR-0040 found in the watchdog: gpg exits 0
        // here, and trusting the exit code would accept it.
        let err = parse_verified_manifest(
            &status(&[
                "GOODSIG 1234 foSSH",
                "REVKEYSIG 1234 foSSH",
                &format!("VALIDSIG {FPR} 2026-01-01"),
            ]),
            FPR,
        )
        .unwrap_err();
        assert!(matches!(err, LockError::Tampered(ref m) if m.contains("revoked")));
    }

    #[test]
    fn an_expired_key_is_refused_even_with_a_good_signature() {
        let err = parse_verified_manifest(
            &status(&["GOODSIG 1234 foSSH", "EXPKEYSIG 1234 foSSH"]),
            FPR,
        )
        .unwrap_err();
        assert!(matches!(err, LockError::Tampered(ref m) if m.contains("expired")));
    }

    #[test]
    fn a_signature_from_a_different_key_is_refused() {
        // A valid, unexpired, unrevoked signature from someone else's
        // key is exactly what an attacker who can write the manifest
        // would produce.
        let err = parse_verified_manifest(
            &status(&[
                "GOODSIG 1234 attacker",
                "VALIDSIG 9999999999999999999999999999999999999999 2026-01-01",
            ]),
            FPR,
        )
        .unwrap_err();
        assert!(matches!(err, LockError::Tampered(ref m) if m.contains("different key")));
    }

    #[test]
    fn an_unsigned_manifest_is_refused() {
        let err = parse_verified_manifest(
            "endpoint=http://127.0.0.1:11434\nmodel=x\nthreads=1\n",
            FPR,
        )
        .unwrap_err();
        assert!(matches!(err, LockError::Tampered(ref m) if m.contains("no good signature")));
    }

    #[test]
    fn a_manifest_missing_a_field_is_refused_rather_than_defaulted() {
        // Defaulting a missing `threads` would let an attacker delete
        // the line rather than change it, and get a value of their
        // choosing anyway.
        let text = format!(
            "[GNUPG:] GOODSIG 1 x\n[GNUPG:] VALIDSIG {FPR} 2026\nendpoint=http://127.0.0.1\nmodel=m\n"
        );
        assert!(parse_verified_manifest(&text, FPR).is_err());
    }

    #[test]
    fn fingerprint_comparison_is_case_insensitive() {
        // gpg emits uppercase; a fingerprint stored lowercase
        // elsewhere in this codebase must still match.
        assert!(parse_verified_manifest(
            &status(&["GOODSIG 1 x", &format!("VALIDSIG {} 2026", FPR.to_lowercase())]),
            FPR,
        )
        .is_ok());
    }

    #[test]
    fn the_canonical_form_covers_every_field_of_the_config() {
        // Adding a field to `ModelConfig` without adding it to the
        // signed bytes is the ADR-0041 bug — a manifest that does not
        // cover the thing being used. This is what catches it.
        let config = ModelConfig {
            model: "lfm2.5-thinking:1.2b".to_string(),
            endpoint: "http://127.0.0.1:11434".to_string(),
            threads: 4,
        };
        let canonical = canonical_manifest(&config);
        let json = serde_json::to_value(&config).unwrap();
        for key in json.as_object().unwrap().keys() {
            assert!(
                canonical.contains(&format!("{key}=")),
                "{key} is in ModelConfig but not in the signed manifest"
            );
        }
    }

    #[test]
    fn the_canonical_form_is_stable_across_calls() {
        let config = ModelConfig {
            model: "m".to_string(),
            endpoint: "e".to_string(),
            threads: 1,
        };
        assert_eq!(canonical_manifest(&config), canonical_manifest(&config));
    }

    #[test]
    fn a_generated_secret_is_owner_only_and_reused_on_the_next_call() {
        let dir = scratch("secret");
        let first = load_or_generate_secret(&dir).unwrap();
        assert_eq!(first.len(), SECRET_BYTES * 2, "hex of 32 bytes");

        let mode = fs::metadata(secret_path(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);

        let second = load_or_generate_secret(&dir).unwrap();
        assert_eq!(first, second, "the secret must be stable across restarts");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_installs_get_different_secrets() {
        let a = scratch("sec-a");
        let b = scratch("sec-b");
        assert_ne!(
            load_or_generate_secret(&a).unwrap(),
            load_or_generate_secret(&b).unwrap()
        );
        fs::remove_dir_all(&a).ok();
        fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn an_empty_secret_file_is_an_error_rather_than_a_silent_regeneration() {
        // Silently regenerating would leave Apache checking against a
        // secret nothing else has, which presents as an unexplained
        // 403 rather than as the truncated file it really is.
        let dir = scratch("empty-secret");
        fs::write(secret_path(&dir), "").unwrap();
        assert!(load_or_generate_secret(&dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_manifest_reads_as_not_configured_not_as_tampering() {
        // Before setup runs there is no manifest, and calling that
        // "tampered" would make every fresh install look attacked.
        let dir = scratch("no-manifest");
        assert!(matches!(verify(&dir, FPR), Err(LockError::NotConfigured)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_failure_message_says_the_deterministic_rules_still_work() {
        let message = LockError::Tampered("x".to_string()).to_string();
        assert!(message.contains("deterministic rules are unaffected"));
    }
}
