use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SECRET_BYTES: usize = 32;

pub const SECRET_FILE: &str = "model-access-secret";
pub const MANIFEST_FILE: &str = "model-config.asc";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model: String,
    pub endpoint: String,
    pub threads: usize,
}

#[derive(Debug)]
pub enum LockError {

    NotConfigured,

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

fn read_random_hex(bytes: usize) -> Result<String, LockError> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| LockError::Io(format!("/dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn canonical_manifest(config: &ModelConfig) -> String {
    format!(
        "endpoint={}\nmodel={}\nthreads={}\n",
        config.endpoint, config.model, config.threads
    )
}

pub fn verify(state_dir: &Path, expected_fingerprint: &str) -> Result<ModelConfig, LockError> {
    let path = manifest_path(state_dir);
    if !path.exists() {
        return Err(LockError::NotConfigured);
    }

    let status_path = std::env::temp_dir().join(format!(
        "fossh-model-status-{}-{}",
        std::process::id(),
        read_random_hex(8).unwrap_or_else(|_| "0".repeat(16))
    ));

    let output = std::process::Command::new("gpg")
        .arg("--batch")
        .arg("--no-tty")
        .arg("--status-file")
        .arg(&status_path)
        .arg("--decrypt")
        .arg(&path)
        .output();

    let result = (|| {
        let output = output.map_err(|e| LockError::Gpg(format!("could not run gpg: {e}")))?;
        let status = std::fs::read_to_string(&status_path).map_err(|e| {
            LockError::Gpg(format!(
                "gpg wrote no status output, so nothing about this signature could be \
                 established: {e}"
            ))
        })?;

        let body = String::from_utf8_lossy(&output.stdout);
        parse_verified_manifest_parts(&status, &body, expected_fingerprint)
    })();

    let _ = std::fs::remove_file(&status_path);
    result
}

pub fn parse_verified_manifest(
    gpg_output: &str,
    expected_fingerprint: &str,
) -> Result<ModelConfig, LockError> {
    parse_verified_manifest_parts(gpg_output, gpg_output, expected_fingerprint)
}

pub fn parse_verified_manifest_parts(
    status: &str,
    body: &str,
    expected_fingerprint: &str,
) -> Result<ModelConfig, LockError> {
    let mut good = false;
    let mut fingerprint_matches = false;

    for line in status.lines() {

        let rest = line.strip_prefix("[GNUPG:] ").unwrap_or(line);
        let mut parts = rest.split_whitespace();
        match parts.next() {
            Some("GOODSIG") => good = true,

            Some("REVKEYSIG") => {
                return Err(LockError::Tampered(
                    "the signing key is revoked".to_string(),
                ));
            }
            Some("EXPKEYSIG") => {
                return Err(LockError::Tampered(
                    "the signing key has expired".to_string(),
                ));
            }
            Some("EXPSIG") => {
                return Err(LockError::Tampered("the signature has expired".to_string()));
            }
            Some("BADSIG") => {
                return Err(LockError::Tampered(
                    "the signature does not match".to_string(),
                ));
            }
            Some("ERRSIG") => {
                return Err(LockError::Tampered(
                    "the signature could not be checked".to_string(),
                ));
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

    parse_manifest_body(body)
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
    fn a_document_cannot_forge_status_lines_from_its_own_body() {

        let forged_body = format!(
            "endpoint=http://evil.invalid:11434\nmodel=attacker:1.0\nthreads=64\n\
             [GNUPG:] GOODSIG DEADBEEF someone\n[GNUPG:] VALIDSIG {FPR} 2026-01-01\n"
        );

        let real_status = "NEWSIG\nERRSIG DEADBEEF 22 10 01 1786789346 9\nNO_PUBKEY DEADBEEF\n";

        let err = parse_verified_manifest_parts(real_status, &forged_body, FPR).unwrap_err();
        assert!(
            matches!(err, LockError::Tampered(_)),
            "a forged status line in the document body was believed: {err:?}"
        );
    }

    #[test]
    fn status_lines_are_accepted_with_or_without_the_stream_prefix() {

        let bare = format!("GOODSIG 1 x\nVALIDSIG {FPR} 2026-01-01\n");
        let body = "endpoint=http://127.0.0.1:11434\nmodel=m\nthreads=4\n";
        assert!(parse_verified_manifest_parts(&bare, body, FPR).is_ok());

        let prefixed = format!("[GNUPG:] GOODSIG 1 x\n[GNUPG:] VALIDSIG {FPR} 2026-01-01\n");
        assert!(parse_verified_manifest_parts(&prefixed, body, FPR).is_ok());
    }

    #[test]
    fn an_unsigned_manifest_is_refused() {
        let err =
            parse_verified_manifest("endpoint=http://127.0.0.1:11434\nmodel=x\nthreads=1\n", FPR)
                .unwrap_err();
        assert!(matches!(err, LockError::Tampered(ref m) if m.contains("no good signature")));
    }

    #[test]
    fn a_manifest_missing_a_field_is_refused_rather_than_defaulted() {

        let text = format!(
            "[GNUPG:] GOODSIG 1 x\n[GNUPG:] VALIDSIG {FPR} 2026\nendpoint=http://127.0.0.1\nmodel=m\n"
        );
        assert!(parse_verified_manifest(&text, FPR).is_err());
    }

    #[test]
    fn fingerprint_comparison_is_case_insensitive() {

        assert!(
            parse_verified_manifest(
                &status(&[
                    "GOODSIG 1 x",
                    &format!("VALIDSIG {} 2026", FPR.to_lowercase())
                ]),
                FPR,
            )
            .is_ok()
        );
    }

    #[test]
    fn the_canonical_form_covers_every_field_of_the_config() {

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
    fn a_generated_secret_has_no_trailing_newline() {

        let dir = scratch("no-newline");
        let secret = load_or_generate_secret(&dir).unwrap();
        let raw = fs::read(secret_path(&dir)).unwrap();
        assert!(
            !raw.ends_with(b"\n"),
            "the secret file must not end in a newline"
        );
        assert!(!raw.ends_with(b"\r"));
        assert_eq!(raw, secret.as_bytes());
        assert!(raw.iter().all(|b| b.is_ascii_hexdigit()));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_generated_secret_is_owner_only_and_reused_on_the_next_call() {
        let dir = scratch("secret");
        let first = load_or_generate_secret(&dir).unwrap();
        assert_eq!(first.len(), SECRET_BYTES * 2, "hex of 32 bytes");

        let mode = fs::metadata(secret_path(&dir))
            .unwrap()
            .permissions()
            .mode();
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

        let dir = scratch("empty-secret");
        fs::write(secret_path(&dir), "").unwrap();
        assert!(load_or_generate_secret(&dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_manifest_reads_as_not_configured_not_as_tampering() {

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
