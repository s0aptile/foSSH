use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fossh_ingest::random::read_random_bytes;

const OPENSSL_PATH: &str = "/usr/bin/openssl";

const VALIDITY_DAYS: u32 = 3650;

#[derive(Debug)]
pub enum TlsIdentityError {
    InvalidCommonName(String),
    Generate(String),
    Io(std::io::Error),
    Random(String),
}

impl std::fmt::Display for TlsIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommonName(cn) => write!(f, "invalid common name {cn:?}"),
            Self::Generate(e) => write!(f, "generating TLS identity: {e}"),
            Self::Io(e) => write!(f, "TLS identity I/O error: {e}"),
            Self::Random(e) => write!(f, "TLS identity: {e}"),
        }
    }
}

impl std::error::Error for TlsIdentityError {}

impl From<std::io::Error> for TlsIdentityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct TlsIdentity {
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
}

fn validate_common_name(common_name: &str) -> Result<(), TlsIdentityError> {
    let ok = !common_name.is_empty()
        && common_name.len() <= 64
        && common_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(TlsIdentityError::InvalidCommonName(common_name.to_string()))
    }
}

fn cert_is_valid(path: &Path) -> bool {
    path.is_file()
        && Command::new(OPENSSL_PATH)
            .args(["x509", "-in"])
            .arg(path)
            .args(["-noout", "-checkend", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

fn key_is_valid(path: &Path) -> bool {
    path.is_file()
        && Command::new(OPENSSL_PATH)
            .args(["pkey", "-in"])
            .arg(path)
            .arg("-noout")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

fn random_hex_suffix(n: usize) -> Result<String, TlsIdentityError> {
    let bytes = read_random_bytes(n).map_err(|e| TlsIdentityError::Random(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn generate_into(tmp_dir: &Path, common_name: &str) -> Result<(), TlsIdentityError> {
    let cert_path = tmp_dir.join("cert.pem");
    let key_path = tmp_dir.join("key.pem");

    let status = Command::new(OPENSSL_PATH)
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
        ])
        .args(["-days", &VALIDITY_DAYS.to_string(), "-nodes"])
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .args(["-subj", &format!("/CN={common_name}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| TlsIdentityError::Generate(e.to_string()))?;

    if !status.success() {
        return Err(TlsIdentityError::Generate(format!(
            "openssl req exited {status}"
        )));
    }

    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

    for path in [&cert_path, &key_path] {
        let f = fs::File::open(path)?;
        f.sync_all()?;
    }
    Ok(())
}

pub fn ensure_identity(dir: &Path, common_name: &str) -> Result<TlsIdentity, TlsIdentityError> {
    validate_common_name(common_name)?;

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;

    let current_link = dir.join("current");

    if let Some(resolved) = resolve_current(dir, &current_link) {
        let cert_pem_path = resolved.join("cert.pem");
        let key_pem_path = resolved.join("key.pem");
        if cert_is_valid(&cert_pem_path) && key_is_valid(&key_pem_path) {
            return Ok(TlsIdentity {
                cert_pem_path,
                key_pem_path,
            });
        }
    }

    let suffix = random_hex_suffix(8)?;
    let gen_dir_name = format!("gen-{}-{suffix}", std::process::id());
    let gen_dir = dir.join(&gen_dir_name);
    fs::DirBuilder::new().mode(0o700).create(&gen_dir)?;
    let cert_pem_path = gen_dir.join("cert.pem");
    let key_pem_path = gen_dir.join("key.pem");

    let tmp_link = dir.join(format!(".current-tmp-{}-{suffix}", std::process::id()));

    let result: Result<(), TlsIdentityError> =
        generate_into(&gen_dir, common_name).and_then(|()| {

            if fs::symlink_metadata(&current_link).is_ok_and(|m| m.is_dir()) {
                let _ = fs::remove_dir_all(&current_link);
            }
            let _ = fs::remove_file(&tmp_link);
            std::os::unix::fs::symlink(&gen_dir_name, &tmp_link)?;
            fs::rename(&tmp_link, &current_link).map_err(TlsIdentityError::Io)
        });

    match result {
        Ok(()) => Ok(TlsIdentity {
            cert_pem_path,
            key_pem_path,
        }),
        Err(e) => {

            let _ = fs::remove_dir_all(&gen_dir);
            let _ = fs::remove_file(&tmp_link);
            Err(e)
        }
    }
}

fn resolve_current(dir: &Path, current_link: &Path) -> Option<PathBuf> {
    let target = fs::read_link(current_link).ok()?;
    Some(dir.join(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fossh-admin-tls-identity-test-{name}-{}-{}",
            std::process::id(),
            random_hex_suffix(4).unwrap()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn first_call_generates_a_real_certificate_and_key() {
        let dir = scratch_dir("fresh");
        let id = ensure_identity(&dir, "fossh-admin-test-fresh").unwrap();
        assert!(id.cert_pem_path.is_file());
        assert!(id.key_pem_path.is_file());
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("-----END CERTIFICATE-----"));
        let mode = fs::metadata(&id.key_pem_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "dir itself must be 0700, not umask-dependent"
        );
        let gen_dir_mode = fs::metadata(id.cert_pem_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            gen_dir_mode, 0o700,
            "the generation directory must be 0700, not umask-dependent"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn second_call_returns_the_identical_certificate() {
        let dir = scratch_dir("stable");
        let first = ensure_identity(&dir, "fossh-admin-test-a").unwrap();
        let first_cert = read(&first.cert_pem_path);
        let second = ensure_identity(&dir, "a-different-cn-should-not-matter").unwrap();
        assert_eq!(first_cert, read(&second.cert_pem_path));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_different_directories_get_two_different_certificates() {
        let dir_a = scratch_dir("dir-a");
        let dir_b = scratch_dir("dir-b");
        let a = ensure_identity(&dir_a, "fossh-admin-test-a2").unwrap();
        let b = ensure_identity(&dir_b, "fossh-admin-test-b2").unwrap();
        assert_ne!(read(&a.cert_pem_path), read(&b.cert_pem_path));
        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }

    fn seed_leftover(dir: &Path, cert_bytes: &[u8], key_bytes: &[u8]) {
        let gen_dir = dir.join("gen-fake-leftover");
        fs::create_dir_all(&gen_dir).unwrap();
        fs::write(gen_dir.join("cert.pem"), cert_bytes).unwrap();
        fs::write(gen_dir.join("key.pem"), key_bytes).unwrap();
        std::os::unix::fs::symlink("gen-fake-leftover", dir.join("current")).unwrap();
    }

    #[test]
    fn a_corrupt_leftover_is_regenerated_not_trusted() {
        let dir = scratch_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();
        seed_leftover(&dir, b"not a certificate", b"not a key");
        let id = ensure_identity(&dir, "fossh-admin-test-recovers").unwrap();
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert_ne!(cert, "not a certificate");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_expired_certificate_is_not_trusted() {
        let dir = scratch_dir("expired");
        fs::create_dir_all(&dir).unwrap();
        let gen_dir = dir.join("gen-fake-expired");
        fs::create_dir_all(&gen_dir).unwrap();
        let cert_path = gen_dir.join("cert.pem");
        let key_path = gen_dir.join("key.pem");
        let status = Command::new(OPENSSL_PATH)
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
            ])
            .args([
                "-not_before",
                "20200101000000Z",
                "-not_after",
                "20210101000000Z",
            ])
            .arg("-keyout")
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .args(["-subj", "/CN=already-expired"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "test setup: generating an expired cert must itself succeed"
        );
        let expired_bytes = read(&cert_path);
        std::os::unix::fs::symlink("gen-fake-expired", dir.join("current")).unwrap();

        let id = ensure_identity(&dir, "fossh-admin-test-replaces-expired").unwrap();
        assert_ne!(read(&id.cert_pem_path), expired_bytes);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_leftover_real_directory_at_current_is_recovered_from() {

        let dir = scratch_dir("real-dir-leftover");
        let current = dir.join("current");
        fs::create_dir_all(&current).unwrap();
        fs::write(current.join("cert.pem"), b"not a certificate").unwrap();
        fs::write(current.join("key.pem"), b"not a key").unwrap();
        let id = ensure_identity(&dir, "fossh-admin-test-real-dir-leftover").unwrap();
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn common_name_with_dn_metacharacters_is_rejected() {
        for bad in [
            "innocuous/O=Evil Corp/OU=Fake Unit",
            "has=equals",
            "",
            &"a".repeat(65),
        ] {
            let dir = scratch_dir("badcn");
            assert!(
                matches!(
                    ensure_identity(&dir, bad),
                    Err(TlsIdentityError::InvalidCommonName(_))
                ),
                "should reject common_name {bad:?}"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    fn is_matched_pair(cert_path: &Path, key_path: &Path) -> bool {
        let cert_pubkey = Command::new(OPENSSL_PATH)
            .args(["x509", "-in"])
            .arg(cert_path)
            .args(["-noout", "-pubkey"])
            .output()
            .unwrap();
        let key_pubkey = Command::new(OPENSSL_PATH)
            .args(["pkey", "-in"])
            .arg(key_path)
            .args(["-pubout"])
            .output()
            .unwrap();
        cert_pubkey.status.success()
            && key_pubkey.status.success()
            && cert_pubkey.stdout == key_pubkey.stdout
    }

    #[test]
    fn concurrent_first_callers_all_get_a_stable_matched_pair_each() {

        let dir = std::sync::Arc::new(scratch_dir("concurrent"));
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let dir = std::sync::Arc::clone(&dir);
                std::thread::spawn(move || ensure_identity(&dir, "fossh-admin-test-race").unwrap())
            })
            .collect();
        let ids: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, id) in ids.iter().enumerate() {
            assert!(
                cert_is_valid(&id.cert_pem_path),
                "racer {i}'s own cert must be valid"
            );
            assert!(
                key_is_valid(&id.key_pem_path),
                "racer {i}'s own key must be valid"
            );
            assert!(
                is_matched_pair(&id.cert_pem_path, &id.key_pem_path),
                "racer {i}'s own returned cert and key must be a genuinely matched pair, \
                 not torn from two different generations"
            );
        }

        let settled = ensure_identity(&dir, "fossh-admin-test-race-settled").unwrap();
        assert!(is_matched_pair(
            &settled.cert_pem_path,
            &settled.key_pem_path
        ));
        fs::remove_dir_all(&*dir).ok();
    }

    #[test]
    fn a_reader_polling_across_a_republish_never_observes_a_torn_pair() {

        let dir = std::sync::Arc::new(scratch_dir("torn-read"));
        ensure_identity(&dir, "fossh-admin-test-torn-read-seed").unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let republisher = {
            let dir = std::sync::Arc::clone(&dir);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {

                    let _ = fs::remove_file(dir.join("current"));
                    let _ = ensure_identity(&dir, "fossh-admin-test-torn-read-republish");
                }
            })
        };

        let mut observed_any = false;
        for _ in 0..200 {
            if let Ok(id) = ensure_identity(&dir, "fossh-admin-test-torn-read-observer") {
                observed_any = true;
                assert!(
                    is_matched_pair(&id.cert_pem_path, &id.key_pem_path),
                    "an observer must never see a torn cert/key pair, even mid-republish"
                );
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        republisher.join().unwrap();
        assert!(
            observed_any,
            "test setup: the observer loop should have succeeded at least once"
        );
        fs::remove_dir_all(&*dir).ok();
    }
}
