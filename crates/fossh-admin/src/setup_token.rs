use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use fossh_ingest::random::read_random_bytes;

#[derive(Debug)]
pub enum SetupTokenError {
    Random(String),
    Io(std::io::Error),
}

impl std::fmt::Display for SetupTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Random(e) => write!(f, "reading random bytes: {e}"),
            Self::Io(e) => write!(f, "setup-token file I/O: {e}"),
        }
    }
}

impl std::error::Error for SetupTokenError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenHash(pub [u8; 32]);

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub struct GeneratedToken {
    pub plaintext: Zeroizing<String>,
    pub hash: TokenHash,
}

pub fn generate() -> Result<GeneratedToken, SetupTokenError> {
    let raw = read_random_bytes(32).map_err(|e| SetupTokenError::Random(e.to_string()))?;
    let plaintext = fossh_core::base32::encode(&raw);
    let hash = TokenHash(sha256(plaintext.as_bytes()));
    Ok(GeneratedToken {
        plaintext: Zeroizing::new(plaintext),
        hash,
    })
}

pub fn verify(submitted: &str, stored: TokenHash) -> bool {
    let submitted_hash = sha256(submitted.as_bytes());
    submitted_hash.ct_eq(&stored.0).into()
}

pub fn hash_of(plaintext: &str) -> TokenHash {
    TokenHash(sha256(plaintext.as_bytes()))
}

pub fn write_token_file(path: &Path, plaintext: &str) -> Result<(), SetupTokenError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut file = opts.open(path).map_err(SetupTokenError::Io)?;
    file.write_all(plaintext.as_bytes())
        .map_err(SetupTokenError::Io)?;
    file.sync_all().map_err(SetupTokenError::Io)?;
    Ok(())
}

pub fn burn(
    token_path: &Path,
    invalidate_hash: impl FnOnce() -> Result<(), SetupTokenError>,
) -> Result<(), SetupTokenError> {
    invalidate_hash()?;
    match fs::remove_file(token_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SetupTokenError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fossh-admin-setup-token-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn generated_token_round_trips_through_verify() {
        let generated = generate().unwrap();
        assert!(verify(&generated.plaintext, generated.hash));
    }

    #[test]
    fn wrong_token_does_not_verify() {
        let generated = generate().unwrap();
        assert!(!verify("not-the-right-token", generated.hash));
    }

    #[test]
    fn hash_of_reproduces_the_same_hash_generate_computed() {
        let generated = generate().unwrap();
        assert_eq!(hash_of(&generated.plaintext), generated.hash);
        assert!(verify(&generated.plaintext, hash_of(&generated.plaintext)));
    }

    #[test]
    fn two_generated_tokens_are_different() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(*a.plaintext, *b.plaintext);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn write_token_file_creates_with_0600() {
        let path = scratch_path("perms");
        let _ = fs::remove_file(&path);
        write_token_file(&path, "sometoken").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn write_token_file_refuses_to_overwrite_an_existing_file() {
        let path = scratch_path("no-overwrite");
        let _ = fs::remove_file(&path);
        write_token_file(&path, "first").unwrap();
        let result = write_token_file(&path, "second");
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn burn_invalidates_hash_and_deletes_the_file() {
        let path = scratch_path("burn-happy");
        let _ = fs::remove_file(&path);
        write_token_file(&path, "sometoken").unwrap();
        let invalidated = AtomicBool::new(false);

        burn(&path, || {
            invalidated.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();

        assert!(invalidated.load(Ordering::SeqCst));
        assert!(!path.exists());
    }

    #[test]
    fn burn_is_idempotent_if_the_file_is_already_gone() {
        let path = scratch_path("burn-already-gone");
        let _ = fs::remove_file(&path);

        burn(&path, || Ok(())).unwrap();
    }

    #[test]
    fn burn_does_not_delete_the_file_if_hash_invalidation_fails() {
        let path = scratch_path("burn-invalidate-fails");
        let _ = fs::remove_file(&path);
        write_token_file(&path, "sometoken").unwrap();

        let result = burn(&path, || {
            Err(SetupTokenError::Io(std::io::Error::other(
                "simulated failure",
            )))
        });

        assert!(result.is_err());
        assert!(
            path.exists(),
            "the plaintext file must survive a failed hash invalidation — \
             burning it first would strand a token whose hash is still live"
        );
        fs::remove_file(&path).ok();
    }
}
