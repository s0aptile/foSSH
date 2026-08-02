//! §2.6: the first-run setup-token model.
//!
//! On first start, the watchdog generates a random, high-entropy setup
//! token and writes the plaintext **once** to a fixed, discoverable
//! path (`/etc/fossh/setup-token`, mode 0600) — the user-friendly
//! half: no need to catch it in terminal/systemd scrollback during
//! install. Internally, only `SHA256(token)` is ever stored beyond
//! that one file — the secure half. Verification is a constant-time
//! comparison of `SHA256(submitted)` against the stored hash. The
//! moment setup completes successfully, the token file is deleted and
//! the stored hash is invalidated in the same operation — see `burn`
//! for the exact ordering and why it's deliberate, not incidental.
//!
//! `SHA256`, specifically, per §2.6's own wording — not `BLAKE3`, which
//! the rest of this project uses for everything else. Followed
//! literally rather than substituted for consistency: this is the one
//! place the chapter names a specific primitive, and there's no reason
//! to relitigate a locked decision just to make one file match the
//! others. `TokenHash` is a newtype specifically so a `BLAKE3` hash
//! from elsewhere in the codebase can never be passed here (or vice
//! versa) and compile.

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

/// `SHA256(token)` — 32 bytes, per §2.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenHash(pub [u8; 32]);

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A freshly generated token: the plaintext (zeroized on drop, meant
/// to be shown/written exactly once) and the hash that gets stored.
pub struct GeneratedToken {
    pub plaintext: Zeroizing<String>,
    pub hash: TokenHash,
}

/// Generates a new setup token: 32 random bytes, base32-encoded (same
/// alphabet as write keys, §8) so it's easy to read off a screen and
/// paste without ambiguous characters.
pub fn generate() -> Result<GeneratedToken, SetupTokenError> {
    let raw = read_random_bytes(32).map_err(|e| SetupTokenError::Random(e.to_string()))?;
    let plaintext = fossh_core::base32::encode(&raw);
    let hash = TokenHash(sha256(plaintext.as_bytes()));
    Ok(GeneratedToken {
        plaintext: Zeroizing::new(plaintext),
        hash,
    })
}

/// Constant-time check of a submitted token against the stored hash
/// (S5) — never compare the plaintext strings directly, and never
/// compare hashes with anything but a constant-time equality check.
pub fn verify(submitted: &str, stored: TokenHash) -> bool {
    let submitted_hash = sha256(submitted.as_bytes());
    submitted_hash.ct_eq(&stored.0).into()
}

/// Hashes a plaintext this caller already holds by some other means —
/// for a standalone TUI reloading a token file it didn't just generate
/// in this process (a real install's watchdog holds the hash directly
/// instead and never needs this; see `fossh-tui`'s module docs on
/// standalone/demo mode). Same primitive `generate()` uses internally,
/// exposed so a second, independent `sha256` implementation doesn't
/// need to exist anywhere just to re-derive the same hash.
pub fn hash_of(plaintext: &str) -> TokenHash {
    TokenHash(sha256(plaintext.as_bytes()))
}

/// Writes `plaintext` to `path` (0600, create-new) — the one time the
/// plaintext ever touches disk. Fails if a file already exists at
/// `path`, rather than silently overwriting a token a previous
/// incomplete run may still be relying on.
pub fn write_token_file(path: &Path, plaintext: &str) -> Result<(), SetupTokenError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut file = opts.open(path).map_err(SetupTokenError::Io)?;
    file.write_all(plaintext.as_bytes())
        .map_err(SetupTokenError::Io)?;
    file.sync_all().map_err(SetupTokenError::Io)?;
    Ok(())
}

/// §2.6: "The moment setup completes successfully, the token file is
/// deleted and the stored hash is invalidated in the same operation —
/// nothing remains that could be replayed even if the file had been
/// copied earlier." True atomicity across two separate pieces of
/// on-disk state (the hash store, the plaintext file) isn't available
/// in plain POSIX without a shared transaction log, so the ordering
/// here is deliberate rather than incidental: invalidate the hash
/// *first* (the security-critical half — once `invalidate_hash`
/// succeeds, `verify` can never succeed again for this token no matter
/// what happens next), then delete the plaintext file (cleanup; if
/// this step fails or the process dies before it runs, the leftover
/// file is inert text an operator can remove by hand, not a live
/// credential). The reverse order would leave the strictly worse
/// window: plaintext gone, but the hash still live and usable by
/// anyone holding a copy made before deletion.
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
        // File never created — burn must still succeed (a retry after
        // a partial failure must not itself fail on "file not found").
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
