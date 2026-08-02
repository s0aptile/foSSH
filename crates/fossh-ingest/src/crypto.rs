//! §3.8: encrypts spool frames at rest with ChaCha20-Poly1305 (AEAD),
//! keyed by the per-install data-encryption key `fossh-admin::data_key`
//! manages. A fresh random 12-byte nonce is generated per call and
//! prepended to the returned ciphertext — safe to reuse the same key
//! across every frame this way, since each frame gets its own nonce
//! (the one thing that must never repeat under a given key for this
//! construction to hold).
//!
//! Deliberately not exposed as a general-purpose "encrypt anything"
//! API — `seal`/`open` exist for exactly one caller (`spool.rs`) and
//! one shape of data (an already-length-framed, CRC-guarded payload),
//! not as reusable crypto plumbing for anything else this crate might
//! grow later.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::IngestError;
use crate::random::read_random_bytes;

const NONCE_LEN: usize = 12;

/// Encrypts `plaintext` under `key`, returning `nonce ‖ ciphertext‖tag`.
/// Infallible in practice for this crate's inputs (a fixed 32-byte key,
/// a fresh 12-byte nonce, no associated data, plaintext far under
/// ChaCha20-Poly1305's ~64 GiB limit) — the one documented failure
/// mode `aead::Aead::encrypt` has doesn't apply here, so this panics
/// rather than threading a practically-unreachable error type through
/// every caller.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, IngestError> {
    let nonce_bytes = read_random_bytes(NONCE_LEN)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("ChaCha20-Poly1305 encryption cannot fail for a fixed-size key/nonce and no AAD");

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Inverse of `seal`. Any failure — too short to even contain a nonce,
/// wrong key, or a tampered/corrupt ciphertext — is reported as
/// `IngestError::CorruptFrame`: from the verifier's side, "the wrong
/// key" and "someone altered this" are indistinguishable and must fail
/// the same uniform way (S2), the same reasoning this codebase already
/// applies to signature verification elsewhere (`fossh_ingest::auth`).
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, IngestError> {
    if sealed.len() < NONCE_LEN {
        return Err(IngestError::CorruptFrame);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| IngestError::CorruptFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_round_trips() {
        let key = [7u8; 32];
        let plaintext = b"a spool frame's payload bytes";
        let sealed = seal(&key, plaintext).unwrap();
        assert_eq!(open(&key, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"").unwrap();
        assert_eq!(open(&key, &sealed).unwrap(), b"");
    }

    #[test]
    fn two_seals_of_the_same_plaintext_produce_different_ciphertext() {
        let key = [7u8; 32];
        let a = seal(&key, b"same plaintext").unwrap();
        let b = seal(&key, b"same plaintext").unwrap();
        assert_ne!(a, b, "a fresh random nonce per call must change the output");
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let sealed = seal(&[7u8; 32], b"secret").unwrap();
        assert!(matches!(
            open(&[8u8; 32], &sealed),
            Err(IngestError::CorruptFrame)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let key = [7u8; 32];
        let mut sealed = seal(&key, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(matches!(
            open(&key, &sealed),
            Err(IngestError::CorruptFrame)
        ));
    }

    #[test]
    fn truncated_below_nonce_length_fails_cleanly() {
        let key = [7u8; 32];
        assert!(matches!(
            open(&key, &[0u8; NONCE_LEN - 1]),
            Err(IngestError::CorruptFrame)
        ));
        assert!(matches!(open(&key, &[]), Err(IngestError::CorruptFrame)));
    }

    #[test]
    fn truncated_ciphertext_fails_cleanly() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"secret").unwrap();
        let truncated = &sealed[..sealed.len() - 3];
        assert!(matches!(
            open(&key, truncated),
            Err(IngestError::CorruptFrame)
        ));
    }
}
