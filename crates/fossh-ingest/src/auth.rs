use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use ed25519_dalek::{Signer, Verifier};
use subtle::ConstantTimeEq;

use crate::IngestError;

pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

pub fn canonical_string(method: &str, path: &str, ts: i64, nonce: &str, body: &[u8]) -> String {
    let body_hash = blake3::hash(body);
    format!("{method}\n{path}\n{ts}\n{nonce}\n{}", body_hash.to_hex())
}

pub fn sign(signing_key: &ed25519_dalek::SigningKey, canonical: &str) -> ed25519_dalek::Signature {
    signing_key.sign(canonical.as_bytes())
}

pub fn verify_signature(
    verifying_key: &ed25519_dalek::VerifyingKey,
    canonical: &str,
    presented_sig: &ed25519_dalek::Signature,
) -> bool {
    verifying_key
        .verify(canonical.as_bytes(), presented_sig)
        .is_ok()
}

pub fn verify_signature_b32(
    verifying_key_bytes: &[u8; 32],
    canonical: &str,
    presented_sig_b32: &str,
) -> bool {
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes) else {
        return false;
    };
    let Some(bytes) = fossh_core::base32::decode(presented_sig_b32) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
        return false;
    };
    verify_signature(
        &verifying_key,
        canonical,
        &ed25519_dalek::Signature::from_bytes(&sig_bytes),
    )
}

pub fn timestamp_in_window(ts: i64, now: i64) -> bool {
    now.saturating_sub(ts).saturating_abs() <= TIMESTAMP_WINDOW_SECS
}

pub fn verify_bearer_key(presented_key: &[u8; 32], stored_key_hash: &[u8; 32]) -> bool {
    blake3::hash(presented_key)
        .as_bytes()
        .ct_eq(stored_key_hash)
        .into()
}

pub fn parse_write_key_token(token: &str) -> Option<(&str, [u8; 32])> {
    let rest = token.strip_prefix("fossh_")?;
    let (slug, key_b32) = rest.rsplit_once('_')?;
    if slug.is_empty() {
        return None;
    }
    let key_bytes = fossh_core::base32::decode(key_b32)?;
    let key: [u8; 32] = key_bytes.try_into().ok()?;
    Some((slug, key))
}

const NONCE_CACHE_SLOTS: u64 = 65_536;
const NONCE_CACHE_TTL_SECS: i64 = 600;
const SLOT_BYTES: usize = 16;

pub struct NonceCache {
    path: PathBuf,
}

impl NonceCache {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn fingerprint(site_id: u32, nonce: &str) -> u64 {
        let mut buf = Vec::with_capacity(4 + nonce.len());
        buf.extend_from_slice(&site_id.to_be_bytes());
        buf.extend_from_slice(nonce.as_bytes());
        let hash = blake3::hash(&buf);
        u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("8 bytes"))
    }

    pub fn check_and_record(
        &self,
        site_id: u32,
        nonce: &str,
        now: i64,
    ) -> Result<bool, IngestError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let fingerprint = Self::fingerprint(site_id, nonce);
        let slot = fingerprint % NONCE_CACHE_SLOTS;
        let offset = slot * SLOT_BYTES as u64;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        file.lock()?;
        let needed_len = NONCE_CACHE_SLOTS * SLOT_BYTES as u64;
        if file.metadata()?.len() < needed_len {
            file.set_len(needed_len)?;
        }

        file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; SLOT_BYTES];
        file.read_exact(&mut buf)?;
        let stored_fp = u64::from_le_bytes(buf[0..8].try_into().expect("8 bytes"));
        let stored_exp = i64::from_le_bytes(buf[8..16].try_into().expect("8 bytes"));

        let is_replay = stored_fp == fingerprint && stored_exp > now;

        let mut out = [0u8; SLOT_BYTES];
        out[0..8].copy_from_slice(&fingerprint.to_le_bytes());
        out[8..16].copy_from_slice(&(now + NONCE_CACHE_TTL_SECS).to_le_bytes());
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&out)?;

        Ok(is_replay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_string_matches_the_spec_shape() {
        let s = canonical_string("POST", "/e", 1_700_000_000, "abc123", b"{}");
        let parts: Vec<&str> = s.split('\n').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "POST");
        assert_eq!(parts[1], "/e");
        assert_eq!(parts[2], "1700000000");
        assert_eq!(parts[3], "abc123");
        assert_eq!(parts[4].len(), 64, "blake3 hex digest is 64 chars");
    }

    fn keypair(seed: u8) -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (signing_key, verifying_key) = keypair(7);
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig = sign(&signing_key, &canonical);
        assert!(verify_signature(&verifying_key, &canonical, &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (signing_key, _) = keypair(7);
        let (_, wrong_verifying_key) = keypair(8);
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig = sign(&signing_key, &canonical);
        assert!(!verify_signature(&wrong_verifying_key, &canonical, &sig));
    }

    #[test]
    fn verify_signature_b32_round_trips_the_wire_format() {
        let (signing_key, verifying_key) = keypair(7);
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig_b32 = fossh_core::base32::encode(&sign(&signing_key, &canonical).to_bytes());
        assert!(verify_signature_b32(
            &verifying_key.to_bytes(),
            &canonical,
            &sig_b32
        ));
    }

    #[test]
    fn verify_signature_b32_rejects_malformed_header_without_panicking() {
        let (_, verifying_key) = keypair(7);
        let pubkey_bytes = verifying_key.to_bytes();
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        assert!(!verify_signature_b32(
            &pubkey_bytes,
            &canonical,
            "not-valid-base32!!!"
        ));
        assert!(!verify_signature_b32(&pubkey_bytes, &canonical, "MY"));
        assert!(!verify_signature_b32(&pubkey_bytes, &canonical, ""));
    }

    #[test]
    fn verify_signature_b32_rejects_a_pubkey_that_is_not_a_valid_point() {

        let (signing_key, _) = keypair(7);
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig_b32 = fossh_core::base32::encode(&sign(&signing_key, &canonical).to_bytes());
        assert!(!verify_signature_b32(&[0xFFu8; 32], &canonical, &sig_b32));
    }

    #[test]
    fn verify_rejects_tampered_canonical() {
        let (signing_key, verifying_key) = keypair(7);
        let sig = sign(
            &signing_key,
            &canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}"),
        );
        let tampered = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{\"x\":1}");
        assert!(!verify_signature(&verifying_key, &tampered, &sig));
    }

    #[test]
    fn stolen_verifying_key_bytes_cannot_be_used_to_forge_a_signature() {
        let (signing_key, verifying_key) = keypair(7);
        let stolen_pubkey_bytes = verifying_key.to_bytes();
        drop(signing_key);

        let forged_canonical =
            canonical_string("POST", "/e", 1_900_000_000, "attacker-nonce", b"{}");

        let attacker_signing_key = ed25519_dalek::SigningKey::from_bytes(&stolen_pubkey_bytes);
        let forged_sig = sign(&attacker_signing_key, &forged_canonical);
        let forged_sig_b32 = fossh_core::base32::encode(&forged_sig.to_bytes());

        assert!(
            !verify_signature_b32(&stolen_pubkey_bytes, &forged_canonical, &forged_sig_b32),
            "a signature forged from stolen verifier bytes alone must not verify"
        );
    }

    #[test]
    fn timestamp_window_boundaries() {
        assert!(timestamp_in_window(1000, 1000));
        assert!(timestamp_in_window(1000, 1300));
        assert!(timestamp_in_window(1000, 700));
        assert!(!timestamp_in_window(1000, 1301));
        assert!(!timestamp_in_window(1000, 699));
    }

    #[test]
    fn extreme_timestamps_are_rejected_without_overflowing() {
        let now = 1_700_000_000_i64;
        for ts in [i64::MIN, i64::MIN + 1, -i64::MAX, i64::MAX, i64::MAX - 1] {
            assert!(
                !timestamp_in_window(ts, now),
                "ts={ts} is nowhere near now={now} and must be rejected"
            );
        }

        for now in [i64::MIN, i64::MAX] {
            assert!(!timestamp_in_window(1_700_000_000, now));
        }

        assert!(!timestamp_in_window(i64::MIN, i64::MAX));
        assert!(!timestamp_in_window(i64::MAX, i64::MIN));

        assert!(timestamp_in_window(i64::MAX, i64::MAX));
        assert!(timestamp_in_window(i64::MIN, i64::MIN));
    }

    #[test]
    fn bearer_key_verification() {
        let write_key = [7u8; 32];
        let hash = *blake3::hash(&write_key).as_bytes();
        assert!(verify_bearer_key(&write_key, &hash));
        assert!(!verify_bearer_key(&[8u8; 32], &hash));
    }

    #[test]
    fn parse_write_key_token_round_trips() {
        let raw_key = [0x42u8; 32];
        let token = format!("fossh_blog_{}", fossh_core::base32::encode(&raw_key));
        assert_eq!(parse_write_key_token(&token), Some(("blog", raw_key)));
    }

    #[test]
    fn parse_write_key_token_handles_underscores_in_slug() {
        let raw_key = [0x42u8; 32];
        let token = format!(
            "fossh_my_long_slug_{}",
            fossh_core::base32::encode(&raw_key)
        );
        assert_eq!(
            parse_write_key_token(&token),
            Some(("my_long_slug", raw_key))
        );
    }

    #[test]
    fn parse_write_key_token_rejects_malformed_tokens() {
        assert_eq!(parse_write_key_token("not-a-fossh-key"), None);
        assert_eq!(parse_write_key_token("fossh_"), None);
        assert_eq!(parse_write_key_token("fossh_onlyoneseg"), None);
        assert_eq!(parse_write_key_token("fossh_blog_notbase32!!!"), None);
        assert_eq!(
            parse_write_key_token("fossh_blog_MY"),
            None,
            "valid base32 but wrong decoded length"
        );
    }

    #[test]
    fn full_round_trip_matches_what_verify_bearer_key_expects() {
        let raw_key = [0xABu8; 32];
        let stored_hash = *blake3::hash(&raw_key).as_bytes();
        let token = format!("fossh_blog_{}", fossh_core::base32::encode(&raw_key));

        let (slug, presented_key) = parse_write_key_token(&token).unwrap();
        assert_eq!(slug, "blog");
        assert!(verify_bearer_key(&presented_key, &stored_hash));
    }

    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fossh-nonce-test-{name}-{}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn fresh_nonce_is_not_a_replay() {
        let path = scratch_path("fresh");
        let cache = NonceCache::new(path.clone());
        assert!(
            !cache
                .check_and_record(1, "unique-nonce-1", 1_700_000_000)
                .unwrap()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn repeated_nonce_within_ttl_is_a_replay() {
        let path = scratch_path("replay");
        let cache = NonceCache::new(path.clone());
        assert!(!cache.check_and_record(1, "n", 1_700_000_000).unwrap());
        assert!(
            cache.check_and_record(1, "n", 1_700_000_100).unwrap(),
            "same nonce within TTL must replay"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn same_nonce_different_site_is_not_a_replay() {
        let path = scratch_path("diff-site");
        let cache = NonceCache::new(path.clone());
        assert!(!cache.check_and_record(1, "n", 1_700_000_000).unwrap());
        assert!(
            !cache.check_and_record(2, "n", 1_700_000_000).unwrap(),
            "nonces are scoped per site"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn nonce_after_ttl_expiry_is_not_a_replay() {
        let path = scratch_path("expired");
        let cache = NonceCache::new(path.clone());
        assert!(!cache.check_and_record(1, "n", 1_700_000_000).unwrap());
        let after_ttl = 1_700_000_000 + NONCE_CACHE_TTL_SECS + 1;
        assert!(
            !cache.check_and_record(1, "n", after_ttl).unwrap(),
            "expired nonce is not a replay"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn two_simultaneous_identical_requests_produce_exactly_one_accept_one_replay() {
        for attempt in 0..200u32 {
            let path = scratch_path(&format!("race-{attempt}"));
            let cache_a = std::sync::Arc::new(NonceCache::new(path.clone()));
            let cache_b = std::sync::Arc::clone(&cache_a);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let barrier_b = std::sync::Arc::clone(&barrier);

            let t_b = std::thread::spawn(move || {
                barrier_b.wait();
                cache_b.check_and_record(1, "same-nonce", 1_700_000_000)
            });

            barrier.wait();
            let result_a = cache_a.check_and_record(1, "same-nonce", 1_700_000_000);
            let result_b = t_b.join().unwrap();

            let a = result_a.unwrap();
            let b = result_b.unwrap();
            assert_ne!(
                a, b,
                "attempt {attempt}: exactly one of two simultaneous identical requests \
                 must be accepted and the other rejected as a replay, got a={a} b={b}"
            );
            std::fs::remove_file(&path).ok();
        }
    }
}
