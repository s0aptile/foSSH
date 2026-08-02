//! §8 authentication: HMAC-signed requests (server-side integrations) and
//! bearer-token mode (browser-beacon usage, where signing is impossible).
//!
//! **Signing-key resolution (see DECISIONS.md for the full ADR).** §8
//! states both "only `BLAKE3(key)` is stored" *and* `sig =
//! BLAKE3-keyed(write_key, canonical)` — read completely literally, those
//! two sentences make signed-mode verification impossible: a keyed hash
//! can only be verified with the same key it was made with, and a
//! one-way hash of that key isn't the key. The resolution used here,
//! throughout this crate: the value everyone calls `key_hash` —
//! `BLAKE3(write_key)`, computed once by the client from the write key
//! `fossh site create` displayed, and stored server-side in
//! `sites.key_hash` — *is* the actual signing key for the keyed hash, not
//! a hash the server would need to reverse. The client signs with
//! `BLAKE3(write_key)`; the server verifies with the identical
//! `sites.key_hash` it already has on file. Nobody transmits or stores
//! the original 32 random bytes past the moment `fossh site create`
//! prints them. This is the same shape as any system that stores
//! `hash(secret)` and treats the hash itself as the live verifier — it's
//! sound because `key_hash` is exactly as secret as `write_key` was
//! (both require having seen the original credential; `BLAKE3` isn't
//! invertible), it just isn't the literal bytes the operator copy-pastes.
//!
//! Functions below take `signing_key: &[u8; 32]` rather than `write_key`
//! to name this precisely: callers pass `site.key_hash`, not a raw key.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use subtle::ConstantTimeEq;

use crate::IngestError;

pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// §8: `canonical = method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ BLAKE3(body)`
pub fn canonical_string(method: &str, path: &str, ts: i64, nonce: &str, body: &[u8]) -> String {
    let body_hash = blake3::hash(body);
    format!("{method}\n{path}\n{ts}\n{nonce}\n{}", body_hash.to_hex())
}

/// §8: `sig = BLAKE3-keyed(signing_key, canonical)` — see the module doc
/// comment for what `signing_key` actually is (`site.key_hash`).
pub fn sign(signing_key: &[u8; 32], canonical: &str) -> [u8; 32] {
    *blake3::keyed_hash(signing_key, canonical.as_bytes()).as_bytes()
}

/// Constant-time signature check (S5: `subtle::ConstantTimeEq`).
pub fn verify_signature(signing_key: &[u8; 32], canonical: &str, presented_sig: &[u8; 32]) -> bool {
    sign(signing_key, canonical).ct_eq(presented_sig).into()
}

/// Convenience wrapper for the actual wire format: `X-FoSSH-Sig` arrives
/// as base32 text, not raw bytes. A malformed (wrong-length or
/// non-base32) header is just "not a match" — never a distinct error path
/// an attacker could use to distinguish "bad encoding" from "bad
/// signature" (S2: fail closed, uniformly).
pub fn verify_signature_b32(
    signing_key: &[u8; 32],
    canonical: &str,
    presented_sig_b32: &str,
) -> bool {
    match fossh_core::base32::decode(presented_sig_b32) {
        Some(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(sig) => verify_signature(signing_key, canonical, &sig),
            Err(_) => false,
        },
        None => false,
    }
}

/// §8: "Reject if `|now − ts| > 300`."
pub fn timestamp_in_window(ts: i64, now: i64) -> bool {
    (now - ts).abs() <= TIMESTAMP_WINDOW_SECS
}

/// Bearer-mode key check (§8's "Bearer-only mode... permitted for browser-
/// beacon usage where signing is impossible"): the presented key's
/// `BLAKE3` hash must match the site's stored `key_hash`, in constant time.
///
/// Takes the raw 32-byte write key, *not* the `fossh_<slug>_<base32>`
/// wire token — §8 stores `BLAKE3(key)` where `key` is those 32 bytes;
/// hashing the formatted token string (prefix and base32 encoding
/// included) would hash something else entirely and never match what
/// `fossh site create` computed. Callers holding the wire token need to
/// strip the `fossh_<slug>_` prefix and base32-decode the remainder
/// first — see `parse_write_key_token` below.
pub fn verify_bearer_key(presented_key: &[u8; 32], stored_key_hash: &[u8; 32]) -> bool {
    blake3::hash(presented_key)
        .as_bytes()
        .ct_eq(stored_key_hash)
        .into()
}

/// Splits a write-key token shaped `fossh_<slug>_<base32>` (§8) into the
/// slug and the raw 32-byte key — decoding the base32 portion, *not*
/// returning it as text. Shared by `fossh-cgi` (bearer-mode `Authorization`
/// header) and `fossh-ffi` (`fossh_set_key`, §11) — both need the exact
/// same parse, and getting it wrong (comparing `BLAKE3` of the base32
/// string, or of the whole token, instead of the decoded bytes) means
/// authentication can never match what `fossh site create` stored (see
/// `verify_bearer_key`'s doc comment). Slugs may themselves contain `_`,
/// so this splits on the *last* `_` rather than the first.
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
const SLOT_BYTES: usize = 16; // 8-byte fingerprint + 8-byte expiry (i64, LE)

/// §8's "nonce replay cache: mmap'd ring buffer of 64-bit nonce hashes,
/// 600s TTL, per site" — implemented as a fixed-size, direct-mapped
/// (single slot per hash bucket) file instead of an mmap'd ring buffer;
/// see the crate-level doc comment for why (S1 forbids `unsafe` here, and
/// mapping a file requires it).
///
/// `NONCE_CACHE_SLOTS = 65_536` (a 1 MiB file per site) is a capacity
/// choice, not a correctness one: at S10's default rate limit (60/s,
/// burst 600), a 600s TTL window holds on the order of 10⁴–10⁵ live
/// nonces, so collisions are possible under sustained high traffic. A
/// collision only *reduces* replay protection (an older nonce's slot gets
/// reused early) — it never produces a false "replay" rejection of a
/// distinct nonce, because the full 64-bit fingerprint is compared before
/// a hit is reported, not just the slot index. Best-effort by design, like
/// nearly every bounded-memory replay cache.
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

    /// Returns `true` if `(site_id, nonce)` was already recorded within
    /// its TTL (→ caller must reject the request as a replay). Always
    /// records the pair for next time, whether or not this call reports
    /// a replay.
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
        let needed_len = NONCE_CACHE_SLOTS * SLOT_BYTES as u64;
        if file.metadata()?.len() < needed_len {
            file.set_len(needed_len)?; // sparse-extend; unwritten slots read as zero
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

    #[test]
    fn sign_and_verify_round_trip() {
        let key = [7u8; 32];
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig = sign(&key, &canonical);
        assert!(verify_signature(&key, &canonical, &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig = sign(&[7u8; 32], &canonical);
        assert!(!verify_signature(&[8u8; 32], &canonical, &sig));
    }

    #[test]
    fn verify_signature_b32_round_trips_the_wire_format() {
        let key = [7u8; 32];
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        let sig_b32 = fossh_core::base32::encode(&sign(&key, &canonical));
        assert!(verify_signature_b32(&key, &canonical, &sig_b32));
    }

    #[test]
    fn verify_signature_b32_rejects_malformed_header_without_panicking() {
        let key = [7u8; 32];
        let canonical = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}");
        assert!(!verify_signature_b32(
            &key,
            &canonical,
            "not-valid-base32!!!"
        ));
        assert!(!verify_signature_b32(&key, &canonical, "MY")); // valid base32, wrong length
        assert!(!verify_signature_b32(&key, &canonical, ""));
    }

    #[test]
    fn verify_rejects_tampered_canonical() {
        let key = [7u8; 32];
        let sig = sign(
            &key,
            &canonical_string("POST", "/e", 1_700_000_000, "n1", b"{}"),
        );
        let tampered = canonical_string("POST", "/e", 1_700_000_000, "n1", b"{\"x\":1}");
        assert!(!verify_signature(&key, &tampered, &sig));
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
}
