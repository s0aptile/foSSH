//! §8 authentication: Ed25519-signed requests (server-side integrations)
//! and bearer-token mode (browser-beacon usage, where signing is
//! impossible).
//!
//! **Signed mode is asymmetric, not HMAC (see DECISIONS.md, ADR-0015 and
//! its follow-up).** An earlier design signed with `site.key_hash` —
//! `BLAKE3(write_key)`, the same value stored server-side as the bearer
//! verifier — as a symmetric keyed-hash key. That was a pass-the-hash
//! flaw: the server has to hold `key_hash` in immediately usable form to
//! check bearer auth, so anyone who read that value (a stolen database, a
//! leaked `site_cache` JSON file) could compute valid signatures without
//! ever having seen `write_key` itself. Ed25519 fixes this structurally:
//! `sites.sign_pubkey` is a public key, useless for producing a
//! signature, only for checking one. The matching private key lives only
//! on the client, generated once and never transmitted or stored
//! server-side.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use ed25519_dalek::{Signer, Verifier};
use subtle::ConstantTimeEq;

use crate::IngestError;

pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// §8: `canonical = method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ BLAKE3(body)`
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

/// Convenience wrapper for the actual wire format: `X-FoSSH-Sig` arrives
/// as base32 text, not raw bytes, and the verifying key as stored
/// (`site.sign_pubkey`) is raw 32 bytes, not `ed25519_dalek`'s own type.
/// A malformed header or a pubkey that isn't a valid compressed Edwards
/// point is just "not a match" — never a distinct error path an attacker
/// could use to distinguish one failure mode from another (S2: fail
/// closed, uniformly).
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

/// §8: "Reject if `|now − ts| > 300`."
///
/// `ts` is whatever the client put in the timestamp header, parsed as an
/// `i64` and checked here before any site lookup or signature check — so
/// `i64::MIN` reaches this function from an unauthenticated request with
/// no valid key. `now - ts` then overflows, and `.abs()` on `i64::MIN`
/// overflows too.
///
/// In the shipped release profile that wrapped rather than panicked, and
/// the wrapped magnitude happened to land outside the 300-second window,
/// so the request was still rejected. Correct by luck. In any build with
/// `overflow-checks` on — every `cargo test` and `cargo build`, and any
/// release build hardened the usual way — the same request panics, and
/// this workspace ships `panic = "abort"`, which for the persistent
/// `fossh-fcgi` transport means one crafted request takes down the
/// process serving every site on it.
///
/// Saturating arithmetic gives the same answer as the ideal-integer
/// version for every input, and the same answer in every profile.
pub fn timestamp_in_window(ts: i64, now: i64) -> bool {
    now.saturating_sub(ts).saturating_abs() <= TIMESTAMP_WINDOW_SECS
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
        file.lock()?;
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
        assert!(!verify_signature_b32(&pubkey_bytes, &canonical, "MY")); // valid base32, wrong length
        assert!(!verify_signature_b32(&pubkey_bytes, &canonical, ""));
    }

    #[test]
    fn verify_signature_b32_rejects_a_pubkey_that_is_not_a_valid_point() {
        // All-0xFF is not a valid compressed Edwards point — must fail
        // closed (`VerifyingKey::from_bytes` returns `Err`), not panic.
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

    /// B-03 regression: with an asymmetric scheme, the value the server
    /// stores (`verifying_key.to_bytes()`, what a stolen `sites` table or
    /// `site_cache` JSON file would actually expose) is a public key —
    /// signing with it directly, the way the old BLAKE3-keyed-hash design
    /// let an attacker sign with `key_hash`, must be structurally
    /// impossible, not just prevented by convention.
    #[test]
    fn stolen_verifying_key_bytes_cannot_be_used_to_forge_a_signature() {
        let (signing_key, verifying_key) = keypair(7);
        let stolen_pubkey_bytes = verifying_key.to_bytes();
        drop(signing_key); // the attacker never had this — only the line above

        let forged_canonical =
            canonical_string("POST", "/e", 1_900_000_000, "attacker-nonce", b"{}");

        // The only "signing" operation an attacker holding just the public
        // key bytes could even attempt is treating them as if they were a
        // seed. That produces a self-consistent but *different* keypair —
        // its signature does not verify against the real, stolen pubkey.
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

    /// `ts` is client-controlled and reaches `timestamp_in_window`
    /// before any authentication, so these are reachable from an
    /// anonymous request. Under `overflow-checks` — which is on for
    /// this very test binary — the old `(now - ts).abs()` panicked on
    /// each of them.
    #[test]
    fn extreme_timestamps_are_rejected_without_overflowing() {
        let now = 1_700_000_000_i64;
        for ts in [i64::MIN, i64::MIN + 1, -i64::MAX, i64::MAX, i64::MAX - 1] {
            assert!(
                !timestamp_in_window(ts, now),
                "ts={ts} is nowhere near now={now} and must be rejected"
            );
        }
        // And the same from the other side, in case `now` is ever
        // sourced from something less trustworthy than the system clock.
        for now in [i64::MIN, i64::MAX] {
            assert!(!timestamp_in_window(1_700_000_000, now));
        }
        // Saturation must not create a false accept: two extremes that
        // are genuinely far apart stay far apart.
        assert!(!timestamp_in_window(i64::MIN, i64::MAX));
        assert!(!timestamp_in_window(i64::MAX, i64::MIN));
        // ...and two that are genuinely equal stay equal.
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
