//! P2 — rotating-salt visitor hashing:
//! `visitor_id = truncate64(BLAKE3_keyed(daily_salt, client_ip ‖ ua_string ‖ site_id))`
//!
//! `daily_salt` is the BLAKE3 key (`keyed_hash`, not `hash` of a
//! `salt ‖ message` concatenation) — the same construction
//! `fossh_ingest::auth::sign` already uses for the per-site write-key
//! MAC, for the same reason: `keyed_hash` is BLAKE3's own documented,
//! domain-separated API for exactly this "secret + message" shape,
//! rather than relying on prefix-hashing being safe by coincidence.
//!
//! This module only computes the hash. Salt *generation*, *rotation at UTC
//! midnight*, and *tmpfs persistence with `shred` on rotation* are process
//! lifecycle concerns that need a filesystem and a clock — they live in
//! `fossh-ingest`, which owns a `Zeroizing<[u8; 32]>` salt and calls into
//! this pure function once per event.

use zeroize::Zeroizing;

use crate::types::SiteId;

/// Daily salt length in bytes (P2: "32 random bytes").
pub const SALT_LEN: usize = 32;

/// Computes the day-scoped visitor hash.
///
/// `daily_salt`, `client_ip`, and `ua_string` are borrowed only for the
/// duration of this call; this function's own intermediate concatenation
/// buffer is held in `Zeroizing` and wiped on return. The *caller* remains
/// responsible for zeroizing its own copies of `client_ip` / `ua_string`
/// immediately after this call returns, per P2 ("raw inputs are zeroized
/// immediately after hashing") and §11 ("consumed, hashed/bucketed, and
/// zeroized within the call") — this function cannot zero memory it does
/// not own.
pub fn hash_visitor(
    daily_salt: &[u8; SALT_LEN],
    client_ip: &str,
    ua_string: &str,
    site_id: SiteId,
) -> u64 {
    let mut input = Zeroizing::new(Vec::with_capacity(
        client_ip.len() + ua_string.len() + 4,
    ));
    input.extend_from_slice(client_ip.as_bytes());
    input.extend_from_slice(ua_string.as_bytes());
    input.extend_from_slice(&site_id.get().to_be_bytes());

    let digest = blake3::keyed_hash(daily_salt, &input);
    let bytes = digest.as_bytes();
    u64::from_be_bytes(bytes[0..8].try_into().expect("blake3 output is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(byte: u8) -> [u8; SALT_LEN] {
        [byte; SALT_LEN]
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let a = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        let b = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_changes_hash() {
        let a = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        let b = hash_visitor(&salt(2), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        assert_ne!(
            a, b,
            "rotating the salt must change the visitor hash — that's the whole point of P2"
        );
    }

    #[test]
    fn different_ip_changes_hash() {
        let a = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        let b = hash_visitor(&salt(1), "203.0.113.8", "Mozilla/5.0 Test", SiteId::new(42));
        assert_ne!(a, b);
    }

    #[test]
    fn different_ua_changes_hash() {
        let a = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        let b = hash_visitor(
            &salt(1),
            "203.0.113.7",
            "Mozilla/5.0 Other",
            SiteId::new(42),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_site_changes_hash() {
        let a = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(42));
        let b = hash_visitor(&salt(1), "203.0.113.7", "Mozilla/5.0 Test", SiteId::new(43));
        assert_ne!(a, b, "hashes must not be linkable across sites");
    }

    #[test]
    fn empty_ip_and_ua_do_not_panic() {
        let _ = hash_visitor(&salt(1), "", "", SiteId::new(1));
    }

    #[test]
    fn same_salt_and_site_but_no_collisions_across_a_sample() {
        // Not a formal proof of collision-resistance — just a sanity check
        // that varying the IP octet actually spreads across the output.
        let mut hashes = std::collections::HashSet::new();
        for i in 0..=255u8 {
            let ip = format!("10.0.0.{i}");
            hashes.insert(hash_visitor(&salt(9), &ip, "ua", SiteId::new(1)));
        }
        assert_eq!(
            hashes.len(),
            256,
            "expected all 256 addresses to hash distinctly"
        );
    }
}
