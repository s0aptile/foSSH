//! Resolving the real visitor IP when `fossh-cgi` sits behind something
//! that legitimately relays on a visitor's behalf: a reverse proxy that
//! terminates the actual connection (nginx in front of `fcgiwrap`), or
//! a shared-hosting PHP script relaying server-side because it has no
//! other way to run foSSH itself (see `docs/INTEGRATION-php.md`'s
//! shared-hosting section, and `bindings/php/src/Client.php`'s HTTP
//! remote mode).
//!
//! Off by default: `REMOTE_ADDR` (the raw TCP peer the webserver
//! itself saw) is used as-is, exactly as before this existed. Trusting
//! `X-Forwarded-For` at all is an explicit, per-deployment operator
//! choice (`FOSSH_TRUST_FORWARDED_FOR`, read in `main.rs`).
//!
//! # Why this counts hops instead of taking the leftmost entry
//!
//! `X-Forwarded-For` is built left to right: each hop appends the peer
//! *it* saw. The leftmost entry is therefore the only one nobody
//! trustworthy wrote — it is whatever the original client sent, and a
//! client can send anything.
//!
//! That matters here more than it does for most software that reads
//! this header, because the value feeds three things at once:
//!
//! - the visitor hash (P2), so fabricated addresses become fabricated
//!   *visitors* — enough of them and a group that k-anonymity was
//!   suppressing crosses the threshold and gets published;
//! - `IpFailBucket`, the throttle on write-key guessing, so a fresh
//!   fake address per request means a fresh full allowance per request
//!   and the throttle never fires;
//! - country attribution.
//!
//! None of that is theoretical. `docs/INTEGRATION-php.md` records the
//! throttle bypass being run against the compiled binary: 40 wrong-key
//! requests, each with a different spoofed value, 40 × `401` and never
//! one `429`.
//!
//! Counting from the right fixes it structurally. With one trusted
//! proxy in front, the rightmost entry is the peer *that proxy* saw —
//! written by the proxy, not by the client — and no header the client
//! sends can displace it, because whatever they send only pushes their
//! own entries further left. `nginx`'s ordinary
//! `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`
//! produces exactly this shape. Two proxies, second from the right, and
//! so on; the operator states how many they actually have.
//!
//! An entry that is not a syntactically valid IP address is not used
//! either, so a client cannot smuggle something shaped like anything
//! else into a value that goes on to be hashed and stored.
//!
//! Note this only ever runs *after* `handler::authenticate` succeeds —
//! an unauthenticated request never reaches anywhere this value is
//! used for anything privacy-relevant.

use std::net::IpAddr;

/// How many hops in front of foSSH are under the operator's control.
///
/// `0` disables the header entirely (the default). `1` is one reverse
/// proxy or one relaying script; `2` is a CDN in front of that, and so
/// on. Deliberately small: an operator who thinks they have more than a
/// handful of trusted proxies has misunderstood the setting.
pub const TRUSTED_HOPS_MAX: u8 = 8;

/// `forwarded_for` is `HTTP_X_FORWARDED_FOR`'s raw value, if present.
///
/// With `trusted_hops == 0`, returns `remote_addr` unchanged. Otherwise
/// returns the entry `trusted_hops` places from the right — the address
/// seen by the outermost hop the operator vouches for — provided it
/// parses as an IP address. Anything else (header absent, too few
/// entries, entry unparseable) falls back to `remote_addr`.
///
/// Falling back rather than failing is deliberate: a request that
/// arrives without the expected header is far more likely to be an
/// operator whose proxy configuration does not match what they declared
/// than an attack, and `remote_addr` is always a real observed peer.
/// The cost of the fallback is degraded per-visitor uniqueness, not a
/// wrong or forgeable answer.
pub fn resolve_client_ip(
    remote_addr: &str,
    forwarded_for: Option<&str>,
    trusted_hops: u8,
) -> String {
    if trusted_hops == 0 {
        return remote_addr.to_string();
    }
    let Some(header) = forwarded_for else {
        return remote_addr.to_string();
    };

    let entries: Vec<&str> = header.split(',').map(str::trim).collect();
    let hops = usize::from(trusted_hops.min(TRUSTED_HOPS_MAX));
    // `entries.len() - hops`: with one trusted hop that is the last
    // entry, with two the second to last. Underflow means the header is
    // shorter than the declared topology, so there is no entry a
    // trusted hop wrote and nothing here is usable.
    let Some(index) = entries.len().checked_sub(hops) else {
        return remote_addr.to_string();
    };

    match entries.get(index).copied().map(strip_port) {
        Some(candidate) if candidate.parse::<IpAddr>().is_ok() => candidate.to_string(),
        _ => remote_addr.to_string(),
    }
}

/// Parses `FOSSH_TRUST_FORWARDED_FOR` into a hop count.
///
/// Lives here rather than in each binary so `fossh-cgi` and
/// `fossh-fcgi` cannot drift into reading the same variable two
/// different ways — which they were already one edit away from, having
/// each spelled the same `matches!` by hand.
///
/// `1` keeps meaning what it meant when this was a boolean: it now says
/// "one trusted proxy" instead of "trust the header", which is what
/// every deployment that set it actually has. Anything unrecognised is
/// `0` — an operator who typos this should lose the feature, not gain a
/// forgeable one.
pub fn trusted_hops_from_env(value: Option<&str>) -> u8 {
    match value.map(str::trim) {
        None | Some("") => 0,
        Some("true") | Some("yes") | Some("on") => 1,
        Some("false") | Some("no") | Some("off") => 0,
        Some(n) => n.parse::<u8>().unwrap_or(0).min(TRUSTED_HOPS_MAX),
    }
}

/// Some proxies append `addr:port` rather than a bare address, and
/// IPv6 literals arrive bracketed. Neither form parses as an `IpAddr`,
/// and dropping the request over that would push an operator toward
/// turning the whole check off.
fn strip_port(entry: &str) -> &str {
    if let Some(rest) = entry.strip_prefix('[') {
        // `[::1]:8080` or `[::1]` — everything up to the closing bracket.
        return rest.split(']').next().unwrap_or(rest);
    }
    // `1.2.3.4:80` has exactly one colon; a bare IPv6 literal has
    // several, and stripping at the first would corrupt it.
    match entry.split_once(':') {
        Some((head, tail)) if !tail.contains(':') => head,
        _ => entry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hops_always_uses_remote_addr_even_if_header_present() {
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1"), 0),
            "203.0.113.9"
        );
    }

    #[test]
    fn trust_with_no_header_falls_back_to_remote_addr() {
        assert_eq!(resolve_client_ip("203.0.113.9", None, 1), "203.0.113.9");
    }

    #[test]
    fn trust_with_empty_or_blank_header_falls_back_to_remote_addr() {
        assert_eq!(resolve_client_ip("203.0.113.9", Some(""), 1), "203.0.113.9");
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("   "), 1),
            "203.0.113.9"
        );
    }

    #[test]
    fn one_trusted_hop_takes_the_entry_that_hop_wrote() {
        // What nginx's `$proxy_add_x_forwarded_for` produces: the
        // client's own header, then the peer nginx actually saw.
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("198.51.100.1"), 1),
            "198.51.100.1"
        );
    }

    /// The whole point. A client that sends its own `X-Forwarded-For`
    /// pushes its fabrication to the left; the entry nginx appends is
    /// still the address it genuinely observed, and that is the one
    /// used.
    #[test]
    fn a_client_supplied_entry_cannot_displace_the_proxys_own() {
        let spoofed = "9.9.9.9, 198.51.100.1"; // client claimed 9.9.9.9
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(spoofed), 1),
            "198.51.100.1"
        );

        // Nor by sending a whole fake chain.
        let long_spoof = "1.1.1.1, 2.2.2.2, 3.3.3.3, 198.51.100.1";
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(long_spoof), 1),
            "198.51.100.1"
        );
    }

    #[test]
    fn two_trusted_hops_step_one_further_left() {
        // CDN then nginx: the CDN appended the real client, nginx
        // appended the CDN.
        let header = "9.9.9.9, 198.51.100.1, 203.0.113.7";
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(header), 2),
            "198.51.100.1"
        );
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(header), 1),
            "203.0.113.7"
        );
    }

    #[test]
    fn declaring_more_hops_than_the_header_has_falls_back() {
        // The operator says two proxies; only one entry arrived. No
        // entry here was written by a hop they vouch for.
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1"), 2),
            "203.0.113.9"
        );
    }

    #[test]
    fn an_entry_that_is_not_an_ip_address_is_not_used() {
        for junk in [
            "not-an-ip",
            "unknown",            // RFC 7239's own placeholder
            "_hidden",            // an obfuscated identifier
            "198.51.100.1 hello", // trailing garbage
            "999.999.999.999",
            "<script>",
            "'; DROP TABLE events;--",
        ] {
            assert_eq!(
                resolve_client_ip("203.0.113.9", Some(junk), 1),
                "203.0.113.9",
                "{junk:?} must not become a stored client address"
            );
        }
    }

    #[test]
    fn ipv6_and_port_suffixed_forms_are_understood() {
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("2001:db8::1"), 1),
            "2001:db8::1"
        );
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("[2001:db8::1]:443"), 1),
            "2001:db8::1"
        );
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("[2001:db8::1]"), 1),
            "2001:db8::1"
        );
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("198.51.100.1:41234"), 1),
            "198.51.100.1"
        );
    }

    #[test]
    fn env_parsing_is_conservative_and_keeps_the_old_spelling_working() {
        assert_eq!(trusted_hops_from_env(None), 0);
        assert_eq!(trusted_hops_from_env(Some("")), 0);
        assert_eq!(trusted_hops_from_env(Some("0")), 0);
        // Everything the docs ever told anyone to write.
        assert_eq!(trusted_hops_from_env(Some("1")), 1);
        assert_eq!(trusted_hops_from_env(Some("true")), 1);
        assert_eq!(trusted_hops_from_env(Some(" 1 ")), 1);
        assert_eq!(trusted_hops_from_env(Some("2")), 2);
        assert_eq!(trusted_hops_from_env(Some("false")), 0);
        // A typo must not turn into trust.
        for junk in ["yes please", "-1", "one", "1.0", "999999", "١"] {
            assert_eq!(
                trusted_hops_from_env(Some(junk)),
                0,
                "{junk:?} is not a hop count and must disable the header"
            );
        }
        assert_eq!(trusted_hops_from_env(Some("200")), TRUSTED_HOPS_MAX);
    }

    #[test]
    fn hop_counts_beyond_the_cap_are_clamped_not_wrapped() {
        let header = "1.1.1.1, 2.2.2.2, 3.3.3.3";
        // 200 hops is nonsense; it must not underflow, panic, or
        // somehow select an entry.
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some(header), 200),
            "203.0.113.9"
        );
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some(header), u8::MAX),
            "203.0.113.9"
        );
    }
}
