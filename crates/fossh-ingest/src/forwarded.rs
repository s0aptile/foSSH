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
//! choice (`FOSSH_TRUST_FORWARDED_FOR`, read in `main.rs`) — the same
//! "an unauthenticated header claiming to be a real IP proves nothing
//! by itself, but the operator's own configuration choice to trust it
//! in a setup they control is meaningful" reasoning most web frameworks
//! apply here (Rails' `trusted_proxies`, Express's `trust proxy`, ...).
//! Note this only ever runs *after* `handler::authenticate` succeeds —
//! an unauthenticated request never reaches anywhere this value is
//! used for anything privacy-relevant (P2's visitor hashing).

/// `forwarded_for` is `HTTP_X_FORWARDED_FOR`'s raw value, if present —
/// conventionally a comma-separated list, leftmost entry = the
/// original client, each hop after it appending its own address to the
/// right. Returns that leftmost entry, trimmed, when trusting it;
/// otherwise (not trusting, or the header absent/empty) returns
/// `remote_addr` unchanged.
pub fn resolve_client_ip(remote_addr: &str, forwarded_for: Option<&str>, trust: bool) -> String {
    if !trust {
        return remote_addr.to_string();
    }
    match forwarded_for
        .and_then(|h| h.split(',').next())
        .map(str::trim)
    {
        Some(first) if !first.is_empty() => first.to_string(),
        _ => remote_addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distrust_always_uses_remote_addr_even_if_header_present() {
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1"), false),
            "203.0.113.9"
        );
    }

    #[test]
    fn trust_with_no_header_falls_back_to_remote_addr() {
        assert_eq!(resolve_client_ip("203.0.113.9", None, true), "203.0.113.9");
    }

    #[test]
    fn trust_with_empty_or_blank_header_falls_back_to_remote_addr() {
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some(""), true),
            "203.0.113.9"
        );
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("   "), true),
            "203.0.113.9"
        );
    }

    #[test]
    fn trust_takes_the_leftmost_comma_separated_entry_trimmed() {
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1, 203.0.113.9"), true),
            "198.51.100.1"
        );
    }

    #[test]
    fn trust_with_single_entry_no_comma() {
        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1"), true),
            "198.51.100.1"
        );
    }
}
