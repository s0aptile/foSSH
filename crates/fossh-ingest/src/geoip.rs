//! Country resolution from a client IP address via an offline MMDB
//! database (`fossh_core::config::CountryDb`'s `Custom`/`Builtin` path,
//! or nothing at all for `None`) — the *only* place in this codebase a
//! raw IP address is looked at for GeoIP purposes.
//!
//! README's "What it will never do" is explicit: "No raw IP addresses
//! at rest. Not even temporarily, not even in logs." Everything here is
//! shaped around that:
//!
//! - [`resolve`] takes the IP as a borrowed `&str`, does exactly one
//!   [`maxminddb::Reader::lookup`] call, and returns only a
//!   [`Country`] — never a `Result` that could carry the IP in an
//!   `Err`, never a log line, never a panic. The `&str` goes out of
//!   scope when `resolve` returns; nothing it touches writes it
//!   anywhere first.
//! - Every failure mode — no database configured, the database file
//!   missing/unreadable/corrupt, the address not in the database, or a
//!   record with no usable ISO country code — degrades to
//!   `Country::UNKNOWN` ("ZZ", already a fully valid value per §10, not
//!   an error sentinel). None of them panic; none of them block
//!   ingestion; none of them are distinguishable from each other by a
//!   caller, on purpose — a corrupt database and an address that's
//!   simply not in it should look identical from the outside.
//! - [`GeoipReader::open`] itself never touches an IP at all — it only
//!   ever sees a filesystem path — so even the "load the database"
//!   half of this module has nothing to leak.

use std::path::Path;

use fossh_core::types::Country;

/// A loaded (or explicitly absent) offline country database. Built once
/// — at process start in `fossh-cgi`/`fossh-fcgi`'s `main.rs`, from
/// `Config.country_db` — and then borrowed for the lifetime of every
/// `ingest::decide` call that needs it, not reopened per request: the
/// backing file is several megabytes and never changes between
/// requests, unlike the small per-site state `SaltManager`/`TokenBucket`
/// re-read on every call.
pub struct GeoipReader(Option<maxminddb::Reader<Vec<u8>>>);

impl GeoipReader {
    /// `path = None` is `country_db = "none"` (§10): [`resolve`] always
    /// returns `Country::UNKNOWN`, with no filesystem access at all.
    ///
    /// `Some(path)` that fails to open — missing file, unreadable
    /// permissions, present but not a valid MMDB — also degrades to an
    /// always-`UNKNOWN` reader rather than propagating an error:
    /// ingestion must never depend on this file being present or
    /// well-formed. The open failure itself never involves an IP, so
    /// there is nothing unsafe about surfacing *that* — callers that
    /// want to know it happened can compare `is_active()` against
    /// whether a path was configured — but this module doesn't log it
    /// itself, to keep "who logs what" centralized in one place per
    /// this project's existing convention (transports own their own
    /// logging; library crates return values).
    pub fn open(path: Option<&Path>) -> Self {
        let reader = path.and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self(reader)
    }

    /// A reader with no backing database — `country_db = "none"`, or
    /// nothing configured. Every [`resolve`] call returns
    /// `Country::UNKNOWN` immediately, no I/O.
    pub fn none() -> Self {
        Self(None)
    }

    /// Whether a database is actually loaded and will be consulted —
    /// `false` for both `GeoipReader::none()` and an `open()` that
    /// failed. Informational only (e.g. startup logging of *whether*
    /// GeoIP is active); never used to decide fail-open vs fail-closed
    /// behavior, since [`resolve`] already fails closed unconditionally.
    pub fn is_active(&self) -> bool {
        self.0.is_some()
    }

    /// Resolves `ip` to its ISO-3166-1 alpha-2 country code, or
    /// `Country::UNKNOWN` on any of: no database loaded, `ip` doesn't
    /// parse, the address has no entry, the entry has no `country`
    /// record, or that record's `iso_code` isn't the two-uppercase-ASCII
    /// shape `Country::parse` requires.
    ///
    /// Exactly one `Reader::lookup` call. `ip` is read only to parse it
    /// and hand it to that single call; nothing here retains it, logs
    /// it, or includes it in a returned value on any path — the return
    /// type is `Country`, which structurally cannot carry an IP address.
    pub fn resolve(&self, ip: &str) -> Country {
        let Some(reader) = &self.0 else {
            return Country::UNKNOWN;
        };
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return Country::UNKNOWN;
        };
        let Ok(result) = reader.lookup(addr) else {
            return Country::UNKNOWN;
        };
        let Ok(Some(record)) = result.decode::<maxminddb::geoip2::Country>() else {
            return Country::UNKNOWN;
        };
        record
            .country
            .iso_code
            .and_then(Country::parse)
            .unwrap_or(Country::UNKNOWN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn real_db_path() -> Option<std::path::PathBuf> {
        // Populated once the operator-downloaded db-ip.com "IP to
        // Country Lite" file lands (see NOTICE); skipped, not failed,
        // when it hasn't — this module must be fully testable without
        // it (fail-closed paths below), and a missing optional fixture
        // is not this crate's failure.
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/geoip/dbip-country-lite-2026-08.mmdb");
        p.is_file().then_some(p)
    }

    #[test]
    fn no_database_configured_is_always_unknown() {
        let reader = GeoipReader::open(None);
        assert!(!reader.is_active());
        assert_eq!(reader.resolve("8.8.8.8"), Country::UNKNOWN);
        assert_eq!(reader.resolve("2001:4860:4860::8888"), Country::UNKNOWN);
    }

    #[test]
    fn none_constructor_is_always_unknown_with_no_io() {
        let reader = GeoipReader::none();
        assert!(!reader.is_active());
        assert_eq!(reader.resolve("203.0.113.9"), Country::UNKNOWN);
    }

    #[test]
    fn missing_database_file_fails_closed_not_panics() {
        let missing = Path::new("/nonexistent/path/does-not-exist.mmdb");
        let reader = GeoipReader::open(Some(missing));
        assert!(!reader.is_active());
        assert_eq!(reader.resolve("203.0.113.9"), Country::UNKNOWN);
    }

    #[test]
    fn corrupt_database_file_fails_closed_not_panics() {
        let dir =
            std::env::temp_dir().join(format!("fossh-geoip-corrupt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corrupt.mmdb");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"this is not a valid MMDB file, just noise")
                .unwrap();
        }

        let reader = GeoipReader::open(Some(&path));
        assert!(!reader.is_active());
        assert_eq!(reader.resolve("203.0.113.9"), Country::UNKNOWN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_file_fails_closed_not_panics() {
        let dir =
            std::env::temp_dir().join(format!("fossh-geoip-empty-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.mmdb");
        std::fs::File::create(&path).unwrap();

        let reader = GeoipReader::open(Some(&path));
        assert!(!reader.is_active());
        assert_eq!(reader.resolve("203.0.113.9"), Country::UNKNOWN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn garbage_ip_string_fails_closed_not_panics() {
        // Exercises the parse-failure path even against a real,
        // successfully-opened database, when one is available.
        let reader = match real_db_path() {
            Some(p) => GeoipReader::open(Some(&p)),
            None => GeoipReader::none(),
        };
        assert_eq!(reader.resolve("not-an-ip-address"), Country::UNKNOWN);
        assert_eq!(reader.resolve(""), Country::UNKNOWN);
        assert_eq!(reader.resolve("999.999.999.999"), Country::UNKNOWN);
    }

    // --- Real-data tests: run only when the operator-downloaded
    // database is present at `assets/geoip/`; `cargo test` must pass
    // identically whether or not it is, so every assertion below is
    // gated on `real_db_path()` up front rather than assumed present.

    #[test]
    fn real_database_resolves_a_known_google_dns_ip_to_us() {
        let Some(path) = real_db_path() else {
            eprintln!("skipping: no real geoip database at assets/geoip/");
            return;
        };
        let reader = GeoipReader::open(Some(&path));
        assert!(reader.is_active(), "a present, valid mmdb must load");
        // 8.8.8.8 (Google Public DNS) is one of the most stable
        // real-world IP -> country fixtures available: it has been
        // US-announced and US-hosted for well over a decade.
        assert_eq!(reader.resolve("8.8.8.8").as_str(), "US");
    }

    #[test]
    fn real_database_resolves_a_known_ipv6_address_to_a_real_country() {
        let Some(path) = real_db_path() else {
            eprintln!("skipping: no real geoip database at assets/geoip/");
            return;
        };
        let reader = GeoipReader::open(Some(&path));
        // 2606:4700:4700::1111 (Cloudflare DNS) is globally anycast, so
        // *which* country a given database attributes it to is
        // provider/methodology-dependent — this free db-ip.com dataset
        // says CA, MaxMind's has historically said US, and both are
        // defensible for an anycast address. What this test actually
        // verifies is the thing that's NOT provider-dependent: the IPv6
        // path through `resolve` (parse, lookup, decode) works end to
        // end against a real database and returns a real, valid
        // ISO-3166-1 alpha-2 code — not `UNKNOWN`, not a panic.
        let country = reader.resolve("2606:4700:4700::1111");
        assert_ne!(
            country,
            Country::UNKNOWN,
            "a well-known, globally-routed IPv6 address must resolve to *some* real country"
        );
    }

    #[test]
    fn real_database_private_and_reserved_ranges_are_unknown_not_a_panic() {
        let Some(path) = real_db_path() else {
            eprintln!("skipping: no real geoip database at assets/geoip/");
            return;
        };
        let reader = GeoipReader::open(Some(&path));
        // RFC 1918 space is never in a public country database.
        assert_eq!(reader.resolve("10.0.0.1"), Country::UNKNOWN);
        assert_eq!(reader.resolve("192.168.1.1"), Country::UNKNOWN);
        assert_eq!(reader.resolve("127.0.0.1"), Country::UNKNOWN);
    }
}
