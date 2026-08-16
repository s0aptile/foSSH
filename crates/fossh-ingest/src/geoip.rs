use std::path::Path;

use fossh_core::types::Country;

pub struct GeoipReader(Option<maxminddb::Reader<Vec<u8>>>);

impl GeoipReader {

    pub fn open(path: Option<&Path>) -> Self {
        let reader = path.and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self(reader)
    }

    pub fn none() -> Self {
        Self(None)
    }

    pub fn is_active(&self) -> bool {
        self.0.is_some()
    }

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

        let reader = match real_db_path() {
            Some(p) => GeoipReader::open(Some(&p)),
            None => GeoipReader::none(),
        };
        assert_eq!(reader.resolve("not-an-ip-address"), Country::UNKNOWN);
        assert_eq!(reader.resolve(""), Country::UNKNOWN);
        assert_eq!(reader.resolve("999.999.999.999"), Country::UNKNOWN);
    }

    #[test]
    fn real_database_resolves_a_known_google_dns_ip_to_us() {
        let Some(path) = real_db_path() else {
            eprintln!("skipping: no real geoip database at assets/geoip/");
            return;
        };
        let reader = GeoipReader::open(Some(&path));
        assert!(reader.is_active(), "a present, valid mmdb must load");

        assert_eq!(reader.resolve("8.8.8.8").as_str(), "US");
    }

    #[test]
    fn real_database_resolves_a_known_ipv6_address_to_a_real_country() {
        let Some(path) = real_db_path() else {
            eprintln!("skipping: no real geoip database at assets/geoip/");
            return;
        };
        let reader = GeoipReader::open(Some(&path));

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

        assert_eq!(reader.resolve("10.0.0.1"), Country::UNKNOWN);
        assert_eq!(reader.resolve("192.168.1.1"), Country::UNKNOWN);
        assert_eq!(reader.resolve("127.0.0.1"), Country::UNKNOWN);
    }
}
