use std::net::IpAddr;

pub const TRUSTED_HOPS_MAX: u8 = 8;

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

    let Some(index) = entries.len().checked_sub(hops) else {
        return remote_addr.to_string();
    };

    match entries.get(index).copied().map(strip_port) {
        Some(candidate) if candidate.parse::<IpAddr>().is_ok() => candidate.to_string(),
        _ => remote_addr.to_string(),
    }
}

pub fn trusted_hops_from_env(value: Option<&str>) -> u8 {
    match value.map(str::trim) {
        None | Some("") => 0,
        Some("true") | Some("yes") | Some("on") => 1,
        Some("false") | Some("no") | Some("off") => 0,
        Some(n) => n.parse::<u8>().unwrap_or(0).min(TRUSTED_HOPS_MAX),
    }
}

fn strip_port(entry: &str) -> &str {
    if let Some(rest) = entry.strip_prefix('[') {

        return rest.split(']').next().unwrap_or(rest);
    }

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

        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("198.51.100.1"), 1),
            "198.51.100.1"
        );
    }

    #[test]
    fn a_client_supplied_entry_cannot_displace_the_proxys_own() {
        let spoofed = "9.9.9.9, 198.51.100.1";
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(spoofed), 1),
            "198.51.100.1"
        );

        let long_spoof = "1.1.1.1, 2.2.2.2, 3.3.3.3, 198.51.100.1";
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some(long_spoof), 1),
            "198.51.100.1"
        );
    }

    #[test]
    fn two_trusted_hops_step_one_further_left() {

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

        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("198.51.100.1"), 2),
            "203.0.113.9"
        );
    }

    #[test]
    fn an_entry_that_is_not_an_ip_address_is_not_used() {
        for junk in [
            "not-an-ip",
            "unknown",
            "_hidden",
            "198.51.100.1 hello",
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

        assert_eq!(trusted_hops_from_env(Some("1")), 1);
        assert_eq!(trusted_hops_from_env(Some("true")), 1);
        assert_eq!(trusted_hops_from_env(Some(" 1 ")), 1);
        assert_eq!(trusted_hops_from_env(Some("2")), 2);
        assert_eq!(trusted_hops_from_env(Some("false")), 0);

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
