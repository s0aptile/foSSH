pub const RECOMMENDED_FLOOR: (u32, u32) = (2, 17);

pub fn parse_ldd_version(stdout: &str) -> Option<(u32, u32)> {
    let first_line = stdout.lines().next()?;
    let last_token = first_line.split_whitespace().last()?;
    let (major, minor) = last_token.split_once('.')?;
    let major: u32 = major.parse().ok()?;
    let minor_digits: String = minor.chars().take_while(|c| c.is_ascii_digit()).collect();
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

pub fn meets_floor(version: (u32, u32), floor: (u32, u32)) -> bool {
    version >= floor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fedora_format() {
        assert_eq!(
            parse_ldd_version("ldd (GNU libc) 2.43\nCopyright (C) 2024 ..."),
            Some((2, 43))
        );
    }

    #[test]
    fn parses_ubuntu_format_with_patch_suffix_in_parenthetical_only() {
        assert_eq!(
            parse_ldd_version("ldd (Ubuntu GLIBC 2.31-0ubuntu9.9) 2.31\n"),
            Some((2, 31))
        );
    }

    #[test]
    fn parses_debian_format() {
        assert_eq!(
            parse_ldd_version("ldd (Debian GLIBC 2.36-9+deb12u4) 2.36\n"),
            Some((2, 36))
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse_ldd_version(""), None);
    }

    #[test]
    fn rejects_input_with_no_dot() {
        assert_eq!(parse_ldd_version("not a version string at all"), None);
    }

    #[test]
    fn rejects_non_numeric_version_token() {
        assert_eq!(parse_ldd_version("ldd (GNU libc) abc.def"), None);
    }

    #[test]
    fn floor_comparison_is_lexicographic_on_major_then_minor() {
        assert!(meets_floor((2, 43), RECOMMENDED_FLOOR));
        assert!(meets_floor((2, 17), RECOMMENDED_FLOOR));
        assert!(!meets_floor((2, 16), RECOMMENDED_FLOOR));
        assert!(meets_floor((3, 0), (2, 43)));
        assert!(!meets_floor((1, 99), RECOMMENDED_FLOOR));
    }
}
