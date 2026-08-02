//! Pure parsing/comparison for the glibc-floor gate (Fedora-native
//! deployment chapter, §2.5/§3.1). This module does no I/O at all —
//! it neither spawns `ldd` nor reads the running host's actual glibc
//! version. The caller (`fossh-cli`'s `doctor` and `glibc-check`
//! subcommands, and — later — an `ExecStartPre=` hook in the systemd
//! unit) is responsible for actually invoking `ldd --version` and
//! handing its stdout to `parse_ldd_version`.
//!
//! Deliberately not wired into `fossh-cgi`'s per-request path: that
//! binary is re-exec'd by the webserver (or `fcgiwrap`) on every single
//! request, and the host's glibc version cannot change between one
//! request and the next — spawning a subprocess to re-check it on every
//! invocation would burn real budget against §7.1's sub-5ms p99 target
//! for nothing. See DECISIONS.md's ADR on this.

/// The locked-in floor (§2.5's "candidate: 2.17, matching the
/// RHEL7/CentOS7 era"), finalized here as the actual comparison value.
pub const RECOMMENDED_FLOOR: (u32, u32) = (2, 17);

/// Parses the `(major, minor)` glibc version out of `ldd --version`'s
/// stdout. Takes the last whitespace-separated token on the first
/// line — every glibc distro variant this was checked against (`ldd
/// (GNU libc) 2.43` on Fedora, `ldd (Ubuntu GLIBC 2.31-0ubuntu9.9)
/// 2.31`, `ldd (Debian GLIBC 2.36-9+deb12u4) 2.36`) ends that line with
/// a bare `MAJOR.MINOR`, even when an earlier parenthetical carries a
/// distro-patched suffix.
pub fn parse_ldd_version(stdout: &str) -> Option<(u32, u32)> {
    let first_line = stdout.lines().next()?;
    let last_token = first_line.split_whitespace().last()?;
    let (major, minor) = last_token.split_once('.')?;
    let major: u32 = major.parse().ok()?;
    let minor_digits: String = minor.chars().take_while(|c| c.is_ascii_digit()).collect();
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

/// `true` if `version` meets or exceeds `floor` (major first, then
/// minor within the same major).
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
