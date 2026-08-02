//! `fossh glibc-check` — standalone, fast preflight gate meant for the
//! systemd unit's `ExecStartPre=` (§3.2/§3.11): "detect the host's
//! glibc version and refuse to run with a clear error if the host is
//! below the floor, rather than failing with an opaque dynamic-linker
//! error." Deliberately does not touch `fossh.toml`, the database, or
//! anything else `doctor`'s fuller suite checks — a fresh `dnf install`
//! with no site configured yet must still be gateable before the
//! service is allowed to start at all, and systemd should not have to
//! run the full `doctor` suite (which touches the database) just to
//! decide whether to start.

use crate::common::detect_glibc_version;

pub fn run(_args: &[String]) -> i32 {
    let floor = fossh_core::glibc_gate::RECOMMENDED_FLOOR;

    let version = match detect_glibc_version() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fossh glibc-check: {e}");
            return 1;
        }
    };

    if fossh_core::glibc_gate::meets_floor(version, floor) {
        println!(
            "fossh glibc-check: {}.{} >= required floor {}.{} — ok",
            version.0, version.1, floor.0, floor.1
        );
        0
    } else {
        eprintln!(
            "fossh glibc-check: this host's glibc is {}.{}, below foSSH's required floor of \
             {}.{}. Refusing to start the Fedora-native service on this host rather than fail \
             later with an opaque dynamic-linker error — see DURUM.md §2.5.",
            version.0, version.1, floor.0, floor.1
        );
        1
    }
}

#[cfg(test)]
mod tests {
    // `run()` itself always shells out to the real `ldd` on this host —
    // there's no fake-able seam here without threading a trait/closure
    // through just for a test, which isn't worth it for a ~15-line
    // function. `detect_glibc_version`'s exit-status handling and
    // `glibc_gate`'s parsing are exercised directly in `common.rs` and
    // `fossh-core`, respectively — this module is glue over both.
    use super::*;

    #[test]
    fn runs_against_the_real_host_without_panicking() {
        // This environment's real ldd (2.43) is above the floor, so
        // this doubles as a real-host smoke test, not just "didn't
        // crash" — see DURUM.md's §3.1 retrospective for why a
        // below-floor case isn't faked here.
        assert_eq!(run(&[]), 0);
    }
}
