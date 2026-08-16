use crate::args::wants_help;
use crate::common::detect_glibc_version;

const HELP: &str = "usage: fossh glibc-check\n\n\
Standalone preflight gate for the systemd unit's ExecStartPre= — checks\n\
only the host's glibc floor (§2.5), nothing else. Exit 0 = ok, 1 = below\n\
floor or could not determine.";

pub fn run(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{HELP}");
        return 0;
    }
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
             later with an opaque dynamic-linker error.",
            version.0, version.1, floor.0, floor.1
        );
        1
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn runs_against_the_real_host_without_panicking() {

        assert_eq!(run(&[]), 0);
    }
}
