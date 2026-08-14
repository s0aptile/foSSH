//! `fossh {init,site,query,maintain,export,doctor}` (§9). Hand-rolled
//! argument parsing (ADR-0003) — each subcommand parses its own flags.

#![forbid(unsafe_code)]

mod args;
mod commands;
mod common;
mod date;

const VERSION_LINE: &str = concat!(
    "fossh ",
    env!("CARGO_PKG_VERSION"),
    " — $0aptile / github.com/s0aptile"
);

const HELP: &str = "\
foSSH — privacy-preserving, embeddable telemetry. Light. Small. Compact.

USAGE:
    fossh <COMMAND> [ARGS]

COMMANDS:
    init [--dir PATH]
        Initialize a data directory and write a default ./fossh.toml.

    site create <slug> [--allow name,name] [--public-key]
    site list
    site disable <slug>
    site rotate-key <slug>
        Manage sites and their write keys.

    query --site <slug> --from YYYY-MM-DD --to YYYY-MM-DD
          [--group-by path,country,...] [--metric hits,uniques,p50,p95]
          [--format table|json|csv]
        Read aggregated, k-anonymized stats.

    maintain
        Drain spool files into the database, enforce retention, vacuum.

    export --site <slug> --format ndjson [--from YYYY-MM-DD] [--to YYYY-MM-DD]
        Export rollup aggregates (never raw rows) as newline-delimited JSON.

    doctor
        Verify permissions, config sanity, and privacy/security invariants
        against the live install.

    glibc-check
        Fast standalone preflight gate for the Fedora-native systemd unit's
        ExecStartPre= — checks only the host's glibc floor (§2.5), nothing
        else. Exit 0 = ok, 1 = below floor or could not determine.

    --version, -V   Print the version.
    --help, -h      Print this help.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("init") => commands::init::run(&args[1..]),
        Some("site") => commands::site::run(&args[1..]),
        Some("query") => commands::query::run(&args[1..]),
        Some("maintain") => commands::maintain::run(&args[1..]),
        Some("export") => commands::export::run(&args[1..]),
        Some("doctor") => commands::doctor::run(&args[1..]),
        Some("glibc-check") => commands::glibc_check::run(&args[1..]),
        Some("--version") | Some("-V") => {
            println!("{VERSION_LINE}");
            0
        }
        Some("--help") | Some("-h") | None => {
            print!("{HELP}");
            0
        }
        Some(other) => {
            eprintln!("fossh: unknown command '{other}'\n");
            print!("{HELP}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_args_prints_help_and_succeeds() {
        assert_eq!(run(&[]), 0);
    }

    #[test]
    fn help_flags_succeed() {
        assert_eq!(run(&["--help".to_string()]), 0);
        assert_eq!(run(&["-h".to_string()]), 0);
    }

    #[test]
    fn version_flags_succeed() {
        assert_eq!(run(&["--version".to_string()]), 0);
        assert_eq!(run(&["-V".to_string()]), 0);
    }

    #[test]
    fn unknown_command_is_exit_code_2() {
        assert_eq!(run(&["bogus-command".to_string()]), 2);
    }

    #[test]
    fn site_with_no_subcommand_is_exit_code_2() {
        assert_eq!(run(&["site".to_string()]), 2);
    }
}
