//! Shared helpers used across subcommands.

use std::path::{Path, PathBuf};

use fossh_core::config::Config;

pub fn load_config() -> Config {
    match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fossh: config error: {e}");
            std::process::exit(1);
        }
    }
}

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("fossh.db")
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Shared by `doctor` and `glibc-check` (§2.5/§3.1) so the two never
/// drift out of sync on how `ldd --version` gets turned into a
/// pass/fail — they did drift once already: both call sites used to
/// spawn `ldd` and inspect `output.stdout` without ever checking
/// `output.status`, so an `ldd` that *failed* (non-zero exit — e.g. a
/// half-broken glibc install, exactly the kind of host this check
/// exists to catch) but still printed something matching
/// `MAJOR.MINOR`-shaped text on stdout would parse as a clean pass.
/// Caught in adversarial review before either call site shipped; fixed
/// once, here, instead of twice.
pub fn detect_glibc_version() -> Result<(u32, u32), String> {
    let output = std::process::Command::new("ldd")
        .arg("--version")
        .output()
        .map_err(|e| format!("could not run `ldd --version`: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "`ldd --version` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("(no output)")
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    fossh_core::glibc_gate::parse_ldd_version(&stdout)
        .ok_or_else(|| format!("could not parse `ldd --version` output: {stdout:?}"))
}

pub fn open_store(data_dir: &Path) -> fossh_store::Store {
    match fossh_store::Store::open(&db_path(data_dir)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "fossh: could not open database at {}: {e}",
                db_path(data_dir).display()
            );
            std::process::exit(1);
        }
    }
}
