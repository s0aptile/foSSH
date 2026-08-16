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

pub fn load_data_key(data_dir: &Path) -> zeroize::Zeroizing<[u8; 32]> {
    match fossh_admin::data_key::load_or_generate(&data_dir.join(".data_key")) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("fossh: could not load data-encryption key: {e}");
            std::process::exit(1);
        }
    }
}

pub fn open_store(data_dir: &Path) -> fossh_store::Store {
    let key = load_data_key(data_dir);
    match fossh_store::Store::open_encrypted(&db_path(data_dir), &key) {
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
