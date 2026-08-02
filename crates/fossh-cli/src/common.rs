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
