use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fossh_core::config::{Config, CountryDb};

use crate::args::{flag_value, wants_help};
use crate::common::db_path;

const HELP: &str = "usage: fossh init [--dir PATH]\n\n\
Initialize a data directory (default /var/lib/fossh) and write a default\n\
./fossh.toml, if one doesn't already exist.";

pub fn run(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{HELP}");
        return 0;
    }
    let dir = flag_value(args, "--dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fossh"));

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("fossh init: creating {}: {e}", dir.display());
        return 1;
    }
    if let Err(e) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
        eprintln!("fossh init: setting permissions on {}: {e}", dir.display());
        return 1;
    }

    let data_key = match fossh_admin::data_key::load_or_generate(&dir.join(".data_key")) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("fossh init: could not load data-encryption key: {e}");
            return 1;
        }
    };

    if let Err(e) = fossh_store::Store::open_encrypted(&db_path(&dir), &data_key) {
        eprintln!("fossh init: initializing database: {e}");
        return 1;
    }

    let config_path = PathBuf::from("./fossh.toml");
    if config_path.exists() {
        println!(
            "{} already exists — leaving it as-is.",
            config_path.display()
        );
    } else {

        let config = Config {
            data_dir: dir.clone(),
            country_db: CountryDb::None,
            ..Config::default()
        };
        let toml_text = match toml::to_string_pretty(&config) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("fossh init: serializing default config: {e}");
                return 1;
            }
        };
        if let Err(e) = fs::write(&config_path, toml_text) {
            eprintln!("fossh init: writing {}: {e}", config_path.display());
            return 1;
        }
        println!("Wrote {}", config_path.display());
    }

    println!("Initialized foSSH data directory at {}", dir.display());
    0
}
