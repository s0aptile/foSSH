//! `fossh site create|list|disable|rotate-key` (§9).

use fossh_core::base32;

use crate::args::{comma_list, flag_value, has_flag, positional};
use crate::common::{load_config, open_store, unix_now};

const USAGE: &str = "usage: fossh site <create|list|disable|rotate-key> ...";

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("create") => create(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("disable") => disable(&args[1..]),
        Some("rotate-key") => rotate_key(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

fn print_new_key(slug: &str, write_key: &[u8; 32]) {
    let key = format!("fossh_{slug}_{}", base32::encode(write_key));
    println!("Write key (displayed once — store it now, it cannot be shown again):");
    println!("  {key}");
}

fn create(args: &[String]) -> i32 {
    let Some(slug) = positional(args) else {
        eprintln!("usage: fossh site create <slug> [--allow name,name] [--public-key]");
        return 2;
    };
    let allowlist = flag_value(args, "--allow")
        .map(comma_list)
        .unwrap_or_default();
    let public = has_flag(args, "--public-key");

    let config = load_config();
    let store = open_store(&config.data_dir);

    let write_key_bytes = match fossh_ingest::random::read_random_bytes(32) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fossh site create: generating a write key: {e}");
            return 1;
        }
    };
    let mut write_key = [0u8; 32];
    write_key.copy_from_slice(&write_key_bytes);
    let key_hash = *blake3::hash(&write_key).as_bytes();

    if let Err(e) = store.create_site(slug, &key_hash, &allowlist, unix_now(), public) {
        eprintln!("fossh site create: {e}");
        return 1;
    }
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        _ => {
            eprintln!("fossh site create: site was created but could not be re-read");
            return 1;
        }
    };
    if let Err(e) = fossh_ingest::site_cache::write(&config.data_dir, &site) {
        eprintln!("fossh site create: writing site cache: {e}");
        return 1;
    }

    println!("Site '{slug}' created (public={public}, allowlist={allowlist:?}).");
    print_new_key(slug, &write_key);
    0
}

fn list(_args: &[String]) -> i32 {
    let config = load_config();
    let store = open_store(&config.data_dir);
    let sites = match store.list_sites() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fossh site list: {e}");
            return 1;
        }
    };
    if sites.is_empty() {
        println!("(no sites)");
        return 0;
    }
    println!("{:<20} {:<8} {:<8} allowlist", "slug", "public", "disabled");
    for site in sites {
        println!(
            "{:<20} {:<8} {:<8} {}",
            site.slug,
            site.public,
            site.disabled,
            site.allowlist.join(",")
        );
    }
    0
}

fn disable(args: &[String]) -> i32 {
    let Some(slug) = positional(args) else {
        eprintln!("usage: fossh site disable <slug>");
        return 2;
    };
    let config = load_config();
    let store = open_store(&config.data_dir);
    match store.disable_site(slug) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("fossh site disable: no such site '{slug}'");
            return 1;
        }
        Err(e) => {
            eprintln!("fossh site disable: {e}");
            return 1;
        }
    }
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        _ => {
            eprintln!("fossh site disable: site was disabled but could not be re-read");
            return 1;
        }
    };
    if let Err(e) = fossh_ingest::site_cache::write(&config.data_dir, &site) {
        eprintln!("fossh site disable: updating site cache: {e}");
        return 1;
    }
    println!("Site '{slug}' disabled.");
    0
}

fn rotate_key(args: &[String]) -> i32 {
    let Some(slug) = positional(args) else {
        eprintln!("usage: fossh site rotate-key <slug>");
        return 2;
    };
    let config = load_config();
    let store = open_store(&config.data_dir);

    let write_key_bytes = match fossh_ingest::random::read_random_bytes(32) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fossh site rotate-key: generating a write key: {e}");
            return 1;
        }
    };
    let mut write_key = [0u8; 32];
    write_key.copy_from_slice(&write_key_bytes);
    let key_hash = *blake3::hash(&write_key).as_bytes();

    match store.rotate_site_key(slug, &key_hash) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("fossh site rotate-key: no such site '{slug}'");
            return 1;
        }
        Err(e) => {
            eprintln!("fossh site rotate-key: {e}");
            return 1;
        }
    }
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        _ => {
            eprintln!("fossh site rotate-key: key was rotated but the site could not be re-read");
            return 1;
        }
    };
    if let Err(e) = fossh_ingest::site_cache::write(&config.data_dir, &site) {
        eprintln!("fossh site rotate-key: updating site cache: {e}");
        return 1;
    }

    println!("Key rotated for site '{slug}'. The old key stops working immediately.");
    print_new_key(slug, &write_key);
    0
}
