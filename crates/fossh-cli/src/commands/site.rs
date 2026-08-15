//! `fossh site create|list|disable|rotate-key` (§9).

use fossh_core::base32;

use crate::args::{comma_list, flag_value, has_flag, positional, wants_help};
use crate::common::{load_config, open_store, unix_now};

const USAGE: &str = "usage: fossh site <create|list|disable|rotate-key|rotate-signing-key> ...";
const HELP: &str = "usage: fossh site <SUBCOMMAND>\n\n\
SUBCOMMANDS:\n    \
    create <slug> [--allow name,name] [--public-key]\n    \
    list\n    \
    disable <slug>\n    \
    rotate-key <slug>\n    \
    rotate-signing-key <slug>\n\n\
Manage sites, their bearer write keys, and their signed-mode signing keys.";

pub fn run(args: &[String]) -> i32 {
    // Only intercepts `fossh site --help`/`-h` itself — once a
    // subcommand is chosen, that subcommand's own `wants_help` check
    // handles it, so e.g. `site create --help` shows create's usage,
    // not this generic one.
    if matches!(
        args.first().map(String::as_str),
        Some("--help") | Some("-h")
    ) {
        println!("{HELP}");
        return 0;
    }
    match args.first().map(String::as_str) {
        Some("create") => create(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("disable") => disable(&args[1..]),
        Some("rotate-key") => rotate_key(&args[1..]),
        Some("rotate-signing-key") => rotate_signing_key(&args[1..]),
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

/// Generates a fresh Ed25519 keypair for signed-mode auth (§8, B-03 fix:
/// the server stores only `verifying_key`, never anything the private
/// key could be recovered from — see `fossh-ingest`'s `auth.rs` module
/// doc comment). Returns the raw 32-byte verifying key alongside the
/// `SigningKey` so callers can both persist the public half and print
/// the private half in the same operation.
fn generate_signing_keypair() -> Result<(ed25519_dalek::SigningKey, [u8; 32]), String> {
    let seed_bytes = fossh_ingest::random::read_random_bytes(32).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = *signing_key.verifying_key().as_bytes();
    Ok((signing_key, verifying_key))
}

fn print_new_signing_key(slug: &str, signing_key: &ed25519_dalek::SigningKey) {
    let key = format!(
        "fossh_sign_{slug}_{}",
        base32::encode(&signing_key.to_bytes())
    );
    println!("Signing key (for signed-mode/server-to-server auth — displayed once, store it now):");
    println!("  {key}");
}

fn create(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("usage: fossh site create <slug> [--allow name,name] [--public-key]");
        return 0;
    }
    let Some(slug) = positional(args) else {
        eprintln!("usage: fossh site create <slug> [--allow name,name] [--public-key]");
        return 2;
    };
    // `fossh-store` itself has no slug format/emptiness check (it's a
    // free-text column) — an empty or whitespace-only slug reaches here
    // easily by accident (an unset shell variable in a provisioning
    // script: `fossh site create "$SLUG"`) and would otherwise silently
    // create a site with no usable name.
    if slug.trim().is_empty() {
        eprintln!("fossh site create: <slug> must not be empty");
        return 2;
    }
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

    let (signing_key, sign_pubkey) = match generate_signing_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("fossh site create: generating a signing key: {e}");
            return 1;
        }
    };

    if let Err(e) = store.create_site(
        slug,
        &key_hash,
        Some(&sign_pubkey),
        &allowlist,
        unix_now(),
        public,
    ) {
        // `fossh-store`'s error is a thin wrapper over the raw sqlite
        // message ("sqlite: UNIQUE constraint failed: sites.slug") —
        // meaningless to an operator who doesn't know the schema.
        // Recognized by string match rather than by depending on
        // `rusqlite` directly here just to match on its error kind (out
        // of `fossh-cli`'s dependency budget, S11, for one message).
        if e.to_string().contains("UNIQUE constraint failed") {
            eprintln!(
                "fossh site create: a site named '{slug}' already exists — use `fossh site rotate-key {slug}` for a new write key, or pick a different slug"
            );
        } else {
            eprintln!("fossh site create: {e}");
        }
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
    print_new_signing_key(slug, &signing_key);
    0
}

fn list(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("usage: fossh site list");
        return 0;
    }
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
    if wants_help(args) {
        println!("usage: fossh site disable <slug>");
        return 0;
    }
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
    if wants_help(args) {
        println!("usage: fossh site rotate-key <slug>");
        return 0;
    }
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

/// Rotates only a site's signed-mode verifying key — independent of
/// `rotate_key`'s bearer write key, since B-03's fix made these two
/// separate credentials (`fossh-store::Store::set_sign_pubkey`). Also
/// the migration path for a site created before this fix: those sites
/// have no `sign_pubkey` on file yet (signed-mode auth for them fails
/// closed — see `fossh-ingest::ingest::authenticate`), and this command
/// is how an operator opts them in without disturbing their existing
/// bearer write key or anything already integrated against it.
fn rotate_signing_key(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("usage: fossh site rotate-signing-key <slug>");
        return 0;
    }
    let Some(slug) = positional(args) else {
        eprintln!("usage: fossh site rotate-signing-key <slug>");
        return 2;
    };
    let config = load_config();
    let store = open_store(&config.data_dir);

    let (signing_key, sign_pubkey) = match generate_signing_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("fossh site rotate-signing-key: generating a signing key: {e}");
            return 1;
        }
    };

    match store.set_sign_pubkey(slug, &sign_pubkey) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("fossh site rotate-signing-key: no such site '{slug}'");
            return 1;
        }
        Err(e) => {
            eprintln!("fossh site rotate-signing-key: {e}");
            return 1;
        }
    }
    let site = match store.find_site_by_slug(slug) {
        Ok(Some(s)) => s,
        _ => {
            eprintln!(
                "fossh site rotate-signing-key: key was rotated but the site could not be re-read"
            );
            return 1;
        }
    };
    if let Err(e) = fossh_ingest::site_cache::write(&config.data_dir, &site) {
        eprintln!("fossh site rotate-signing-key: updating site cache: {e}");
        return 1;
    }

    println!(
        "Signing key rotated for site '{slug}'. The old signing key stops working immediately; the bearer write key is unaffected."
    );
    print_new_signing_key(slug, &signing_key);
    0
}
