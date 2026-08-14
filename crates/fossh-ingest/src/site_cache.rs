//! §7.1: "Do not open SQLite on the CGI hot path." That constraint isn't
//! just about the spool write — resolving *which site* a request belongs
//! to (its write key hash, allowlist, `disabled`/`public` flags) would
//! otherwise mean a SQLite query on every single request, which is
//! exactly the cost §7.1 is telling us to avoid.
//!
//! This module is the fix: a small JSON file per site at
//! `data_dir/sites/<slug>.json`, holding exactly what the hot path needs
//! to authenticate and validate a request without touching the database.
//! `fossh-store` remains the single source of truth — this is a derived,
//! disposable cache. Whatever calls `Store::create_site` /
//! `disable_site` / `rotate_site_key` (`fossh-cli`, M4) is responsible
//! for calling the matching function here in the same operation, so the
//! cache never drifts from the database it mirrors. `fossh doctor` (M4)
//! should check the two agree.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use fossh_core::base32;
use fossh_core::types::SiteId;

use crate::IngestError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedSite {
    pub id: u32,
    pub slug: String,
    pub key_hash_b32: String,
    #[serde(default)]
    pub sign_pubkey_b32: Option<String>,
    pub allowlist: Vec<String>,
    pub disabled: bool,
    pub public: bool,
}

impl CachedSite {
    pub fn from_site(site: &fossh_store::Site) -> Self {
        Self {
            id: site.id.get(),
            slug: site.slug.clone(),
            key_hash_b32: base32::encode(&site.key_hash),
            sign_pubkey_b32: site.sign_pubkey.map(|k| base32::encode(&k)),
            allowlist: site.allowlist.clone(),
            disabled: site.disabled,
            public: site.public,
        }
    }

    pub fn site_id(&self) -> SiteId {
        SiteId::new(self.id)
    }

    pub fn key_hash(&self) -> Option<[u8; 32]> {
        let bytes = base32::decode(&self.key_hash_b32)?;
        <[u8; 32]>::try_from(bytes).ok()
    }

    /// Signed-mode verifying key, if this site has one — sites migrated
    /// from before the Ed25519 fix (see `auth.rs`'s module doc comment)
    /// have `None` here until an operator runs `fossh site
    /// rotate-signing-key`, which is why signed-mode auth for them is
    /// refused, not silently downgraded to some other check.
    pub fn sign_pubkey(&self) -> Option<[u8; 32]> {
        let bytes = base32::decode(self.sign_pubkey_b32.as_deref()?)?;
        <[u8; 32]>::try_from(bytes).ok()
    }
}

/// `slug` reaches this module straight from attacker-controlled input on
/// the hot path — `read` is called from `fossh_ingest::ingest::authenticate`
/// with `HTTP_X_FOSSH_KEY_ID` (signed mode) or the `fossh_<slug>_<base32>`
/// bearer-token's own slug segment (bearer mode), in both cases *before*
/// any signature/key check runs. Nothing upstream constrains its charset —
/// there is no documented slug grammar and `Store::create_site` accepts any
/// `&str`. Rejecting anything that could act as a path component (a `/` or
/// `\` separator, a NUL byte, or the `.`/`..` special segments) before ever
/// joining it onto `data_dir` closes a real path-traversal hole: without
/// this, a request header like `X-FoSSH-Key-Id: ../../../../etc/passwd`
/// would make this module attempt to read a file outside `data_dir/sites/`
/// entirely, pre-authentication, on every request.
fn is_safe_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug != "."
        && slug != ".."
        && !slug.contains('/')
        && !slug.contains('\\')
        && !slug.contains('\0')
}

fn cache_path(data_dir: &Path, slug: &str) -> Option<PathBuf> {
    if !is_safe_slug(slug) {
        return None;
    }
    Some(data_dir.join("sites").join(format!("{slug}.json")))
}

/// Writes (or overwrites) a site's cache entry. Called by whatever
/// mutates the site in `fossh-store` — see the module doc comment.
pub fn write(data_dir: &Path, site: &fossh_store::Site) -> Result<(), IngestError> {
    let dir = data_dir.join("sites");
    fs::create_dir_all(&dir)?;
    let cached = CachedSite::from_site(site);
    let json = serde_json::to_vec_pretty(&cached)?;
    let Some(path) = cache_path(data_dir, &site.slug) else {
        return Err(IngestError::InvalidSlug);
    };
    // Write-then-rename: a reader (the CGI hot path) must never observe a
    // half-written file, even though updates here are rare (site
    // create/disable/rotate) compared to reads (every request).
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Reads a site's cache entry by slug. `Ok(None)` means no such site (or
/// no cache yet built for it) — callers treat that the same as "unknown
/// site", not as an error. A slug that isn't safe to use as a path
/// component (see `is_safe_slug`) is folded into this same "unknown site"
/// case rather than ever touching the filesystem with it — it can never
/// have been a real site's slug in the first place, since `write` refuses
/// to create a cache entry under one.
pub fn read(data_dir: &Path, slug: &str) -> Result<Option<CachedSite>, IngestError> {
    let Some(path) = cache_path(data_dir, slug) else {
        return Ok(None);
    };
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(IngestError::Io(e)),
    }
}

/// Removes a site's cache entry (used when a site is disabled hard enough
/// to be pulled from the fast path entirely, or in tests). Not currently
/// called by any production path — `disabled` is tracked as a field, not
/// by cache absence, so a disabled site still resolves (to a `401`)
/// instead of falling through to "unknown site" with a less specific
/// response.
#[allow(dead_code)]
pub fn remove(data_dir: &Path, slug: &str) -> Result<(), IngestError> {
    let Some(path) = cache_path(data_dir, slug) else {
        return Ok(()); // never a real cache entry — nothing to remove
    };
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(IngestError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-sitecache-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn sample_site() -> fossh_store::Site {
        fossh_store::Site {
            id: SiteId::new(7),
            slug: "blog".to_string(),
            key_hash: [0x42; 32],
            sign_pubkey: Some([0x11; 32]),
            allowlist: vec!["pageview".to_string(), "signup.completed".to_string()],
            created_at: 1_700_000_000,
            disabled: false,
            public: true,
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = scratch_dir("roundtrip");
        let site = sample_site();
        write(&dir, &site).unwrap();

        let cached = read(&dir, "blog").unwrap().expect("cache entry exists");
        assert_eq!(cached.slug, "blog");
        assert_eq!(cached.site_id(), site.id);
        assert_eq!(cached.key_hash().unwrap(), site.key_hash);
        assert_eq!(cached.sign_pubkey(), site.sign_pubkey);
        assert_eq!(cached.allowlist, site.allowlist);
        assert!(!cached.disabled);
        assert!(cached.public);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_site_with_no_signing_key_yet_reads_back_as_none() {
        let dir = scratch_dir("no-signing-key");
        let mut site = sample_site();
        site.sign_pubkey = None;
        write(&dir, &site).unwrap();

        let cached = read(&dir, "blog").unwrap().expect("cache entry exists");
        assert_eq!(cached.sign_pubkey(), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_cache_file_written_before_sign_pubkey_existed_still_reads() {
        let dir = scratch_dir("pre-fix-cache-file");
        fs::create_dir_all(dir.join("sites")).unwrap();
        fs::write(
            dir.join("sites").join("blog.json"),
            r#"{"id":7,"slug":"blog","key_hash_b32":"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","allowlist":[],"disabled":false,"public":false}"#,
        )
        .unwrap();

        let cached = read(&dir, "blog").unwrap().expect("cache entry exists");
        assert_eq!(cached.sign_pubkey_b32, None);
        assert_eq!(cached.sign_pubkey(), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_slug_reads_as_none_not_an_error() {
        let dir = scratch_dir("missing");
        assert_eq!(read(&dir, "nope").unwrap(), None);
    }

    #[test]
    fn write_overwrites_a_previous_entry() {
        let dir = scratch_dir("overwrite");
        let mut site = sample_site();
        write(&dir, &site).unwrap();
        site.disabled = true;
        write(&dir, &site).unwrap();

        let cached = read(&dir, "blog").unwrap().unwrap();
        assert!(cached.disabled);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_then_read_is_none() {
        let dir = scratch_dir("remove");
        let site = sample_site();
        write(&dir, &site).unwrap();
        remove(&dir, "blog").unwrap();
        assert_eq!(read(&dir, "blog").unwrap(), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_of_nonexistent_is_not_an_error() {
        let dir = scratch_dir("remove-missing");
        remove(&dir, "never-existed").unwrap();
    }

    #[test]
    fn is_safe_slug_rejects_path_traversal_shapes() {
        assert!(!is_safe_slug(""));
        assert!(!is_safe_slug("."));
        assert!(!is_safe_slug(".."));
        assert!(!is_safe_slug("../etc/passwd"));
        assert!(!is_safe_slug("../../secret"));
        assert!(!is_safe_slug("a/b"));
        assert!(!is_safe_slug("/etc/passwd"));
        assert!(!is_safe_slug("a\\b"));
        assert!(!is_safe_slug("a\0b"));
        assert!(is_safe_slug("blog"));
        assert!(is_safe_slug("my-site_2"));
        assert!(is_safe_slug(".hidden")); // odd, but not path-traversing
    }

    /// The regression this whole module exists to prevent: `read` is
    /// called pre-authentication with attacker-controlled input (see the
    /// module doc comment on `is_safe_slug`) — a traversal-shaped slug
    /// must never let a file outside `data_dir/sites/` be read back as a
    /// `CachedSite`, even when a real, validly-shaped JSON file happens to
    /// sit exactly where the traversal points.
    #[test]
    fn read_never_escapes_the_sites_directory_via_path_traversal() {
        let dir = scratch_dir("traversal-read");
        fs::create_dir_all(&dir).unwrap();

        // A decoy file one level above `sites/`, at exactly the path
        // `sites/../decoy.json` (== `dir/decoy.json`) would resolve to —
        // valid `CachedSite` JSON, so a successful traversal would report
        // a real (if fake) site rather than merely erroring.
        let decoy = CachedSite {
            id: 999,
            slug: "decoy".to_string(),
            key_hash_b32: base32::encode(&[0x11; 32]),
            sign_pubkey_b32: None,
            allowlist: vec!["pwned".to_string()],
            disabled: false,
            public: true,
        };
        fs::write(
            dir.join("decoy.json"),
            serde_json::to_vec_pretty(&decoy).unwrap(),
        )
        .unwrap();

        for traversal_slug in ["../decoy", "..\\decoy", "/decoy"] {
            assert_eq!(
                read(&dir, traversal_slug).unwrap(),
                None,
                "traversal slug {traversal_slug:?} must not resolve to the decoy file"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_refuses_an_unsafe_slug_instead_of_writing_outside_sites() {
        let dir = scratch_dir("traversal-write");
        let mut site = sample_site();
        site.slug = "../escape".to_string();
        let err = write(&dir, &site).unwrap_err();
        assert!(matches!(err, IngestError::InvalidSlug));
        assert!(
            !dir.join("escape.json").exists(),
            "must not have written outside data_dir/sites/"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_with_an_unsafe_slug_is_a_harmless_no_op() {
        let dir = scratch_dir("traversal-remove");
        // Must not error and, more importantly, must not touch anything
        // outside `data_dir/sites/`.
        remove(&dir, "../whatever").unwrap();
    }
}
