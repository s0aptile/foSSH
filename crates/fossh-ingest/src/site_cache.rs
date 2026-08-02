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
}

fn cache_path(data_dir: &Path, slug: &str) -> PathBuf {
    data_dir.join("sites").join(format!("{slug}.json"))
}

/// Writes (or overwrites) a site's cache entry. Called by whatever
/// mutates the site in `fossh-store` — see the module doc comment.
pub fn write(data_dir: &Path, site: &fossh_store::Site) -> Result<(), IngestError> {
    let dir = data_dir.join("sites");
    fs::create_dir_all(&dir)?;
    let cached = CachedSite::from_site(site);
    let json = serde_json::to_vec_pretty(&cached)?;
    let path = cache_path(data_dir, &site.slug);
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
/// site", not as an error.
pub fn read(data_dir: &Path, slug: &str) -> Result<Option<CachedSite>, IngestError> {
    let path = cache_path(data_dir, slug);
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
    match fs::remove_file(cache_path(data_dir, slug)) {
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
        assert_eq!(cached.allowlist, site.allowlist);
        assert!(!cached.disabled);
        assert!(cached.public);
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
}
