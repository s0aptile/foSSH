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

    pub fn sign_pubkey(&self) -> Option<[u8; 32]> {
        let bytes = base32::decode(self.sign_pubkey_b32.as_deref()?)?;
        <[u8; 32]>::try_from(bytes).ok()
    }
}

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

pub fn write(data_dir: &Path, site: &fossh_store::Site) -> Result<(), IngestError> {
    let dir = data_dir.join("sites");
    fs::create_dir_all(&dir)?;
    let cached = CachedSite::from_site(site);
    let json = serde_json::to_vec_pretty(&cached)?;
    let Some(path) = cache_path(data_dir, &site.slug) else {
        return Err(IngestError::InvalidSlug);
    };

    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, json)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

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

#[allow(dead_code)]
pub fn remove(data_dir: &Path, slug: &str) -> Result<(), IngestError> {
    let Some(path) = cache_path(data_dir, slug) else {
        return Ok(());
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
        assert!(is_safe_slug(".hidden"));
    }

    #[test]
    fn read_never_escapes_the_sites_directory_via_path_traversal() {
        let dir = scratch_dir("traversal-read");
        fs::create_dir_all(&dir).unwrap();

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

        remove(&dir, "../whatever").unwrap();
    }
}
