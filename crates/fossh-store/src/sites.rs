//! Site CRUD (§9: `fossh site create|list|disable|rotate-key`). Key
//! *generation* and the write-key wire format (`fossh_<slug>_<base32>`)
//! belong to whichever crate authenticates requests (`fossh-ingest`) and
//! whichever generates them for an operator (`fossh-cli`) — this module
//! only ever sees and stores `BLAKE3(key)`, never the key itself (§8: "the
//! key itself is never stored").
//!
//! `public` (added beyond §6's literal `CREATE TABLE`, see DECISIONS.md):
//! §8 describes bearer-mode keys as "flagged `public=1` at creation, ...
//! rate-limited harder, and [restricted to] the site's allowlist" — a
//! column §6's own schema snippet never defines. `fossh-ingest` uses it to
//! decide both the harder rate limit and whether to echo `Origin` back in
//! `Access-Control-Allow-Origin` (only ever for public/browser-facing
//! sites; signed server-to-server requests aren't browser requests, so
//! CORS doesn't apply to them at all).

use rusqlite::{OptionalExtension, params};

use fossh_core::types::SiteId;

use crate::{Store, StoreError};

#[derive(Debug, Clone, PartialEq)]
pub struct Site {
    pub id: SiteId,
    pub slug: String,
    pub key_hash: [u8; 32],
    pub sign_pubkey: Option<[u8; 32]>,
    pub allowlist: Vec<String>,
    pub created_at: i64,
    pub disabled: bool,
    pub public: bool,
}

#[allow(clippy::too_many_arguments)]
fn row_to_site(
    id: i64,
    slug: String,
    key_hash: Vec<u8>,
    sign_pubkey: Option<Vec<u8>>,
    allowlist_json: String,
    created_at: i64,
    disabled: i64,
    public: i64,
) -> Result<Site, StoreError> {
    let key_hash: [u8; 32] = key_hash.try_into().map_err(|_| StoreError::CorruptSketch)?;
    let sign_pubkey = sign_pubkey
        .map(|b| <[u8; 32]>::try_from(b).map_err(|_| StoreError::CorruptSketch))
        .transpose()?;
    let allowlist: Vec<String> = serde_json::from_str(&allowlist_json)?;
    Ok(Site {
        id: SiteId::new(id as u32),
        slug,
        key_hash,
        sign_pubkey,
        allowlist,
        created_at,
        disabled: disabled != 0,
        public: public != 0,
    })
}

const SITE_COLUMNS: &str =
    "id, slug, key_hash, sign_pubkey, allowlist, created_at, disabled, public";

#[allow(clippy::type_complexity)]
fn map_site_row(
    row: &rusqlite::Row,
) -> rusqlite::Result<(
    i64,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    i64,
    i64,
    i64,
)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn create_site(
        &self,
        slug: &str,
        key_hash: &[u8; 32],
        sign_pubkey: Option<&[u8; 32]>,
        allowlist: &[String],
        created_at: i64,
        public: bool,
    ) -> Result<SiteId, StoreError> {
        let allowlist_json = serde_json::to_string(allowlist)?;
        self.conn.execute(
            "INSERT INTO sites (slug, key_hash, sign_pubkey, allowlist, created_at, disabled, public) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                slug,
                key_hash.as_slice(),
                sign_pubkey.map(|k| k.as_slice()),
                allowlist_json,
                created_at,
                public
            ],
        )?;
        Ok(SiteId::new(self.conn.last_insert_rowid() as u32))
    }

    pub fn find_site_by_key_hash(&self, key_hash: &[u8; 32]) -> Result<Option<Site>, StoreError> {
        self.conn
            .query_row(
                &format!("SELECT {SITE_COLUMNS} FROM sites WHERE key_hash = ?1"),
                params![key_hash.as_slice()],
                map_site_row,
            )
            .optional()?
            .map(|(id, slug, kh, spk, al, ca, d, p)| row_to_site(id, slug, kh, spk, al, ca, d, p))
            .transpose()
    }

    pub fn find_site_by_slug(&self, slug: &str) -> Result<Option<Site>, StoreError> {
        self.conn
            .query_row(
                &format!("SELECT {SITE_COLUMNS} FROM sites WHERE slug = ?1"),
                params![slug],
                map_site_row,
            )
            .optional()?
            .map(|(id, slug, kh, spk, al, ca, d, p)| row_to_site(id, slug, kh, spk, al, ca, d, p))
            .transpose()
    }

    pub fn list_sites(&self) -> Result<Vec<Site>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {SITE_COLUMNS} FROM sites ORDER BY id"))?;
        let rows = stmt.query_map([], map_site_row)?;
        rows.map(|r| {
            let (id, slug, kh, spk, al, ca, d, p) = r?;
            row_to_site(id, slug, kh, spk, al, ca, d, p)
        })
        .collect()
    }

    /// Returns whether a site was found and disabled.
    pub fn disable_site(&self, slug: &str) -> Result<bool, StoreError> {
        let affected = self.conn.execute(
            "UPDATE sites SET disabled = 1 WHERE slug = ?1",
            params![slug],
        )?;
        Ok(affected > 0)
    }

    /// Returns whether a site was found and rotated. Only `key_hash`
    /// (the bearer-mode verifier) changes — `sign_pubkey` is a separate
    /// credential with its own rotation entry point, `set_sign_pubkey`.
    pub fn rotate_site_key(&self, slug: &str, new_key_hash: &[u8; 32]) -> Result<bool, StoreError> {
        let affected = self.conn.execute(
            "UPDATE sites SET key_hash = ?1 WHERE slug = ?2",
            params![new_key_hash.as_slice(), slug],
        )?;
        Ok(affected > 0)
    }

    /// Returns whether a site was found and given a new signed-mode
    /// verifying key. Independent of `rotate_site_key`: a site's bearer
    /// write key and its signed-mode keypair are two different
    /// credentials, rotated separately.
    pub fn set_sign_pubkey(&self, slug: &str, new_sign_pubkey: &[u8; 32]) -> Result<bool, StoreError> {
        let affected = self.conn.execute(
            "UPDATE sites SET sign_pubkey = ?1 WHERE slug = ?2",
            params![new_sign_pubkey.as_slice(), slug],
        )?;
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn create_and_find_by_slug() {
        let store = Store::open_in_memory().unwrap();
        let allow = vec!["pageview".to_string(), "signup.completed".to_string()];
        let id = store
            .create_site("blog", &hash_of(1), None, &allow, 1_700_000_000, false)
            .unwrap();

        let site = store
            .find_site_by_slug("blog")
            .unwrap()
            .expect("site exists");
        assert_eq!(site.id, id);
        assert_eq!(site.slug, "blog");
        assert_eq!(site.key_hash, hash_of(1));
        assert_eq!(site.sign_pubkey, None);
        assert_eq!(site.allowlist, allow);
        assert!(!site.disabled);
        assert!(!site.public);
    }

    #[test]
    fn create_site_can_carry_a_sign_pubkey_from_the_start() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site(
                "blog",
                &hash_of(1),
                Some(&hash_of(9)),
                &[],
                1_700_000_000,
                false,
            )
            .unwrap();
        let site = store.find_site_by_slug("blog").unwrap().unwrap();
        assert_eq!(site.sign_pubkey, Some(hash_of(9)));
    }

    #[test]
    fn public_flag_is_stored() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(1), None, &[], 1_700_000_000, true)
            .unwrap();
        let site = store.find_site_by_slug("blog").unwrap().unwrap();
        assert!(site.public);
    }

    #[test]
    fn find_by_key_hash() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(7), None, &[], 1_700_000_000, false)
            .unwrap();
        let site = store
            .find_site_by_key_hash(&hash_of(7))
            .unwrap()
            .expect("found by key hash");
        assert_eq!(site.slug, "blog");
        assert!(store.find_site_by_key_hash(&hash_of(8)).unwrap().is_none());
    }

    #[test]
    fn slug_must_be_unique() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(1), None, &[], 1_700_000_000, false)
            .unwrap();
        let result = store.create_site("blog", &hash_of(2), None, &[], 1_700_000_001, false);
        assert!(
            result.is_err(),
            "duplicate slug must be rejected (UNIQUE constraint)"
        );
    }

    #[test]
    fn list_sites_returns_all_in_creation_order() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("a", &hash_of(1), None, &[], 1, false)
            .unwrap();
        store
            .create_site("b", &hash_of(2), None, &[], 2, false)
            .unwrap();
        let sites = store.list_sites().unwrap();
        assert_eq!(
            sites.iter().map(|s| s.slug.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn disable_site_marks_disabled_and_reports_whether_found() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(1), None, &[], 1, false)
            .unwrap();
        assert!(store.disable_site("blog").unwrap());
        assert!(!store.disable_site("does-not-exist").unwrap());

        let site = store.find_site_by_slug("blog").unwrap().unwrap();
        assert!(site.disabled);
    }

    #[test]
    fn rotate_key_updates_hash_and_old_hash_stops_matching() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(1), None, &[], 1, false)
            .unwrap();
        assert!(store.rotate_site_key("blog", &hash_of(2)).unwrap());

        assert!(store.find_site_by_key_hash(&hash_of(1)).unwrap().is_none());
        assert!(store.find_site_by_key_hash(&hash_of(2)).unwrap().is_some());
    }

    #[test]
    fn rotate_key_on_missing_slug_reports_false() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.rotate_site_key("nope", &hash_of(1)).unwrap());
    }

    #[test]
    fn set_sign_pubkey_is_independent_of_the_bearer_key_hash() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_site("blog", &hash_of(1), None, &[], 1, false)
            .unwrap();
        assert!(store.set_sign_pubkey("blog", &hash_of(9)).unwrap());

        let site = store.find_site_by_slug("blog").unwrap().unwrap();
        assert_eq!(site.key_hash, hash_of(1), "bearer key_hash must be untouched");
        assert_eq!(site.sign_pubkey, Some(hash_of(9)));
    }

    #[test]
    fn set_sign_pubkey_on_missing_slug_reports_false() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.set_sign_pubkey("nope", &hash_of(1)).unwrap());
    }
}
