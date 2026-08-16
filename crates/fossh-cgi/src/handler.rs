use std::path::{Path, PathBuf};

use fossh_core::types::SiteId;
use fossh_ingest::geoip::GeoipReader;
use fossh_ingest::ingest::{self, IngestDecision};
use fossh_ingest::spool;

pub type CgiEnv = ingest::IngestEnv;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgiResponse {
    pub status: u16,
    pub allow_origin: Option<String>,

    pub spool_write_failed: bool,
}

impl CgiResponse {
    fn plain(status: u16) -> Self {
        Self {
            status,
            allow_origin: None,
            spool_write_failed: false,
        }
    }
}

fn site_dir(data_dir: &Path, site_id: SiteId) -> PathBuf {
    data_dir.join("sites").join(site_id.get().to_string())
}

fn spool_dir(data_dir: &Path, site_id: SiteId) -> PathBuf {
    site_dir(data_dir, site_id).join("spool")
}

pub struct HandleParams<'a> {
    pub env: &'a CgiEnv,
    pub body: &'a [u8],
    pub data_dir: &'a Path,

    pub salt_dir: &'a Path,

    pub data_key: &'a [u8; 32],
    pub rate_limit_per_sec: u32,
    pub rate_limit_burst: u32,
    pub respect_optout_signals: bool,
    pub now: i64,

    pub country_db: &'a GeoipReader,
}

pub fn handle_ingest(params: &HandleParams) -> CgiResponse {
    let decision = ingest::decide(&ingest::DecideParams {
        env: params.env,
        body: params.body,
        data_dir: params.data_dir,
        salt_dir: params.salt_dir,
        rate_limit_per_sec: params.rate_limit_per_sec,
        rate_limit_burst: params.rate_limit_burst,
        respect_optout_signals: params.respect_optout_signals,
        now: params.now,
        country_db: params.country_db,
    });

    match decision {
        IngestDecision::Status {
            status,
            allow_origin,
        } => CgiResponse {
            status,
            allow_origin,
            spool_write_failed: false,
        },
        IngestDecision::Commit {
            site_id,
            events,
            allow_origin,
        } => {
            let dir = spool_dir(params.data_dir, site_id);
            let mut any_failed = false;
            for event in &events {
                if spool::append_frame(&dir, event, params.data_key).is_err() {
                    any_failed = true;
                }
            }
            CgiResponse {
                status: 204,
                allow_origin,
                spool_write_failed: any_failed,
            }
        }
    }
}

pub fn handle_healthz() -> CgiResponse {
    CgiResponse::plain(204)
}

pub fn route(params: &HandleParams) -> CgiResponse {
    if params.env.method == "GET" && params.env.path_info == "/healthz" {
        return handle_healthz();
    }
    handle_ingest(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::base32;
    use fossh_ingest::site_cache;
    use fossh_store::Site;
    use std::fs;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-cgi-handler-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn seed_site(
        data_dir: &Path,
        slug: &str,
        key_hash: [u8; 32],
        allowlist: &[&str],
        public: bool,
    ) {
        let site = Site {
            id: SiteId::new(1),
            slug: slug.to_string(),
            key_hash,
            sign_pubkey: None,
            allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
            created_at: 1_700_000_000,
            disabled: false,
            public,
        };
        site_cache::write(data_dir, &site).unwrap();
    }

    fn bearer_token_for(slug: &str, raw_key: &[u8; 32]) -> String {
        format!("fossh_{slug}_{}", base32::encode(raw_key))
    }

    fn base_env() -> CgiEnv {
        CgiEnv {
            method: "POST".to_string(),
            path_info: "/e".to_string(),
            remote_addr: "203.0.113.9".to_string(),
            user_agent: "Mozilla/5.0 Chrome/126.0.0.0".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn healthz_never_touches_data_dir() {
        let resp = route(&HandleParams {
            env: &CgiEnv {
                method: "GET".to_string(),
                path_info: "/healthz".to_string(),
                ..Default::default()
            },
            body: b"",
            data_dir: Path::new("/nonexistent/path/that/does/not/exist"),
            salt_dir: Path::new("/nonexistent/path/that/does/not/exist"),
            data_key: &TEST_KEY,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
            country_db: &GeoipReader::none(),
        });
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn a_status_decision_passes_through_unchanged() {
        let dir = scratch_dir("no-auth");
        let resp = handle_ingest(&HandleParams {
            env: &base_env(),
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            data_key: &TEST_KEY,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
            country_db: &GeoipReader::none(),
        });
        assert_eq!(resp.status, 401);
        assert!(!resp.spool_write_failed);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_commit_decision_is_204_and_spools_a_frame() {
        let dir = scratch_dir("bearer-happy");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));
        env.origin = Some("https://blog.example.com".to_string());

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body: br#"{"name":"pageview","path":"/hello"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            data_key: &TEST_KEY,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
            country_db: &GeoipReader::none(),
        });
        assert_eq!(resp.status, 204);
        assert!(!resp.spool_write_failed);
        assert_eq!(
            resp.allow_origin.as_deref(),
            Some("https://blog.example.com"),
            "public site echoes Origin"
        );

        let frames = spool::read_frames(
            &spool_dir(&dir, SiteId::new(1)).join("current.bin"),
            &TEST_KEY,
        )
        .unwrap();
        assert_eq!(frames.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_commit_batch_spools_nothing_and_still_reports_204() {
        let dir = scratch_dir("empty-batch");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body: b"[]",
            data_dir: &dir,
            salt_dir: &dir,
            data_key: &TEST_KEY,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
            country_db: &GeoipReader::none(),
        });
        assert_eq!(resp.status, 204);
        assert!(!resp.spool_write_failed);

        let spool_path = spool_dir(&dir, SiteId::new(1)).join("current.bin");
        assert!(
            !spool_path.exists(),
            "an empty batch must not create a spool file at all"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
