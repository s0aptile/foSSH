//! Request-handling decision logic, kept separate from `main.rs`'s CGI
//! env/stdin I/O glue so it's unit-testable without mocking a process
//! environment. Never touches SQLite (§7.1) — site resolution reads
//! `fossh_ingest::site_cache` instead; the spool write is the only
//! filesystem mutation on this path.

use std::path::{Path, PathBuf};

use fossh_core::types::{Country, SiteId};
use fossh_ingest::auth::{self, NonceCache};
use fossh_ingest::pipeline::{self, PipelineError, PipelineOutcome, RequestContext};
use fossh_ingest::ratelimit::TokenBucket;
use fossh_ingest::salt::SaltManager;
use fossh_ingest::site_cache::{self, CachedSite};
use fossh_ingest::spool;

#[derive(Debug, Default, Clone)]
pub struct CgiEnv {
    pub method: String,
    pub path_info: String,
    pub query_string: String,
    pub remote_addr: String,
    pub user_agent: String,
    pub referer: Option<String>,
    pub dnt: bool,
    pub gpc: bool,
    pub key_id: Option<String>,
    pub ts_header: Option<String>,
    pub nonce_header: Option<String>,
    pub sig_header: Option<String>,
    pub authorization: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgiResponse {
    pub status: u16,
    pub allow_origin: Option<String>,
    /// §7.1: "If the spool is unwritable, drop the event and exit
    /// non-zero — never block the request." The response is still built
    /// normally; `main` reads this flag afterward to decide the process
    /// exit code, separately from what was already sent to the client.
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

    fn with_origin(status: u16, allow_origin: Option<String>) -> Self {
        Self {
            status,
            allow_origin,
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

// Note there is no per-site salt path here, unlike spool/ratelimit/nonces
// below. `daily_salt` is deliberately *one* directory shared by every
// site on the install (`Config.salt_dir`, §10) — P2's hash formula
// already mixes `site_id` into `visitor_id` itself
// (`BLAKE3(daily_salt ‖ client_ip ‖ ua_string ‖ site_id)`), so sharing the
// salt does not make visitors linkable across sites; the site separation
// comes from `site_id` being part of the hash input, not from the salt.
// A separate salt file per site would just be an unshared duplicate of
// the same rotation, and would leave `Config.salt_dir` unused.

fn ratelimit_path(data_dir: &Path, site_id: SiteId) -> PathBuf {
    site_dir(data_dir, site_id).join("ratelimit.bin")
}

fn nonce_cache_path(data_dir: &Path, site_id: SiteId) -> PathBuf {
    site_dir(data_dir, site_id).join("nonces.bin")
}

enum AuthOutcome {
    Ok(CachedSite),
    Unauthorized,
}

fn authenticate(env: &CgiEnv, body: &[u8], data_dir: &Path, now: i64) -> AuthOutcome {
    if let Some(header) = &env.authorization {
        let Some(token) = header.strip_prefix("Bearer ") else {
            return AuthOutcome::Unauthorized;
        };
        let Some((slug, presented_key)) = auth::parse_write_key_token(token) else {
            return AuthOutcome::Unauthorized;
        };
        let site = match site_cache::read(data_dir, slug) {
            Ok(Some(s)) if !s.disabled => s,
            _ => return AuthOutcome::Unauthorized,
        };
        let Some(stored_hash) = site.key_hash() else {
            return AuthOutcome::Unauthorized;
        };
        return if auth::verify_bearer_key(&presented_key, &stored_hash) {
            AuthOutcome::Ok(site)
        } else {
            AuthOutcome::Unauthorized
        };
    }

    let (Some(key_id), Some(ts_str), Some(nonce), Some(sig)) = (
        &env.key_id,
        &env.ts_header,
        &env.nonce_header,
        &env.sig_header,
    ) else {
        return AuthOutcome::Unauthorized;
    };

    let Ok(ts) = ts_str.parse::<i64>() else {
        return AuthOutcome::Unauthorized;
    };
    if !auth::timestamp_in_window(ts, now) {
        return AuthOutcome::Unauthorized;
    }

    let site = match site_cache::read(data_dir, key_id) {
        Ok(Some(s)) if !s.disabled => s,
        _ => return AuthOutcome::Unauthorized,
    };
    let Some(signing_key) = site.key_hash() else {
        return AuthOutcome::Unauthorized;
    };

    let canonical = auth::canonical_string(&env.method, &env.path_info, ts, nonce, body);
    if !auth::verify_signature_b32(&signing_key, &canonical, sig) {
        return AuthOutcome::Unauthorized;
    }

    let nonce_cache = NonceCache::new(nonce_cache_path(data_dir, site.site_id()));
    match nonce_cache.check_and_record(site.id, nonce, now) {
        Ok(false) => AuthOutcome::Ok(site),
        Ok(true) => AuthOutcome::Unauthorized, // replay
        Err(_) => AuthOutcome::Unauthorized,   // S2: fail closed on cache I/O failure too
    }
}

fn cors_origin(env: &CgiEnv, site: &CachedSite) -> Option<String> {
    if site.public {
        env.origin.clone()
    } else {
        None
    }
}

/// §8: "[public keys] are rate-limited harder" — halved, floor 1.
fn effective_rate_limit(per_sec: u32, burst: u32, public: bool) -> (u32, u32) {
    if public {
        ((per_sec / 2).max(1), (burst / 2).max(1))
    } else {
        (per_sec, burst)
    }
}

pub struct HandleParams<'a> {
    pub env: &'a CgiEnv,
    pub body: &'a [u8],
    pub data_dir: &'a Path,
    /// One directory shared by every site — see the comment above on why
    /// this isn't `site_dir`-scoped like spool/ratelimit/nonces.
    pub salt_dir: &'a Path,
    pub rate_limit_per_sec: u32,
    pub rate_limit_burst: u32,
    pub respect_optout_signals: bool,
    pub now: i64,
}

/// `POST /e` and `GET /e.gif` — everything from auth through spooling.
pub fn handle_ingest(params: &HandleParams) -> CgiResponse {
    let env = params.env;

    let site = match authenticate(env, params.body, params.data_dir, params.now) {
        AuthOutcome::Ok(site) => site,
        AuthOutcome::Unauthorized => return CgiResponse::plain(401),
    };

    let (per_sec, burst) = effective_rate_limit(
        params.rate_limit_per_sec,
        params.rate_limit_burst,
        site.public,
    );
    let bucket = TokenBucket::new(
        ratelimit_path(params.data_dir, site.site_id()),
        per_sec,
        burst,
    );
    match bucket.try_consume(params.now) {
        Ok(true) => {}
        Ok(false) => return CgiResponse::with_origin(429, cors_origin(env, &site)),
        Err(_) => return CgiResponse::plain(500),
    }

    let salt_mgr = SaltManager::new(params.salt_dir.to_path_buf());
    let salt = match salt_mgr.current() {
        Ok(s) => s,
        Err(_) => return CgiResponse::plain(500),
    };

    let ctx = RequestContext {
        site_id: site.site_id(),
        site_allowlist: &site.allowlist,
        client_ip: &env.remote_addr,
        user_agent: &env.user_agent,
        referrer_header: env.referer.as_deref(),
        dnt: env.dnt,
        gpc: env.gpc,
        respect_optout_signals: params.respect_optout_signals,
        now: params.now,
        daily_salt: &salt,
        // No GeoIP database wired up yet (`country_db` support is a
        // later milestone) — "ZZ" (unknown) is a fully valid, supported
        // value per §10, not an error fallback.
        country: Country::UNKNOWN,
    };

    let outcome = match (env.method.as_str(), env.path_info.as_str()) {
        ("POST", "/e") => pipeline::from_json_body(params.body, &ctx),
        ("GET", "/e.gif") => pipeline::from_query_string(&env.query_string, &ctx),
        _ => return CgiResponse::with_origin(422, cors_origin(env, &site)),
    };

    match outcome {
        Ok(PipelineOutcome::OptedOut) => CgiResponse::with_origin(204, cors_origin(env, &site)),
        Ok(PipelineOutcome::Accepted(events)) => {
            let dir = spool_dir(params.data_dir, site.site_id());
            let mut any_failed = false;
            for event in &events {
                if spool::append_frame(&dir, event).is_err() {
                    any_failed = true;
                }
            }
            CgiResponse {
                status: 204,
                allow_origin: cors_origin(env, &site),
                spool_write_failed: any_failed,
            }
        }
        Err(PipelineError::TooLarge) => CgiResponse::with_origin(413, cors_origin(env, &site)),
        Err(PipelineError::Invalid(_)) => CgiResponse::with_origin(422, cors_origin(env, &site)),
    }
}

/// `GET /healthz` — "204, no auth, no body, no info leak" (§7.1). No
/// `data_dir` access at all, deliberately: nothing about this route
/// should be able to fail in a way that reveals anything about site
/// configuration or storage state.
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
    use fossh_store::Site;
    use std::fs;

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
            allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
            created_at: 1_700_000_000,
            disabled: false,
            public,
        };
        site_cache::write(data_dir, &site).unwrap();
    }

    /// Builds a bearer token the same way `fossh site create` does:
    /// `fossh_<slug>_<base32(raw_key)>`. Using this (instead of a
    /// hand-typed literal token string) is what makes these tests catch
    /// the raw-key-vs-string-hashing bug this file used to have.
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
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 204);
    }

    #[test]
    fn no_auth_headers_is_401() {
        let dir = scratch_dir("no-auth");
        let resp = handle_ingest(&HandleParams {
            env: &base_env(),
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 401);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bearer_auth_happy_path_is_204_and_spools_a_frame() {
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
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 204);
        assert!(!resp.spool_write_failed);
        assert_eq!(
            resp.allow_origin.as_deref(),
            Some("https://blog.example.com"),
            "public site echoes Origin"
        );

        let frames =
            spool::read_frames(&spool_dir(&dir, SiteId::new(1)).join("current.bin")).unwrap();
        assert_eq!(frames.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bearer_auth_wrong_key_is_401() {
        let dir = scratch_dir("bearer-wrong");
        let real_key = [0xABu8; 32];
        let real_key_hash = *blake3::hash(&real_key).as_bytes();
        seed_site(&dir, "blog", real_key_hash, &["pageview"], true);

        // Correctly *shaped* (32 raw bytes, properly base32-encoded) but a
        // different key entirely — exercises the hash-mismatch path
        // specifically, not "token fails to even parse".
        let wrong_key = [0xCDu8; 32];
        let mut env = base_env();
        env.authorization = Some(format!("Bearer {}", bearer_token_for("blog", &wrong_key)));
        let resp = handle_ingest(&HandleParams {
            env: &env,
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 401);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_auth_happy_path() {
        let dir = scratch_dir("signed-happy");
        let signing_key = [9u8; 32]; // stands in for `site.key_hash` — see auth.rs's module doc comment
        seed_site(&dir, "blog", signing_key, &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(base32::encode(&auth::sign(&signing_key, &canonical)));

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.allow_origin, None,
            "signed (non-public) sites never get a CORS echo"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_auth_replayed_nonce_is_401() {
        let dir = scratch_dir("signed-replay");
        let signing_key = [9u8; 32];
        seed_site(&dir, "blog", signing_key, &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(base32::encode(&auth::sign(&signing_key, &canonical)));

        let params = HandleParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        };
        assert_eq!(handle_ingest(&params).status, 204);
        assert_eq!(
            handle_ingest(&params).status,
            401,
            "the same nonce presented twice must be rejected"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_auth_stale_timestamp_is_401() {
        let dir = scratch_dir("signed-stale");
        let signing_key = [9u8; 32];
        seed_site(&dir, "blog", signing_key, &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string()); // request "now" below is far outside the 300s window
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(base32::encode(&auth::sign(&signing_key, &canonical)));

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_001_000,
        });
        assert_eq!(resp.status, 401);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disabled_site_is_401_even_with_a_valid_signature() {
        let dir = scratch_dir("disabled");
        let signing_key = [9u8; 32];
        let site = Site {
            id: SiteId::new(1),
            slug: "blog".to_string(),
            key_hash: signing_key,
            allowlist: vec!["pageview".to_string()],
            created_at: 1_700_000_000,
            disabled: true,
            public: false,
        };
        site_cache::write(&dir, &site).unwrap();

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(base32::encode(&auth::sign(&signing_key, &canonical)));

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 401);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_route_under_valid_auth_is_422() {
        let dir = scratch_dir("unknown-route");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.method = "DELETE".to_string();
        env.authorization = Some(format!("Bearer {token}"));

        let resp = handle_ingest(&HandleParams {
            env: &env,
            body: b"",
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        });
        assert_eq!(resp.status, 422);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn public_site_gets_halved_rate_limit() {
        let dir = scratch_dir("public-ratelimit");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));

        let params = HandleParams {
            env: &env,
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 2, // configured burst 2 -> public sites get floor(2/2)=1
            respect_optout_signals: true,
            now: 1_700_000_000,
        };
        assert_eq!(
            handle_ingest(&params).status,
            204,
            "first event within the halved burst of 1"
        );
        assert_eq!(
            handle_ingest(&params).status,
            429,
            "second event exceeds the halved burst"
        );
        fs::remove_dir_all(&dir).ok();
    }

    // Token parsing itself (`parse_write_key_token`) is tested where it
    // now lives, in `fossh_ingest::auth`. `bearer_token_for` above and
    // the auth-flow tests earlier in this module already exercise it
    // end to end through `authenticate`.
}
