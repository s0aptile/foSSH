//! Transport-agnostic ingest decision logic (M7): authenticate,
//! per-site rate-limit, and validate/parse via `pipeline` — shared
//! between every ingest transport (CGI's per-request spool-append,
//! FastCGI's persistent direct-to-SQLite batching, and any future one)
//! so a security-critical path like auth and rate-limiting is written
//! and reviewed exactly once, not once per transport. Deliberately
//! stops short of persisting anything: that step differs genuinely
//! per transport (§7.1's spool-first design vs §7.2's direct writes),
//! so it stays the caller's job. `/healthz` is *not* handled here —
//! it's a trivial two-line short-circuit each transport's own top-level
//! routing does before ever reaching this module, not worth centralizing.

use std::path::{Path, PathBuf};

use fossh_core::types::{Country, Event, SiteId};

use crate::auth::{self, NonceCache};
use crate::pipeline::{self, PipelineError, PipelineOutcome, RequestContext};
use crate::ratelimit::TokenBucket;
use crate::salt::SaltManager;
use crate::site_cache::{self, CachedSite};

/// Everything about an ingest request that isn't specific to a
/// particular transport's own wire framing — CGI env vars, a FastCGI
/// PARAMS record, or an HTTP listener's headers/query string all
/// resolve into exactly this shape before reaching `decide`.
#[derive(Debug, Default, Clone)]
pub struct IngestEnv {
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

pub struct DecideParams<'a> {
    pub env: &'a IngestEnv,
    pub body: &'a [u8],
    pub data_dir: &'a Path,
    /// One directory shared by every site, not `site_dir`-scoped — see
    /// `RequestContext`'s own daily-salt field for why sharing it
    /// doesn't make visitors linkable across sites.
    pub salt_dir: &'a Path,
    pub rate_limit_per_sec: u32,
    pub rate_limit_burst: u32,
    pub respect_optout_signals: bool,
    pub now: i64,
}

pub enum IngestDecision {
    /// Nothing to persist — send this status as the whole response.
    /// Covers auth failure, rate-limit, size/validation errors, an
    /// unrecognized route under otherwise-valid auth, and a DNT/GPC
    /// opt-out (204, recording nothing, not even an aggregate counter).
    Status {
        status: u16,
        allow_origin: Option<String>,
    },
    /// Validated and ready to persist; respond 204. `site_id` rides
    /// alongside `events` rather than being read back out of
    /// `events[0]` so an empty accepted batch (`[]`, valid per the wire
    /// protocol's batch form) still identifies which site's
    /// rate-limit/salt state this request touched.
    Commit {
        site_id: SiteId,
        events: Vec<Event>,
        allow_origin: Option<String>,
    },
}

fn site_dir(data_dir: &Path, site_id: SiteId) -> PathBuf {
    data_dir.join("sites").join(site_id.get().to_string())
}

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

fn authenticate(env: &IngestEnv, body: &[u8], data_dir: &Path, now: i64) -> AuthOutcome {
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

fn cors_origin(env: &IngestEnv, site: &CachedSite) -> Option<String> {
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

/// `POST /e` and `GET /e.gif` — everything from auth through deciding
/// what (if anything) needs to be persisted. Does not persist it.
pub fn decide(params: &DecideParams) -> IngestDecision {
    let env = params.env;

    let site = match authenticate(env, params.body, params.data_dir, params.now) {
        AuthOutcome::Ok(site) => site,
        AuthOutcome::Unauthorized => {
            return IngestDecision::Status {
                status: 401,
                allow_origin: None,
            };
        }
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
        Ok(false) => {
            return IngestDecision::Status {
                status: 429,
                allow_origin: cors_origin(env, &site),
            };
        }
        Err(_) => {
            return IngestDecision::Status {
                status: 500,
                allow_origin: None,
            };
        }
    }

    let salt_mgr = SaltManager::new(params.salt_dir.to_path_buf());
    let salt = match salt_mgr.current() {
        Ok(s) => s,
        Err(_) => {
            return IngestDecision::Status {
                status: 500,
                allow_origin: None,
            };
        }
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
        _ => {
            return IngestDecision::Status {
                status: 422,
                allow_origin: cors_origin(env, &site),
            };
        }
    };

    match outcome {
        Ok(PipelineOutcome::OptedOut) => IngestDecision::Status {
            status: 204,
            allow_origin: cors_origin(env, &site),
        },
        Ok(PipelineOutcome::Accepted(events)) => IngestDecision::Commit {
            site_id: site.site_id(),
            events,
            allow_origin: cors_origin(env, &site),
        },
        Err(PipelineError::TooLarge) => IngestDecision::Status {
            status: 413,
            allow_origin: cors_origin(env, &site),
        },
        Err(PipelineError::Invalid(_)) => IngestDecision::Status {
            status: 422,
            allow_origin: cors_origin(env, &site),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::base32;
    use fossh_store::Site;
    use std::fs;
    use std::path::PathBuf;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-ingest-decide-test-{name}-{}",
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

    fn bearer_token_for(slug: &str, raw_key: &[u8; 32]) -> String {
        format!("fossh_{slug}_{}", base32::encode(raw_key))
    }

    fn base_env() -> IngestEnv {
        IngestEnv {
            method: "POST".to_string(),
            path_info: "/e".to_string(),
            remote_addr: "203.0.113.9".to_string(),
            user_agent: "Mozilla/5.0 Chrome/126.0.0.0".to_string(),
            ..Default::default()
        }
    }

    fn decide_default(dir: &Path, env: &IngestEnv, body: &[u8]) -> IngestDecision {
        decide(&DecideParams {
            env,
            body,
            data_dir: dir,
            salt_dir: dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_000_000,
        })
    }

    #[test]
    fn no_auth_headers_is_401() {
        let dir = scratch_dir("no-auth");
        let decision = decide_default(&dir, &base_env(), br#"{"name":"pageview"}"#);
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 401, .. }
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bearer_auth_wrong_key_is_401() {
        let dir = scratch_dir("bearer-wrong");
        let real_key = [0xABu8; 32];
        let real_key_hash = *blake3::hash(&real_key).as_bytes();
        seed_site(&dir, "blog", real_key_hash, &["pageview"], true);

        // Correctly *shaped* (32 raw bytes, properly base32-encoded) but
        // a different key entirely — exercises the hash-mismatch path
        // specifically, not "token fails to even parse".
        let wrong_key = [0xCDu8; 32];
        let mut env = base_env();
        env.authorization = Some(format!("Bearer {}", bearer_token_for("blog", &wrong_key)));

        let decision = decide_default(&dir, &env, br#"{"name":"pageview"}"#);
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 401, .. }
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_auth_happy_path_is_a_commit_with_no_cors_echo() {
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

        match decide_default(&dir, &env, body) {
            IngestDecision::Commit { allow_origin, .. } => {
                assert_eq!(
                    allow_origin, None,
                    "signed (non-public) sites never get a CORS echo"
                );
            }
            _ => panic!("expected Commit"),
        }
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

        assert!(matches!(
            decide_default(&dir, &env, body),
            IngestDecision::Commit { .. }
        ));
        assert!(
            matches!(
                decide_default(&dir, &env, body),
                IngestDecision::Status { status: 401, .. }
            ),
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

        let decision = decide(&DecideParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_001_000,
        });
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 401, .. }
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bearer_auth_happy_path_produces_a_commit_with_the_right_site_and_events() {
        let dir = scratch_dir("bearer-happy");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));
        env.origin = Some("https://blog.example.com".to_string());

        let decision = decide_default(&dir, &env, br#"{"name":"pageview","path":"/hello"}"#);
        match decision {
            IngestDecision::Commit {
                site_id,
                events,
                allow_origin,
            } => {
                assert_eq!(site_id, SiteId::new(1));
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].name.as_str(), "pageview");
                assert_eq!(allow_origin.as_deref(), Some("https://blog.example.com"));
            }
            _ => panic!("expected Commit"),
        }
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

        let decision = decide_default(&dir, &env, body);
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 401, .. }
        ));
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

        let params = DecideParams {
            env: &env,
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 2, // configured burst 2 -> public sites get floor(2/2)=1
            respect_optout_signals: true,
            now: 1_700_000_000,
        };
        assert!(matches!(decide(&params), IngestDecision::Commit { .. }));
        assert!(matches!(
            decide(&params),
            IngestDecision::Status { status: 429, .. }
        ));
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

        let decision = decide_default(&dir, &env, b"");
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 422, .. }
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_accepted_batch_still_carries_the_right_site_id() {
        // `[]` is a valid (if useless) JSON batch per the wire protocol
        // — `Commit` must not assume `events` is non-empty to know
        // which site's state this request touched.
        let dir = scratch_dir("empty-batch");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        seed_site(&dir, "blog", key_hash, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));

        let decision = decide_default(&dir, &env, b"[]");
        match decision {
            IngestDecision::Commit {
                site_id, events, ..
            } => {
                assert_eq!(site_id, SiteId::new(1));
                assert!(events.is_empty());
            }
            _ => panic!("expected Commit with an empty event list"),
        }
        fs::remove_dir_all(&dir).ok();
    }
}
