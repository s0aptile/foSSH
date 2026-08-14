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

use fossh_core::types::{Event, SiteId};

use crate::auth::{self, NonceCache};
use crate::geoip::GeoipReader;
use crate::pipeline::{self, PipelineError, PipelineOutcome, RequestContext};
use crate::ratelimit::{IpFailBucket, TokenBucket};
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
    /// Built once at process start from `Config.country_db` (§10), not
    /// per request — see `geoip::GeoipReader`'s own doc comment for why.
    /// `GeoipReader::none()` (no database loaded) makes every event
    /// `Country::UNKNOWN`, which is the correct, fully-supported
    /// behavior for `country_db = "none"` and for any deployment that
    /// hasn't configured a database yet.
    pub country_db: &'a GeoipReader,
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

/// Deliberately *not* under `sites/<slug>/` like the two paths above —
/// this bucket is keyed by source IP, not by site, and has to exist
/// (and mean the same thing) for a request that never resolved to any
/// site at all, which is exactly the case it exists to cover. One file,
/// shared across every site this install serves.
fn ip_fail_bucket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("ip_fail_ratelimit.bin")
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
    let Some(verifying_key) = site.sign_pubkey() else {
        return AuthOutcome::Unauthorized;
    };

    let canonical = auth::canonical_string(&env.method, &env.path_info, ts, nonce, body);
    if !auth::verify_signature_b32(&verifying_key, &canonical, sig) {
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
            // No `site_id` was ever resolved on this path, so `TokenBucket`
            // below (keyed by `site_id`, only ever reached from the `Ok`
            // arm) never sees this request — S10 scopes it per-site on
            // purpose. Left alone, that means a source that never had a
            // valid key gets zero in-app throttling at all: confirmed
            // empirically, not just from reading the call graph — 80
            // back-to-back wrong-key requests against a real site all
            // came back 401, never once 429. `IpFailBucket` (see its own
            // doc comment in ratelimit.rs) closes that gap specifically:
            // keyed by source IP, consulted only here, on the failure
            // path — a caller that always authenticates correctly (the
            // shared-hosting relay / second-VPS shape this matters most
            // for, per docs/INTEGRATION-php.md and docs/DEPLOY-apache.md)
            // never touches it. An I/O error recording the attempt still
            // answers 401, not 500 — the request was already being
            // refused either way; a bookkeeping failure on *how many
            // times* that's happened must not change that it's refused
            // (S2's fail-closed posture is about the auth decision
            // itself, already made above, not about this counter).
            let ip_bucket = IpFailBucket::new(ip_fail_bucket_path(params.data_dir));
            let status = match ip_bucket.record_failure(&env.remote_addr, params.now) {
                Ok(true) | Err(_) => 401,
                Ok(false) => 429,
            };
            return IngestDecision::Status {
                status,
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
        // `resolve` itself fails closed to `Country::UNKNOWN` for a
        // `none()` reader, a database that failed to load, an address
        // with no entry, or any decode failure — see `geoip.rs`. Reuses
        // `env.remote_addr`, the same already-resolved client IP
        // `client_ip` above uses (via `forwarded::resolve_client_ip`
        // upstream in the transport's `main.rs`) — not a second,
        // parallel way of extracting an address.
        country: params.country_db.resolve(&env.remote_addr),
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
        sign_pubkey: Option<[u8; 32]>,
        allowlist: &[&str],
        public: bool,
    ) {
        let site = Site {
            id: SiteId::new(1),
            slug: slug.to_string(),
            key_hash,
            sign_pubkey,
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

    fn signing_keypair(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let verifying_key_bytes = signing_key.verifying_key().to_bytes();
        (signing_key, verifying_key_bytes)
    }

    fn signed_header(signing_key: &ed25519_dalek::SigningKey, canonical: &str) -> String {
        base32::encode(&auth::sign(signing_key, canonical).to_bytes())
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
            country_db: &GeoipReader::none(),
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
        seed_site(&dir, "blog", real_key_hash, None, &["pageview"], true);

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
        let (signing_key, verifying_key) = signing_keypair(9);
        seed_site(&dir, "blog", [0u8; 32], Some(verifying_key), &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(signed_header(&signing_key, &canonical));

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

    /// B-03 regression: a site created before the Ed25519 fix (or never
    /// opted into signed mode via `rotate-signing-key`) has no
    /// `sign_pubkey` on file. Signed-mode auth for it must fail closed,
    /// not fall back to any other value — see `authenticate`'s
    /// `site.sign_pubkey()` check.
    #[test]
    fn signed_auth_against_a_site_with_no_sign_pubkey_yet_is_401() {
        let dir = scratch_dir("signed-no-pubkey");
        let (signing_key, _unrelated_verifying_key) = signing_keypair(9);
        seed_site(&dir, "blog", [0u8; 32], None, &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(signed_header(&signing_key, &canonical));

        let decision = decide_default(&dir, &env, body);
        assert!(matches!(
            decision,
            IngestDecision::Status { status: 401, .. }
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// B-03 regression, exercised through the real `decide()` entry
    /// point: an attacker holding only what a stolen `sites` row or
    /// leaked `site_cache` JSON file would expose (`site.key_hash`, the
    /// bearer verifier) must not be able to forge a signed-mode request.
    /// Under the old BLAKE3-keyed-hash design this exact scenario
    /// produced a `Commit` — it must now be a `401`.
    #[test]
    fn stolen_key_hash_alone_cannot_forge_a_signed_request() {
        let dir = scratch_dir("b03-regression");
        let write_key = [0x77u8; 32];
        let key_hash = *blake3::hash(&write_key).as_bytes();
        let (_real_signing_key, real_verifying_key) = signing_keypair(9);
        seed_site(&dir, "blog", key_hash, Some(real_verifying_key), &["pageview"], false);
        let _ = write_key;

        let stolen_key_hash = key_hash;
        let attacker_signing_key = ed25519_dalek::SigningKey::from_bytes(&stolen_key_hash);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("attacker-nonce".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical =
            auth::canonical_string("POST", "/e", 1_700_000_000, "attacker-nonce", body);
        env.sig_header = Some(signed_header(&attacker_signing_key, &canonical));

        let decision = decide_default(&dir, &env, body);
        assert!(
            matches!(decision, IngestDecision::Status { status: 401, .. }),
            "a request forged from the stolen bearer verifier alone must be rejected"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_auth_replayed_nonce_is_401() {
        let dir = scratch_dir("signed-replay");
        let (signing_key, verifying_key) = signing_keypair(9);
        seed_site(&dir, "blog", [0u8; 32], Some(verifying_key), &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string());
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(signed_header(&signing_key, &canonical));

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
        let (signing_key, verifying_key) = signing_keypair(9);
        seed_site(&dir, "blog", [0u8; 32], Some(verifying_key), &["pageview"], false);

        let mut env = base_env();
        env.key_id = Some("blog".to_string());
        env.ts_header = Some("1700000000".to_string()); // request "now" below is far outside the 300s window
        env.nonce_header = Some("nonce-1".to_string());
        let body: &[u8] = br#"{"name":"pageview"}"#;
        let canonical = auth::canonical_string("POST", "/e", 1_700_000_000, "nonce-1", body);
        env.sig_header = Some(signed_header(&signing_key, &canonical));

        let decision = decide(&DecideParams {
            env: &env,
            body,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            now: 1_700_001_000,
            country_db: &GeoipReader::none(),
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
        seed_site(&dir, "blog", key_hash, None, &["pageview"], true);
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
        let (signing_key, verifying_key) = signing_keypair(9);
        let site = Site {
            id: SiteId::new(1),
            slug: "blog".to_string(),
            key_hash: [0u8; 32],
            sign_pubkey: Some(verifying_key),
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
        env.sig_header = Some(signed_header(&signing_key, &canonical));

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
        seed_site(&dir, "blog", key_hash, None, &["pageview"], true);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));

        let geoip = GeoipReader::none();
        let params = DecideParams {
            env: &env,
            body: br#"{"name":"pageview"}"#,
            data_dir: &dir,
            salt_dir: &dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 2, // configured burst 2 -> public sites get floor(2/2)=1
            respect_optout_signals: true,
            now: 1_700_000_000,
            country_db: &geoip,
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
        seed_site(&dir, "blog", key_hash, None, &["pageview"], true);
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
        seed_site(&dir, "blog", key_hash, None, &["pageview"], true);
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

    // ---- IpFailBucket wiring: the fix for the empirically-confirmed
    // gap (80 back-to-back wrong-key requests from one source, all 401,
    // never once 429 — see ratelimit.rs's own doc comment on
    // `IpFailBucket` and this file's `decide()` for the full story) ----

    #[test]
    fn a_sustained_wrong_key_flood_from_one_source_eventually_gets_429() {
        let dir = scratch_dir("ip-fail-flood");
        let real_key = [0xABu8; 32];
        let real_key_hash = *blake3::hash(&real_key).as_bytes();
        seed_site(&dir, "blog", real_key_hash, None, &["pageview"], true);

        let wrong_key = [0xCDu8; 32];
        let mut env = base_env();
        env.authorization = Some(format!("Bearer {}", bearer_token_for("blog", &wrong_key)));

        // IpFailBucket's burst is 20 (ratelimit.rs) — the real-world
        // reproduction that motivated this fix ran 80 straight requests
        // and got 401 every single time. Reproduce the same shape here:
        // the first 20 must still be 401 (each one legitimately *is*
        // unauthorized, and the caller must keep saying so, not switch
        // to 429 prematurely)...
        for i in 0..20 {
            let decision = decide_default(&dir, &env, br#"{"name":"pageview"}"#);
            assert!(
                matches!(decision, IngestDecision::Status { status: 401, .. }),
                "request {i} within the burst allowance must still be 401"
            );
        }
        // ...and the 21st, same instant, must now be 429 — this is
        // exactly the transition that never happened before this fix.
        let decision = decide_default(&dir, &env, br#"{"name":"pageview"}"#);
        assert!(
            matches!(decision, IngestDecision::Status { status: 429, .. }),
            "a sustained flood of wrong-key requests from one source must eventually get 429, not 401 forever"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legitimate_high_volume_caller_never_touches_the_ip_fail_bucket() {
        // The whole reason IpFailBucket is only consulted on the
        // *failure* path: a shared-hosting relay or a second VPS
        // (docs/INTEGRATION-php.md, docs/DEPLOY-apache.md) sends every
        // real visitor's event from the same source IP, correctly
        // authenticated, at real volume — that traffic must never be
        // throttled by this new mechanism, only by the pre-existing
        // per-site TokenBucket it already correctly respects.
        let dir = scratch_dir("ip-fail-legit-caller");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        // A generous per-site limit so this test is only ever exercising
        // IpFailBucket's behavior, not TokenBucket's.
        seed_site(&dir, "blog", key_hash, None, &["pageview"], false);
        let token = bearer_token_for("blog", &raw_key);

        let mut env = base_env();
        env.authorization = Some(format!("Bearer {token}"));

        // Comfortably past IpFailBucket's burst of 20 — if a correctly-
        // authenticated request touched that bucket at all, this would
        // start failing well before 100 iterations.
        for i in 0..100 {
            let decision = decide(&DecideParams {
                env: &env,
                body: br#"{"name":"pageview"}"#,
                data_dir: &dir,
                salt_dir: &dir,
                rate_limit_per_sec: 10_000,
                rate_limit_burst: 10_000,
                respect_optout_signals: true,
                now: 1_700_000_000,
                country_db: &GeoipReader::none(),
            });
            assert!(
                matches!(decision, IngestDecision::Commit { .. }),
                "correctly-authenticated request {i} must never be throttled by the failed-auth bucket"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_throttled_failure_history_does_not_block_a_subsequent_correct_key_request() {
        let dir = scratch_dir("ip-fail-recovers");
        let real_key = [0xABu8; 32];
        let real_key_hash = *blake3::hash(&real_key).as_bytes();
        seed_site(&dir, "blog", real_key_hash, None, &["pageview"], true);

        let wrong_key = [0xCDu8; 32];
        let mut bad_env = base_env();
        bad_env.authorization = Some(format!("Bearer {}", bearer_token_for("blog", &wrong_key)));

        for _ in 0..21 {
            decide_default(&dir, &bad_env, br#"{"name":"pageview"}"#);
        }
        let throttled = decide_default(&dir, &bad_env, br#"{"name":"pageview"}"#);
        assert!(matches!(
            throttled,
            IngestDecision::Status { status: 429, .. }
        ));

        // A *correctly*-authenticated request from the same source,
        // right after, must not be caught up in the same throttling —
        // the bucket only ever records failures, so it has nothing to
        // do with this request at all.
        let token = bearer_token_for("blog", &real_key);
        let mut good_env = base_env();
        good_env.authorization = Some(format!("Bearer {token}"));
        let ok_decision = decide_default(&dir, &good_env, br#"{"name":"pageview"}"#);
        assert!(
            matches!(ok_decision, IngestDecision::Commit { .. }),
            "a correctly-authenticated request from a source with a throttled failure history must still succeed"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
