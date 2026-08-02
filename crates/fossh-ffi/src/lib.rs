//! §11 C ABI: the embedded (FFI) deployment shape — "no process, no
//! socket, no port." This is the *only* crate in the whole project where
//! `unsafe` is permitted (S1: `#![forbid(unsafe_code)]` everywhere else).
//! Every `unsafe` block below is confined to converting a raw pointer
//! handed across the FFI boundary into a safe Rust reference/slice/`&str`
//! — nothing past that conversion is ever `unsafe`; all the actual logic
//! is ordinary calls into `fossh-core`/`fossh-store`/`fossh-ingest`.
//!
//! Every `extern "C" fn` below wraps its body in `catch_unwind` (S2, §11:
//! "a panic becomes `FOSSH_ERR_INTERNAL`, never an unwind across the FFI
//! boundary" — unwinding into C is undefined behavior, not just "a bug").
//! That's *why* this crate is a separate Cargo workspace with
//! `panic = "unwind"` rather than joining the root workspace's
//! `panic = "abort"` profile: `catch_unwind` cannot catch anything under
//! `panic = "abort"`, since the process is already gone by the time it
//! would run. See `DECISIONS.md` ADR-0002.
//!
//! `fossh_ctx` is `Send + Sync`; all mutable state lives behind one
//! `Mutex`, held only across the write path (§11).
//!
//! Unlike `fossh-cgi` (a network-facing CGI process, where every request
//! must prove possession of a site's write key via HMAC or bearer auth —
//! §8), a host process linking this library *is* the trusted caller:
//! there is no network hop to defend against for an in-process function
//! call. `fossh_set_key` therefore authenticates once, at setup, by
//! looking the site up in the database and checking the presented key's
//! hash — not by re-deriving an HMAC signature per call the way `fossh-cgi`
//! does for network requests.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::sync::Mutex;

use fossh_core::config::Config;
use fossh_core::types::{Country, Event, SiteId};
use fossh_ingest::pipeline::{self, EventFields, PipelineError, PipelineOutcome, RequestContext};
use fossh_ingest::salt::InMemorySalt;
use fossh_ingest::{auth, compact, spool};
use fossh_store::Store;

/// §11: "`fossh_abi_version()` returns a `u32` the bindings check at
/// load." Bump on any breaking change to the functions below.
pub const FOSSH_ABI_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn fossh_abi_version() -> u32 {
    FOSSH_ABI_VERSION
}

/// Stable, versioned error codes (§11). Negative on every rejection path;
/// `0` is success. Never carries a dynamic message — `fossh_last_error`
/// maps each variant to one of a fixed set of strings, on purpose: S2
/// forbids leaking anything caller-controlled (a name, a path, a JSON
/// parse error naming a byte offset into the caller's own data) back
/// across a boundary whose whole point is not to have a body/message
/// channel for the ingest path.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FosshError {
    Internal = -1,
    InvalidArgument = -2,
    NoKeySet = -3,
    Unauthorized = -4,
    Rejected = -5,
    TooLarge = -6,
    RateLimited = -7,
    WriteFailed = -8,
}

impl FosshError {
    fn as_str(self) -> &'static str {
        match self {
            FosshError::Internal => "INTERNAL",
            FosshError::InvalidArgument => "INVALID_ARGUMENT",
            FosshError::NoKeySet => "NO_KEY_SET",
            FosshError::Unauthorized => "UNAUTHORIZED",
            FosshError::Rejected => "REJECTED",
            FosshError::TooLarge => "TOO_LARGE",
            FosshError::RateLimited => "RATE_LIMITED",
            FosshError::WriteFailed => "WRITE_FAILED",
        }
    }
}

impl From<PipelineError> for FosshError {
    fn from(e: PipelineError) -> Self {
        match e {
            PipelineError::TooLarge => FosshError::TooLarge,
            PipelineError::Invalid(_) => FosshError::Rejected,
        }
    }
}

/// Just `id` and `allowlist` — the two things every recording call
/// actually needs. `slug` and `public` aren't kept here: nothing in this
/// crate reads `slug` after `fossh_set_key` resolves it, and `public`'s
/// only role anywhere in the project (§8: public keys "rate-limited
/// harder") is about *browser-facing* bearer-mode traffic through
/// `fossh-cgi` — an FFI caller is always a trusted host process, never a
/// browser, so that distinction has nothing to apply to here.
struct SiteContext {
    id: SiteId,
    allowlist: Vec<String>,
}

struct CtxState {
    config: Config,
    store: Store,
    site: Option<SiteContext>,
    salt: InMemorySalt,
    last_error: FosshError,
}

/// Opaque handle (`fossh_ctx*` in the C header). All mutable state is
/// behind one `Mutex`, held only across the write path (§11: "internal
/// state behind a `Mutex` on the write path only").
///
/// Named exactly `fossh_ctx` (not idiomatic Rust `UpperCamelCase`) on
/// purpose: `§11`'s header sketch spells the C typedef `fossh_ctx`, and
/// `cbindgen` (M8) uses a type's Rust name verbatim unless told to rename
/// it — matching the spec's spelling here means one less thing to
/// configure, and a struct that appears in `include/fossh.h` exactly as
/// C code expects to write it.
#[allow(non_camel_case_types)]
pub struct fossh_ctx {
    inner: Mutex<CtxState>,
}

fn rate_limit_path(data_dir: &std::path::Path, site_id: SiteId) -> PathBuf {
    data_dir
        .join("sites")
        .join(site_id.get().to_string())
        .join("ratelimit.bin")
}

fn spool_dir(data_dir: &std::path::Path, site_id: SiteId) -> PathBuf {
    data_dir
        .join("sites")
        .join(site_id.get().to_string())
        .join("spool")
}

/// Folds one already-assembled `Event` into the site's rate limiter, then
/// either the spool or the database directly, per `config.mode` (§7.3).
/// Shared by every recording entry point (`fossh_pageview`, `fossh_event`,
/// `fossh_timing`, `fossh_record_env`) so `FOSSH_MODE` and rate limiting
/// are handled in exactly one place.
fn record(state: &mut CtxState, event: Event) -> Result<(), FosshError> {
    let site = state.site.as_ref().ok_or(FosshError::NoKeySet)?;

    let bucket = fossh_ingest::ratelimit::TokenBucket::new(
        rate_limit_path(&state.config.data_dir, site.id),
        state.config.rate_limit.per_sec,
        state.config.rate_limit.burst,
    );
    match bucket.try_consume(event.ts) {
        Ok(true) => {}
        Ok(false) => return Err(FosshError::RateLimited),
        Err(_) => return Err(FosshError::Internal),
    }

    match state.config.mode {
        fossh_core::config::Mode::Direct => {
            state
                .store
                .record_event(&event)
                .map_err(|_| FosshError::WriteFailed)?;
        }
        fossh_core::config::Mode::Spool => {
            spool::append_frame(&spool_dir(&state.config.data_dir, site.id), &event)
                .map_err(|_| FosshError::WriteFailed)?;
        }
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds a `RequestContext` and runs one set of already-typed fields
/// through the shared pipeline (`fossh_ingest::pipeline::assemble_event`)
/// and then `record`. `client_ip`/`user_agent` are consumed by this call
/// and never retained past it (§11: "consumed, hashed/bucketed, and
/// zeroized within the call" — `hash_visitor` zeroizes its own
/// concatenation buffer, and neither string is copied anywhere else here).
#[allow(clippy::too_many_arguments)]
fn record_fields(
    state: &mut CtxState,
    fields: EventFields,
    client_ip: &str,
    user_agent: &str,
    referrer_header: Option<&str>,
    dnt: bool,
    gpc: bool,
) -> Result<(), FosshError> {
    let site = state.site.as_ref().ok_or(FosshError::NoKeySet)?;
    let allowlist = site.allowlist.clone();
    let site_id = site.id;
    let now = unix_now();
    let salt = *state.salt.current().map_err(|_| FosshError::Internal)?;
    let respect_optout_signals = state.config.respect_optout_signals;

    let ctx = RequestContext {
        site_id,
        site_allowlist: &allowlist,
        client_ip,
        user_agent,
        referrer_header,
        dnt,
        gpc,
        respect_optout_signals,
        now,
        daily_salt: &salt,
        country: Country::UNKNOWN,
    };

    if respect_optout_signals && (dnt || gpc) {
        return Ok(()); // P5: opted out — not an error, just nothing recorded
    }

    let event = pipeline::assemble_event(fields, &ctx)?;
    record(state, event)
}

// ---------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------

/// # Safety
/// `config_path`, if non-null, must point to a valid, NUL-terminated,
/// UTF-8 C string that remains valid for the duration of this call only
/// (§11: "borrowed for the call only; foSSH copies what it keeps").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_init(config_path: *const c_char) -> *mut fossh_ctx {
    let result = catch_unwind(|| {
        let config = if config_path.is_null() {
            Config::load().ok()?
        } else {
            // SAFETY: caller contract above; `CStr::from_ptr` requires a
            // valid NUL-terminated string, which is exactly what's promised.
            let path_str = unsafe { CStr::from_ptr(config_path) }.to_str().ok()?;
            Config::from_file(std::path::Path::new(path_str)).ok()?
        };
        let db_path = config.data_dir.join("fossh.db");
        let store = Store::open(&db_path).ok()?;
        let salt = InMemorySalt::new().ok()?;
        let state = CtxState {
            config,
            store,
            site: None,
            salt,
            last_error: FosshError::Internal,
        };
        Some(Box::into_raw(Box::new(fossh_ctx {
            inner: Mutex::new(state),
        })))
    });
    match result {
        Ok(Some(ptr)) => ptr,
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `ctx` must be either null (a no-op) or a pointer previously returned by
/// `fossh_init` and not yet passed to `fossh_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_free(ctx: *mut fossh_ctx) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        // SAFETY: caller contract above — a pointer `fossh_init` produced
        // via `Box::into_raw`, not yet freed. Reconstructing the `Box`
        // here and letting it drop is exactly the matching deallocation.
        drop(unsafe { Box::from_raw(ctx) });
    });
}

/// # Safety
/// `ctx` must be a valid, non-null pointer from `fossh_init`. `buf` must
/// point to at least `len` writable bytes (or `len` may be `0`, in which
/// case `buf` is never dereferenced).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_last_error(
    ctx: *const fossh_ctx,
    buf: *mut c_char,
    len: usize,
) -> i32 {
    if ctx.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let message = state.last_error.as_str().as_bytes();
        // SAFETY: forwarded from this function's own caller contract.
        unsafe { write_c_string_truncated(message, buf, len) };
        0
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// Copies as much of `message` as fits into `buf`, truncating to
/// `len - 1` bytes and always writing a NUL terminator — never more than
/// `len` bytes total. A no-op if `len == 0` or `buf` is null.
///
/// Pulled out of `fossh_last_error` as its own function specifically so
/// it's testable (including under Miri — see `tests::miri_safe`) without
/// needing a live `fossh_ctx`, which would mean going through
/// `fossh_init` and, transitively, `rusqlite`'s bundled SQLite — a
/// compiled C library Miri cannot interpret. This function is the entire
/// reason `fossh_last_error` needs `unsafe` at all, so it's exactly the
/// part worth being able to verify on its own.
///
/// # Safety
/// `buf` must be valid for `len` writes, unless `len == 0` (in which case
/// `buf` may be null and is never dereferenced).
unsafe fn write_c_string_truncated(message: &[u8], buf: *mut c_char, len: usize) {
    if len == 0 || buf.is_null() {
        return;
    }
    let n = message.len().min(len - 1);
    // SAFETY: caller contract guarantees `buf` has room for `len` bytes;
    // `n < len`, so writing `n` bytes plus a NUL at offset `n` stays
    // within that region.
    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
}

// ---------------------------------------------------------------------
// Auth context
// ---------------------------------------------------------------------

/// # Safety
/// `ctx` must be valid and non-null. `key` must be a valid, NUL-terminated,
/// UTF-8 C string, borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_set_key(ctx: *mut fossh_ctx, key: *const c_char) -> i32 {
    if ctx.is_null() || key.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let key_str = match unsafe { CStr::from_ptr(key) }.to_str() {
            Ok(s) => s,
            Err(_) => return FosshError::InvalidArgument as i32,
        };
        let Some((slug, raw_key)) = auth::parse_write_key_token(key_str) else {
            return FosshError::InvalidArgument as i32;
        };

        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let site = match state.store.find_site_by_slug(slug) {
            Ok(Some(s)) => s,
            Ok(None) => {
                state.last_error = FosshError::Unauthorized;
                return FosshError::Unauthorized as i32;
            }
            Err(_) => {
                state.last_error = FosshError::Internal;
                return FosshError::Internal as i32;
            }
        };
        if site.disabled || !auth::verify_bearer_key(&raw_key, &site.key_hash) {
            state.last_error = FosshError::Unauthorized;
            return FosshError::Unauthorized as i32;
        }

        state.site = Some(SiteContext {
            id: site.id,
            allowlist: site.allowlist,
        });
        0
    });
    result.unwrap_or(FosshError::Internal as i32)
}

// ---------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------

/// Converts a nullable, borrowed C string into `Option<&str>` — `None`
/// for a null pointer, `Some("")` for an empty (but non-null) string.
/// Invalid UTF-8 is treated as absent (§11 gives these fields no way to
/// report a distinct "not valid UTF-8" outcome; falling back to "not
/// provided" is the closer-to-`None` reading than fabricating a value).
///
/// # Safety
/// `ptr`, if non-null, must be a valid NUL-terminated C string, borrowed
/// for the duration of the call.
unsafe fn opt_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: forwarded from this function's own caller contract.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// # Safety
/// `ctx` must be valid and non-null. `path`, `referrer`, `client_ip`,
/// `user_agent` — each either null or a valid NUL-terminated UTF-8 C
/// string, borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_pageview(
    ctx: *mut fossh_ctx,
    path: *const c_char,
    referrer: *const c_char,
    client_ip: *const c_char,
    user_agent: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above; each `opt_str` call forwards the
        // same "valid NUL-terminated string or null" guarantee for its
        // own argument.
        let (path, referrer, client_ip, user_agent) = unsafe {
            (
                opt_str(path),
                opt_str(referrer),
                opt_str(client_ip),
                opt_str(user_agent),
            )
        };
        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };

        let fields = EventFields {
            name: "pageview".to_string(),
            kind: Some("pageview".to_string()),
            path: path.map(str::to_string),
            referrer: referrer.map(str::to_string),
            value: None,
            props: std::collections::HashMap::new(),
        };
        match record_fields(
            &mut state,
            fields,
            client_ip.unwrap_or(""),
            user_agent.unwrap_or(""),
            referrer,
            false,
            false,
        ) {
            Ok(()) => 0,
            Err(e) => {
                state.last_error = e;
                e as i32
            }
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// # Safety
/// `ctx` must be valid and non-null. `name` must be a valid NUL-terminated
/// UTF-8 C string. `props_json`, if non-null, must be a valid
/// NUL-terminated UTF-8 C string holding a JSON object of string values,
/// at most 1 KiB. All borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_event(
    ctx: *mut fossh_ctx,
    name: *const c_char,
    value: i64,
    props_json: *const c_char,
) -> i32 {
    if ctx.is_null() || name.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above.
        let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(_) => return FosshError::InvalidArgument as i32,
        };
        // SAFETY: caller contract above.
        let props_str = unsafe { opt_str(props_json) };
        if props_str.is_some_and(|s| s.len() > 1024) {
            return FosshError::InvalidArgument as i32;
        }
        let props: std::collections::HashMap<String, String> = match props_str {
            Some(s) => match serde_json::from_str(s) {
                Ok(p) => p,
                Err(_) => return FosshError::InvalidArgument as i32,
            },
            None => std::collections::HashMap::new(),
        };

        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let fields = EventFields {
            name: name_str.to_string(),
            kind: Some("action".to_string()),
            path: None,
            referrer: None,
            value: Some(value),
            props,
        };
        match record_fields(&mut state, fields, "", "", None, false, false) {
            Ok(()) => 0,
            Err(e) => {
                state.last_error = e;
                e as i32
            }
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// # Safety
/// `ctx` must be valid and non-null. `name` must be a valid NUL-terminated
/// UTF-8 C string, borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_timing(
    ctx: *mut fossh_ctx,
    name: *const c_char,
    millis: i64,
) -> i32 {
    if ctx.is_null() || name.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above.
        let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(_) => return FosshError::InvalidArgument as i32,
        };
        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let fields = EventFields {
            name: name_str.to_string(),
            kind: Some("timing".to_string()),
            path: None,
            referrer: None,
            value: Some(millis),
            props: std::collections::HashMap::new(),
        };
        match record_fields(&mut state, fields, "", "", None, false, false) {
            Ok(()) => 0,
            Err(e) => {
                state.last_error = e;
                e as i32
            }
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// CGI-style entry point: hand foSSH a raw request environment (`envp`,
/// `envc` entries shaped `KEY=VALUE`, matching RFC 3875 var names — see
/// `fossh-cgi`) and a body; foSSH extracts method/path/headers itself and
/// runs the same allowlist/validation/opt-out pipeline as every other
/// transport. A non-empty body is parsed as a JSON event or batch
/// (mirroring `POST /e`); an empty body falls back to `QUERY_STRING`
/// (mirroring `GET /e.gif`).
///
/// # Safety
/// `ctx` must be valid and non-null. `envp` must point to `envc` valid,
/// NUL-terminated UTF-8 C strings (or `envc` may be `0`, in which case
/// `envp` is never read). `body` must point to at least `body_len` bytes
/// (or `body_len` may be `0`, in which case `body` may be null). All
/// borrowed for this call only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_record_env(
    ctx: *mut fossh_ctx,
    envp: *const *const c_char,
    envc: usize,
    body: *const u8,
    body_len: usize,
) -> i32 {
    if ctx.is_null() || (envc > 0 && envp.is_null()) {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        let mut env = std::collections::HashMap::new();
        for i in 0..envc {
            // SAFETY: caller contract guarantees `envp` has `envc` valid
            // entries; each entry is a valid NUL-terminated C string.
            let entry = unsafe { CStr::from_ptr(*envp.add(i)) };
            let Ok(entry) = entry.to_str() else { continue };
            if let Some((k, v)) = entry.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
        let body_bytes: &[u8] = if body_len == 0 || body.is_null() {
            &[]
        } else {
            // SAFETY: caller contract above.
            unsafe { std::slice::from_raw_parts(body, body_len) }
        };

        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let Some(site) = state.site.as_ref() else {
            return FosshError::NoKeySet as i32;
        };
        let allowlist = site.allowlist.clone();
        let site_id = site.id;

        let now = unix_now();
        let salt = match state.salt.current() {
            Ok(s) => *s,
            Err(_) => return FosshError::Internal as i32,
        };
        let dnt = env.get("HTTP_DNT").map(String::as_str) == Some("1");
        let gpc = env.get("HTTP_SEC_GPC").map(String::as_str) == Some("1");
        let respect_optout_signals = state.config.respect_optout_signals;

        let request_ctx = RequestContext {
            site_id,
            site_allowlist: &allowlist,
            client_ip: env.get("REMOTE_ADDR").map(String::as_str).unwrap_or(""),
            user_agent: env.get("HTTP_USER_AGENT").map(String::as_str).unwrap_or(""),
            referrer_header: env.get("HTTP_REFERER").map(String::as_str),
            dnt,
            gpc,
            respect_optout_signals,
            now,
            daily_salt: &salt,
            country: Country::UNKNOWN,
        };

        let outcome = if !body_bytes.is_empty() {
            pipeline::from_json_body(body_bytes, &request_ctx)
        } else {
            let query = env.get("QUERY_STRING").map(String::as_str).unwrap_or("");
            pipeline::from_query_string(query, &request_ctx)
        };

        match outcome {
            Ok(PipelineOutcome::OptedOut) => 0,
            Ok(PipelineOutcome::Accepted(events)) => {
                for event in events {
                    if let Err(e) = record(&mut state, event) {
                        state.last_error = e;
                        return e as i32;
                    }
                }
                0
            }
            Err(e) => {
                let e = FosshError::from(e);
                state.last_error = e;
                e as i32
            }
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// "Force spool/tx flush; safe to call at shutdown" (§11). For
/// `mode = "direct"` there is nothing to flush — `record_event` commits
/// its own transaction per call. For `mode = "spool"`, drains everything
/// queued for this site straight into the database immediately, rather
/// than waiting for the next `fossh maintain`/compactor cycle — so a host
/// process that calls this before exiting never strands events in the spool.
///
/// # Safety
/// `ctx` must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_flush(ctx: *mut fossh_ctx) -> i32 {
    if ctx.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {
        // SAFETY: caller contract above.
        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let Some(site) = state.site.as_ref() else {
            return 0;
        }; // nothing to flush without a site
        if state.config.mode != fossh_core::config::Mode::Spool {
            return 0;
        }
        let dir = spool_dir(&state.config.data_dir, site.id);
        match compact::drain_site_spool(&mut state.store, &dir) {
            Ok(_) => 0,
            Err(_) => FosshError::Internal as i32,
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

/// The subset of tests that can actually run under Miri (S1: unsafe code
/// needs "a corresponding Miri test"). `cargo miri test` cannot get past
/// `Store::open` for *any* other test in this crate — `rusqlite`'s
/// `bundled` feature vendors and compiles the real SQLite C library, and
/// Miri interprets Rust MIR, not arbitrary compiled C; calling into it
/// fails with "can't call foreign function `sqlite3_threadsafe`", which
/// is a fundamental Miri limitation, not a bug here (confirmed by
/// running with `MIRIFLAGS=-Zmiri-disable-isolation` too, which only
/// gets one test further before hitting the same wall). `opt_str` and
/// `write_c_string_truncated` are the *only* two functions in this crate
/// — in the only crate in the whole project where `unsafe` is permitted
/// at all (S1) — that actually touch a raw pointer without going through
/// `fossh_ctx`/`Store`, so they're also the only ones Miri can exercise
/// end to end. Run with:
/// `cargo +nightly miri test --lib miri_safe`
#[cfg(test)]
mod miri_safe {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn opt_str_null_is_none() {
        assert_eq!(unsafe { opt_str(std::ptr::null()) }, None);
    }

    #[test]
    fn opt_str_valid_utf8_round_trips() {
        let s = CString::new("hello").unwrap();
        assert_eq!(unsafe { opt_str(s.as_ptr()) }, Some("hello"));
    }

    #[test]
    fn opt_str_empty_string_is_some_empty() {
        let s = CString::new("").unwrap();
        assert_eq!(unsafe { opt_str(s.as_ptr()) }, Some(""));
    }

    #[test]
    fn opt_str_invalid_utf8_is_none() {
        let bytes = [0xFFu8, 0xFE, 0x00];
        let ptr = bytes.as_ptr().cast::<c_char>();
        assert_eq!(unsafe { opt_str(ptr) }, None);
    }

    #[test]
    fn write_c_string_truncated_fits_exactly() {
        let mut buf = [0i8; 6]; // "hello\0"
        unsafe { write_c_string_truncated(b"hello", buf.as_mut_ptr(), buf.len()) };
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn write_c_string_truncated_shorter_buffer() {
        let mut buf = [0i8; 3]; // room for 2 bytes + NUL
        unsafe { write_c_string_truncated(b"hello", buf.as_mut_ptr(), buf.len()) };
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "he");
    }

    #[test]
    fn write_c_string_truncated_zero_length_never_touches_buf() {
        // A dangling/null pointer is fine here specifically because
        // len == 0 means the function must return before dereferencing it.
        unsafe { write_c_string_truncated(b"hello", std::ptr::null_mut(), 0) };
    }

    #[test]
    fn write_c_string_truncated_empty_message() {
        let mut buf = [1i8; 4]; // pre-filled with non-zero to prove it gets NUL'd
        unsafe { write_c_string_truncated(b"", buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn write_c_string_truncated_buffer_of_one_byte_is_just_the_nul() {
        let mut buf = [1i8; 1];
        unsafe { write_c_string_truncated(b"hello", buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf[0], 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-ffi-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Sets up a data dir, a site in it, and returns
    /// `(ctx, write_key_token)` — mirrors what `fossh site create` would
    /// have produced, without spawning the CLI binary from a unit test.
    ///
    /// # Safety
    /// None beyond the usual test-process assumptions — calls
    /// `fossh_init` with a valid, freshly written config path.
    unsafe fn setup(name: &str) -> (*mut fossh_ctx, String) {
        let dir = scratch_dir(name);
        let db_path = dir.join("fossh.db");
        let store = Store::open(&db_path).unwrap();
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        store
            .create_site(
                "blog",
                &key_hash,
                &["pageview".to_string(), "signup".to_string()],
                1_700_000_000,
                false,
            )
            .unwrap();
        drop(store); // fossh_init below reopens it

        // `Mode::Direct`: most tests using this helper check
        // `store.count_events` directly, which only sees writes that
        // skip the spool. `flush_drains_the_spool_in_spool_mode` below
        // builds its own config with `Mode::Spool` instead of using this
        // helper, specifically to exercise the other path.
        let config = Config {
            data_dir: dir.clone(),
            mode: fossh_core::config::Mode::Direct,
            ..Config::default()
        };
        let config_path = dir.join("fossh.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let config_path_c = CString::new(config_path.to_str().unwrap()).unwrap();
        // SAFETY: config_path_c is a valid NUL-terminated C string, live
        // for the duration of this call.
        let ctx = unsafe { fossh_init(config_path_c.as_ptr()) };
        assert!(
            !ctx.is_null(),
            "fossh_init must succeed against a freshly created config/db"
        );

        let token = format!("fossh_blog_{}", fossh_core::base32::encode(&raw_key));
        (ctx, token)
    }

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(fossh_abi_version(), 1);
    }

    #[test]
    fn init_with_null_path_falls_back_to_config_load() {
        // Config::load() with no FOSSH_CONFIG/./fossh.toml/etc present
        // falls back to Config::default(), whose data_dir (/var/lib/fossh)
        // this process can't necessarily write to — so this just checks
        // fossh_init doesn't panic/segfault on a null path, not that it
        // succeeds.
        unsafe {
            let ctx = fossh_init(std::ptr::null());
            if !ctx.is_null() {
                fossh_free(ctx);
            }
        }
    }

    #[test]
    fn free_of_null_is_a_safe_no_op() {
        unsafe { fossh_free(std::ptr::null_mut()) };
    }

    #[test]
    fn set_key_with_correct_token_succeeds() {
        unsafe {
            let (ctx, token) = setup("set-key-ok");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn set_key_with_wrong_key_is_unauthorized() {
        unsafe {
            let (ctx, _) = setup("set-key-wrong");
            let wrong = format!("fossh_blog_{}", fossh_core::base32::encode(&[0xCDu8; 32]));
            let wrong_c = CString::new(wrong).unwrap();
            assert_eq!(
                fossh_set_key(ctx, wrong_c.as_ptr()),
                FosshError::Unauthorized as i32
            );
            fossh_free(ctx);
        }
    }

    #[test]
    fn set_key_with_unknown_slug_is_unauthorized() {
        unsafe {
            let (ctx, _) = setup("set-key-unknown-slug");
            let unknown = format!(
                "fossh_nosuchsite_{}",
                fossh_core::base32::encode(&[0xABu8; 32])
            );
            let unknown_c = CString::new(unknown).unwrap();
            assert_eq!(
                fossh_set_key(ctx, unknown_c.as_ptr()),
                FosshError::Unauthorized as i32
            );
            fossh_free(ctx);
        }
    }

    #[test]
    fn recording_before_set_key_is_no_key_set() {
        unsafe {
            let (ctx, _) = setup("no-key");
            let name = CString::new("pageview").unwrap();
            assert_eq!(
                fossh_pageview(
                    ctx,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                FosshError::NoKeySet as i32
            );
            assert_eq!(
                fossh_timing(ctx, name.as_ptr(), 5),
                FosshError::NoKeySet as i32
            );
            fossh_free(ctx);
        }
    }

    #[test]
    fn pageview_round_trips_in_direct_mode() {
        unsafe {
            let (ctx, token) = setup("pageview-direct");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let path = CString::new("/blog/hello").unwrap();
            let ip = CString::new("203.0.113.9").unwrap();
            let ua = CString::new("Mozilla/5.0 Chrome/126.0.0.0").unwrap();
            let rc = fossh_pageview(
                ctx,
                path.as_ptr(),
                std::ptr::null(),
                ip.as_ptr(),
                ua.as_ptr(),
            );
            assert_eq!(rc, 0);

            // Test-only introspection into our own ctx to verify the
            // write landed — not part of the public C ABI contract.
            let state = (*ctx).inner.lock().unwrap();
            let site_id = state.site.as_ref().unwrap().id;
            assert_eq!(state.store.count_events(site_id).unwrap(), 1);
            drop(state);
            fossh_free(ctx);
        }
    }

    #[test]
    fn event_rejects_name_not_on_allowlist() {
        unsafe {
            let (ctx, token) = setup("event-not-allowlisted");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let name = CString::new("totally.unlisted").unwrap();
            let rc = fossh_event(ctx, name.as_ptr(), 1, std::ptr::null());
            assert_eq!(rc, FosshError::Rejected as i32);
            fossh_free(ctx);
        }
    }

    #[test]
    fn event_with_empty_props_json_succeeds() {
        // "signup" is allowlisted in `setup`; an empty JSON object has no
        // keys to check against the allowlist, so this exercises the
        // props_json parse path succeeding structurally.
        unsafe {
            let (ctx, token) = setup("event-props");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let name = CString::new("signup").unwrap();
            let props = CString::new("{}").unwrap();
            let rc = fossh_event(ctx, name.as_ptr(), 1, props.as_ptr());
            assert_eq!(rc, 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn event_with_allowlisted_prop_key_round_trips() {
        // `setup` allowlists "signup" (as a name) but not "plan" (as a
        // prop key) — expect a clean REJECTED, exercising the same
        // allowlist check the JSON/query-string transports share.
        unsafe {
            let (ctx, token) = setup("event-props-allowlisted");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let name = CString::new("signup").unwrap();
            let props = CString::new(r#"{"plan":"pro"}"#).unwrap();
            let rc = fossh_event(ctx, name.as_ptr(), 1, props.as_ptr());
            assert_eq!(rc, FosshError::Rejected as i32);
            fossh_free(ctx);
        }
    }

    #[test]
    fn event_rejects_oversized_props_json() {
        unsafe {
            let (ctx, token) = setup("event-props-oversized");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let name = CString::new("signup").unwrap();
            let big = format!("{{\"k\":\"{}\"}}", "a".repeat(2000));
            let big_c = CString::new(big).unwrap();
            let rc = fossh_event(ctx, name.as_ptr(), 1, big_c.as_ptr());
            assert_eq!(rc, FosshError::InvalidArgument as i32);
            fossh_free(ctx);
        }
    }

    #[test]
    fn timing_round_trips() {
        // "db.query" isn't allowlisted in `setup` — expect a clean
        // rejection, not a crash, exercising the same path a real timing
        // call takes.
        unsafe {
            let (ctx, token) = setup("timing");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let name = CString::new("db.query").unwrap();
            let rc = fossh_timing(ctx, name.as_ptr(), 42);
            assert_eq!(rc, FosshError::Rejected as i32);
            fossh_free(ctx);
        }
    }

    #[test]
    fn last_error_reports_the_fixed_string_for_the_last_failure() {
        unsafe {
            let (ctx, _) = setup("last-error");
            let name = CString::new("pageview").unwrap();
            let _ = fossh_timing(ctx, name.as_ptr(), 1); // NO_KEY_SET, no key set yet

            let mut buf = [0i8; 64];
            let rc = fossh_last_error(ctx, buf.as_mut_ptr(), buf.len());
            assert_eq!(rc, 0);
            let s = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "NO_KEY_SET");
            fossh_free(ctx);
        }
    }

    #[test]
    fn last_error_truncates_to_a_short_buffer_without_overflowing() {
        unsafe {
            let (ctx, _) = setup("last-error-truncate");
            let name = CString::new("pageview").unwrap();
            let _ = fossh_timing(ctx, name.as_ptr(), 1);

            let mut buf = [0i8; 4]; // shorter than "NO_KEY_SET"
            let rc = fossh_last_error(ctx, buf.as_mut_ptr(), buf.len());
            assert_eq!(rc, 0);
            let s = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(
                s.len(),
                3,
                "must fit within len-1 bytes plus a NUL terminator"
            );
            fossh_free(ctx);
        }
    }

    #[test]
    fn last_error_with_zero_length_buffer_does_not_dereference_buf() {
        unsafe {
            let (ctx, _) = setup("last-error-zero-len");
            let rc = fossh_last_error(ctx, std::ptr::null_mut(), 0);
            assert_eq!(rc, 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn set_key_with_invalid_utf8_is_invalid_argument() {
        unsafe {
            let (ctx, _) = setup("invalid-utf8-key");
            let bytes = [0x66, 0x6F, 0x73, 0x73, 0x68, 0xFF, 0xFE, 0x00]; // "fossh" + invalid UTF-8 + NUL
            let rc = fossh_set_key(ctx, bytes.as_ptr().cast::<c_char>());
            assert_eq!(rc, FosshError::InvalidArgument as i32);
            fossh_free(ctx);
        }
    }

    #[test]
    fn null_ctx_is_invalid_argument_not_a_crash() {
        unsafe {
            assert_eq!(
                fossh_set_key(std::ptr::null_mut(), std::ptr::null()),
                FosshError::InvalidArgument as i32
            );
            assert_eq!(
                fossh_flush(std::ptr::null_mut()),
                FosshError::InvalidArgument as i32
            );
            assert_eq!(
                fossh_pageview(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                FosshError::InvalidArgument as i32
            );
        }
    }

    #[test]
    fn record_env_mirrors_json_body_path() {
        unsafe {
            let (ctx, token) = setup("record-env-json");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let vars = [
                CString::new("REMOTE_ADDR=203.0.113.5").unwrap(),
                CString::new("HTTP_USER_AGENT=curl/8.0").unwrap(),
            ];
            let envp: Vec<*const c_char> = vars.iter().map(|s| s.as_ptr()).collect();
            let body = br#"{"name":"pageview"}"#;
            let rc = fossh_record_env(ctx, envp.as_ptr(), envp.len(), body.as_ptr(), body.len());
            assert_eq!(rc, 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn record_env_mirrors_query_string_path_when_body_is_empty() {
        unsafe {
            let (ctx, token) = setup("record-env-query");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let vars = [CString::new("QUERY_STRING=name=pageview").unwrap()];
            let envp: Vec<*const c_char> = vars.iter().map(|s| s.as_ptr()).collect();
            let rc = fossh_record_env(ctx, envp.as_ptr(), envp.len(), std::ptr::null(), 0);
            assert_eq!(rc, 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn record_env_respects_dnt() {
        unsafe {
            let (ctx, token) = setup("record-env-dnt");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let vars = [CString::new("HTTP_DNT=1").unwrap()];
            let envp: Vec<*const c_char> = vars.iter().map(|s| s.as_ptr()).collect();
            let body = br#"{"name":"pageview"}"#;
            let rc = fossh_record_env(ctx, envp.as_ptr(), envp.len(), body.as_ptr(), body.len());
            assert_eq!(
                rc, 0,
                "opted-out is success (nothing recorded), not an error"
            );

            let state = (*ctx).inner.lock().unwrap();
            let site_id = state.site.as_ref().unwrap().id;
            assert_eq!(state.store.count_events(site_id).unwrap(), 0);
            drop(state);
            fossh_free(ctx);
        }
    }

    #[test]
    fn flush_without_a_site_is_a_safe_no_op() {
        unsafe {
            let (ctx, _) = setup("flush-no-site");
            assert_eq!(fossh_flush(ctx), 0);
            fossh_free(ctx);
        }
    }

    #[test]
    fn flush_drains_the_spool_in_spool_mode() {
        unsafe {
            let dir = scratch_dir("flush-spool");
            let db_path = dir.join("fossh.db");
            let store = Store::open(&db_path).unwrap();
            let raw_key = [0xEFu8; 32];
            let key_hash = *blake3::hash(&raw_key).as_bytes();
            store
                .create_site(
                    "blog",
                    &key_hash,
                    &["pageview".to_string()],
                    1_700_000_000,
                    false,
                )
                .unwrap();
            drop(store);

            let config = Config {
                data_dir: dir.clone(),
                mode: fossh_core::config::Mode::Spool,
                ..Config::default()
            };
            let config_path = dir.join("fossh.toml");
            std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
            let config_path_c = CString::new(config_path.to_str().unwrap()).unwrap();
            let ctx = fossh_init(config_path_c.as_ptr());
            assert!(!ctx.is_null());

            let token = format!("fossh_blog_{}", fossh_core::base32::encode(&raw_key));
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let path = CString::new("/x").unwrap();
            assert_eq!(
                fossh_pageview(
                    ctx,
                    path.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                0
            );
            assert_eq!(fossh_flush(ctx), 0);

            let state = (*ctx).inner.lock().unwrap();
            let site_id = state.site.as_ref().unwrap().id;
            assert_eq!(
                state.store.count_events(site_id).unwrap(),
                1,
                "flush must drain the spool into the database"
            );
            drop(state);
            fossh_free(ctx);
        }
    }
}
