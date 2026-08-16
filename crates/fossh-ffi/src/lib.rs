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
use zeroize::Zeroizing;

pub const FOSSH_ABI_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn fossh_abi_version() -> u32 {
    FOSSH_ABI_VERSION
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FosshError {

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

struct SiteContext {
    id: SiteId,
    allowlist: Vec<String>,
}

struct CtxState {
    config: Config,
    store: Store,
    site: Option<SiteContext>,
    salt: InMemorySalt,

    data_key: Zeroizing<[u8; 32]>,
    last_error: FosshError,
}

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
            spool::append_frame(
                &spool_dir(&state.config.data_dir, site.id),
                &event,
                &state.data_key,
            )
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
        return Ok(());
    }

    let event = pipeline::assemble_event(fields, &ctx)?;
    record(state, event)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_init(config_path: *const c_char) -> *mut fossh_ctx {
    let result = catch_unwind(|| {
        let config = if config_path.is_null() {
            Config::load().ok()?
        } else {

            let path_str = unsafe { CStr::from_ptr(config_path) }.to_str().ok()?;
            Config::from_file(std::path::Path::new(path_str)).ok()?
        };
        let db_path = config.data_dir.join("fossh.db");
        let salt = InMemorySalt::new().ok()?;

        let data_key =
            fossh_admin::data_key::load_or_generate(&config.data_dir.join(".data_key")).ok()?;
        let store = Store::open_encrypted(&db_path, &data_key).ok()?;
        let state = CtxState {
            config,
            store,
            site: None,
            salt,
            data_key,
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_free(ctx: *mut fossh_ctx) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(|| {

        drop(unsafe { Box::from_raw(ctx) });
    });
}

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

        let ctx = unsafe { &*ctx };
        let Ok(state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let message = state.last_error.as_str().as_bytes();

        unsafe { write_c_string_truncated(message, buf, len) };
        0
    });
    result.unwrap_or(FosshError::Internal as i32)
}

unsafe fn write_c_string_truncated(message: &[u8], buf: *mut c_char, len: usize) {
    if len == 0 || buf.is_null() {
        return;
    }
    let n = message.len().min(len - 1);

    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_set_key(ctx: *mut fossh_ctx, key: *const c_char) -> i32 {
    if ctx.is_null() || key.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {

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

unsafe fn opt_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

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

        let (path, referrer, client_ip, user_agent) = unsafe {
            (
                opt_str(path),
                opt_str(referrer),
                opt_str(client_ip),
                opt_str(user_agent),
            )
        };

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

        let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(_) => return FosshError::InvalidArgument as i32,
        };

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

        let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) => s,
            Err(_) => return FosshError::InvalidArgument as i32,
        };

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

            let raw = unsafe { *envp.add(i) };
            if raw.is_null() {
                continue;
            }
            let entry = unsafe { CStr::from_ptr(raw) };
            let Ok(entry) = entry.to_str() else { continue };
            if let Some((k, v)) = entry.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
        let body_bytes: &[u8] = if body_len == 0 || body.is_null() {
            &[]
        } else {

            unsafe { std::slice::from_raw_parts(body, body_len) }
        };

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fossh_flush(ctx: *mut fossh_ctx) -> i32 {
    if ctx.is_null() {
        return FosshError::InvalidArgument as i32;
    }
    let result = catch_unwind(|| {

        let ctx = unsafe { &*ctx };
        let Ok(mut state) = ctx.inner.lock() else {
            return FosshError::Internal as i32;
        };
        let Some(site) = state.site.as_ref() else {
            return 0;
        };
        if state.config.mode != fossh_core::config::Mode::Spool {
            return 0;
        }
        let dir = spool_dir(&state.config.data_dir, site.id);

        let data_key: Zeroizing<[u8; 32]> = Zeroizing::new(*state.data_key);
        match compact::drain_site_spool(&mut state.store, &dir, &data_key) {
            Ok(_) => 0,
            Err(_) => FosshError::Internal as i32,
        }
    });
    result.unwrap_or(FosshError::Internal as i32)
}

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
        let mut buf = [0i8; 6];
        unsafe { write_c_string_truncated(b"hello", buf.as_mut_ptr(), buf.len()) };
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn write_c_string_truncated_shorter_buffer() {
        let mut buf = [0i8; 3];
        unsafe { write_c_string_truncated(b"hello", buf.as_mut_ptr(), buf.len()) };
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "he");
    }

    #[test]
    fn write_c_string_truncated_zero_length_never_touches_buf() {

        unsafe { write_c_string_truncated(b"hello", std::ptr::null_mut(), 0) };
    }

    #[test]
    fn write_c_string_truncated_empty_message() {
        let mut buf = [1i8; 4];
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
                None,
                &["pageview".to_string(), "signup".to_string()],
                1_700_000_000,
                false,
            )
            .unwrap();
        drop(store);

        let config = Config {
            data_dir: dir.clone(),
            mode: fossh_core::config::Mode::Direct,
            ..Config::default()
        };
        let config_path = dir.join("fossh.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let config_path_c = CString::new(config_path.to_str().unwrap()).unwrap();

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
            let _ = fossh_timing(ctx, name.as_ptr(), 1);

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

            let mut buf = [0i8; 4];
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
            let bytes = [0x66, 0x6F, 0x73, 0x73, 0x68, 0xFF, 0xFE, 0x00];
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
    fn record_env_skips_null_entries_rather_than_dereferencing_them() {
        unsafe {
            let (ctx, token) = setup("record-env-null-hole");
            let token_c = CString::new(token).unwrap();
            assert_eq!(fossh_set_key(ctx, token_c.as_ptr()), 0);

            let head = CString::new("REMOTE_ADDR=203.0.113.5").unwrap();
            let tail = CString::new("QUERY_STRING=name=pageview").unwrap();
            let envp: Vec<*const c_char> = vec![
                head.as_ptr(),
                std::ptr::null(),
                tail.as_ptr(),
                std::ptr::null(),
            ];

            let rc = fossh_record_env(ctx, envp.as_ptr(), envp.len(), std::ptr::null(), 0);
            assert_eq!(rc, 0, "a null hole must not fail the call");

            let state = (*ctx).inner.lock().unwrap();
            let site_id = state.site.as_ref().unwrap().id;
            assert_eq!(
                state.store.count_events(site_id).unwrap(),
                1,
                "QUERY_STRING sat after the hole and must still have been read"
            );
            drop(state);
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
                    None,
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
