//! Operator-added external services, authenticated by an API key the
//! operator supplies. Storage, validation, and redaction only — this
//! module contains no network code whatsoever, and that is structural
//! rather than incidental.
//!
//! ## Why the network half deliberately isn't here
//!
//! `fossh-cgi` and `fossh-fcgi` both depend on this crate (for
//! `data_key`), so anything in `fossh-admin` is by construction in the
//! ingest path's dependency tree. The ingest path's "zero outbound
//! network access" property (`THREAT_MODEL.md`, `PRIVACY.md`) is worth
//! more than the convenience of keeping delivery next to storage, so
//! the actual outbound request lives in `fossh-agent`
//! (`integrations_net.rs`) — a binary no ingest component depends on,
//! links against, or can reach. Check it with
//! `cargo tree -p fossh-cgi | grep fossh-agent`: nothing. See
//! ADR-0062.
//!
//! ## What an integration is allowed to be
//!
//! An operator-named endpoint plus a credential. foSSH does not ship
//! per-vendor integrations and does not pretend to: rather than a
//! closed list of service names this project has never tested against,
//! the model is the one thing every HTTP API actually differs on,
//! which is *where the key goes* — `Authorization: Bearer <key>`, or a
//! named header of the operator's choosing. That covers essentially
//! every real API without ever claiming support for a specific one.
//!
//! ## At rest
//!
//! The whole record set — names, endpoints, and keys alike — is sealed
//! as a single ChaCha20-Poly1305 blob under the per-install data key
//! (`data_key.rs`), reusing `fossh_ingest::crypto`'s already-reviewed
//! `seal`/`open` rather than a second construction. Endpoints are
//! sealed too, not just credentials: an internal hostname is itself
//! something an operator may reasonably not want readable by anything
//! that can read the file.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Bounds every operator-supplied string this module accepts. None of
/// these are protocol limits — they exist so a mistaken paste (a whole
/// file into the key field) fails immediately and legibly instead of
/// being sealed, written, and then rejected much later by something
/// downstream.
const MAX_NAME_LEN: usize = 64;
const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_API_KEY_LEN: usize = 8192;
/// A ceiling on the sealed file this module will even attempt to open,
/// so a corrupt or hostile file can't be turned into an unbounded
/// allocation by the act of reading it.
const MAX_FILE_LEN: u64 = 1024 * 1024;
const MAX_INTEGRATIONS: usize = 64;

pub const FILE_NAME: &str = "integrations.enc";

pub fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "placement", rename_all = "snake_case")]
pub enum Auth {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// `<name>: <key>` — for the many APIs that use their own header
    /// (`X-Api-Key`, `Api-Key`, `Private-Token`, …).
    Header { name: String },
}

impl Auth {
    /// The header this integration will actually send, as a
    /// `(name, value)` pair. Returned in a `Zeroizing` wrapper because
    /// the value contains the credential in full.
    pub fn header(&self, api_key: &str) -> (String, Zeroizing<String>) {
        match self {
            Auth::Bearer => (
                "Authorization".to_string(),
                Zeroizing::new(format!("Bearer {api_key}")),
            ),
            Auth::Header { name } => (name.clone(), Zeroizing::new(api_key.to_string())),
        }
    }
}

/// The two verbs that actually matter for reaching an API with a
/// credential. Deliberately not the full set: `PUT`/`PATCH`/`DELETE`
/// are all state-changing verbs that a *connectivity test* has no
/// business sending at an operator's live service, and nothing else in
/// foSSH needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The default, and the right one for anything that will be read
    /// from. Safe to send at an unknown endpoint.
    #[default]
    Get,
    /// What most webhook-shaped endpoints require. A connectivity test
    /// against one of these really does deliver a request, so the body
    /// says so in as many words — see `TEST_BODY`.
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// The body a `POST` connectivity test sends. Self-describing on
/// purpose: whoever is on the receiving end, possibly months later
/// reading a log, should be able to tell what this was without having
/// to ask.
pub const TEST_BODY: &str =
    r#"{"source":"fossh","event":"connectivity-test","note":"sent by an operator from the foSSH console to verify this integration's endpoint and credential; carries no telemetry"}"#;

/// One configured service. `api_key` is deliberately not `pub`: every
/// path that reads it has to go through `api_key()`, which makes the
/// handful of places that legitimately need the plaintext greppable in
/// one search rather than scattered across field accesses.
#[derive(Clone, Serialize, Deserialize)]
pub struct Integration {
    pub name: String,
    pub endpoint: String,
    pub auth: Auth,
    /// `#[serde(default)]` so a file written before this field existed
    /// still loads, as a `GET`, instead of failing shut as `Corrupt`.
    #[serde(default)]
    pub method: Method,
    pub created_at: i64,
    api_key: String,
}

/// Hand-written specifically so no `{:?}` anywhere — a log line, a
/// panic message, an `assert_eq!` failure in a test — can ever print a
/// credential. The derived impl would have.
impl std::fmt::Debug for Integration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Integration")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("created_at", &self.created_at)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl Integration {
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// The only representation of a key that may leave this process.
    ///
    /// Last four characters, and only when the key is long enough that
    /// four characters is a small fraction of it. A short key gets no
    /// hint at all rather than a proportionally large one — showing
    /// four of six characters is not a hint, it is most of the secret.
    /// Counted in `char`s, not bytes, so a multi-byte key can't be
    /// sliced mid-codepoint.
    pub fn key_hint(&self) -> Option<String> {
        let chars: Vec<char> = self.api_key.chars().collect();
        if chars.len() < 12 {
            return None;
        }
        Some(chars[chars.len() - 4..].iter().collect())
    }
}

#[derive(Debug)]
pub enum IntegrationError {
    /// The operator supplied something this module refuses to store.
    /// Carries a message written to be shown directly in the console.
    Invalid(String),
    /// A name that is already taken.
    Duplicate(String),
    NotFound(String),
    /// More integrations than `MAX_INTEGRATIONS`.
    TooMany,
    Io(String),
    /// The file exists but did not decrypt or did not parse. Wrong key
    /// and deliberate tampering are indistinguishable from here and
    /// are reported identically, the same way `fossh_ingest::crypto`'s
    /// own `open` already treats them (S2).
    Corrupt,
}

impl std::fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrationError::Invalid(m) => write!(f, "{m}"),
            IntegrationError::Duplicate(n) => {
                write!(f, "an integration named \"{n}\" already exists")
            }
            IntegrationError::NotFound(n) => write!(f, "no integration named \"{n}\""),
            IntegrationError::TooMany => write!(
                f,
                "this install already has the maximum of {MAX_INTEGRATIONS} integrations"
            ),
            IntegrationError::Io(m) => write!(f, "{m}"),
            IntegrationError::Corrupt => write!(
                f,
                "the integrations file could not be decrypted — it is either corrupt or was \
                 written under a different data key"
            ),
        }
    }
}

impl std::error::Error for IntegrationError {}

/// A name is used as a stable identifier in the console, in CLI
/// arguments, and as a lookup key — so it is restricted to something
/// that can't be confused with anything else, can't need quoting, and
/// can't contain a character that would change the meaning of a line
/// it gets printed on.
pub fn validate_name(name: &str) -> Result<(), IntegrationError> {
    if name.is_empty() {
        return Err(IntegrationError::Invalid(
            "an integration needs a name".to_string(),
        ));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(IntegrationError::Invalid(format!(
            "an integration name is limited to {MAX_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(IntegrationError::Invalid(
            "an integration name may only contain lowercase letters, digits, \"-\" and \"_\""
                .to_string(),
        ));
    }
    Ok(())
}

/// HTTPS is required, with one carve-out.
///
/// Sending a bearer credential over cleartext HTTP hands it to anything
/// on the path, so `http://` is refused rather than warned about. The
/// carve-out is loopback: an operator testing an integration against
/// something running on the same machine has no network to be exposed
/// on, and refusing that case would push people toward disabling the
/// check entirely, which is worse. Loopback is matched on the parsed
/// host, not by substring — `https://127.0.0.1.evil.example` must not
/// pass, and neither must `http://evil.example/?x=127.0.0.1`.
pub fn validate_endpoint(endpoint: &str) -> Result<(), IntegrationError> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(IntegrationError::Invalid(format!(
            "an endpoint URL is limited to {MAX_ENDPOINT_LEN} characters"
        )));
    }
    // Control characters in a URL would be smuggled straight into the
    // request line by anything that builds one by concatenation.
    if endpoint.chars().any(|c| c.is_control() || c == ' ') {
        return Err(IntegrationError::Invalid(
            "an endpoint URL may not contain spaces or control characters".to_string(),
        ));
    }

    let rest = if let Some(r) = endpoint.strip_prefix("https://") {
        return validate_host_present(r);
    } else if let Some(r) = endpoint.strip_prefix("http://") {
        r
    } else {
        return Err(IntegrationError::Invalid(
            "an endpoint URL must start with https://".to_string(),
        ));
    };

    validate_host_present(rest)?;
    let host = host_of(rest);
    if is_loopback(host) {
        Ok(())
    } else {
        Err(IntegrationError::Invalid(
            "http:// is only allowed for loopback addresses — an API key sent over plain HTTP is \
             readable by anything on the path, so a remote endpoint must be https://"
                .to_string(),
        ))
    }
}

fn validate_host_present(rest: &str) -> Result<(), IntegrationError> {
    if host_of(rest).is_empty() {
        return Err(IntegrationError::Invalid(
            "that endpoint URL has no host in it".to_string(),
        ));
    }
    Ok(())
}

/// The authority component, minus any `userinfo@` prefix and minus any
/// `:port`. Splitting on every delimiter that can end an authority
/// (`/`, `?`, `#`) matters: `https://127.0.0.1#@evil.example` and
/// `https://127.0.0.1?@evil.example` both have to resolve to the same
/// host a real URL parser would find, not to whatever a naive
/// last-`@`-wins split returns.
fn host_of(rest: &str) -> &str {
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let after_userinfo = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    // An IPv6 literal is bracketed and contains colons of its own, so
    // the port split has to happen after the bracket, not before it.
    if let Some(close) = after_userinfo.find(']') {
        return &after_userinfo[..=close];
    }
    match after_userinfo.split_once(':') {
        Some((h, _port)) => h,
        None => after_userinfo,
    }
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host == "[::1]" {
        return true;
    }
    // The whole 127.0.0.0/8 block, not just 127.0.0.1.
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

/// A header name goes into the request verbatim, so it is restricted to
/// exactly RFC 9110's `token` production. Anything looser lets a name
/// containing `:` or CRLF rewrite the rest of the request.
pub fn validate_header_name(name: &str) -> Result<(), IntegrationError> {
    if name.is_empty() {
        return Err(IntegrationError::Invalid(
            "a custom header needs a name".to_string(),
        ));
    }
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(IntegrationError::Invalid(format!(
            "a header name is limited to {MAX_HEADER_NAME_LEN} characters"
        )));
    }
    const TOKEN_SPECIALS: &[char] = &[
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~',
    ];
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || TOKEN_SPECIALS.contains(&c))
    {
        return Err(IntegrationError::Invalid(
            "that is not a valid HTTP header name — letters, digits and !#$%&'*+-.^_`|~ only"
                .to_string(),
        ));
    }
    Ok(())
}

/// The security-load-bearing one.
///
/// The key becomes a header *value*. A key containing CR or LF would
/// end the header and let everything after it be read as further
/// headers — request splitting, using a credential field as the
/// injection point. Rejecting every control character (not just CR/LF)
/// is the conservative version of that check, and costs nothing: no
/// real API key contains one.
pub fn validate_api_key(api_key: &str) -> Result<(), IntegrationError> {
    if api_key.is_empty() {
        return Err(IntegrationError::Invalid(
            "an integration needs an API key".to_string(),
        ));
    }
    if api_key.len() > MAX_API_KEY_LEN {
        return Err(IntegrationError::Invalid(format!(
            "an API key is limited to {MAX_API_KEY_LEN} characters — this looks like a whole file \
             rather than a key"
        )));
    }
    if api_key.chars().any(|c| c.is_control()) {
        return Err(IntegrationError::Invalid(
            "that API key contains a line break or control character — those cannot be sent in an \
             HTTP header, and a key normally has neither"
                .to_string(),
        ));
    }
    // Leading/trailing whitespace in a pasted key is a real and common
    // paste artefact. Rejecting is better than silently trimming: a
    // silently-trimmed key that still doesn't work sends the operator
    // hunting in the wrong place.
    if api_key.trim() != api_key {
        return Err(IntegrationError::Invalid(
            "that API key has leading or trailing whitespace — remove it, or the request will be \
             signed with a key the service doesn't recognise"
                .to_string(),
        ));
    }
    Ok(())
}

/// The whole configured set. Loaded, mutated, and written back as a
/// unit — there are at most `MAX_INTEGRATIONS` of them, so there is no
/// reason to complicate this with partial updates.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Integrations {
    #[serde(default)]
    pub items: Vec<Integration>,
}

impl Integrations {
    /// A missing file is an empty set, not an error — an install that
    /// has never added an integration is the normal case.
    pub fn load(data_dir: &Path, key: &[u8; 32]) -> Result<Self, IntegrationError> {
        let path = store_path(data_dir);
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(IntegrationError::Io(format!("{}: {e}", path.display()))),
        };
        if meta.len() > MAX_FILE_LEN {
            return Err(IntegrationError::Corrupt);
        }
        let sealed =
            fs::read(&path).map_err(|e| IntegrationError::Io(format!("{}: {e}", path.display())))?;
        let plaintext = Zeroizing::new(
            fossh_ingest::crypto::open(key, &sealed).map_err(|_| IntegrationError::Corrupt)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| IntegrationError::Corrupt)
    }

    /// Replaces the file atomically: a temp file in the same directory,
    /// created 0600 *before* anything is written to it, fsynced, then
    /// `rename`d over the destination and the directory fsynced too.
    ///
    /// `rename`, not the create-once hard-link dance `data_key.rs`
    /// uses: that pattern is right for a file that must never be
    /// replaced once it exists, and wrong for one whose whole purpose
    /// is to be edited. A reader either sees the complete old file or
    /// the complete new one, never a partial write.
    pub fn save(&self, data_dir: &Path, key: &[u8; 32]) -> Result<(), IntegrationError> {
        let path = store_path(data_dir);
        let plaintext = Zeroizing::new(
            serde_json::to_vec(self)
                .map_err(|e| IntegrationError::Io(format!("serialising integrations: {e}")))?,
        );
        let sealed = fossh_ingest::crypto::seal(key, &plaintext)
            .map_err(|e| IntegrationError::Io(format!("sealing integrations: {e}")))?;

        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| IntegrationError::Io(format!("{}: {e}", tmp.display())))?;
            f.write_all(&sealed)
                .map_err(|e| IntegrationError::Io(format!("{}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| IntegrationError::Io(format!("{}: {e}", tmp.display())))?;
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(IntegrationError::Io(format!("{}: {e}", path.display())));
        }
        // Without this the rename itself can be lost on power failure
        // even though the file's own contents were synced.
        if let Ok(dir) = fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Integration> {
        self.items.iter().find(|i| i.name == name)
    }

    pub fn add(
        &mut self,
        name: &str,
        endpoint: &str,
        auth: Auth,
        method: Method,
        api_key: &str,
        now: i64,
    ) -> Result<(), IntegrationError> {
        validate_name(name)?;
        validate_endpoint(endpoint)?;
        validate_api_key(api_key)?;
        if let Auth::Header { name: header } = &auth {
            validate_header_name(header)?;
        }
        if self.get(name).is_some() {
            return Err(IntegrationError::Duplicate(name.to_string()));
        }
        if self.items.len() >= MAX_INTEGRATIONS {
            return Err(IntegrationError::TooMany);
        }
        self.items.push(Integration {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            auth,
            method,
            created_at: now,
            api_key: api_key.to_string(),
        });
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), IntegrationError> {
        let before = self.items.len();
        self.items.retain(|i| i.name != name);
        if self.items.len() == before {
            return Err(IntegrationError::NotFound(name.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-integrations-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_are_restricted_to_something_unambiguous() {
        assert!(validate_name("my-webhook").is_ok());
        assert!(validate_name("s3_backup2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("Has Capitals").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("semi;colon").is_err());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn plain_http_is_refused_for_anything_that_is_not_loopback() {
        assert!(validate_endpoint("https://api.example.com/hook").is_ok());
        assert!(validate_endpoint("http://127.0.0.1:8080/hook").is_ok());
        assert!(validate_endpoint("http://127.5.5.5/hook").is_ok());
        assert!(validate_endpoint("http://localhost/hook").is_ok());
        assert!(validate_endpoint("http://LocalHost/hook").is_ok());
        assert!(validate_endpoint("http://[::1]:9000/hook").is_ok());
        assert!(validate_endpoint("http://api.example.com/hook").is_err());
        assert!(validate_endpoint("ftp://api.example.com/hook").is_err());
        assert!(validate_endpoint("api.example.com").is_err());
    }

    #[test]
    fn loopback_is_matched_on_the_real_host_not_a_substring() {
        // Every one of these contains "127.0.0.1" or "localhost"
        // somewhere while resolving to a completely different host. A
        // substring check would have let all of them send a key in
        // cleartext to an attacker-chosen server.
        assert!(validate_endpoint("http://127.0.0.1.evil.example/hook").is_err());
        assert!(validate_endpoint("http://localhost.evil.example/hook").is_err());
        assert!(validate_endpoint("http://evil.example/?h=127.0.0.1").is_err());
        assert!(validate_endpoint("http://evil.example/#127.0.0.1").is_err());
        assert!(validate_endpoint("http://evil.example/127.0.0.1").is_err());
        // userinfo: the host is what follows the last '@', so this one
        // really is loopback and must pass.
        assert!(validate_endpoint("http://127.0.0.1@localhost/hook").is_ok());
        // ...and this one really is not, despite the loopback prefix.
        assert!(validate_endpoint("http://localhost@evil.example/hook").is_err());
        // A '#' or '?' before the '@' ends the authority, so the '@'
        // is in the fragment/query and the host is still evil.example.
        assert!(validate_endpoint("http://evil.example#@localhost/").is_err());
        assert!(validate_endpoint("http://evil.example?@localhost/").is_err());
    }

    #[test]
    fn an_api_key_with_a_line_break_is_refused() {
        // The one check in this module that is genuinely a
        // vulnerability if it is missing: this value goes into an HTTP
        // header, and CRLF in a header value is request splitting.
        assert!(validate_api_key("sk_live_abcdef123456").is_ok());
        assert!(validate_api_key("key\r\nX-Injected: yes").is_err());
        assert!(validate_api_key("key\nX-Injected: yes").is_err());
        assert!(validate_api_key("key\rmore").is_err());
        assert!(validate_api_key("key\0more").is_err());
        assert!(validate_api_key("key\twith-tab").is_err());
        assert!(validate_api_key("").is_err());
        assert!(validate_api_key(" leading").is_err());
        assert!(validate_api_key("trailing ").is_err());
        assert!(validate_api_key(&"k".repeat(MAX_API_KEY_LEN + 1)).is_err());
    }

    #[test]
    fn a_header_name_cannot_smuggle_a_second_header() {
        assert!(validate_header_name("X-Api-Key").is_ok());
        assert!(validate_header_name("Private-Token").is_ok());
        assert!(validate_header_name("X-Api-Key: v\r\nX-Evil").is_err());
        assert!(validate_header_name("has space").is_err());
        assert!(validate_header_name("colon:inside").is_err());
        assert!(validate_header_name("").is_err());
    }

    #[test]
    fn a_key_hint_never_reveals_a_meaningful_fraction_of_a_short_key() {
        let mut set = Integrations::default();
        set.add(
            "short",
            "https://api.example.com",
            Auth::Bearer,
            Method::Get,
            "abcdefgh",
            0,
        )
        .unwrap();
        assert_eq!(
            set.get("short").unwrap().key_hint(),
            None,
            "an 8-character key must get no hint at all"
        );

        set.add(
            "long",
            "https://api.example.com",
            Auth::Bearer,
            Method::Get,
            "sk_live_0123456789wxyz",
            0,
        )
        .unwrap();
        assert_eq!(set.get("long").unwrap().key_hint().unwrap(), "wxyz");
    }

    #[test]
    fn a_key_hint_slices_on_char_boundaries_not_bytes() {
        let mut set = Integrations::default();
        // 16 multi-byte characters — a byte-index slice would panic.
        set.add(
            "unicode",
            "https://api.example.com",
            Auth::Bearer,
            Method::Get,
            &"é".repeat(16),
            0,
        )
        .unwrap();
        assert_eq!(set.get("unicode").unwrap().key_hint().unwrap(), "éééé");
    }

    #[test]
    fn debug_output_never_contains_the_key() {
        let mut set = Integrations::default();
        set.add(
            "web",
            "https://api.example.com",
            Auth::Bearer,
            Method::Get,
            "sk_live_TOPSECRETVALUE",
            0,
        )
        .unwrap();
        let rendered = format!("{:?}", set);
        assert!(
            !rendered.contains("TOPSECRET"),
            "a credential reached a Debug rendering: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn a_saved_set_round_trips_through_the_sealed_file() {
        let dir = scratch_dir("roundtrip");
        let key = [3u8; 32];
        let mut set = Integrations::default();
        set.add(
            "alerts",
            "https://hooks.example.com/x",
            Auth::Header {
                name: "X-Api-Key".to_string(),
            },
            Method::Post,
            "sk_live_abcdefghijkl",
            1_700_000_000,
        )
        .unwrap();
        set.save(&dir, &key).unwrap();

        let loaded = Integrations::load(&dir, &key).unwrap();
        assert_eq!(loaded.items.len(), 1);
        let one = loaded.get("alerts").unwrap();
        assert_eq!(one.api_key(), "sk_live_abcdefghijkl");
        assert_eq!(one.endpoint, "https://hooks.example.com/x");
        assert_eq!(
            one.auth,
            Auth::Header {
                name: "X-Api-Key".to_string()
            }
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_file_on_disk_never_contains_the_key_in_cleartext() {
        // The point of sealing it. Worth asserting directly rather
        // than trusting that `save` called `seal`.
        let dir = scratch_dir("sealed");
        let key = [4u8; 32];
        let mut set = Integrations::default();
        set.add(
            "alerts",
            "https://hooks.internal.example/x",
            Auth::Bearer,
            Method::Get,
            "sk_live_PLAINTEXTCANARY",
            0,
        )
        .unwrap();
        set.save(&dir, &key).unwrap();

        let raw = fs::read(store_path(&dir)).unwrap();
        let haystack = String::from_utf8_lossy(&raw);
        assert!(!haystack.contains("PLAINTEXTCANARY"));
        // The endpoint is sealed too, per this module's own doc.
        assert!(!haystack.contains("hooks.internal.example"));
        assert!(!haystack.contains("alerts"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_file_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("mode");
        let key = [5u8; 32];
        let set = Integrations::default();
        set.save(&dir, &key).unwrap();
        let mode = fs::metadata(store_path(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_set_rather_than_an_error() {
        let dir = scratch_dir("absent");
        let loaded = Integrations::load(&dir, &[6u8; 32]).unwrap();
        assert!(loaded.items.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_written_under_a_different_key_reports_corrupt_not_empty() {
        // Failing open here — treating an undecryptable file as "no
        // integrations" — would silently drop the operator's whole
        // configuration and then happily overwrite it on the next save.
        let dir = scratch_dir("wrongkey");
        let mut set = Integrations::default();
        set.add("a", "https://x.example", Auth::Bearer, Method::Get, "sk_abcdefghijkl", 0)
            .unwrap();
        set.save(&dir, &[7u8; 32]).unwrap();

        assert!(matches!(
            Integrations::load(&dir, &[8u8; 32]),
            Err(IntegrationError::Corrupt)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tampered_file_reports_corrupt() {
        let dir = scratch_dir("tampered");
        let key = [9u8; 32];
        let mut set = Integrations::default();
        set.add("a", "https://x.example", Auth::Bearer, Method::Get, "sk_abcdefghijkl", 0)
            .unwrap();
        set.save(&dir, &key).unwrap();

        let path = store_path(&dir);
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        fs::write(&path, &raw).unwrap();

        assert!(matches!(
            Integrations::load(&dir, &key),
            Err(IntegrationError::Corrupt)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adding_a_duplicate_name_is_refused_rather_than_shadowing() {
        let mut set = Integrations::default();
        set.add("a", "https://x.example", Auth::Bearer, Method::Get, "sk_abcdefghijkl", 0)
            .unwrap();
        assert!(matches!(
            set.add("a", "https://y.example", Auth::Bearer, Method::Get, "sk_mnopqrstuvwx", 0),
            Err(IntegrationError::Duplicate(_))
        ));
        assert_eq!(set.items.len(), 1);
    }

    #[test]
    fn removing_something_that_is_not_there_is_an_error_not_a_silent_success() {
        let mut set = Integrations::default();
        assert!(matches!(
            set.remove("nope"),
            Err(IntegrationError::NotFound(_))
        ));
    }

    #[test]
    fn a_rejected_add_leaves_the_set_untouched() {
        // Validation runs before the push, so a bad key must not
        // half-add anything.
        let mut set = Integrations::default();
        assert!(set
            .add("ok-name", "https://x.example", Auth::Bearer, Method::Get, "bad\nkey", 0)
            .is_err());
        assert!(set.items.is_empty());
        assert!(set
            .add(
                "ok-name",
                "https://x.example",
                Auth::Header {
                    name: "Bad Header".to_string()
                },
                Method::Get,
                "sk_abcdefghijkl",
                0
            )
            .is_err());
        assert!(set.items.is_empty());
    }

    #[test]
    fn the_number_of_integrations_is_capped() {
        let mut set = Integrations::default();
        for i in 0..MAX_INTEGRATIONS {
            set.add(
                &format!("n{i}"),
                "https://x.example",
                Auth::Bearer,
                Method::Get,
                "sk_abcdefghijkl",
                0,
            )
            .unwrap();
        }
        assert!(matches!(
            set.add("one-too-many", "https://x.example", Auth::Bearer, Method::Get, "sk_abcdefghijkl", 0),
            Err(IntegrationError::TooMany)
        ));
    }

    #[test]
    fn bearer_and_custom_headers_render_the_way_the_service_expects() {
        let (n, v) = Auth::Bearer.header("sk_live_x");
        assert_eq!(n, "Authorization");
        assert_eq!(v.as_str(), "Bearer sk_live_x");

        let (n, v) = Auth::Header {
            name: "X-Api-Key".to_string(),
        }
        .header("sk_live_x");
        assert_eq!(n, "X-Api-Key");
        assert_eq!(v.as_str(), "sk_live_x");
    }

    #[test]
    fn saving_over_an_existing_file_replaces_it_atomically_and_leaves_no_temp_behind() {
        let dir = scratch_dir("replace");
        let key = [10u8; 32];
        let mut set = Integrations::default();
        set.add("a", "https://x.example", Auth::Bearer, Method::Get, "sk_abcdefghijkl", 0)
            .unwrap();
        set.save(&dir, &key).unwrap();
        set.add("b", "https://y.example", Auth::Bearer, Method::Get, "sk_mnopqrstuvwx", 0)
            .unwrap();
        set.save(&dir, &key).unwrap();

        assert_eq!(Integrations::load(&dir, &key).unwrap().items.len(), 2);
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }
}
