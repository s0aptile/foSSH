use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_NAME_LEN: usize = 64;
const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_API_KEY_LEN: usize = 8192;

const MAX_FILE_LEN: u64 = 1024 * 1024;
const MAX_INTEGRATIONS: usize = 64;

pub const FILE_NAME: &str = "integrations.enc";

pub const LOCK_FILE_NAME: &str = "integrations.lock";

pub fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCK_FILE_NAME)
}

pub fn modify<T>(
    data_dir: &Path,
    key: &[u8; 32],
    change: impl FnOnce(&mut Integrations) -> Result<T, IntegrationError>,
) -> Result<T, IntegrationError> {
    use nix::fcntl::{Flock, FlockArg};

    std::fs::create_dir_all(data_dir)
        .map_err(|e| IntegrationError::Io(format!("{}: {e}", data_dir.display())))?;
    let path = lock_path(data_dir);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| IntegrationError::Io(format!("{}: {e}", path.display())))?;

    let _guard = Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_f, e)| IntegrationError::Io(format!("locking {}: {e}", path.display())))?;

    let mut set = Integrations::load(data_dir, key)?;
    let outcome = change(&mut set)?;
    set.save(data_dir, key)?;
    Ok(outcome)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "placement", rename_all = "snake_case")]
pub enum Auth {

    Bearer,

    Header { name: String },
}

impl Auth {

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {

    #[default]
    Get,

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

pub const TEST_BODY: &str = r#"{"source":"fossh","event":"connectivity-test","note":"sent by an operator from the foSSH console to verify this integration's endpoint and credential; carries no telemetry"}"#;

#[derive(Clone, Serialize, Deserialize)]
pub struct Integration {
    pub name: String,
    pub endpoint: String,
    pub auth: Auth,

    #[serde(default)]
    pub method: Method,
    pub created_at: i64,
    api_key: String,
}

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

    Invalid(String),

    Duplicate(String),
    NotFound(String),

    TooMany,
    Io(String),

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

pub fn validate_endpoint(endpoint: &str) -> Result<(), IntegrationError> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(IntegrationError::Invalid(format!(
            "an endpoint URL is limited to {MAX_ENDPOINT_LEN} characters"
        )));
    }

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

fn host_of(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let after_userinfo = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };

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

    match host.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

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

    if api_key.trim() != api_key {
        return Err(IntegrationError::Invalid(
            "that API key has leading or trailing whitespace — remove it, or the request will be \
             signed with a key the service doesn't recognise"
                .to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Integrations {
    #[serde(default)]
    pub items: Vec<Integration>,
}

impl Integrations {

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
        let sealed = fs::read(&path)
            .map_err(|e| IntegrationError::Io(format!("{}: {e}", path.display())))?;
        let plaintext = Zeroizing::new(
            fossh_ingest::crypto::open(key, &sealed).map_err(|_| IntegrationError::Corrupt)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| IntegrationError::Corrupt)
    }

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

        assert!(validate_endpoint("http://127.0.0.1.evil.example/hook").is_err());
        assert!(validate_endpoint("http://localhost.evil.example/hook").is_err());
        assert!(validate_endpoint("http://evil.example/?h=127.0.0.1").is_err());
        assert!(validate_endpoint("http://evil.example/#127.0.0.1").is_err());
        assert!(validate_endpoint("http://evil.example/127.0.0.1").is_err());

        assert!(validate_endpoint("http://127.0.0.1@localhost/hook").is_ok());

        assert!(validate_endpoint("http://localhost@evil.example/hook").is_err());

        assert!(validate_endpoint("http://evil.example#@localhost/").is_err());
        assert!(validate_endpoint("http://evil.example?@localhost/").is_err());
    }

    #[test]
    fn every_alternate_loopback_spelling_curl_understands_is_refused_here() {

        assert!(validate_endpoint("http://0177.0.0.1/hook").is_err());
        assert!(validate_endpoint("http://2130706433/hook").is_err());
        assert!(validate_endpoint("http://127.1/hook").is_err());
        assert!(validate_endpoint("http://[::ffff:127.0.0.1]/hook").is_err());

        assert!(validate_endpoint("http://127.0.0.1%2eevil.example/").is_err());

        for ok in [
            "http://127.0.0.1:9/",
            "http://localhost:9/",
            "http://[::1]:9/",

            "http://127.0.0.1@localhost:9/",
        ] {
            assert!(validate_endpoint(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn an_api_key_with_a_line_break_is_refused() {

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
    fn concurrent_writers_do_not_lose_each_others_additions() {

        use std::sync::Barrier;

        let dir = scratch_dir("concurrent");
        let key = [11u8; 32];
        const N: usize = 16;
        let barrier = Barrier::new(N);

        std::thread::scope(|scope| {
            for i in 0..N {
                let dir = &dir;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    modify(dir, &key, |set| {
                        set.add(
                            &format!("svc{i}"),
                            "https://x.example/hook",
                            Auth::Bearer,
                            Method::Get,
                            "sk_live_abcdefghijkl",
                            0,
                        )
                    })
                    .expect("every add should succeed");
                });
            }
        });

        let loaded = Integrations::load(&dir, &key).unwrap();
        assert_eq!(
            loaded.items.len(),
            N,
            "an add reported success and then was not there: {:?}",
            (0..N)
                .map(|i| format!("svc{i}"))
                .filter(|n| loaded.get(n).is_none())
                .collect::<Vec<_>>()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_concurrent_remove_is_not_undone_by_a_stale_writer() {

        use std::sync::Barrier;

        let dir = scratch_dir("concurrent-remove");
        let key = [12u8; 32];
        modify(&dir, &key, |set| {
            set.add(
                "gone",
                "https://x.example",
                Auth::Bearer,
                Method::Get,
                "sk_live_abcdefghijkl",
                0,
            )
        })
        .unwrap();

        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                modify(&dir, &key, |set| set.remove("gone")).unwrap();
            });
            scope.spawn(|| {
                barrier.wait();
                let _ = modify(&dir, &key, |set| {
                    set.add(
                        "other",
                        "https://y.example",
                        Auth::Bearer,
                        Method::Get,
                        "sk_live_mnopqrstuvwx",
                        0,
                    )
                });
            });
        });

        let loaded = Integrations::load(&dir, &key).unwrap();
        assert!(loaded.get("gone").is_none(), "a removed entry came back");
        assert!(loaded.get("other").is_some(), "the concurrent add was lost");
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

        let dir = scratch_dir("wrongkey");
        let mut set = Integrations::default();
        set.add(
            "a",
            "https://x.example",
            Auth::Bearer,
            Method::Get,
            "sk_abcdefghijkl",
            0,
        )
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
        set.add(
            "a",
            "https://x.example",
            Auth::Bearer,
            Method::Get,
            "sk_abcdefghijkl",
            0,
        )
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
        set.add(
            "a",
            "https://x.example",
            Auth::Bearer,
            Method::Get,
            "sk_abcdefghijkl",
            0,
        )
        .unwrap();
        assert!(matches!(
            set.add(
                "a",
                "https://y.example",
                Auth::Bearer,
                Method::Get,
                "sk_mnopqrstuvwx",
                0
            ),
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

        let mut set = Integrations::default();
        assert!(
            set.add(
                "ok-name",
                "https://x.example",
                Auth::Bearer,
                Method::Get,
                "bad\nkey",
                0
            )
            .is_err()
        );
        assert!(set.items.is_empty());
        assert!(
            set.add(
                "ok-name",
                "https://x.example",
                Auth::Header {
                    name: "Bad Header".to_string()
                },
                Method::Get,
                "sk_abcdefghijkl",
                0
            )
            .is_err()
        );
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
            set.add(
                "one-too-many",
                "https://x.example",
                Auth::Bearer,
                Method::Get,
                "sk_abcdefghijkl",
                0
            ),
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
        set.add(
            "a",
            "https://x.example",
            Auth::Bearer,
            Method::Get,
            "sk_abcdefghijkl",
            0,
        )
        .unwrap();
        set.save(&dir, &key).unwrap();
        set.add(
            "b",
            "https://y.example",
            Auth::Bearer,
            Method::Get,
            "sk_mnopqrstuvwx",
            0,
        )
        .unwrap();
        set.save(&dir, &key).unwrap();

        assert_eq!(Integrations::load(&dir, &key).unwrap().items.len(), 2);
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
