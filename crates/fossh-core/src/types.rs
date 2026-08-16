use crate::ua::{BrowserFamily, DeviceClass, OsFamily};
use crate::validate::{Key, Name, Val};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SiteId(u32);

impl SiteId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Country([u8; 2]);

impl Country {
    pub const UNKNOWN: Country = Country(*b"ZZ");

    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() == 2 && b[0].is_ascii_uppercase() && b[1].is_ascii_uppercase() {
            Some(Country([b[0], b[1]]))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("Country bytes are always two ASCII uppercase letters")
    }
}

impl Default for Country {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl std::fmt::Display for Country {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path(String);

impl Path {
    pub fn from_raw(raw: &str) -> Self {
        Self(crate::sanitize_path::sanitize_path(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

const KNOWN_MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk", "com.tr", "gov.tr", "edu.tr",
    "org.tr", "net.tr", "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz", "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "gov.za", "com.mx", "org.mx", "gob.mx", "co.in", "net.in", "org.in",
    "gov.in", "co.kr", "or.kr", "go.kr", "com.cn", "net.cn", "org.cn", "gov.cn", "com.sg",
    "com.hk",
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Host(String);

impl Host {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_trusted(s: String) -> Self {
        Self(s)
    }

    pub fn from_referrer_url(url: &str) -> Option<Self> {
        let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        let authority = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
        let host_and_port = authority.rsplit('@').next().unwrap_or(authority);

        let host = if let Some(rest) = host_and_port.strip_prefix('[') {

            rest.split(']')
                .next()
                .map(|h| format!("[{h}]"))
                .unwrap_or_default()
        } else {
            host_and_port.split(':').next().unwrap_or("").to_string()
        };
        let host = host.trim().to_ascii_lowercase();

        if !looks_like_host(&host) {
            return None;
        }
        Some(Self(registrable_domain(&host)))
    }
}

fn looks_like_host(h: &str) -> bool {
    if h.is_empty() {
        return false;
    }
    if h.starts_with('[') && h.ends_with(']') {
        return h.len() > 2;
    }
    h.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && h.contains('.')
}

fn registrable_domain(host: &str) -> String {
    if host.starts_with('[') {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if labels.len() >= 3 && KNOWN_MULTI_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        format!("{}.{}", labels[labels.len() - 3], last_two)
    } else {
        last_two
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventKind {
    Pageview = 0,
    Action = 1,
    Timing = 2,
    Error = 3,
}

impl EventKind {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::Pageview),
            1 => Some(Self::Action),
            2 => Some(Self::Timing),
            3 => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub site_id: SiteId,

    pub ts: i64,
    pub kind: EventKind,
    pub name: Name,
    pub path: Option<Path>,
    pub referrer: Option<Host>,
    pub country: Country,
    pub browser: BrowserFamily,
    pub os: OsFamily,
    pub device: DeviceClass,

    pub visitor: Option<u64>,

    pub value: Option<i64>,
    pub props: Vec<(Key, Val)>,
}

impl Event {

    pub fn validate(&self) -> Result<(), crate::validate::ValidationError> {
        crate::validate::validate_prop_count(&self.props)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_parses_valid_codes() {
        assert!(Country::parse("US").is_some());
        assert!(Country::parse("TR").is_some());
        assert_eq!(Country::parse("US").unwrap().as_str(), "US");
    }

    #[test]
    fn country_rejects_lowercase_and_wrong_length() {
        assert!(Country::parse("us").is_none());
        assert!(Country::parse("USA").is_none());
        assert!(Country::parse("U").is_none());
        assert!(Country::parse("").is_none());
    }

    #[test]
    fn country_default_is_unknown_sentinel() {
        assert_eq!(Country::default().as_str(), "ZZ");
    }

    #[test]
    fn path_goes_through_sanitize() {
        let p = Path::from_raw("/users/12345678/edit?x=1");
        assert_eq!(p.as_str(), "/users/:id/edit");
    }

    #[test]
    fn host_extracts_registrable_domain() {
        assert_eq!(
            Host::from_referrer_url("https://www.google.com/search?q=x")
                .unwrap()
                .as_str(),
            "google.com"
        );
        assert_eq!(
            Host::from_referrer_url("http://sub.deep.example.com/a/b")
                .unwrap()
                .as_str(),
            "example.com"
        );
        assert_eq!(
            Host::from_referrer_url("https://example.com")
                .unwrap()
                .as_str(),
            "example.com"
        );
        assert_eq!(
            Host::from_referrer_url("https://user:pass@example.com:8080/path")
                .unwrap()
                .as_str(),
            "example.com"
        );
    }

    #[test]
    fn host_handles_multi_label_suffixes() {
        assert_eq!(
            Host::from_referrer_url("https://blog.example.co.uk/post/1")
                .unwrap()
                .as_str(),
            "example.co.uk"
        );
        assert_eq!(
            Host::from_referrer_url("https://www.haberler.com.tr/gundem")
                .unwrap()
                .as_str(),
            "haberler.com.tr"
        );
    }

    #[test]
    fn host_rejects_garbage() {
        assert!(Host::from_referrer_url("not a url").is_none());
        assert!(Host::from_referrer_url("").is_none());
        assert!(Host::from_referrer_url("https://").is_none());
        assert!(Host::from_referrer_url("localhost").is_none());
    }

    #[test]
    fn host_never_retains_path_or_query() {
        let h = Host::from_referrer_url("https://example.com/secret/path?token=abc123").unwrap();
        assert_eq!(h.as_str(), "example.com");
        assert!(!h.as_str().contains("secret"));
        assert!(!h.as_str().contains("token"));
    }

    #[test]
    fn event_kind_roundtrip() {
        for k in [
            EventKind::Pageview,
            EventKind::Action,
            EventKind::Timing,
            EventKind::Error,
        ] {
            assert_eq!(EventKind::from_i64(k.as_i64()), Some(k));
        }
        assert_eq!(EventKind::from_i64(99), None);
    }

    #[test]
    fn event_validate_enforces_prop_count() {
        let too_many: Vec<(Key, Val)> = (0..17)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v").unwrap(),
                )
            })
            .collect();
        let ev = Event {
            site_id: SiteId::new(1),
            ts: 0,
            kind: EventKind::Pageview,
            name: Name::parse("pageview").unwrap(),
            path: None,
            referrer: None,
            country: Country::UNKNOWN,
            browser: BrowserFamily::Other,
            os: OsFamily::Other,
            device: DeviceClass::Unknown,
            visitor: None,
            value: None,
            props: too_many,
        };
        assert!(ev.validate().is_err());
    }
}
