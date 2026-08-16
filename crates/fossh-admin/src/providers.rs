use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::integrations::{Auth, Method, validate_endpoint, validate_header_name};

const MAX_PROVIDERS: usize = 256;
const MAX_PROVIDER_BYTES: u64 = 64 * 1024;

pub const SYSTEM_DIR: &str = "/usr/share/fossh/providers";
pub const SITE_DIR: &str = "/etc/fossh/providers.d";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {

    pub key: String,
    pub label: String,
    #[serde(default)]
    pub placeholder: String,
    #[serde(default)]
    pub help: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,

    #[serde(default)]
    pub docs: String,

    pub endpoint: String,
    #[serde(default)]
    pub method: Method,

    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,

    #[serde(default)]
    pub key_hint: String,
}

#[derive(Debug)]
pub enum ProviderError {
    Invalid { id: String, reason: String },
    MissingField(String),
    Io(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Invalid { id, reason } => {
                write!(f, "the provider \"{id}\" is not usable: {reason}")
            }
            ProviderError::MissingField(k) => write!(f, "\"{k}\" still needs a value"),
            ProviderError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl Provider {

    pub fn auth(&self) -> Auth {
        match &self.auth_header {
            None => Auth::Bearer,
            Some(name) => Auth::Header { name: name.clone() },
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let bad = |reason: &str| ProviderError::Invalid {
            id: self.id.clone(),
            reason: reason.to_string(),
        };

        if self.id.is_empty()
            || !self
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(bad(
                "an id may only contain lowercase letters, digits and \"-\"",
            ));
        }
        if self.name.is_empty() {
            return Err(bad("it has no display name"));
        }
        if let Some(header) = &self.auth_header {
            validate_header_name(header).map_err(|e| bad(&e.to_string()))?;
        }
        if !self.docs.is_empty() && !self.docs.starts_with("https://") {
            return Err(bad("its docs link is not an https:// URL"));
        }

        let declared: Vec<&str> = self.fields.iter().map(|f| f.key.as_str()).collect();
        for placeholder in placeholders(&self.endpoint) {
            if !declared.contains(&placeholder.as_str()) {
                return Err(bad(&format!(
                    "its endpoint uses {{{placeholder}}}, which is not one of its fields"
                )));
            }
        }
        for field in &self.fields {
            if field.key.is_empty()
                || !field
                    .key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return Err(bad(
                    "a field key may only contain lowercase letters, digits and \"_\"",
                ));
            }
            if !self.endpoint.contains(&format!("{{{}}}", field.key)) {
                return Err(bad(&format!(
                    "it asks for \"{}\" but never uses it in the endpoint",
                    field.key
                )));
            }
        }

        if placeholders(&self.endpoint).is_empty() {
            validate_endpoint(&self.endpoint).map_err(|e| bad(&e.to_string()))?;
        }
        Ok(())
    }

    pub fn render_endpoint(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<String, ProviderError> {
        let mut out = self.endpoint.clone();
        for field in &self.fields {
            let value = values
                .get(&field.key)
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ProviderError::MissingField(field.key.clone()))?;

            if value.chars().any(|c| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(c, '/' | '?' | '#' | '@' | '\\' | ':')
            }) {
                return Err(ProviderError::Invalid {
                    id: self.id.clone(),
                    reason: format!(
                        "the value for \"{}\" contains a character that would change which \
                         server this address points at",
                        field.key
                    ),
                });
            }
            out = out.replace(&format!("{{{}}}", field.key), value);
        }

        if let Some(left) = placeholders(&out).first() {
            return Err(ProviderError::MissingField(left.clone()));
        }
        validate_endpoint(&out).map_err(|e| ProviderError::Invalid {
            id: self.id.clone(),
            reason: e.to_string(),
        })?;
        Ok(out)
    }
}

fn placeholders(template: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let name = &after[..close];
        if !name.is_empty() && !found.iter().any(|f: &String| f == name) {
            found.push(name.to_string());
        }
        rest = &after[close + 1..];
    }
    found
}

pub fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(SYSTEM_DIR), PathBuf::from(SITE_DIR)];
    let user = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    if let Some(base) = user {
        dirs.push(base.join("fossh/providers.d"));
    }
    dirs
}

pub fn load_from(dirs: &[PathBuf]) -> (Vec<Provider>, Vec<ProviderError>) {
    let mut by_id: BTreeMap<String, Provider> = BTreeMap::new();
    let mut problems = Vec::new();

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();

        paths.sort();

        for path in paths {
            if by_id.len() >= MAX_PROVIDERS {
                problems.push(ProviderError::Io(format!(
                    "more than {MAX_PROVIDERS} providers found; the rest were ignored"
                )));
                break;
            }
            match load_one(&path) {
                Ok(provider) => {
                    by_id.insert(provider.id.clone(), provider);
                }
                Err(e) => problems.push(e),
            }
        }
    }
    (by_id.into_values().collect(), problems)
}

pub fn load() -> (Vec<Provider>, Vec<ProviderError>) {
    load_from(&search_dirs())
}

fn load_one(path: &Path) -> Result<Provider, ProviderError> {
    let name = path.display().to_string();
    let meta = std::fs::metadata(path).map_err(|e| ProviderError::Io(format!("{name}: {e}")))?;
    if meta.len() > MAX_PROVIDER_BYTES {
        return Err(ProviderError::Io(format!(
            "{name}: larger than {MAX_PROVIDER_BYTES} bytes, which no provider definition is"
        )));
    }
    let text =
        std::fs::read_to_string(path).map_err(|e| ProviderError::Io(format!("{name}: {e}")))?;
    let provider: Provider =
        toml::from_str(&text).map_err(|e| ProviderError::Io(format!("{name}: {e}")))?;
    provider.validate()?;
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn base() -> Provider {
        Provider {
            id: "example".to_string(),
            name: "Example".to_string(),
            docs: "https://docs.example.com/keys".to_string(),
            endpoint: "https://api.example.com/v1/events".to_string(),
            method: Method::Post,
            auth_header: Some("X-Api-Key".to_string()),
            fields: vec![],
            key_hint: "starts with ex_".to_string(),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_well_formed_provider_validates() {
        assert!(base().validate().is_ok());
    }

    #[test]
    fn a_provider_with_a_bad_header_name_is_refused() {
        let mut p = base();
        p.auth_header = Some("X-Api-Key: injected\r\nEvil".to_string());
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_provider_whose_endpoint_is_plain_http_is_refused() {
        let mut p = base();
        p.endpoint = "http://api.example.com/v1".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_placeholder_with_no_matching_field_is_refused() {

        let mut p = base();
        p.endpoint = "https://api.{region}.example.com/v1".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_field_the_endpoint_never_uses_is_refused() {

        let mut p = base();
        p.fields = vec![Field {
            key: "region".to_string(),
            label: "Region".to_string(),
            placeholder: String::new(),
            help: String::new(),
        }];
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_template_renders_and_is_validated_after_substitution_not_before() {
        let mut p = base();
        p.endpoint = "https://api.{region}.example.com/v1/events".to_string();
        p.fields = vec![Field {
            key: "region".to_string(),
            label: "Region".to_string(),
            placeholder: "eu-west-1".to_string(),
            help: String::new(),
        }];
        assert!(p.validate().is_ok());

        let rendered = p
            .render_endpoint(&values(&[("region", "eu-west-1")]))
            .unwrap();
        assert_eq!(rendered, "https://api.eu-west-1.example.com/v1/events");
    }

    #[test]
    fn a_field_value_cannot_redirect_the_finished_url_to_another_host() {

        let mut p = base();
        p.endpoint = "https://api.{region}.example.com/v1".to_string();
        p.fields = vec![Field {
            key: "region".to_string(),
            label: "Region".to_string(),
            placeholder: String::new(),
            help: String::new(),
        }];

        for hostile in [
            "evil.invalid/",
            "x@evil.invalid",
            "x?@evil.invalid",
            "x#@evil.invalid",
            "x:9999",
            "x\\evil.invalid",
            "x evil",
        ] {
            assert!(
                p.render_endpoint(&values(&[("region", hostile)])).is_err(),
                "{hostile:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_missing_field_value_is_named_rather_than_left_as_a_brace() {
        let mut p = base();
        p.endpoint = "https://api.{region}.example.com/v1".to_string();
        p.fields = vec![Field {
            key: "region".to_string(),
            label: "Region".to_string(),
            placeholder: String::new(),
            help: String::new(),
        }];
        match p.render_endpoint(&values(&[])) {
            Err(ProviderError::MissingField(k)) => assert_eq!(k, "region"),
            other => panic!("expected a named missing field, got {other:?}"),
        }

        assert!(p.render_endpoint(&values(&[("region", "   ")])).is_err());
    }

    #[test]
    fn placeholders_are_found_once_each_and_in_order() {
        assert_eq!(placeholders("https://{a}.x/{b}/{a}"), vec!["a", "b"]);
        assert_eq!(placeholders("https://x/"), Vec::<String>::new());

        assert_eq!(placeholders("https://{unclosed"), Vec::<String>::new());
        assert_eq!(placeholders("}{"), Vec::<String>::new());
    }

    #[test]
    fn no_auth_header_means_a_bearer_token() {
        let mut p = base();
        p.auth_header = None;
        assert_eq!(p.auth(), Auth::Bearer);
        p.auth_header = Some("DD-API-KEY".to_string());
        assert_eq!(
            p.auth(),
            Auth::Header {
                name: "DD-API-KEY".to_string()
            }
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-providers-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SAMPLE: &str = r#"
id = "sample"
name = "Sample Service"
docs = "https://docs.example.com"
endpoint = "https://api.example.com/v1/events"
method = "post"
auth_header = "X-Api-Key"
"#;

    #[test]
    fn providers_load_from_a_directory() {
        let dir = scratch("load");
        fs::write(dir.join("sample.toml"), SAMPLE).unwrap();
        let (providers, problems) = load_from(&[dir.clone()]);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "sample");
        assert_eq!(providers[0].method, Method::Post);
        assert!(problems.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn one_broken_file_does_not_take_away_the_others() {

        let dir = scratch("broken");
        fs::write(dir.join("good.toml"), SAMPLE).unwrap();
        fs::write(dir.join("bad.toml"), "this is not toml at all {{{").unwrap();
        fs::write(dir.join("notes.txt"), "ignored, wrong extension").unwrap();

        let (providers, problems) = load_from(&[dir.clone()]);
        assert_eq!(providers.len(), 1, "the good one must still load");
        assert_eq!(problems.len(), 1, "and the bad one must be reported");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_later_directory_overrides_an_earlier_one_by_id() {
        let system = scratch("override-system");
        let site = scratch("override-site");
        fs::write(system.join("s.toml"), SAMPLE).unwrap();
        fs::write(
            site.join("s.toml"),
            SAMPLE.replace(
                "https://api.example.com/v1/events",
                "https://api.internal.example/v1/events",
            ),
        )
        .unwrap();

        let (providers, _) = load_from(&[system.clone(), site.clone()]);
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].endpoint,
            "https://api.internal.example/v1/events"
        );
        fs::remove_dir_all(&system).ok();
        fs::remove_dir_all(&site).ok();
    }

    #[test]
    fn a_directory_that_does_not_exist_is_skipped_silently() {

        let (providers, problems) = load_from(&[PathBuf::from("/nonexistent/fossh/providers")]);
        assert!(providers.is_empty());
        assert!(problems.is_empty());
    }

    #[test]
    fn an_oversized_file_is_refused_rather_than_read() {
        let dir = scratch("huge");
        fs::write(
            dir.join("huge.toml"),
            "x".repeat(MAX_PROVIDER_BYTES as usize + 1),
        )
        .unwrap();
        let (providers, problems) = load_from(&[dir.clone()]);
        assert!(providers.is_empty());
        assert_eq!(problems.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_bundled_provider_is_valid() {

        let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/providers");
        let (providers, problems) = load_from(&[bundled]);
        assert!(
            problems.is_empty(),
            "bundled providers have problems: {problems:?}"
        );
        assert!(
            !providers.is_empty(),
            "no bundled providers were found at all"
        );
        for p in &providers {
            assert!(p.validate().is_ok(), "{} is invalid", p.id);
            assert!(!p.docs.is_empty(), "{} has no docs link", p.id);
        }
    }
}
