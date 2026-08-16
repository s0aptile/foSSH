use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::validate::ENV_VALUE_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Spool,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CountryDb {
    #[default]
    Builtin,
    None,
    Custom(PathBuf),
}

impl<'de> Deserialize<'de> for CountryDb {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(CountryDb::from_str(&s))
    }
}

impl Serialize for CountryDb {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CountryDb::Builtin => serializer.serialize_str("builtin"),
            CountryDb::None => serializer.serialize_str("none"),
            CountryDb::Custom(p) => serializer.serialize_str(&p.to_string_lossy()),
        }
    }
}

impl CountryDb {

    pub fn from_str(s: &str) -> Self {
        match s {
            "builtin" => CountryDb::Builtin,
            "none" => CountryDb::None,
            _ => CountryDb::Custom(PathBuf::from(s)),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            CountryDb::Builtin | CountryDb::None => None,
            CountryDb::Custom(p) => Some(p.as_path()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct RateLimit {
    #[serde(default = "default_per_sec")]
    pub per_sec: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            per_sec: default_per_sec(),
            burst: default_burst(),
        }
    }
}

fn default_per_sec() -> u32 {
    60
}
fn default_burst() -> u32 {
    600
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub bind: String,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/fossh")
}
fn default_retention_days() -> u32 {
    90
}
fn default_k_anonymity() -> u32 {
    5
}

pub const RETENTION_DAYS_MAX: u32 = 10_000;
fn default_true() -> bool {
    true
}
fn default_salt_dir() -> PathBuf {
    PathBuf::from("/run/fossh")
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_k_anonymity")]
    pub k_anonymity: u32,
    #[serde(default = "default_true")]
    pub respect_optout_signals: bool,
    #[serde(default)]
    pub country_db: CountryDb,
    #[serde(default = "default_salt_dir")]
    pub salt_dir: PathBuf,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub listener: Option<ListenerConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            mode: Mode::default(),
            retention_days: default_retention_days(),
            k_anonymity: default_k_anonymity(),
            respect_optout_signals: true,
            country_db: CountryDb::default(),
            salt_dir: default_salt_dir(),
            rate_limit: RateLimit::default(),
            listener: None,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    ForbiddenBindAddress {
        value: String,
    },
    InvalidBindAddress {
        value: String,
    },
    EnvValueTooLarge {
        key: &'static str,
        len: usize,
    },
    EnvValueInvalid {
        key: &'static str,
        value: String,
    },
    KAnonymityTooLow {
        value: u32,
    },
    RetentionOutOfRange {
        value: u32,
    },
    RateLimitInvalid {
        reason: &'static str,
    },
}

pub const K_ANONYMITY_MIN: u32 = 2;

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            ConfigError::Parse { path, source } => {
                write!(f, "parsing {}: {source}", path.display())
            }
            ConfigError::ForbiddenBindAddress { value } => write!(
                f,
                "listener.bind = \"{value}\" binds an unspecified address (0.0.0.0 / ::), which \
                 violates S7 (loopback / unix-socket only); use 127.0.0.1:<port> or [::1]:<port>"
            ),
            ConfigError::InvalidBindAddress { value } => {
                write!(
                    f,
                    "listener.bind = \"{value}\" is not a valid socket address"
                )
            }
            ConfigError::EnvValueTooLarge { key, len } => write!(
                f,
                "environment variable {key} is {len} bytes, exceeds the {ENV_VALUE_MAX}-byte cap (S4)"
            ),
            ConfigError::EnvValueInvalid { key, value } => {
                write!(
                    f,
                    "environment variable {key}=\"{value}\" could not be applied"
                )
            }
            ConfigError::KAnonymityTooLow { value } => write!(
                f,
                "k_anonymity = {value} disables the small-group fold entirely (P6): a group with \
                 one visitor would be reported by exact path and exact hit count. The minimum is \
                 {K_ANONYMITY_MIN} and the default is {}. If you want no aggregation privacy at \
                 all, that is not a setting — do not run this.",
                default_k_anonymity()
            ),
            ConfigError::RetentionOutOfRange { value } => write!(
                f,
                "retention_days = {value} is outside 1..={RETENTION_DAYS_MAX}; 0 would delete \
                 every event as soon as it is written"
            ),
            ConfigError::RateLimitInvalid { reason } => {
                write!(f, "rate_limit is unusable: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Parse { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl Config {

    pub fn load() -> Result<Self, ConfigError> {
        let explicit = std::env::var_os("FOSSH_CONFIG").map(PathBuf::from);
        let mut config = match &explicit {
            Some(path) => Self::from_file(path)?,
            None => {
                let cwd_candidate = PathBuf::from("./fossh.toml");
                let etc_candidate = PathBuf::from("/etc/fossh/fossh.toml");
                if cwd_candidate.is_file() {
                    Self::from_file(&cwd_candidate)?
                } else if etc_candidate.is_file() {
                    Self::from_file(&etc_candidate)?
                } else {
                    Self::default()
                }
            }
        };
        config.apply_env_overrides(|key| std::env::var_os(key))?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    fn apply_env_overrides(
        &mut self,
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<(), ConfigError> {
        if let Some(v) = bounded("FOSSH_DATA_DIR", lookup("FOSSH_DATA_DIR"))? {
            self.data_dir = PathBuf::from(v);
        }
        if let Some(v) = bounded("FOSSH_MODE", lookup("FOSSH_MODE"))? {
            self.mode = match v.as_str() {
                "spool" => Mode::Spool,
                "direct" => Mode::Direct,
                _ => {
                    return Err(ConfigError::EnvValueInvalid {
                        key: "FOSSH_MODE",
                        value: v,
                    });
                }
            };
        }
        if let Some(v) = bounded("FOSSH_RETENTION_DAYS", lookup("FOSSH_RETENTION_DAYS"))? {
            self.retention_days = v.parse().map_err(|_| ConfigError::EnvValueInvalid {
                key: "FOSSH_RETENTION_DAYS",
                value: v,
            })?;
        }
        if let Some(v) = bounded("FOSSH_K_ANONYMITY", lookup("FOSSH_K_ANONYMITY"))? {
            self.k_anonymity = v.parse().map_err(|_| ConfigError::EnvValueInvalid {
                key: "FOSSH_K_ANONYMITY",
                value: v,
            })?;
        }
        if let Some(v) = bounded(
            "FOSSH_RESPECT_OPTOUT_SIGNALS",
            lookup("FOSSH_RESPECT_OPTOUT_SIGNALS"),
        )? {
            self.respect_optout_signals = match v.as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => {
                    return Err(ConfigError::EnvValueInvalid {
                        key: "FOSSH_RESPECT_OPTOUT_SIGNALS",
                        value: v,
                    });
                }
            };
        }
        if let Some(v) = bounded("FOSSH_COUNTRY_DB", lookup("FOSSH_COUNTRY_DB"))? {
            self.country_db = CountryDb::from_str(&v);
        }
        if let Some(v) = bounded("FOSSH_SALT_DIR", lookup("FOSSH_SALT_DIR"))? {
            self.salt_dir = PathBuf::from(v);
        }
        if let Some(v) = bounded(
            "FOSSH_RATE_LIMIT_PER_SEC",
            lookup("FOSSH_RATE_LIMIT_PER_SEC"),
        )? {
            self.rate_limit.per_sec = v.parse().map_err(|_| ConfigError::EnvValueInvalid {
                key: "FOSSH_RATE_LIMIT_PER_SEC",
                value: v,
            })?;
        }
        if let Some(v) = bounded("FOSSH_RATE_LIMIT_BURST", lookup("FOSSH_RATE_LIMIT_BURST"))? {
            self.rate_limit.burst = v.parse().map_err(|_| ConfigError::EnvValueInvalid {
                key: "FOSSH_RATE_LIMIT_BURST",
                value: v,
            })?;
        }
        if let Some(v) = bounded("FOSSH_LISTENER_BIND", lookup("FOSSH_LISTENER_BIND"))? {
            self.listener = Some(ListenerConfig { bind: v });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(listener) = &self.listener {
            let addr: SocketAddr =
                listener
                    .bind
                    .parse()
                    .map_err(|_| ConfigError::InvalidBindAddress {
                        value: listener.bind.clone(),
                    })?;
            if addr.ip().is_unspecified() {
                return Err(ConfigError::ForbiddenBindAddress {
                    value: listener.bind.clone(),
                });
            }
        }

        if self.k_anonymity < K_ANONYMITY_MIN {
            return Err(ConfigError::KAnonymityTooLow {
                value: self.k_anonymity,
            });
        }
        if self.retention_days == 0 || self.retention_days > RETENTION_DAYS_MAX {
            return Err(ConfigError::RetentionOutOfRange {
                value: self.retention_days,
            });
        }
        if self.rate_limit.per_sec == 0 {
            return Err(ConfigError::RateLimitInvalid {
                reason: "per_sec = 0 refuses every event; to accept everything, raise the limit",
            });
        }
        if self.rate_limit.burst < self.rate_limit.per_sec {
            return Err(ConfigError::RateLimitInvalid {
                reason: "burst is below per_sec, so the bucket can never hold one second's worth",
            });
        }
        Ok(())
    }
}

fn bounded(
    key: &'static str,
    value: Option<std::ffi::OsString>,
) -> Result<Option<String>, ConfigError> {
    match value {
        None => Ok(None),
        Some(v) => {
            let len = v.len();
            if len > ENV_VALUE_MAX {
                return Err(ConfigError::EnvValueTooLarge { key, len });
            }
            v.into_string()
                .map(Some)
                .map_err(|_| ConfigError::EnvValueInvalid {
                    key,
                    value: "<non-utf8>".to_string(),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn lookup_from<'a>(
        map: &'a HashMap<&'a str, &'a str>,
    ) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |key| map.get(key).map(|v| OsString::from(*v))
    }

    #[test]
    fn k_anonymity_below_the_floor_is_refused() {
        for k in [0, 1] {
            let config = Config {
                k_anonymity: k,
                ..Config::default()
            };
            assert!(
                matches!(
                    config.validate(),
                    Err(ConfigError::KAnonymityTooLow { value }) if value == k
                ),
                "k_anonymity = {k} disables the fold and must be refused"
            );
        }
        for k in [K_ANONYMITY_MIN, 5, 100] {
            let config = Config {
                k_anonymity: k,
                ..Config::default()
            };
            assert!(config.validate().is_ok(), "k_anonymity = {k} is fine");
        }
    }

    #[test]
    fn k_anonymity_floor_is_enforced_through_the_environment_too() {

        for (value, ok) in [("0", false), ("1", false), ("2", true), ("5", true)] {
            let env = HashMap::from([("FOSSH_K_ANONYMITY", value)]);
            let mut config = Config::default();

            config
                .apply_env_overrides(lookup_from(&env))
                .expect("the value parses; it is validate() that must judge it");
            assert_eq!(
                config.validate().is_ok(),
                ok,
                "FOSSH_K_ANONYMITY={value} should {} be accepted",
                if ok { "" } else { "not" }
            );
        }
    }

    #[test]
    fn retention_and_rate_limit_bounds_are_enforced() {
        let zero_retention = Config {
            retention_days: 0,
            ..Config::default()
        };
        assert!(matches!(
            zero_retention.validate(),
            Err(ConfigError::RetentionOutOfRange { value: 0 })
        ));

        let absurd_retention = Config {
            retention_days: RETENTION_DAYS_MAX + 1,
            ..Config::default()
        };
        assert!(matches!(
            absurd_retention.validate(),
            Err(ConfigError::RetentionOutOfRange { .. })
        ));

        let no_events = Config {
            rate_limit: RateLimit {
                per_sec: 0,
                burst: 10,
            },
            ..Config::default()
        };
        assert!(matches!(
            no_events.validate(),
            Err(ConfigError::RateLimitInvalid { .. })
        ));

        let burst_below_rate = Config {
            rate_limit: RateLimit {
                per_sec: 60,
                burst: 10,
            },
            ..Config::default()
        };
        assert!(matches!(
            burst_below_rate.validate(),
            Err(ConfigError::RateLimitInvalid { .. })
        ));
    }

    #[test]
    fn defaults_are_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.k_anonymity, 5);
        assert!(config.respect_optout_signals);
        assert_eq!(
            config.rate_limit,
            RateLimit {
                per_sec: 60,
                burst: 600
            }
        );
    }

    #[test]
    fn parses_the_spec_example_toml() {
        let toml_text = r#"
            data_dir = "/var/lib/fossh"
            mode = "spool"
            retention_days = 90
            k_anonymity = 5
            respect_optout_signals = true
            country_db = "builtin"
            salt_dir = "/run/fossh"
            rate_limit = { per_sec = 60, burst = 600 }
        "#;
        let config: Config = toml::from_str(toml_text).expect("spec example must parse");
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/fossh"));
        assert_eq!(config.mode, Mode::Spool);
        assert_eq!(config.country_db, CountryDb::Builtin);
    }

    #[test]
    fn unknown_key_is_a_fatal_parse_error() {
        let toml_text = r#"retenton_days = 30"#;
        let result: Result<Config, _> = toml::from_str(toml_text);
        assert!(
            result.is_err(),
            "a typo'd key must fail to parse, not be silently dropped"
        );
    }

    #[test]
    fn country_db_variants() {
        assert_eq!(CountryDb::from_str("builtin"), CountryDb::Builtin);
        assert_eq!(CountryDb::from_str("none"), CountryDb::None);
        assert_eq!(
            CountryDb::from_str("/opt/geo/custom.table"),
            CountryDb::Custom(PathBuf::from("/opt/geo/custom.table"))
        );
    }

    #[test]
    fn country_db_path_only_custom_resolves_to_something() {
        assert_eq!(CountryDb::None.path(), None);

        assert_eq!(CountryDb::Builtin.path(), None);
        assert_eq!(
            CountryDb::Custom(PathBuf::from("/opt/geo/custom.table")).path(),
            Some(Path::new("/opt/geo/custom.table"))
        );
    }

    fn with_bind(bind: &str) -> Config {
        Config {
            listener: Some(ListenerConfig {
                bind: bind.to_string(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_unspecified_bind_addresses() {
        assert!(matches!(
            with_bind("0.0.0.0:8080").validate(),
            Err(ConfigError::ForbiddenBindAddress { .. })
        ));
        assert!(matches!(
            with_bind("[::]:8080").validate(),
            Err(ConfigError::ForbiddenBindAddress { .. })
        ));
    }

    #[test]
    fn accepts_loopback_bind_addresses() {
        assert!(with_bind("127.0.0.1:8080").validate().is_ok());
        assert!(with_bind("[::1]:8080").validate().is_ok());
    }

    #[test]
    fn rejects_unparseable_bind_address() {
        assert!(matches!(
            with_bind("not-an-address").validate(),
            Err(ConfigError::InvalidBindAddress { .. })
        ));
    }

    #[test]
    fn env_overrides_applied_in_one_pass() {

        let mut map = HashMap::new();
        map.insert("FOSSH_RETENTION_DAYS", "30");
        map.insert("FOSSH_K_ANONYMITY", "10");
        map.insert("FOSSH_MODE", "direct");
        map.insert("FOSSH_RESPECT_OPTOUT_SIGNALS", "false");
        map.insert("FOSSH_COUNTRY_DB", "none");
        map.insert("FOSSH_RATE_LIMIT_PER_SEC", "120");
        map.insert("FOSSH_RATE_LIMIT_BURST", "1200");
        map.insert("FOSSH_LISTENER_BIND", "127.0.0.1:9000");

        let mut config = Config::default();
        config
            .apply_env_overrides(lookup_from(&map))
            .expect("overrides must apply");

        assert_eq!(config.retention_days, 30);
        assert_eq!(config.k_anonymity, 10);
        assert_eq!(config.mode, Mode::Direct);
        assert!(!config.respect_optout_signals);
        assert_eq!(config.country_db, CountryDb::None);
        assert_eq!(
            config.rate_limit,
            RateLimit {
                per_sec: 120,
                burst: 1200
            }
        );
        assert_eq!(config.listener.unwrap().bind, "127.0.0.1:9000");
    }

    #[test]
    fn env_override_with_garbage_value_is_an_error_not_silently_ignored() {
        let mut map = HashMap::new();
        map.insert("FOSSH_RETENTION_DAYS", "not-a-number");
        let mut config = Config::default();
        let result = config.apply_env_overrides(lookup_from(&map));
        assert!(matches!(
            result,
            Err(ConfigError::EnvValueInvalid {
                key: "FOSSH_RETENTION_DAYS",
                ..
            })
        ));
    }

    #[test]
    fn env_value_over_cap_is_rejected() {
        let big = "x".repeat(ENV_VALUE_MAX + 1);
        let mut map = HashMap::new();
        map.insert("FOSSH_DATA_DIR", big.as_str());
        let mut config = Config::default();
        let result = config.apply_env_overrides(lookup_from(&map));
        assert!(matches!(
            result,
            Err(ConfigError::EnvValueTooLarge {
                key: "FOSSH_DATA_DIR",
                ..
            })
        ));
    }

    #[test]
    fn no_matching_env_keys_leaves_defaults_untouched() {
        let map = HashMap::new();
        let mut config = Config::default();
        config.apply_env_overrides(lookup_from(&map)).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn config_roundtrips_through_toml() {
        let config = Config::default();
        let text = toml::to_string(&config).expect("serialize");
        let parsed: Config = toml::from_str(&text).expect("reparse");
        assert_eq!(config, parsed);
    }
}
