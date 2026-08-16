use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RESERVED: &[&str] = &[
    "agent",
    "telemetry",
    "integrations",
    "providers",
    "setup",
    "operator",
    "watchdog",
    "modules",
    "selfheal",
];

pub const SYSTEM_DIR: &str = "/usr/share/fossh/modules";
pub const SITE_DIR: &str = "/etc/fossh/modules.d";

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_MODULES: usize = 64;

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {

    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: String,

    pub exec: String,
    #[serde(default)]
    pub args: Vec<String>,

    #[serde(default)]
    pub icon: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    #[serde(default, skip_deserializing)]
    pub builtin: bool,
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Debug)]
pub enum ModuleError {
    Invalid { namespace: String, reason: String },
    Io(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleError::Invalid { namespace, reason } => {
                write!(f, "the module \"{namespace}\" was not loaded: {reason}")
            }
            ModuleError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ModuleError {}

pub fn valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 32
        && ns.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl Manifest {
    pub fn validate(&self) -> Result<(), ModuleError> {
        let bad = |reason: &str| ModuleError::Invalid {
            namespace: self.namespace.clone(),
            reason: reason.to_string(),
        };

        if !valid_namespace(&self.namespace) {
            return Err(bad(
                "a namespace must start with a lowercase letter and contain only lowercase \
                 letters, digits and \"_\"",
            ));
        }
        if self.name.trim().is_empty() {
            return Err(bad("it has no display name"));
        }

        if self.builtin {
            return Ok(());
        }
        if RESERVED.contains(&self.namespace.as_str()) {
            return Err(bad(
                "that namespace is served by foSSH itself and cannot be replaced — a module \
                 shadowing a built-in one would intercept everything addressed to it",
            ));
        }
        if self.exec.is_empty() {
            return Err(bad("it declares no program to run"));
        }

        if !self.exec.starts_with('/') {
            return Err(bad("\"exec\" must be an absolute path"));
        }
        if self.exec.chars().any(|c| c.is_control()) {
            return Err(bad("\"exec\" contains a control character"));
        }
        if self.timeout_secs == 0 || self.timeout_secs > 300 {
            return Err(bad("\"timeout_secs\" must be between 1 and 300"));
        }
        Ok(())
    }

    pub fn owns(&self, method: &str) -> bool {
        method
            .split_once('.')
            .is_some_and(|(ns, _)| ns == self.namespace)
    }
}

pub fn builtins() -> Vec<Manifest> {
    let b = |namespace: &str, name: &str, description: &str, icon: &str| Manifest {
        namespace: namespace.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        exec: String::new(),
        args: Vec::new(),
        icon: icon.to_string(),
        timeout_secs: DEFAULT_TIMEOUT_SECS,
        builtin: true,
    };
    vec![
        b(
            "telemetry",
            "Telemetry",
            "Privacy-preserving site analytics: what was visited, without who visited it. \
             The reason most installs exist.",
            "telemetry",
        ),
        b(
            "integrations",
            "External services",
            "Send to an API you control, authenticated with a key you supply.",
            "integrations",
        ),
        b(
            "selfheal",
            "Self-healing",
            "Deterministic checks over the install's own state, each with a remedy.",
            "setup",
        ),
    ]
}

pub fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(SYSTEM_DIR), PathBuf::from(SITE_DIR)];
    let user = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    if let Some(base) = user {
        dirs.push(base.join("fossh/modules.d"));
    }
    dirs
}

pub fn load_from(dirs: &[PathBuf]) -> (Vec<Manifest>, Vec<ModuleError>) {
    let mut by_ns: BTreeMap<String, Manifest> = builtins()
        .into_iter()
        .map(|m| (m.namespace.clone(), m))
        .collect();
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
            if by_ns.len() >= MAX_MODULES {
                problems.push(ModuleError::Io(format!(
                    "more than {MAX_MODULES} modules found; the rest were ignored"
                )));
                break;
            }
            match load_one(&path) {
                Ok(m) => {
                    by_ns.insert(m.namespace.clone(), m);
                }
                Err(e) => problems.push(e),
            }
        }
    }
    (by_ns.into_values().collect(), problems)
}

pub fn load() -> (Vec<Manifest>, Vec<ModuleError>) {
    load_from(&search_dirs())
}

fn load_one(path: &Path) -> Result<Manifest, ModuleError> {
    let name = path.display().to_string();
    let meta = std::fs::metadata(path).map_err(|e| ModuleError::Io(format!("{name}: {e}")))?;
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(ModuleError::Io(format!(
            "{name}: larger than {MAX_MANIFEST_BYTES} bytes, which no manifest is"
        )));
    }
    let text =
        std::fs::read_to_string(path).map_err(|e| ModuleError::Io(format!("{name}: {e}")))?;
    let manifest: Manifest =
        toml::from_str(&text).map_err(|e| ModuleError::Io(format!("{name}: {e}")))?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn dispatch(manifest: &Manifest, request_line: &str) -> Result<String, ModuleError> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    const MAX_REPLY_BYTES: usize = 1024 * 1024;

    let fail = |reason: String| ModuleError::Invalid {
        namespace: manifest.namespace.clone(),
        reason,
    };

    let mut child = Command::new(&manifest.exec)
        .args(&manifest.args)

        .process_group(0)

        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("FOSSH_MODULE_NAMESPACE", &manifest.namespace)
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())

        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| fail(format!("could not start {}: {e}", manifest.exec)))?;

    if let Some(mut stdin) = child.stdin.take() {

        let _ = stdin.write_all(request_line.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("the module's stdout was not available".to_string()))?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();

        let mut reader = BufReader::new(stdout.take(MAX_REPLY_BYTES as u64));
        let read = reader.read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });

    let deadline = std::time::Duration::from_secs(manifest.timeout_secs);
    let outcome = rx.recv_timeout(deadline);

    let pgid = nix::unistd::Pid::from_raw(child.id() as i32);
    let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();

    match outcome {
        Ok(Ok(line)) if !line.trim().is_empty() => Ok(line.trim().to_string()),
        Ok(Ok(_)) => Err(fail("the module answered with nothing".to_string())),
        Ok(Err(e)) => Err(fail(format!("reading the module's reply: {e}"))),
        Err(_) => Err(fail(format!(
            "the module did not answer within {}s",
            manifest.timeout_secs
        ))),
    }
}

pub fn namespace_of(method: &str) -> Option<&str> {
    method.split_once('.').map(|(ns, _)| ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn manifest(ns: &str) -> Manifest {
        Manifest {
            namespace: ns.to_string(),
            name: "Example".to_string(),
            description: String::new(),
            exec: "/usr/libexec/example-module".to_string(),
            args: vec![],
            icon: String::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            builtin: false,
        }
    }

    #[test]
    fn a_well_formed_manifest_validates() {
        assert!(manifest("backup").validate().is_ok());
    }

    #[test]
    fn a_module_cannot_shadow_a_builtin() {

        for reserved in RESERVED {
            let m = manifest(reserved);
            let err = m.validate().unwrap_err();
            assert!(
                matches!(err, ModuleError::Invalid { .. }),
                "{reserved} was accepted"
            );
            assert!(err.to_string().contains("cannot be replaced"));
        }
    }

    #[test]
    fn a_namespace_is_an_identifier_not_a_sentence() {
        assert!(valid_namespace("backup"));
        assert!(valid_namespace("my_module2"));
        assert!(!valid_namespace(""));
        assert!(!valid_namespace("Backup"), "uppercase");
        assert!(!valid_namespace("2fast"), "must start with a letter");
        assert!(!valid_namespace("has space"));
        assert!(
            !valid_namespace("has.dot"),
            "a dot would split the method name"
        );
        assert!(!valid_namespace("has-dash"));
        assert!(!valid_namespace(&"a".repeat(33)));
    }

    #[test]
    fn a_relative_exec_is_refused() {

        let mut m = manifest("backup");
        m.exec = "example-module".to_string();
        assert!(m.validate().is_err());
        m.exec = "../../bin/sh".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn an_absent_exec_is_refused_unless_builtin() {
        let mut m = manifest("backup");
        m.exec = String::new();
        assert!(m.validate().is_err());
        m.builtin = true;
        assert!(m.validate().is_ok(), "built-ins are served in-process");
    }

    #[test]
    fn an_unbounded_timeout_is_refused() {
        let mut m = manifest("backup");
        m.timeout_secs = 0;
        assert!(m.validate().is_err());
        m.timeout_secs = 10_000;
        assert!(m.validate().is_err());
        m.timeout_secs = 30;
        assert!(m.validate().is_ok());
    }

    #[test]
    fn ownership_is_decided_by_the_namespace_before_the_dot() {
        let m = manifest("backup");
        assert!(m.owns("backup.run"));
        assert!(m.owns("backup.list"));
        assert!(!m.owns("backupx.run"), "a prefix is not a namespace");
        assert!(!m.owns("telemetry.query"));
        assert!(!m.owns("backup"), "a method needs a verb");
    }

    #[test]
    fn namespace_of_splits_on_the_first_dot_only() {
        assert_eq!(namespace_of("telemetry.query"), Some("telemetry"));
        assert_eq!(namespace_of("a.b.c"), Some("a"));
        assert_eq!(namespace_of("nodot"), None);
    }

    #[test]
    fn telemetry_is_a_module_like_any_other() {

        let b = builtins();
        let telemetry = b.iter().find(|m| m.namespace == "telemetry").unwrap();
        assert!(telemetry.builtin);
        assert!(telemetry.validate().is_ok());
        assert!(!telemetry.name.is_empty());
        assert!(!telemetry.description.is_empty());
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fossh-modules-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const SAMPLE: &str = r#"
namespace = "backup"
name = "Backups"
description = "Snapshot and restore this install."
exec = "/usr/libexec/fossh-backup"
icon = "empty"
"#;

    #[test]
    fn a_module_loads_alongside_the_builtins() {
        let dir = scratch("load");
        fs::write(dir.join("backup.toml"), SAMPLE).unwrap();
        let (mods, problems) = load_from(&[dir.clone()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(mods.iter().any(|m| m.namespace == "backup"));
        assert!(mods.iter().any(|m| m.namespace == "telemetry" && m.builtin));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_manifest_claiming_a_builtin_namespace_is_rejected_at_load() {

        let dir = scratch("shadow");
        fs::write(
            dir.join("evil.toml"),
            SAMPLE.replace("\"backup\"", "\"telemetry\""),
        )
        .unwrap();
        let (mods, problems) = load_from(&[dir.clone()]);
        assert_eq!(problems.len(), 1);
        let telemetry = mods.iter().find(|m| m.namespace == "telemetry").unwrap();
        assert!(telemetry.builtin, "the real telemetry module was replaced");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn one_broken_manifest_does_not_take_away_the_others() {
        let dir = scratch("broken");
        fs::write(dir.join("good.toml"), SAMPLE).unwrap();
        fs::write(dir.join("bad.toml"), "this is not toml {{{").unwrap();
        fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let (mods, problems) = load_from(&[dir.clone()]);
        assert!(mods.iter().any(|m| m.namespace == "backup"));
        assert_eq!(problems.len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_later_directory_overrides_an_earlier_one() {
        let system = scratch("ovr-sys");
        let site = scratch("ovr-site");
        fs::write(system.join("b.toml"), SAMPLE).unwrap();
        fs::write(
            site.join("b.toml"),
            SAMPLE.replace("/usr/libexec/fossh-backup", "/opt/mine/backup"),
        )
        .unwrap();
        let (mods, _) = load_from(&[system.clone(), site.clone()]);
        let m = mods.iter().find(|m| m.namespace == "backup").unwrap();
        assert_eq!(m.exec, "/opt/mine/backup");
        fs::remove_dir_all(&system).ok();
        fs::remove_dir_all(&site).ok();
    }

    #[test]
    fn a_manifest_cannot_declare_itself_builtin() {

        let dir = scratch("fake-builtin");
        fs::write(
            dir.join("f.toml"),
            "namespace = \"faker\"\nname = \"F\"\nbuiltin = true\n",
        )
        .unwrap();
        let (mods, problems) = load_from(&[dir.clone()]);
        assert!(!mods.iter().any(|m| m.namespace == "faker"));
        assert_eq!(problems.len(), 1, "a manifest with no exec must be refused");
        fs::remove_dir_all(&dir).ok();
    }
}
