//! Modules: what foSSH is, now that telemetry is one of them.
//!
//! The agent protocol already had the shape of a module system before
//! anyone called it that. Every method is `namespace.verb` —
//! `telemetry.query`, `integrations.add`, `providers.list` — and a
//! namespace is exactly what a module owns. Naming it makes the
//! boundary usable by someone outside this repository; it does not
//! invent one.
//!
//! ## What a module is
//!
//! A manifest declaring a namespace, and a program that speaks this
//! protocol. The agent routes `yournamespace.anything` to that
//! program's stdin and returns what comes back on its stdout. A module
//! is therefore written in any language that can read a line and write
//! a line, which is all of them.
//!
//! Telemetry is a module in exactly this sense — it simply happens to
//! be built in, because it is the reason most people install foSSH.
//! Its namespace is reserved and served in-process, and the console
//! renders it through the same list every other module appears in.
//!
//! ## Why a separate process, and not a plugin
//!
//! The same reasoning as ADR-0066, which decided providers would be
//! data rather than code, and it is worth restating because the
//! pressure to relax it will come from somewhere reasonable.
//!
//! This process holds every API key on the install, the setup token,
//! and a private key at the moment it is generated. Code loaded into
//! it gets all of that, and a module ecosystem is a supply chain: one
//! popular module with one bad release would be a credential
//! exfiltration incident across every install that had it, with no
//! revocation mechanism anywhere in this project.
//!
//! A module in its own process starts with nothing. It gets the
//! request that was addressed to it and whatever its manifest declared
//! it needs, and it cannot read this process's memory, its file
//! descriptors, or its environment. That is a real boundary rather
//! than a documented intention, and it costs one `fork`.
//!
//! ## What a module cannot do
//!
//! * Claim a reserved namespace. The built-ins are not overridable —
//!   a module named `telemetry` that shadowed the real one would be
//!   the most direct possible attack on this system.
//! * Inherit the agent's environment. It is spawned with a minimal,
//!   explicit one.
//! * Run without a bound. Every call has a timeout and every reply has
//!   a size cap.
//! * See a credential it was not given. Nothing is passed implicitly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Namespaces the agent serves itself. A manifest claiming one of
/// these is rejected at load, not at call time — a module that
/// shadowed `integrations` could harvest every key on the install.
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

/// How long a module gets to answer one call.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A module's declaration of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The namespace it owns. Also its identity.
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Absolute path to the program that serves it.
    pub exec: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Icon key for the console, resolved through its own icon
    /// system. Absent means the console picks a generic one.
    #[serde(default)]
    pub icon: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Built-in modules are served in-process and have no `exec` to
    /// run. Set by this crate, never by a manifest on disk.
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

/// A namespace is an identifier, not a sentence: it appears in method
/// names, in the console, and in log lines, and anything looser would
/// need quoting somewhere.
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
        // Built-ins own the reserved namespaces by definition, and are
        // served in-process, so the two checks below are about
        // manifests found on disk. `builtin` is `skip_deserializing`,
        // so a file cannot set it and take this branch.
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
        // Absolute, so the module that runs is not decided by whatever
        // PATH the agent happened to inherit.
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

    /// Whether this module owns `method`.
    pub fn owns(&self, method: &str) -> bool {
        method
            .split_once('.')
            .is_some_and(|(ns, _)| ns == self.namespace)
    }
}

/// The built-ins, described the same way an external module describes
/// itself, so the console has one list to render and a developer has
/// one shape to copy.
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

/// Loads every module manifest, built-ins first.
///
/// A manifest that fails validation is skipped and reported rather
/// than aborting: one bad file dropped into a directory must not take
/// away every other module on the system.
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

/// Sends one request to a module's own process and returns its reply.
///
/// The module is spawned per call rather than kept alive. A resident
/// module would be faster and would also mean a third party's process
/// running continuously alongside the thing that holds every
/// credential on the install; per-call is the trade this project
/// makes, and a module that needs to be fast can keep its own state
/// elsewhere.
///
/// Four bounds, all of them load-bearing:
///
/// * **A minimal environment.** The module inherits nothing. Not the
///   agent's `FOSSH_*` variables, not its `PATH`, not anything an
///   operator happened to export. What it gets is stated here, in
///   full, and a module needing more declares it in its manifest.
/// * **A timeout**, from the manifest, capped at 300 s by validation.
/// * **A reply size cap**, so a module cannot exhaust the agent by
///   answering forever.
/// * **One line in, one line out.** The same framing the agent's own
///   protocol uses, so a module is written the same way a client is.
pub fn dispatch(manifest: &Manifest, request_line: &str) -> Result<String, ModuleError> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    /// Generous for a JSON reply, small enough that a runaway module
    /// is bounded long before it matters.
    const MAX_REPLY_BYTES: usize = 1024 * 1024;

    let fail = |reason: String| ModuleError::Invalid {
        namespace: manifest.namespace.clone(),
        reason,
    };

    let mut child = Command::new(&manifest.exec)
        .args(&manifest.args)
        // Its own process group, so a timeout can kill the module AND
        // anything it started. Without this, `child.kill()` reaps only
        // the program named in the manifest: a module that is a shell
        // script wrapping a long-running command leaves that command
        // running forever. Observed directly — a module that hung was
        // killed on schedule and left two orphans behind.
        //
        // `process_group` is safe and stable; the alternative is a
        // pre_exec closure, which is `unsafe` and this crate forbids
        // it.
        .process_group(0)
        // env_clear first: everything the module sees is below this
        // line and nothing above it leaks in.
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("FOSSH_MODULE_NAMESPACE", &manifest.namespace)
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Left attached, so a module's diagnostics reach the journal
        // rather than being swallowed. It is never parsed.
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| fail(format!("could not start {}: {e}", manifest.exec)))?;

    if let Some(mut stdin) = child.stdin.take() {
        // A write failure here usually means the module exited
        // immediately; the read below reports that more usefully than
        // a broken pipe would.
        let _ = stdin.write_all(request_line.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("the module's stdout was not available".to_string()))?;

    // A thread reads while the parent enforces the deadline, because
    // `read_line` has no timeout of its own and a module that never
    // answers must not hold the agent forever.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        // `Read::take` before buffering, so the cap bounds bytes read
        // from the pipe rather than being applied after the fact.
        let mut reader = BufReader::new(stdout.take(MAX_REPLY_BYTES as u64));
        let read = reader.read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });

    let deadline = std::time::Duration::from_secs(manifest.timeout_secs);
    let outcome = rx.recv_timeout(deadline);
    // Reaped either way: a module that timed out is a module that must
    // not be left running — and neither must anything it started.
    // SIGKILL to the whole group, which `process_group(0)` above made
    // the module the leader of.
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

/// The namespace part of `method`, if it has one.
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
        // The most direct attack this system has: a module claiming
        // `integrations` would receive every credential added from
        // the console.
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
        // Otherwise which program runs depends on whatever PATH the
        // agent inherited, which is not a decision a manifest gets to
        // delegate.
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
        // The whole point of the reframing: the flagship is not a
        // special case in the code, only in how much it is used.
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
        // Not at call time. By then the module is installed and the
        // operator believes it works.
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
        // `builtin` is skip_deserializing, so a manifest on disk
        // setting it has no effect — otherwise a module could claim to
        // be served in-process and skip the exec validation entirely.
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
