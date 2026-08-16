use std::io::Write;
use std::process::{Command, Stdio};

use fossh_admin::integrations::{Integration, Method, TEST_BODY};
use zeroize::Zeroizing;

const MAX_TIME_SECS: u32 = 10;
const CONNECT_TIMEOUT_SECS: u32 = 5;
const MAX_RESPONSE_BYTES: u64 = 65_536;

const MAX_BODY_SNIPPET: usize = 2_000;

#[derive(Debug)]
pub struct TestOutcome {
    pub status: u16,

    pub transport_ok: bool,
    pub body_snippet: String,
}

#[derive(Debug)]
pub enum NetError {

    CurlMissing,

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

fn quote_config_value(value: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),

            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    Zeroizing::new(out)
}

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

    cfg.push_str("tlsv1.2\n");

    cfg.push_str("ssl-reqd\n");
    cfg.push_str("silent\n");
    cfg.push_str("show-error\n");

    Zeroizing::new(cfg)
}

fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "<redacted>")
}

pub fn test(integration: &Integration) -> Result<TestOutcome, NetError> {

    let body_path = std::env::temp_dir().join(format!(
        "fossh-agent-probe-{}-{}",
        std::process::id(),
        integration.name
    ));
    let _ = std::fs::remove_file(&body_path);
    let body_path_str = body_path.to_string_lossy().into_owned();

    let config = build_config(integration, &body_path_str);

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
