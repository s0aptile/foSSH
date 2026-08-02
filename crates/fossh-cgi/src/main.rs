//! §7.1: the RFC 3875 CGI entrypoint. Reads the request from the CGI
//! environment + stdin, writes a minimal fixed response, and exits.
//!
//! Deliberately thin: env/stdin I/O here, all actual decision-making in
//! `handler.rs` (unit-tested) and `fossh-ingest`. Panics abort the
//! process (`panic = "abort"`, workspace-wide release profile — see
//! DECISIONS.md's ADR on the `fossh-ffi` workspace split) rather than
//! unwinding, which is this binary's version of S2's "process exit code"
//! panic boundary: nothing is written to stdout until the very end, in
//! one buffered write, so a panic before that point produces no output
//! at all — never a partial or malformed response — and nothing panics
//! prints goes anywhere but stderr, which the client never sees.

mod handler;

use std::io::{self, Read, Write};

use handler::{CgiEnv, HandleParams};

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn read_cgi_env() -> CgiEnv {
    CgiEnv {
        method: env_var("REQUEST_METHOD").unwrap_or_default(),
        path_info: env_var("PATH_INFO").unwrap_or_default(),
        query_string: env_var("QUERY_STRING").unwrap_or_default(),
        remote_addr: env_var("REMOTE_ADDR").unwrap_or_default(),
        user_agent: env_var("HTTP_USER_AGENT").unwrap_or_default(),
        referer: env_var("HTTP_REFERER"),
        dnt: env_var("HTTP_DNT").as_deref() == Some("1"),
        gpc: env_var("HTTP_SEC_GPC").as_deref() == Some("1"),
        key_id: env_var("HTTP_X_FOSSH_KEY_ID"),
        ts_header: env_var("HTTP_X_FOSSH_TS"),
        nonce_header: env_var("HTTP_X_FOSSH_NONCE"),
        sig_header: env_var("HTTP_X_FOSSH_SIG"),
        authorization: env_var("HTTP_AUTHORIZATION"),
        origin: env_var("HTTP_ORIGIN"),
    }
}

enum BodyOutcome {
    Body(Vec<u8>),
    /// CONTENT_LENGTH missing/unparseable — §7.1: "Reject chunked /
    /// missing length."
    MissingLength,
    /// CONTENT_LENGTH parsed fine but exceeds S4's request-body cap.
    TooLarge,
}

/// Reads exactly `CONTENT_LENGTH` bytes from stdin — never more than S4's
/// cap, and the cap is checked against the *declared* length before any
/// allocation or read happens, so an attacker-controlled `CONTENT_LENGTH`
/// can't be used to make this allocate something huge.
fn read_body() -> BodyOutcome {
    let Some(declared) = env_var("CONTENT_LENGTH").and_then(|s| s.parse::<usize>().ok()) else {
        return BodyOutcome::MissingLength;
    };
    if declared > fossh_core::validate::BODY_MAX {
        return BodyOutcome::TooLarge;
    }

    let mut buf = vec![0u8; declared];
    let mut stdin = io::stdin().lock();
    let mut read_total = 0usize;
    while read_total < declared {
        match stdin.read(&mut buf[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(_) => break,
        }
    }
    buf.truncate(read_total);
    BodyOutcome::Body(buf)
}

fn status_line(code: u16) -> &'static str {
    match code {
        204 => "204 No Content",
        401 => "401 Unauthorized",
        413 => "413 Payload Too Large",
        422 => "422 Unprocessable Entity",
        429 => "429 Too Many Requests",
        _ => "500 Internal Server Error",
    }
}

/// §7.1: the ingest response is always this exact shape — fixed headers,
/// no body, ever (not even on error; the status code carries everything).
fn write_response(status: u16, allow_origin: Option<&str>) {
    let mut out = String::new();
    out.push_str("Status: ");
    out.push_str(status_line(status));
    out.push_str("\r\n");
    out.push_str("Cache-Control: no-store\r\n");
    out.push_str("Content-Length: 0\r\n");
    if let Some(origin) = allow_origin {
        out.push_str("Access-Control-Allow-Origin: ");
        out.push_str(origin);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    // One buffered write — see the module doc comment on why that matters
    // for the panic boundary.
    let _ = io::stdout().write_all(out.as_bytes());
}

fn main() {
    let env = read_cgi_env();
    let data_dir = std::env::var_os("FOSSH_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/fossh"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if env.method == "GET" && env.path_info == "/healthz" {
        write_response(204, None);
        return;
    }

    let body = if env.method == "POST" {
        match read_body() {
            BodyOutcome::Body(b) => b,
            BodyOutcome::TooLarge => {
                write_response(413, None);
                std::process::exit(0);
            }
            BodyOutcome::MissingLength => {
                write_response(422, None);
                std::process::exit(0);
            }
        }
    } else {
        Vec::new()
    };

    let params = HandleParams {
        env: &env,
        body: &body,
        data_dir: &data_dir,
        // §10 defaults; a config-driven override lands with `fossh-cli`
        // (M4), which is what actually parses `fossh.toml` for the
        // long-running commands. The CGI hot path stays argument-free.
        rate_limit_per_sec: 60,
        rate_limit_burst: 600,
        respect_optout_signals: true,
        now,
    };

    let response = handler::route(&params);
    write_response(response.status, response.allow_origin.as_deref());

    if response.spool_write_failed {
        std::process::exit(1);
    }
}
