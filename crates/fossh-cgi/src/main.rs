#![forbid(unsafe_code)]

mod handler;
mod privdrop;

use std::io::{self, Read, Write};

use fossh_core::config::CountryDb;
use fossh_ingest::forwarded;
use fossh_ingest::geoip::GeoipReader;
use handler::{CgiEnv, HandleParams};

fn env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= fossh_core::validate::ENV_VALUE_MAX)
}

fn read_cgi_env(trusted_hops: u8) -> CgiEnv {
    let remote_addr = forwarded::resolve_client_ip(
        &env_var("REMOTE_ADDR").unwrap_or_default(),
        env_var("HTTP_X_FORWARDED_FOR").as_deref(),
        trusted_hops,
    );
    CgiEnv {
        method: env_var("REQUEST_METHOD").unwrap_or_default(),
        path_info: env_var("PATH_INFO").unwrap_or_default(),
        query_string: env_var("QUERY_STRING").unwrap_or_default(),
        remote_addr,
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

    MissingLength,

    TooLarge,
}

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

    let _ = io::stdout().write_all(out.as_bytes());
}

fn main() {

    if let Err(e) = privdrop::drop_to_service_user()
        && e != privdrop::PrivDropError::NotRoot
    {
        eprintln!("fossh-cgi: refusing to start: {e}");
        std::process::exit(1);
    }

    let trusted_hops =
        forwarded::trusted_hops_from_env(env_var("FOSSH_TRUST_FORWARDED_FOR").as_deref());
    let env = read_cgi_env(trusted_hops);
    let data_dir = std::env::var_os("FOSSH_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/fossh"));
    let salt_dir = std::env::var_os("FOSSH_SALT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/fossh"));

    let rate_limit_per_sec = env_var("FOSSH_RATE_LIMIT_PER_SEC")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let rate_limit_burst = env_var("FOSSH_RATE_LIMIT_BURST")
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let respect_optout_signals = !matches!(
        env_var("FOSSH_RESPECT_OPTOUT_SIGNALS").as_deref(),
        Some("false") | Some("0")
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let country_db = env_var("FOSSH_COUNTRY_DB")
        .map(|v| CountryDb::from_str(&v))
        .unwrap_or_default();
    let geoip_reader = GeoipReader::open(country_db.path());

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

    let data_key = match fossh_admin::data_key::load_or_generate(&data_dir.join(".data_key")) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("fossh-cgi: could not load data-encryption key: {e}");
            std::process::exit(1);
        }
    };

    let params = HandleParams {
        env: &env,
        body: &body,
        data_dir: &data_dir,
        salt_dir: &salt_dir,
        data_key: &data_key,
        rate_limit_per_sec,
        rate_limit_burst,
        respect_optout_signals,
        now,
        country_db: &geoip_reader,
    };

    let response = handler::route(&params);
    write_response(response.status, response.allow_origin.as_deref());

    if response.spool_write_failed {
        std::process::exit(1);
    }
}
