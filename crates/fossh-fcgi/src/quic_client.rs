use fossh_admin::command_client::{self, Command, Response};
use fossh_admin::tls_identity::{self, TlsIdentity};
use fossh_admin::watchdog_pin;
use fossh_ipc::TlsPaths;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn log(msg: &str) {
    eprintln!("fossh-fcgi(quic): {msg}");
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_path(key: &str, default: &str) -> PathBuf {
    env_var(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

pub struct QuicClientConfig {

    pub bootstrap_socket: PathBuf,

    pub tls_dir: PathBuf,
    pub watchdog_fingerprint_pin: PathBuf,
    pub watchdog_cert_pin: PathBuf,

    pub watchdog_uid: u32,
    pub quic_connect_addr: SocketAddr,
}

#[derive(Debug)]
pub enum ConfigError {
    MissingWatchdogUid,
    InvalidWatchdogUid(String),
    InvalidConnectAddr(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingWatchdogUid => {
                write!(
                    f,
                    "FOSSH_WATCHDOG_UID must be set (no getpwnam lookup here — see this module's own doc comment)"
                )
            }
            Self::InvalidWatchdogUid(s) => write!(f, "FOSSH_WATCHDOG_UID {s:?} is not a valid UID"),
            Self::InvalidConnectAddr(s) => {
                write!(f, "FOSSH_QUIC_CONNECT_ADDR {s:?} is not a valid address")
            }
        }
    }
}

impl QuicClientConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let watchdog_uid: u32 = env_var("FOSSH_WATCHDOG_UID")
            .ok_or(ConfigError::MissingWatchdogUid)?
            .parse()
            .map_err(|_| {
                ConfigError::InvalidWatchdogUid(env_var("FOSSH_WATCHDOG_UID").unwrap_or_default())
            })?;
        let quic_connect_addr: SocketAddr = env_var("FOSSH_QUIC_CONNECT_ADDR")
            .unwrap_or_else(|| "127.0.0.1:7443".to_string())
            .parse()
            .map_err(|_| {
                ConfigError::InvalidConnectAddr(
                    env_var("FOSSH_QUIC_CONNECT_ADDR").unwrap_or_default(),
                )
            })?;
        Ok(Self {
            bootstrap_socket: env_path("FOSSH_BOOTSTRAP_SOCKET", "/run/fossh/bootstrap.sock"),
            tls_dir: env_path("FOSSH_CORE_TLS_DIR", "/var/lib/fossh/tls"),
            watchdog_fingerprint_pin: env_path(
                "FOSSH_WATCHDOG_FINGERPRINT_PIN",
                "/var/lib/fossh/watchdog-fingerprint.pin",
            ),
            watchdog_cert_pin: env_path(
                "FOSSH_WATCHDOG_CERT_PIN",
                "/var/lib/fossh/watchdog-cert.pin",
            ),
            watchdog_uid,
            quic_connect_addr,
        })
    }
}

fn ensure_watchdog_pinned(config: &QuicClientConfig, own_cert_pem: &str) -> Result<(), String> {
    let already_pinned = matches!(
        (
            watchdog_pin::load_pin(&config.watchdog_fingerprint_pin),
            watchdog_pin::load_pin(&config.watchdog_cert_pin),
        ),
        (Ok(Some(_)), Ok(Some(_)))
    );
    if already_pinned {
        return Ok(());
    }
    log(&format!(
        "no watchdog pin yet — waiting on {} for its bootstrap-send (run `fossh-watchdog bootstrap-send` once, from the watchdog side, to complete this)",
        config.bootstrap_socket.display()
    ));
    watchdog_pin::run_bootstrap_listener(
        &config.bootstrap_socket,
        &config.watchdog_fingerprint_pin,
        &config.watchdog_cert_pin,
        own_cert_pem,
        config.watchdog_uid,
    )
    .map(|received| {
        log(&format!(
            "bootstrap handoff complete — watchdog fingerprint {}",
            received.watchdog_fingerprint
        ));
    })
    .map_err(|e| e.to_string())
}

pub fn send_one_reload(identity: &TlsIdentity, config: &QuicClientConfig) -> Result<(), String> {
    let cert_chain_pem = identity.cert_pem_path.to_string_lossy().into_owned();
    let priv_key_pem = identity.key_pem_path.to_string_lossy().into_owned();
    let trusted_peer_cert_pem = config.watchdog_cert_pin.to_string_lossy().into_owned();
    let tls = TlsPaths {
        cert_chain_pem: &cert_chain_pem,
        priv_key_pem: &priv_key_pem,
        trusted_peer_cert_pem: &trusted_peer_cert_pem,
    };

    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut conn, socket) = fossh_ipc::connect(config.quic_connect_addr, &tls, deadline)
        .map_err(|e| format!("connect: {e}"))?;

    const SESSION_STREAM: u64 = 1;
    const COMMAND_STREAM: u64 = 4;

    let (hello_line, _fin) =
        fossh_ipc::recv_from_stream(&mut conn, &socket, SESSION_STREAM, deadline)
            .map_err(|e| format!("recv session hello: {e}"))?;
    let hello_line = String::from_utf8_lossy(&hello_line).into_owned();
    let session_token = command_client::decode_session_hello(&hello_line)
        .map_err(|e| format!("session hello: {e}"))?;

    let command_line = command_client::encode_command(&session_token, Command::Reload);
    fossh_ipc::send_on_stream(
        &mut conn,
        &socket,
        COMMAND_STREAM,
        command_line.as_bytes(),
        true,
        deadline,
    )
    .map_err(|e| format!("send command: {e}"))?;

    let (reply_line, _fin) =
        fossh_ipc::recv_from_stream(&mut conn, &socket, COMMAND_STREAM, deadline)
            .map_err(|e| format!("recv reply: {e}"))?;
    let reply_line = String::from_utf8_lossy(&reply_line).into_owned();
    match command_client::decode_response(&reply_line).map_err(|e| format!("reply: {e}"))? {
        Response::Ok => Ok(()),
        Response::Error(reason) => Err(format!("watchdog refused: {reason}")),

        Response::Status { .. } => {
            Err("watchdog sent a status reply to a reload command".to_string())
        }
    }
}

pub fn block_sighup_process_wide() -> Result<(), String> {
    let mut set = nix::sys::signal::SigSet::empty();
    set.add(nix::sys::signal::Signal::SIGHUP);
    nix::sys::signal::pthread_sigmask(nix::sys::signal::SigmaskHow::SIG_BLOCK, Some(&set), None)
        .map_err(|e| format!("pthread_sigmask: {e}"))
}

pub fn run(config: QuicClientConfig) {
    let identity = match tls_identity::ensure_identity(&config.tls_dir, "fossh-svc") {
        Ok(id) => id,
        Err(e) => {
            log(&format!(
                "could not establish this process's own TLS identity: {e} — QUIC command channel disabled for this process's lifetime"
            ));
            return;
        }
    };
    let own_cert_pem = match std::fs::read_to_string(&identity.cert_pem_path) {
        Ok(s) => s,
        Err(e) => {
            log(&format!(
                "could not read own certificate at {}: {e}",
                identity.cert_pem_path.display()
            ));
            return;
        }
    };
    if let Err(e) = ensure_watchdog_pinned(&config, &own_cert_pem) {
        log(&format!(
            "bootstrap handoff failed: {e} — QUIC command channel disabled for this process's lifetime"
        ));
        return;
    }

    let mut wait_set = nix::sys::signal::SigSet::empty();
    wait_set.add(nix::sys::signal::Signal::SIGHUP);

    log("ready — waiting for SIGHUP to request a reload");
    loop {
        match wait_set.wait() {
            Ok(_) => match send_one_reload(&identity, &config) {
                Ok(()) => log("reload acknowledged by watchdog"),
                Err(e) => log(&format!("reload request failed: {e}")),
            },
            Err(e) => log(&format!("sigwait failed: {e} (retrying)")),
        }
    }
}
