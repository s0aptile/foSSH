//! §3.4's QUIC/mTLS command channel to the watchdog — core's
//! (`fossh-svc`'s) side. Feature-gated (`quic`, off by default — see
//! this crate's own Cargo.toml) since `fossh-ipc` pulls in a genuine,
//! heavy quiche/BoringSSL build no other part of this workspace has
//! any reason to pay for. See DECISIONS.md (ADR-0050) for the full
//! design and the deliberate scope cuts this pass makes.
//!
//! One connection, one command, then close — not a persistent,
//! held-open connection this thread has to reconnect when it drops.
//! `SIGHUP` (blocked process-wide before any other thread starts, via
//! `block_sighup_process_wide`, then consumed one at a time by this
//! thread's own `sigwait` loop — the standard safe pattern for
//! reacting to a signal with ordinary, non-async-signal-safe code)
//! is the trigger: each delivery opens one fresh, mTLS-verified QUIC
//! connection to the watchdog, receives its session hello, sends one
//! `Reload` command, reads the reply, and closes. This sidesteps
//! ADR-0048's item 4 "reconnection handling for when core's own
//! process restarts" concern by construction — there is never a
//! persistent connection outliving one request/reply exchange for
//! that concern to apply to.
//!
//! `Reload` is the only command this pass ever sends. `Restart` is
//! real on the wire (`fossh_admin::command_client::Command::Restart`
//! round-trips correctly, tested) but has no live caller here yet —
//! deliberately: this operator-facing trigger is `SIGHUP`, the
//! conventional "reload" signal, and there is no comparably
//! conventional local signal for "please fully restart me" that
//! wouldn't just be `SIGTERM`/`SIGKILL` (which the watchdog's own
//! crash-detection path already handles without this channel's help
//! at all). A real trigger for `Restart` over this channel is a
//! reasonable follow-up, not built speculatively here.
//!
//! Also deliberately out of scope for this pass, both documented in
//! DECISIONS.md rather than silently assumed: watchdog dispatches
//! both `Restart` and `Reload` to the exact same
//! `Supervisor.restart_if_safe` action (a full tamper-checked
//! respawn) — genuine live config reload without dropping the
//! process is a separate, larger feature `fossh-fcgi` does not have
//! today regardless of this channel; and automatically invoking the
//! bootstrap handoff from the watchdog's own startup remains the
//! same open, manual-operator-step gap `watchdog/bin/main.ml`'s own
//! header comment already documents — this module waits for it
//! (see `ensure_watchdog_pinned` below), it does not trigger it.

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
    env_var(key).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(default))
}

pub struct QuicClientConfig {
    /// §2.4's one-time bootstrap handoff socket — core listens here
    /// (`fossh_admin::watchdog_pin::run_bootstrap_listener`) for the
    /// watchdog's `bootstrap-send` to connect to. Matches
    /// `fossh-fcgi`'s own `FOSSH_FCGI_SOCKET` convention: an
    /// `/run/fossh/*.sock` path, not under the persistent data
    /// directory, since a socket is a live-process-only concern.
    pub bootstrap_socket: PathBuf,
    /// This process's own X.509 identity directory —
    /// `%{_sharedstatedir}/fossh/tls` in the real RPM install (see
    /// packaging/rpm/fossh.spec's `fossh-svc` user), overridable for
    /// tests.
    pub tls_dir: PathBuf,
    pub watchdog_fingerprint_pin: PathBuf,
    pub watchdog_cert_pin: PathBuf,
    /// The real UID of the `fossh-watchdog` system user —
    /// `SO_PEERCRED`'s verification anchor for the bootstrap handoff.
    /// Not looked up by username here: this module has no `nix`
    /// "user"-feature dependency to spend on a single `getpwnam`
    /// call, and every real caller already knows this value from the
    /// same place it already gets `bootstrap_socket`/`tls_dir` (its
    /// own deployment's fixed configuration) — see `from_env`.
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
                write!(f, "FOSSH_WATCHDOG_UID must be set (no getpwnam lookup here — see this module's own doc comment)")
            }
            Self::InvalidWatchdogUid(s) => write!(f, "FOSSH_WATCHDOG_UID {s:?} is not a valid UID"),
            Self::InvalidConnectAddr(s) => write!(f, "FOSSH_QUIC_CONNECT_ADDR {s:?} is not a valid address"),
        }
    }
}

impl QuicClientConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let watchdog_uid: u32 = env_var("FOSSH_WATCHDOG_UID")
            .ok_or(ConfigError::MissingWatchdogUid)?
            .parse()
            .map_err(|_| ConfigError::InvalidWatchdogUid(env_var("FOSSH_WATCHDOG_UID").unwrap_or_default()))?;
        let quic_connect_addr: SocketAddr = env_var("FOSSH_QUIC_CONNECT_ADDR")
            .unwrap_or_else(|| "127.0.0.1:7443".to_string())
            .parse()
            .map_err(|_| {
                ConfigError::InvalidConnectAddr(env_var("FOSSH_QUIC_CONNECT_ADDR").unwrap_or_default())
            })?;
        Ok(Self {
            bootstrap_socket: env_path("FOSSH_BOOTSTRAP_SOCKET", "/run/fossh/bootstrap.sock"),
            tls_dir: env_path("FOSSH_CORE_TLS_DIR", "/var/lib/fossh/tls"),
            watchdog_fingerprint_pin: env_path(
                "FOSSH_WATCHDOG_FINGERPRINT_PIN",
                "/var/lib/fossh/watchdog-fingerprint.pin",
            ),
            watchdog_cert_pin: env_path("FOSSH_WATCHDOG_CERT_PIN", "/var/lib/fossh/watchdog-cert.pin"),
            watchdog_uid,
            quic_connect_addr,
        })
    }
}

/// Blocks until both of the watchdog's pins already exist, or a
/// single bootstrap handoff attempt lands one — `run_bootstrap_listener`
/// itself has no timeout (see `fossh_admin::watchdog_pin`'s own
/// `accept_one_handoff`, a plain blocking `listener.accept()`), so a
/// caller of this function blocks for as long as it takes an operator
/// to run the watchdog's own `bootstrap-send`. Correct for a
/// dedicated background thread with nothing else depending on it
/// completing promptly; would be wrong on `fossh-fcgi`'s actual
/// request-serving path, which this is deliberately kept off of.
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

/// One full connect → session → command → reply → close cycle. `pub`
/// (not just crate-private) specifically so
/// `tests/quic_command_interop.rs` — the real cross-language
/// integration test proving this actually interoperates with the
/// real compiled `fossh-watchdog`, not just with itself — can drive
/// it directly, the same real function `run`'s `SIGHUP` loop below
/// calls, rather than a parallel test-only reimplementation of it.
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
    let (mut conn, socket) =
        fossh_ipc::connect(config.quic_connect_addr, &tls, deadline).map_err(|e| format!("connect: {e}"))?;

    // Stream 1, not 0: QUIC stream IDs encode who may be the first to
    // write on them in their low two bits (0 = client-initiated bidi,
    // 1 = server-initiated bidi), enforced by quiche itself — the
    // watchdog (server) speaks first on this stream with its session
    // hello, so it must be a server-initiated ID. See
    // watchdog/quic/quic_command_server.ml's matching comment for the
    // real, reproduced QUICHE_ERR_INVALID_STREAM_STATE this fixes.
    const SESSION_STREAM: u64 = 1;
    const COMMAND_STREAM: u64 = 4;

    let (hello_line, _fin) = fossh_ipc::recv_from_stream(&mut conn, &socket, SESSION_STREAM, deadline)
        .map_err(|e| format!("recv session hello: {e}"))?;
    let hello_line = String::from_utf8_lossy(&hello_line).into_owned();
    let session_token =
        command_client::decode_session_hello(&hello_line).map_err(|e| format!("session hello: {e}"))?;

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

    let (reply_line, _fin) = fossh_ipc::recv_from_stream(&mut conn, &socket, COMMAND_STREAM, deadline)
        .map_err(|e| format!("recv reply: {e}"))?;
    let reply_line = String::from_utf8_lossy(&reply_line).into_owned();
    match command_client::decode_response(&reply_line).map_err(|e| format!("reply: {e}"))? {
        Response::Ok => Ok(()),
        Response::Error(reason) => Err(format!("watchdog refused: {reason}")),
    }
}

/// Blocks `SIGHUP` in *this* thread's mask — must be called from
/// every thread that must never be torn down by the default
/// terminate-on-SIGHUP disposition, which in practice means calling
/// this in `main` before spawning any other thread: signal masks are
/// inherited by new threads at creation time, not retroactively
/// applied. The dedicated `sigwait` thread spawned by `spawn` below
/// still receives blocked signals via `sigwait` itself — blocking a
/// signal only stops asynchronous delivery/the default disposition,
/// it does not stop `sigwait` from consuming it.
pub fn block_sighup_process_wide() -> Result<(), String> {
    let mut set = nix::sys::signal::SigSet::empty();
    set.add(nix::sys::signal::Signal::SIGHUP);
    nix::sys::signal::pthread_sigmask(nix::sys::signal::SigmaskHow::SIG_BLOCK, Some(&set), None)
        .map_err(|e| format!("pthread_sigmask: {e}"))
}

/// Runs forever on a dedicated background thread: establishes this
/// process's own TLS identity, waits for the watchdog to be pinned
/// (see `ensure_watchdog_pinned`), then blocks in `sigwait` and
/// performs one `send_one_reload` cycle per `SIGHUP` delivered to
/// this process — `kill -HUP $(pidof fossh-fcgi)` is the real,
/// operator-usable trigger this wires up. Every failure is logged and
/// looped past, never allowed to end the thread: a QUIC-layer hiccup
/// on one reload attempt must not silently disable every future one
/// for the rest of this process's life.
pub fn run(config: QuicClientConfig) {
    let identity = match tls_identity::ensure_identity(&config.tls_dir, "fossh-svc") {
        Ok(id) => id,
        Err(e) => {
            log(&format!("could not establish this process's own TLS identity: {e} — QUIC command channel disabled for this process's lifetime"));
            return;
        }
    };
    let own_cert_pem = match std::fs::read_to_string(&identity.cert_pem_path) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("could not read own certificate at {}: {e}", identity.cert_pem_path.display()));
            return;
        }
    };
    if let Err(e) = ensure_watchdog_pinned(&config, &own_cert_pem) {
        log(&format!("bootstrap handoff failed: {e} — QUIC command channel disabled for this process's lifetime"));
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
