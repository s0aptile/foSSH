//! One-shot §3.4 QUIC status query to the watchdog, for the dashboard
//! screen (`ui.rs`'s `draw_dashboard`) — this crate's first network
//! client. Mirrors `crates/fossh-fcgi/src/quic_client.rs`'s own
//! connect → session hello → command → reply → close shape exactly,
//! reusing the same wire protocol (`fossh_admin::command_client`) and
//! the same `Status` command dispatched by
//! `watchdog/quic/quic_command_server.ml`, rather than inventing a
//! second channel to the same process.
//!
//! Deliberately synchronous, blocking I/O called only from an
//! explicit key press (`app::App::refresh_watchdog_status`, bound to
//! `r` on the dashboard screen), never from `App::new()` or the
//! render loop itself: a closed/unreachable watchdog port has no fast
//! ICMP-style refusal over QUIC's UDP transport, so an eager query on
//! every app launch or every redraw would mean blocking the whole
//! TUI's startup on a multi-second timeout in the common case of
//! running this console with no watchdog listening at all (during
//! development, or before the watchdog service has been started —
//! note this is no longer the wizard screen's own situation: as of
//! ADR-0059, `wizard.rs` is a real client of the watchdog's setup
//! protocol, not a standalone/demo mode). Requiring an
//! explicit `r` is a deliberate, documented scope choice, not an
//! oversight — matching the existing telemetry screen's own
//! refresh-on-demand pattern (`app::App::refresh_sites`).
//!
//! Reuses core's own already-established mTLS identity
//! (`FOSSH_CORE_TLS_DIR`, default `/var/lib/fossh/tls`) rather than
//! minting a separate one for this console: the watchdog's QUIC
//! server pins exactly one peer certificate (core's — see
//! `Quic_command_server`'s own module doc, "exactly one watchdog and
//! exactly one core"), so a second, TUI-only identity would need its
//! own pinning step on the watchdog side to be trusted at all, a
//! materially larger feature this pass does not build. This only
//! works when the operator running the TUI can read that identity
//! directory (in practice: root, or a member of the `fossh-svc`
//! group) — an honest, narrower precondition than the wizard screen's
//! own already-privileged setup-token flow, not a new one.

use fossh_admin::command_client::{ChildState, TamperState};

pub struct WatchdogStatus {
    pub child: ChildState,
    pub tamper: TamperState,
}

#[cfg(feature = "quic")]
mod live {
    use super::WatchdogStatus;
    use fossh_admin::command_client::{self, Command, Response};
    use fossh_admin::tls_identity;
    use fossh_ipc::TlsPaths;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn env_var(key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|s| !s.is_empty())
    }

    fn env_path(key: &str, default: &str) -> PathBuf {
        env_var(key)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default))
    }

    pub fn query() -> Result<WatchdogStatus, String> {
        let tls_dir = env_path("FOSSH_CORE_TLS_DIR", "/var/lib/fossh/tls");
        let watchdog_cert_pin = env_path(
            "FOSSH_WATCHDOG_CERT_PIN",
            "/var/lib/fossh/watchdog-cert.pin",
        );
        let quic_connect_addr: SocketAddr = env_var("FOSSH_QUIC_CONNECT_ADDR")
            .unwrap_or_else(|| "127.0.0.1:7443".to_string())
            .parse()
            .map_err(|_| "FOSSH_QUIC_CONNECT_ADDR is not a valid address".to_string())?;

        // Same get-or-generate-once identity core's own quic_client
        // establishes (fossh-svc, FOSSH_CORE_TLS_DIR) — if core has
        // already run at least once, this reuses that exact identity;
        // if not, this call establishes the very same one core's own
        // next start would find already there, per that function's
        // own idempotent-per-directory contract. Either way this
        // process never mints a *second*, differently-trusted
        // identity core doesn't also use.
        let identity = tls_identity::ensure_identity(&tls_dir, "fossh-svc")
            .map_err(|e| format!("could not establish this host's own TLS identity: {e}"))?;
        let cert_chain_pem = identity.cert_pem_path.to_string_lossy().into_owned();
        let priv_key_pem = identity.key_pem_path.to_string_lossy().into_owned();
        let trusted_peer_cert_pem = watchdog_cert_pin.to_string_lossy().into_owned();
        let tls = TlsPaths {
            cert_chain_pem: &cert_chain_pem,
            priv_key_pem: &priv_key_pem,
            trusted_peer_cert_pem: &trusted_peer_cert_pem,
        };

        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut conn, socket) = fossh_ipc::connect(quic_connect_addr, &tls, deadline)
            .map_err(|e| format!("connect: {e}"))?;

        // Same stream numbering as quic_client.rs's send_one_reload —
        // both sides of this channel must agree on these, nothing
        // negotiates them (see quic_command_server.ml's own comment).
        const SESSION_STREAM: u64 = 1;
        const COMMAND_STREAM: u64 = 4;

        let (hello_line, _fin) =
            fossh_ipc::recv_from_stream(&mut conn, &socket, SESSION_STREAM, deadline)
                .map_err(|e| format!("recv session hello: {e}"))?;
        let hello_line = String::from_utf8_lossy(&hello_line).into_owned();
        let session_token = command_client::decode_session_hello(&hello_line)
            .map_err(|e| format!("session hello: {e}"))?;

        let command_line = command_client::encode_command(&session_token, Command::Status);
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
            Response::Status { child, tamper } => Ok(WatchdogStatus { child, tamper }),
            Response::Ok => Err(
                "watchdog sent an OK reply to a status query, which is not a valid reply for \
                     this command"
                    .to_string(),
            ),
            Response::Error(reason) => Err(format!("watchdog refused: {reason}")),
        }
    }
}

#[cfg(not(feature = "quic"))]
mod live {
    use super::WatchdogStatus;

    pub fn query() -> Result<WatchdogStatus, String> {
        Err(
            "this build of fossh-agent was compiled without watchdog QUIC support (rebuild with \
             `--features quic`)"
                .to_string(),
        )
    }
}

pub fn query() -> Result<WatchdogStatus, String> {
    live::query()
}
