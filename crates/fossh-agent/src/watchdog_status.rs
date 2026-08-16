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

            "This build of foSSH cannot talk to the watchdog. That is expected on RHEL, Rocky \
             and Alma, where the watchdog is not available at all; on Fedora it usually means \
             the fossh-watchdog package is not installed."
                .to_string(),
        )
    }
}

pub fn query() -> Result<WatchdogStatus, String> {
    live::query()
}
