//! §3.4: the steady-state watchdog↔core QUIC/mTLS IPC channel. This
//! is core's (`fossh-svc`'s) side, using `quiche`'s safe Rust API
//! directly — no `ctypes`/C ABI needed here, unlike the OCaml
//! watchdog's half (`fossh-quiche-ffi`, `watchdog/lib/quic.ml`).
//!
//! Deliberately blocking I/O with a socket read timeout, not `mio`
//! (which quiche's own examples use) — this project has no async
//! runtime anywhere (see `fossh-fcgi`'s own design notes) and this
//! channel carries occasional, low-frequency status/command traffic
//! between exactly two known peers, not a many-client server; a
//! polling event loop would be solving a problem this channel doesn't
//! have. Deliberately not the full multi-client `ClientMap` shape
//! quiche's own `examples/server.rs` uses either, for the same
//! reason: there is exactly one watchdog and exactly one core per
//! install, never more.
//!
//! This module covers the transport primitives: real, verified
//! connection establishment with mutual TLS and basic stream
//! send/recv. The app-level command protocol (session-token-bound
//! commands, replay protection per §3.4's own requirement) and its
//! wiring into `fossh-fcgi`'s real runtime loop are built too, but
//! live elsewhere — `crates/fossh-admin::command_client` and
//! `crates/fossh-fcgi/src/quic_client.rs` respectively; see ADR-0047/
//! ADR-0050 and dev/DURUM.md for exactly what's connected.

#![forbid(unsafe_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const ALPN: &[u8] = b"fossh-ipc/1";

#[derive(Debug)]
pub enum IpcError {
    Quiche(quiche::Error),
    Io(std::io::Error),
    /// The connection closed (cleanly or not) before the operation
    /// this error is returned from could complete.
    ConnectionClosed,
    /// No progress was possible within the caller's own deadline —
    /// distinct from a QUIC-level idle timeout, which `quiche` itself
    /// already turns into a normal connection close.
    DeadlineExceeded,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quiche(e) => write!(f, "quiche error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::DeadlineExceeded => write!(f, "deadline exceeded"),
        }
    }
}

impl std::error::Error for IpcError {}
impl From<quiche::Error> for IpcError {
    fn from(e: quiche::Error) -> Self {
        Self::Quiche(e)
    }
}
impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct TlsPaths<'a> {
    /// This endpoint's own certificate chain (PEM).
    pub cert_chain_pem: &'a str,
    /// This endpoint's own private key (PEM).
    pub priv_key_pem: &'a str,
    /// The *one* pinned peer certificate (PEM) trusted for
    /// verification — §2.4's per-install pinning, not a CA bundle.
    /// Used as `load_verify_locations_from_file`'s argument: a
    /// self-signed certificate is a perfectly valid trust anchor for
    /// exactly this purpose.
    pub trusted_peer_cert_pem: &'a str,
}

/// Shared by both client and server: real mTLS (`verify_peer(true)`
/// unconditionally — §3.4 is explicit that this channel is
/// bidirectionally verified, not one side trusting the other by
/// default the way quiche's own examples do for demo purposes).
pub fn build_config(tls: &TlsPaths) -> Result<quiche::Config, IpcError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(tls.cert_chain_pem)?;
    config.load_priv_key_from_pem_file(tls.priv_key_pem)?;
    config.load_verify_locations_from_file(tls.trusted_peer_cert_pem)?;
    config.verify_peer(true);
    config.set_application_protos(&[ALPN])?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(4);
    config.set_disable_active_migration(true);
    Ok(config)
}

fn random_conn_id() -> [u8; quiche::MAX_CONN_ID_LEN] {
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    // `getrandom(2)` directly — the same primitive
    // `fossh_ingest::random::read_random_bytes` already wraps
    // elsewhere in this project, reimplemented here rather than
    // taking a dependency on that crate just for this one call (this
    // crate is deliberately excluded from the main workspace and
    // kept dependency-light, matching fossh-quiche-ffi's own reasoning).
    let mut urandom = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    std::io::Read::read_exact(&mut urandom, &mut scid).expect("read /dev/urandom");
    scid
}

/// Drives `conn` (already created via `quiche::connect` or
/// `quiche::accept`) with blocking I/O on `socket` until `done`
/// reports `true` or `deadline` passes. `socket` must already have a
/// read timeout set short enough that this loop can check the
/// deadline between reads — see `set_socket_timeouts`.
///
/// `done` is checked exactly once per iteration, after *both* the
/// recv-drain and the send-drain phases have run — never in between.
/// An earlier version checked it between the two phases as an early
/// exit, which is correct for a "have we become established" check
/// but silently wrong for "send this, then stop": `send_on_stream`'s
/// `|_| true` closure returned `true` on the very first pass, right
/// after the (usually empty, on a pure send) recv-drain phase — before
/// `drive_until` ever reached the send-drain phase that would have
/// actually flushed the just-queued stream data onto the wire.
/// Reproduced for real: `RUST_LOG=trace` showed the queued data only
/// ever reaching the wire as an accidental side effect of a *later*,
/// unrelated `drive_until` call on the same `Connection` (whatever
/// happened to run its own send-drain phase next) — meaning a
/// send-then-immediately-drop caller (exactly what the mTLS test's
/// server thread does) lost the data entirely, since nothing ever
/// triggered that next call before the socket closed. Checking `done`
/// only after both phases, every iteration, closes that gap: a caller
/// that only cares about "did I get to send" is guaranteed at least
/// one real send-drain pass before this function can return.
fn drive_until<F>(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    deadline: Instant,
    mut done: F,
) -> Result<(), IpcError>
where
    F: FnMut(&mut quiche::Connection) -> bool,
{
    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        // A protocol-fatal `recv()` error (e.g. the peer's certificate
        // failing verification) is remembered, not returned
        // immediately — quiche needs the send-drain phase still ahead
        // of us in this same iteration to actually produce the
        // CONNECTION_CLOSE packet notifying the peer; returning
        // early skips that send entirely, so the peer never learns
        // anything was wrong. But the error can't be silently dropped
        // either — an earlier version of this fix did exactly that
        // (just `break`, then fall through to the ordinary `done`
        // check below), and `send_on_stream`'s `|_| true` closure then
        // reported success regardless, since nothing recorded that
        // recv() had failed moments earlier in the very same pass.
        // Reproduced for real, both bugs, before landing on this
        // shape: a client presenting a certificate the server doesn't
        // trust got a `send_on_stream` that returned `Ok(())`.
        let mut recv_error: Option<quiche::Error> = None;

        // Drain every readable packet before sending — mirrors
        // quiche's own examples' read-then-send ordering per pass.
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        to: socket.local_addr()?,
                        from,
                    };
                    match conn.recv(&mut buf[..len], recv_info) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            recv_error = Some(e);
                            break;
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        if conn.is_closed() {
            return Err(IpcError::ConnectionClosed);
        }

        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to)?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }

        if let Some(e) = recv_error {
            return Err(e.into());
        }
        if conn.is_closed() {
            return Err(IpcError::ConnectionClosed);
        }
        if done(conn) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(IpcError::DeadlineExceeded);
        }
    }
}

/// A short, fixed read timeout, independent of the caller's overall
/// deadline — this is what lets `drive_until`'s loop wake up
/// periodically to re-check that deadline and `conn.on_timeout()`,
/// rather than blocking indefinitely on a socket that may never
/// receive another packet (e.g. a peer that silently vanished).
///
/// 2ms, not the 100ms an earlier version used — `drive_until`'s inner
/// recv-drain loop calls `recv_from` repeatedly until it sees
/// `WouldBlock`/`TimedOut`, and a *blocking* socket has no way to
/// return that faster than the full configured timeout, since it
/// genuinely cannot tell "nothing more, ever" apart from "check back
/// very soon" without waiting the timeout out. At 100ms, that cost a
/// full 100ms on *every single pass* of the outer loop, and a real
/// QUIC handshake needs multiple passes. Measured, not estimated, both
/// before and after this fix, with the exact same benchmark (100 real
/// loopback mTLS handshakes, `crates/fossh-ipc`'s own code, not a
/// synthetic stand-in): 100ms timeout gave a 211ms median handshake /
/// 627ms median full round trip (handshake + one stream message each
/// way); 2ms gives 8.8ms / 21.3ms for the same two measurements — roughly
/// 24x and 30x faster, on a channel documented as carrying occasional,
/// low-frequency traffic, not one where the compounding hundreds-of-
/// milliseconds cost would have gone unnoticed for long. 2ms keeps the
/// same "wake up periodically, don't block forever" property this
/// timeout exists for, just without paying for it at 100ms granularity.
fn set_socket_timeouts(socket: &UdpSocket) -> Result<(), IpcError> {
    socket.set_read_timeout(Some(Duration::from_millis(2)))?;
    Ok(())
}

/// Connects to `peer_addr` and drives the handshake to completion (or
/// `deadline`). The returned `(Connection, UdpSocket)` is fully
/// established and ready for `stream_send`/`stream_recv` — the caller
/// keeps driving both with `service` for the connection's remaining
/// lifetime.
pub fn connect(
    peer_addr: SocketAddr,
    tls: &TlsPaths,
    deadline: Instant,
) -> Result<(quiche::Connection, UdpSocket), IpcError> {
    let bind_addr: SocketAddr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    set_socket_timeouts(&socket)?;

    let mut config = build_config(tls)?;
    let scid = quiche::ConnectionId::from_vec(random_conn_id().to_vec());
    let local_addr = socket.local_addr()?;

    let mut conn = quiche::connect(None, &scid, local_addr, peer_addr, &mut config)?;

    // The initial packet has to go out before anything can come back.
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let (write, send_info) = conn.send(&mut out)?;
    socket.send_to(&out[..write], send_info.to)?;

    drive_until(&mut conn, &socket, deadline, |c| c.is_established())?;
    Ok((conn, socket))
}

/// Binds `listen_addr` and accepts exactly one connection, driving it
/// to completion (or `deadline`) — this channel is a single,
/// persistent connection between exactly one watchdog and exactly one
/// core, not a multi-client server (see this module's header
/// comment), so there is no connection-ID-keyed client table here.
pub fn accept_one(
    listen_addr: SocketAddr,
    tls: &TlsPaths,
    deadline: Instant,
) -> Result<(quiche::Connection, UdpSocket), IpcError> {
    let socket = UdpSocket::bind(listen_addr)?;
    set_socket_timeouts(&socket)?;
    let mut config = build_config(tls)?;
    let local_addr = socket.local_addr()?;

    let mut buf = [0u8; 65535];
    let mut conn: Option<quiche::Connection> = None;

    loop {
        match &mut conn {
            None => {
                let (len, from) = loop {
                    match socket.recv_from(&mut buf) {
                        Ok(v) => break v,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            if Instant::now() >= deadline {
                                return Err(IpcError::DeadlineExceeded);
                            }
                        }
                        Err(e) => return Err(e.into()),
                    }
                };

                let scid = quiche::ConnectionId::from_vec(random_conn_id().to_vec());
                let mut new_conn = quiche::accept(&scid, None, local_addr, from, &mut config)?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };
                new_conn.recv(&mut buf[..len], recv_info)?;
                conn = Some(new_conn);
            }
            Some(c) => {
                drive_until(c, &socket, deadline, |c| c.is_established())?;
                let established = c.is_established();
                let _ = established;
                break;
            }
        }
    }

    let conn = conn.expect("loop only exits with conn set");
    Ok((conn, socket))
}

/// Sends `data` on `stream_id`, driving the connection until quiche
/// has flushed everything it's willing to send this pass or the
/// deadline passes.
pub fn send_on_stream(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    stream_id: u64,
    data: &[u8],
    fin: bool,
    deadline: Instant,
) -> Result<(), IpcError> {
    conn.stream_send(stream_id, data, fin)?;
    drive_until(conn, socket, deadline, |_| true)
}

/// Blocks (up to `deadline`) until at least one full message has
/// arrived on `stream_id`, returning it. `fin` tells the caller
/// whether the peer signaled end-of-stream.
///
/// Reads directly inside `drive_until`'s own "are we done" closure,
/// rather than checking `stream_readable` first and reading
/// separately afterward — an earlier version did the latter and hit a
/// real, reproduced bug: the stream's data had genuinely arrived at
/// the QUIC layer (confirmed via `RUST_LOG=trace`, a real `rx frm
/// STREAM ... fin=true` line), but by the time control returned to a
/// *separate* read step outside the loop, the specific interleaving
/// of drive_until's own recv/send passes meant readability was
/// missed on some runs. Folding the actual `stream_recv` call into
/// the closure itself — checked on every single pass of the loop,
/// with `&mut Connection` now that `drive_until` provides one —
/// removes the gap between "observing readable" and "acting on it"
/// entirely.
pub fn recv_from_stream(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    stream_id: u64,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), IpcError> {
    let mut collected = Vec::new();
    let mut got_fin = false;
    let mut buf = [0u8; 65535];

    drive_until(conn, socket, deadline, |c| {
        loop {
            match c.stream_recv(stream_id, &mut buf) {
                Ok((read, fin)) => {
                    collected.extend_from_slice(&buf[..read]);
                    if fin {
                        got_fin = true;
                        return true;
                    }
                    if read == 0 {
                        return false;
                    }
                }
                Err(quiche::Error::Done) => return false,
                // A real per-call error (not just "nothing to read
                // right now") here would otherwise be silently
                // swallowed by the closure's `bool` return type; there
                // is no data-carrying path back to the caller from
                // inside `drive_until`'s closure, so this treats it
                // the same as "not done yet" and lets the *next*
                // pass's `conn.is_closed()` check (drive_until already
                // makes this check on every pass) surface the failure
                // instead, rather than pretending nothing happened.
                Err(_) => return false,
            }
        }
    })?;

    Ok((collected, got_fin))
}
