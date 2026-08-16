#![forbid(unsafe_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const ALPN: &[u8] = b"fossh-ipc/1";

#[derive(Debug)]
pub enum IpcError {
    Quiche(quiche::Error),
    Io(std::io::Error),

    ConnectionClosed,

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

    pub cert_chain_pem: &'a str,

    pub priv_key_pem: &'a str,

    pub trusted_peer_cert_pem: &'a str,
}

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

    let mut urandom = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    std::io::Read::read_exact(&mut urandom, &mut scid).expect("read /dev/urandom");
    scid
}

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

        let mut recv_error: Option<quiche::Error> = None;

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

fn set_socket_timeouts(socket: &UdpSocket) -> Result<(), IpcError> {
    socket.set_read_timeout(Some(Duration::from_millis(2)))?;
    Ok(())
}

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

    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let (write, send_info) = conn.send(&mut out)?;
    socket.send_to(&out[..write], send_info.to)?;

    drive_until(&mut conn, &socket, deadline, |c| c.is_established())?;
    Ok((conn, socket))
}

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

                Err(_) => return false,
            }
        }
    })?;

    Ok((collected, got_fin))
}
