#![forbid(unsafe_code)]

use fossh_fcgi::{connection, protocol, writer};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fossh_core::config::Config;
use fossh_ingest::geoip::GeoipReader;
use fossh_ingest::ingest::{self, IngestDecision};

const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn secure_connection(stream: UnixStream, timeout: Duration) -> Option<UnixStream> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    Some(stream)
}

fn socket_is_live(path: &std::path::Path) -> bool {
    UnixStream::connect(path).is_ok()
}

fn bind_with_correct_permissions(path: &std::path::Path) -> std::io::Result<UnixListener> {
    let previous_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o177));
    let result = UnixListener::bind(path);
    nix::sys::stat::umask(previous_umask);
    result
}

struct Shared {
    data_dir: PathBuf,
    salt_dir: PathBuf,
    rate_limit_per_sec: u32,
    rate_limit_burst: u32,
    respect_optout_signals: bool,
    trusted_hops: u8,
    events_tx: Sender<fossh_core::types::Event>,

    country_db: GeoipReader,
}

fn handle_connection(mut stream: UnixStream, shared: &Shared) {
    loop {
        let request = match connection::read_request(&mut stream, shared.trusted_hops) {
            Ok(connection::RequestOutcome::ConnectionClosed) => return,
            Ok(connection::RequestOutcome::Ingest(req)) => req,
            Err(connection::ReadError::Unsupported { request_id, status }) => {
                let _ = protocol::write_end_request_only(&mut stream, request_id, status);
                return;
            }
            Err(connection::ReadError::BodyTooLarge { request_id }) => {
                let _ = connection::write_ingest_response(&mut stream, request_id, 413, None);
                return;
            }

            Err(connection::ReadError::Io(e)) => {
                eprintln!("fossh-fcgi: connection I/O error: {e}");
                return;
            }
            Err(connection::ReadError::Protocol(e)) => {
                eprintln!("fossh-fcgi: malformed FastCGI stream: {e}");
                return;
            }
        };

        let (status, allow_origin): (u16, Option<String>) =
            if request.env.method == "GET" && request.env.path_info == "/healthz" {
                (204, None)
            } else {
                let decision = ingest::decide(&ingest::DecideParams {
                    env: &request.env,
                    body: &request.body,
                    data_dir: &shared.data_dir,
                    salt_dir: &shared.salt_dir,
                    rate_limit_per_sec: shared.rate_limit_per_sec,
                    rate_limit_burst: shared.rate_limit_burst,
                    respect_optout_signals: shared.respect_optout_signals,
                    now: unix_now(),
                    country_db: &shared.country_db,
                });
                match decision {
                    IngestDecision::Status {
                        status,
                        allow_origin,
                    } => (status, allow_origin),
                    IngestDecision::Commit {
                        events,
                        allow_origin,
                        ..
                    } => {
                        for event in events {

                            if shared.events_tx.send(event).is_err() {
                                break;
                            }
                        }
                        (204, allow_origin)
                    }
                }
            };

        let wrote = connection::write_ingest_response(
            &mut stream,
            request.request_id,
            status,
            allow_origin.as_deref(),
        );
        if wrote.is_err() || !request.keep_conn {
            return;
        }
    }
}

fn spawn_worker_pool(
    size: usize,
    connections: mpsc::Receiver<UnixStream>,
    shared: Arc<Shared>,
) -> Vec<thread::JoinHandle<()>> {
    let connections = Arc::new(Mutex::new(connections));
    (0..size)
        .map(|_| {
            let connections = Arc::clone(&connections);
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                loop {

                    let next = connections.lock().unwrap().recv();
                    match next {
                        Ok(stream) => handle_connection(stream, &shared),
                        Err(_) => return,
                    }
                }
            })
        })
        .collect()
}

fn spawn_maintenance_thread(
    db_path: PathBuf,
    retention_days: u32,
    data_key: zeroize::Zeroizing<[u8; 32]>,
) -> thread::JoinHandle<()> {
    const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);
    const VACUUM_EVERY_N_PASSES: u32 = 24;

    thread::spawn(move || {
        let mut passes: u32 = 0;
        loop {
            thread::sleep(RETENTION_INTERVAL);
            let Ok(mut store) = fossh_store::Store::open_encrypted(&db_path, &data_key) else {
                continue;
            };
            match store.enforce_retention(retention_days, unix_now()) {
                Ok(deleted) if deleted > 0 => {
                    eprintln!("fossh-fcgi: retention deleted {deleted} expired events");
                }
                Ok(_) => {}
                Err(e) => eprintln!("fossh-fcgi: retention pass failed: {e}"),
            }
            passes += 1;
            if passes.is_multiple_of(VACUUM_EVERY_N_PASSES)
                && let Err(e) = store.vacuum()
            {
                eprintln!("fossh-fcgi: vacuum failed: {e}");
            }
        }
    })
}

#[cfg(feature = "quic")]
fn maybe_start_quic_client() {
    if let Err(e) = fossh_fcgi::quic_client::block_sighup_process_wide() {
        eprintln!(
            "fossh-fcgi: could not block SIGHUP for the QUIC command channel: {e} — channel disabled"
        );
        return;
    }
    match fossh_fcgi::quic_client::QuicClientConfig::from_env() {
        Ok(config) => {
            thread::spawn(move || fossh_fcgi::quic_client::run(config));
        }
        Err(e) => eprintln!("fossh-fcgi: QUIC command channel not started: {e}"),
    }
}

#[cfg(not(feature = "quic"))]
fn maybe_start_quic_client() {}

fn main() {

    maybe_start_quic_client();

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fossh-fcgi: config error: {e}");
            std::process::exit(1);
        }
    };

    let socket_path = env_var("FOSSH_FCGI_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/fossh/fcgi.sock"));

    if socket_path.exists() {
        if socket_is_live(&socket_path) {
            eprintln!(
                "fossh-fcgi: {} is already live (another instance is listening) — refusing to start a second one",
                socket_path.display()
            );
            std::process::exit(1);
        }
        let _ = std::fs::remove_file(&socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match bind_with_correct_permissions(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fossh-fcgi: could not bind {}: {e}", socket_path.display());
            std::process::exit(1);
        }
    };

    let data_key = match fossh_admin::data_key::load_or_generate(&config.data_dir.join(".data_key"))
    {
        Ok(key) => key,
        Err(e) => {
            eprintln!("fossh-fcgi: could not load data-encryption key: {e}");
            std::process::exit(1);
        }
    };

    let db_path = config.data_dir.join("fossh.db");
    let store = match fossh_store::Store::open_encrypted(&db_path, &data_key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fossh-fcgi: could not open {}: {e}", db_path.display());
            std::process::exit(1);
        }
    };
    let (events_tx, events_rx) = mpsc::channel();
    thread::spawn(move || writer::run(store, events_rx));
    spawn_maintenance_thread(db_path, config.retention_days, data_key);

    let trusted_hops = fossh_ingest::forwarded::trusted_hops_from_env(
        env_var("FOSSH_TRUST_FORWARDED_FOR").as_deref(),
    );

    let country_db = GeoipReader::open(config.country_db.path());
    let shared = Arc::new(Shared {
        data_dir: config.data_dir.clone(),
        salt_dir: config.salt_dir.clone(),
        rate_limit_per_sec: config.rate_limit.per_sec,
        rate_limit_burst: config.rate_limit.burst,
        respect_optout_signals: config.respect_optout_signals,
        trusted_hops,
        events_tx,
        country_db,
    });

    let worker_count: usize = env_var("FOSSH_FCGI_WORKERS")
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n >= 1)
        .unwrap_or(8);
    let (conn_tx, conn_rx) = mpsc::channel();
    let workers = spawn_worker_pool(worker_count, conn_rx, shared);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let Some(stream) = secure_connection(stream, CONNECTION_IO_TIMEOUT) else {
                    continue;
                };
                if conn_tx.send(stream).is_err() {
                    break;
                }
            }
            Err(e) => eprintln!("fossh-fcgi: accept error: {e}"),
        }
    }

    drop(conn_tx);
    for worker in workers {
        let _ = worker.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::base32;
    use fossh_store::Site;
    use std::io::{Read as _, Write as _};

    fn write_record(
        w: &mut UnixStream,
        kind: protocol::RecordType,
        request_id: u16,
        content: &[u8],
    ) {
        protocol::write_header(
            w,
            &protocol::Header {
                version: protocol::VERSION_1,
                kind,
                request_id,
                content_length: content.len() as u16,
                padding_length: 0,
            },
        )
        .unwrap();
        w.write_all(content).unwrap();
    }

    fn encode_params(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in pairs {
            out.push(k.len() as u8);
            out.push(v.len() as u8);
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn send_request(client: &mut UnixStream, params: &[(&str, &str)], body: &[u8]) {
        let mut begin_body = [0u8; 8];
        begin_body[0..2].copy_from_slice(&1u16.to_be_bytes());
        write_record(client, protocol::RecordType::BeginRequest, 1, &begin_body);
        let encoded = encode_params(params);
        if !encoded.is_empty() {
            write_record(client, protocol::RecordType::Params, 1, &encoded);
        }
        write_record(client, protocol::RecordType::Params, 1, &[]);
        if !body.is_empty() {
            write_record(client, protocol::RecordType::Stdin, 1, body);
        }
        write_record(client, protocol::RecordType::Stdin, 1, &[]);
    }

    fn read_response_stdout(client: &mut UnixStream) -> String {
        let header = protocol::read_header(client).unwrap();
        assert_eq!(header.kind, protocol::RecordType::Stdout);
        let content = protocol::read_record_body(client, &header).unwrap();
        String::from_utf8(content).unwrap()
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-fcgi-main-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_shared(
        data_dir: PathBuf,
    ) -> (
        Arc<Shared>,
        std::sync::mpsc::Receiver<fossh_core::types::Event>,
    ) {
        let (events_tx, events_rx) = mpsc::channel();
        let shared = Arc::new(Shared {
            salt_dir: data_dir.clone(),
            data_dir,
            rate_limit_per_sec: 60,
            rate_limit_burst: 600,
            respect_optout_signals: true,
            trusted_hops: 0,
            events_tx,
            country_db: GeoipReader::none(),
        });
        (shared, events_rx)
    }

    #[test]
    fn healthz_is_204_and_never_touches_data_dir() {

        let (shared, _events_rx) = test_shared(PathBuf::from("/nonexistent/path/for/this/test"));
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_connection(server, &shared));

        send_request(
            &mut client,
            &[("REQUEST_METHOD", "GET"), ("PATH_INFO", "/healthz")],
            b"",
        );
        let text = read_response_stdout(&mut client);
        assert!(text.starts_with("Status: 204 No Content\r\n"));

        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn a_full_bearer_ingest_request_round_trips_and_reaches_the_writer_channel() {
        let dir = scratch_dir("ingest-roundtrip");
        let raw_key = [0xABu8; 32];
        let key_hash = *blake3::hash(&raw_key).as_bytes();
        fossh_ingest::site_cache::write(
            &dir,
            &Site {
                id: fossh_core::types::SiteId::new(1),
                slug: "blog".to_string(),
                key_hash,
                sign_pubkey: None,
                allowlist: vec!["pageview".to_string()],
                created_at: 1_700_000_000,
                disabled: false,
                public: true,
            },
        )
        .unwrap();
        let token = format!("fossh_blog_{}", base32::encode(&raw_key));

        let (shared, events_rx) = test_shared(dir.clone());
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || handle_connection(server, &shared));

        send_request(
            &mut client,
            &[
                ("REQUEST_METHOD", "POST"),
                ("PATH_INFO", "/e"),
                ("REMOTE_ADDR", "203.0.113.9"),
                ("HTTP_AUTHORIZATION", &format!("Bearer {token}")),
            ],
            br#"{"name":"pageview"}"#,
        );
        let text = read_response_stdout(&mut client);
        assert!(text.starts_with("Status: 204 No Content\r\n"));

        let event = events_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("an accepted event must reach the writer channel");
        assert_eq!(event.name.as_str(), "pageview");

        drop(client);
        handle.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secure_connection_sets_a_read_timeout_that_actually_fires() {

        let (client, server) = UnixStream::pair().unwrap();
        let secured = secure_connection(server, Duration::from_millis(100))
            .expect("setting a timeout on a fresh, live socketpair must succeed");

        let start = std::time::Instant::now();
        let mut buf = [0u8; 1];
        let result = (&secured).read(&mut buf);
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "a read on a peer that never sends anything must eventually fail, not succeed"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the read must time out promptly (~100ms), not hang — took {elapsed:?}"
        );
        drop(client);
    }

    #[test]
    fn socket_is_live_is_false_for_a_path_nothing_is_listening_on() {
        let path = std::env::temp_dir().join(format!(
            "fossh-fcgi-liveness-test-nothing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a socket, just a leftover regular file").unwrap();

        assert!(
            !socket_is_live(&path),
            "a stale, non-socket file must not be mistaken for a live listener"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn socket_is_live_is_true_while_a_real_listener_holds_the_path() {
        let path = std::env::temp_dir().join(format!(
            "fossh-fcgi-liveness-test-live-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _listener = UnixListener::bind(&path).unwrap();

        assert!(
            socket_is_live(&path),
            "a path with a real, currently-bound listener must be reported live"
        );
        drop(_listener);
        std::fs::remove_file(&path).ok();
    }

    #[allow(dead_code)]
    fn manual_check_bind_with_correct_permissions_is_0600_and_restores_umask() {
        use std::os::unix::fs::PermissionsExt;

        let original = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
        nix::sys::stat::umask(original);

        let path =
            std::env::temp_dir().join(format!("fossh-fcgi-perm-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let _listener = bind_with_correct_permissions(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the socket file's mode the instant after bind() must already be 0600, \
             not merely correctable afterward"
        );

        let after = nix::sys::stat::umask(original);
        nix::sys::stat::umask(after);
        assert_eq!(
            after, original,
            "the process umask must be exactly what it was before bind_with_correct_permissions ran \
             — this fix must not leak a permanently-tightened umask into the rest of the process"
        );

        drop(_listener);
        std::fs::remove_file(&path).ok();
    }
}
