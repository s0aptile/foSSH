//! §7.2: the persistent FastCGI listener. Unlike `fossh-cgi` (a fresh
//! process per request, spool-first because opening SQLite on that hot
//! path would blow its own <5ms budget), this binary stays up, so it
//! writes accepted events straight to SQLite through one dedicated
//! writer thread (`writer.rs`, batched every 100 events or 500ms) and
//! runs its own retention/vacuum maintenance on a timer instead of
//! relying on an external `fossh maintain` cron job.
//!
//! §3.8: this binary never touches the *spool* file at all (unchanged —
//! ADR-0035 covers why it has no spool-mode alternative despite
//! `Config::mode` existing), but it does load the same per-install
//! data-encryption key `fossh-cgi`/`fossh-cli` use, because the
//! database itself is now encrypted at rest too, not just the spool.
//! `fossh_store::Store::open_encrypted` is what both this process's
//! long-lived `store` (owned by `writer.rs`'s dedicated thread) and the
//! periodic maintenance thread's own reopen use — see
//! `spawn_maintenance_thread` below.
//!
//! No async runtime, per the spec's own constraint: a small, fixed
//! thread pool (`FOSSH_FCGI_WORKERS`, default 8) shares one
//! `mpsc::Receiver<UnixStream>` (the standard "thread pool via a
//! shared channel receiver" shape), fed by a single accept loop.

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

/// Read/write timeout on every accepted connection, in both
/// directions — see the accept loop's own comment for why this exists
/// at all. Generous for a local Unix-socket FastCGI exchange (which
/// should complete in well under a second in practice) while still
/// bounding the worst case a stalled or hostile peer can impose on a
/// worker thread.
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

/// Sets a read *and* write timeout on a freshly accepted connection
/// before it's handed to a worker. Adversarial-review finding: with no
/// timeout at all, a handful of connections that connect and then send
/// nothing (accidental — a stalled reverse-proxy worker — or
/// deliberate) permanently wedges the worker that picks each one up,
/// since the blocking `read()` calls in `connection::read_request`
/// never return on their own. Unlike a stuck `fossh-cgi` request (one
/// process, self-contained), a stuck `fossh-fcgi` worker thread stays
/// stuck for the rest of this daemon's life — with a small fixed pool
/// (default 8), as few as 8 such connections exhausts it entirely.
/// Both directions: a slow client reading the response back is the
/// same class of problem in reverse. `None` means the OS call to set
/// the timeout itself failed (rare — an already-dead socket); refusing
/// that connection outright is safer than handing a worker a stream
/// with an unknown, possibly-unbounded timeout state.
fn secure_connection(stream: UnixStream, timeout: Duration) -> Option<UnixStream> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    Some(stream)
}

/// True if something is genuinely listening at `path` right now.
/// Adversarial-review finding: removing an existing socket path on
/// bare existence, unconditionally, would silently hijack a *live*
/// instance's socket if this process is accidentally started a second
/// time (a misconfigured restart, an operator running it by hand while
/// the systemd-managed one is also up) — the first instance keeps
/// running, orphaned, while every *new* connection now goes to this
/// one instead, with no warning printed anywhere. A successful
/// `connect` means someone is genuinely listening; any failure (nobody
/// home, or the path doesn't even exist) means it's safe to remove and
/// rebind.
fn socket_is_live(path: &std::path::Path) -> bool {
    UnixStream::connect(path).is_ok()
}

/// Binds `path` with the socket file *created* at `0600` from the
/// first instant it exists — never a bind-then-chmod sequence.
/// Adversarial-review finding, verified empirically (a standalone
/// repro measured the file's real mode immediately after `bind()`,
/// before any `chmod`, under this environment's actual umask): a
/// bind-then-chmod sequence leaves the socket file world-connectable
/// (typically `0755`) for a real, non-zero window between the two
/// calls — `connect(2)`'s permission check happens once, at connect
/// time, so a connection made during that window stays valid even
/// after the follow-up `chmod` tightens the file. Fixed the way
/// `fossh_store::Store::open` already solves the identical problem for
/// `fossh.db` (see that function's own doc comment): force the
/// *creation* mode itself to be correct, via a restrictive process
/// umask held only for the `bind()` call, rather than correcting it
/// after the fact. `nix::sys::stat::umask` is a safe wrapper (no
/// `unsafe`, consistent with this crate's own
/// `#![forbid(unsafe_code)]`) around a syscall that changes
/// process-global state — safe to call this early in `main`, before
/// any other thread in this process exists yet to be affected by the
/// restriction being briefly in place. `0o177`: masks every bit
/// `0600` doesn't have out of the `0777` a fresh socket would
/// otherwise be created with (`0777 & !0177 == 0600`).
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
    /// Opened once at process start from `Config.country_db` (see
    /// `main` below), shared read-only across every worker thread for
    /// this process's whole lifetime — not reopened per request. Safe
    /// to share this way: `maxminddb::Reader` is `Send + Sync`, and
    /// `GeoipReader::resolve` takes `&self`, never mutates anything.
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
            // A genuine I/O or framing error: this connection can't be
            // trusted to still be at a record boundary — closing it is
            // the only safe move, same as the S2 "fail closed" posture
            // everywhere else on this path. Logged (not silently
            // dropped): an operator debugging "nginx reports upstream
            // errors" needs to see this side of the socket too.
            Err(connection::ReadError::Io(e)) => {
                eprintln!("fossh-fcgi: connection I/O error: {e}");
                return;
            }
            Err(connection::ReadError::Protocol(e)) => {
                eprintln!("fossh-fcgi: malformed FastCGI stream: {e}");
                return;
            }
        };

        // `GET /healthz` — "204, no auth, no body, no info leak" (§7.1),
        // same as `fossh-cgi`'s own `handle_healthz`: no `data_dir`
        // access at all, so nothing about this route can fail in a way
        // that reveals anything about site configuration or storage
        // state. `ingest::decide` deliberately doesn't handle this
        // itself (see its own module doc) — every transport's own
        // top-level routing must, and this one hadn't yet.
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
                            // The writer thread only ever disappears
                            // during shutdown (its `Receiver` closing
                            // would be the only way `send` fails) —
                            // nothing left to do with this or any later
                            // event in that case.
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
                    // Lock only long enough to pull the next connection
                    // off the shared queue — never held while a request
                    // is actually being handled, or every worker but one
                    // would block on every request.
                    let next = connections.lock().unwrap().recv();
                    match next {
                        Ok(stream) => handle_connection(stream, &shared),
                        Err(_) => return, // sender side closed: shutting down
                    }
                }
            })
        })
        .collect()
}

/// Runs `fossh-store`'s retention + vacuum maintenance on its own
/// timer instead of relying on an external `fossh maintain` cron job —
/// this process is already alive continuously, unlike `fossh-cgi`.
/// Retention runs hourly; `VACUUM` rewrites the whole file, so it runs
/// far less often (once per this many retention passes) to keep that
/// cost proportionate to a persistent database, not a fresh sqlite
/// file every hour.
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
                continue; // transient open failure: try again next interval
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

/// §3.4's QUIC command channel (feature `quic`, off by default — see
/// this crate's own Cargo.toml and `quic_client`'s own module doc).
/// A no-op when the feature isn't compiled in, so `main` below can
/// call this unconditionally rather than needing its own `#[cfg]`.
/// Every failure here is soft (logged, channel left disabled) — this
/// is an additive capability, not a requirement for this process's
/// actual mission of accepting and storing telemetry, and a
/// deployment that hasn't configured (or doesn't want) the watchdog
/// relationship must not have its core service refuse to start over
/// it.
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
    // Must run before any other thread is spawned below — a signal
    // mask is inherited by new threads at creation time, not applied
    // retroactively, and every thread in this process needs SIGHUP
    // blocked so the OS default (terminate) never fires no matter
    // which one the kernel happens to deliver it to; only the
    // dedicated QUIC-client thread ever actually consumes it, via its
    // own `sigwait`. A no-op when the `quic` feature is off.
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

    // §3.8: the same per-install data-encryption key `fossh-cgi` and
    // `fossh-cli` use — loaded once here and moved into both the writer
    // thread's `Store::open_encrypted` call below and the maintenance
    // thread's own periodic reopen.
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
    // Opened once here, not per request — see `Shared::country_db`'s own
    // doc comment. A missing/corrupt/unconfigured database degrades to
    // an inert reader (every event's country is `ZZ`), never a startup
    // failure — see `fossh_ingest::geoip`.
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
                    continue; // couldn't secure this connection — refuse it rather than risk it hanging a worker
                };
                if conn_tx.send(stream).is_err() {
                    break; // every worker panicked/exited: nothing left to hand work to
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

    /// Sends a complete, well-formed FastCGI request over `client` —
    /// the exact byte sequence a real FastCGI client (nginx included)
    /// sends for one request/response cycle.
    fn send_request(client: &mut UnixStream, params: &[(&str, &str)], body: &[u8]) {
        let mut begin_body = [0u8; 8];
        begin_body[0..2].copy_from_slice(&1u16.to_be_bytes()); // Responder
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

    /// Reads the `FCGI_STDOUT` content of one response — enough to
    /// check the `Status:` line without needing to parse the trailing
    /// `FCGI_END_REQUEST` record too.
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
        // Regression test: `ingest::decide` deliberately never handles
        // `/healthz` itself (see its own module doc) — this transport's
        // own `handle_connection` has to, and originally didn't at all,
        // which this exact test would have caught (every `/healthz`
        // request fell through to full auth and came back 401 instead).
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

    // ---- Adversarial-review regression tests (F1, F4, F5) ----

    #[test]
    fn secure_connection_sets_a_read_timeout_that_actually_fires() {
        // Real timing, not just "the setter didn't error": proves a
        // blocking read on a peer that never sends anything actually
        // returns (timed out) rather than hanging forever, which is
        // the entire point of the fix — a short duration here, not the
        // real 30s production constant, so this test stays fast.
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

    // Deliberately *not* a `#[test]`: `bind_with_correct_permissions`
    // mutates the real process-*global* umask (briefly, around one
    // `bind()` call). Proven a real hazard, not a theoretical one, when
    // this was first written as an automated `#[test]` here: it
    // intermittently failed a *different*, unrelated test
    // (`a_full_bearer_ingest_request_round_trips_and_reaches_the_writer_channel`,
    // which creates a file via `fossh_ingest::site_cache::write`
    // without setting an explicit mode of its own) whenever `cargo
    // test`'s default concurrent execution happened to overlap the
    // two — a directory created while this function's restrictive
    // `0o177` umask was briefly live came out `0600` (no execute/search
    // bit), making it untraversable for the other test's own
    // subsequent file creation inside it. `cargo test` has no built-in
    // way to force one test to run in isolation from the rest of the
    // suite without an external crate this project otherwise has no
    // need for (`serial_test`) — rather than add one for this single
    // narrow case, this is verified manually instead, the same way the
    // adversarial review that found the original F4 issue verified it
    // (a standalone repro, not a `cargo test`-embedded one). Kept here,
    // dead but compiled (`#[allow(dead_code)]`), as executable
    // documentation of exactly what "verified" means for this
    // function, rather than a prose claim with nothing backing it — run
    // it by hand (paste its body into a scratch `fn main`, or
    // temporarily restore the `#[test]` attribute and run with
    // `--test-threads=1`) after touching `bind_with_correct_permissions`.
    #[allow(dead_code)]
    fn manual_check_bind_with_correct_permissions_is_0600_and_restores_umask() {
        use std::os::unix::fs::PermissionsExt;

        let original = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
        nix::sys::stat::umask(original); // restore immediately, we only needed to read it

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
        nix::sys::stat::umask(after); // restore again immediately either way
        assert_eq!(
            after, original,
            "the process umask must be exactly what it was before bind_with_correct_permissions ran \
             — this fix must not leak a permanently-tightened umask into the rest of the process"
        );

        drop(_listener);
        std::fs::remove_file(&path).ok();
    }
}
