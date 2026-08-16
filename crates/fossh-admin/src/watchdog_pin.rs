use std::fs;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use fossh_ingest::random::read_random_bytes;

pub const MAX_FINGERPRINT_LEN: usize = 512;

pub const MAX_CERT_PEM_LEN: usize = 8192;

const CERT_PEM_END_MARKER: &str = "-----END CERTIFICATE-----";

#[derive(Debug)]
pub enum PinError {
    Io(std::io::Error),

    Random(String),

    AlreadyPinned,

    WrongPeer {
        expected_uid: u32,
        actual_uid: u32,
    },
    EmptyFingerprint,
    FingerprintTooLarge(usize),
    EmptyCertPem,
    CertPemTooLarge(usize),

    UnterminatedCertPem,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "bootstrap handoff I/O: {e}"),
            Self::Random(e) => write!(f, "bootstrap handoff: {e}"),
            Self::AlreadyPinned => write!(
                f,
                "a watchdog fingerprint is already pinned; remove it explicitly before re-bootstrapping"
            ),
            Self::WrongPeer {
                expected_uid,
                actual_uid,
            } => write!(
                f,
                "handoff connection rejected: expected uid {expected_uid}, got {actual_uid}"
            ),
            Self::EmptyFingerprint => write!(f, "handoff sent an empty fingerprint"),
            Self::FingerprintTooLarge(n) => {
                write!(
                    f,
                    "handoff fingerprint too large ({n} bytes, cap {MAX_FINGERPRINT_LEN})"
                )
            }
            Self::EmptyCertPem => write!(f, "handoff sent an empty certificate"),
            Self::CertPemTooLarge(n) => {
                write!(
                    f,
                    "handoff certificate too large ({n} bytes, cap {MAX_CERT_PEM_LEN})"
                )
            }
            Self::UnterminatedCertPem => write!(
                f,
                "handoff certificate ended before a {CERT_PEM_END_MARKER} line ever arrived"
            ),
        }
    }
}

impl std::error::Error for PinError {}

pub fn load_pin(path: &Path) -> Result<Option<String>, PinError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PinError::Io(e)),
    }
}

fn persist_pin(path: &Path, fingerprint: &str) -> Result<(), PinError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(PinError::Io)?;
    }
    let suffix_bytes = read_random_bytes(8).map_err(|e| PinError::Random(e.to_string()))?;
    let suffix: String = suffix_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let tmp_path = path.with_file_name(format!(
        "{}.tmp-{}-{suffix}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("pin"),
        std::process::id(),
    ));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(PinError::Io)?;
        file.write_all(fingerprint.as_bytes())
            .map_err(PinError::Io)?;
        file.sync_all().map_err(PinError::Io)?;
    }
    let result = fs::hard_link(&tmp_path, path);
    fs::remove_file(&tmp_path).ok();
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(PinError::AlreadyPinned),
        Err(e) => Err(PinError::Io(e)),
    }
}

fn stale_socket_is_safe_to_remove(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    match UnixStream::connect(path) {
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ),
    }
}

fn read_pem_block(reader: &mut impl std::io::BufRead, cap: usize) -> Result<String, PinError> {
    let mut collected = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(PinError::Io)?;
        if n == 0 {
            return Err(PinError::UnterminatedCertPem);
        }
        collected.push_str(&line);
        if collected.len() > cap {
            return Err(PinError::CertPemTooLarge(collected.len()));
        }
        if line.trim_end() == CERT_PEM_END_MARKER {
            return Ok(collected);
        }
    }
}

fn accept_one_handoff(
    listener: &UnixListener,
    expected_watchdog_uid: u32,
) -> Result<(UnixStream, String, String), PinError> {
    let (stream, _) = listener.accept().map_err(PinError::Io)?;

    let creds =
        getsockopt(&stream, PeerCredentials).map_err(|e| PinError::Io(std::io::Error::from(e)))?;
    let actual_uid = creds.uid();
    if actual_uid != expected_watchdog_uid {
        return Err(PinError::WrongPeer {
            expected_uid: expected_watchdog_uid,
            actual_uid,
        });
    }

    let (fingerprint, cert_pem) = {
        let mut reader = std::io::BufReader::new(&stream);

        let mut fingerprint_line = String::new();
        reader
            .by_ref()
            .take(MAX_FINGERPRINT_LEN as u64 + 1)
            .read_line(&mut fingerprint_line)
            .map_err(PinError::Io)?;
        let fingerprint = fingerprint_line.trim().to_string();
        if fingerprint.is_empty() {
            return Err(PinError::EmptyFingerprint);
        }
        if fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err(PinError::FingerprintTooLarge(fingerprint.len()));
        }

        let cert_pem = read_pem_block(&mut reader, MAX_CERT_PEM_LEN)?;
        if cert_pem.trim().is_empty() {
            return Err(PinError::EmptyCertPem);
        }

        (fingerprint, cert_pem)
    };

    Ok((stream, fingerprint, cert_pem))
}

pub struct HandoffReceived {
    pub watchdog_fingerprint: String,
    pub watchdog_cert_pem: String,
}

pub fn run_bootstrap_listener(
    socket_path: &Path,
    fingerprint_pin_path: &Path,
    cert_pin_path: &Path,
    own_cert_pem: &str,
    expected_watchdog_uid: u32,
) -> Result<HandoffReceived, PinError> {
    if load_pin(fingerprint_pin_path)?.is_some() || load_pin(cert_pin_path)?.is_some() {
        return Err(PinError::AlreadyPinned);
    }
    if stale_socket_is_safe_to_remove(socket_path) {
        let _ = fs::remove_file(socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent).map_err(PinError::Io)?;
    }
    let listener = UnixListener::bind(socket_path).map_err(PinError::Io)?;
    let result = accept_one_handoff(&listener, expected_watchdog_uid);
    drop(listener);
    let _ = fs::remove_file(socket_path);
    let (mut stream, fingerprint, cert_pem) = result?;

    persist_pin(fingerprint_pin_path, &fingerprint)?;
    persist_pin(cert_pin_path, &cert_pem)?;

    let reply = if own_cert_pem.ends_with('\n') {
        own_cert_pem.to_string()
    } else {
        format!("{own_cert_pem}\n")
    };
    stream.write_all(reply.as_bytes()).map_err(PinError::Io)?;

    Ok(HandoffReceived {
        watchdog_fingerprint: fingerprint,
        watchdog_cert_pem: cert_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-admin-watchdog-pin-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn my_uid() -> u32 {
        nix::unistd::Uid::current().as_raw()
    }

    const FAKE_WATCHDOG_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nZmFrZS13YXRjaGRvZw==\n-----END CERTIFICATE-----\n";
    const FAKE_CORE_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nZmFrZS1jb3Jl\n-----END CERTIFICATE-----\n";

    #[test]
    fn a_handoff_from_the_expected_uid_is_accepted_and_persisted_at_0600() {
        let dir = scratch_dir("happy-path");
        let socket_path = dir.join("handoff.sock");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");
        let expected_uid = my_uid();

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || -> String {

            for _ in 0..50 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {
                    s.write_all(b"AA:BB:CC:DD:EE:FF\n").unwrap();
                    s.write_all(FAKE_WATCHDOG_CERT_PEM.as_bytes()).unwrap();
                    let mut reply = String::new();
                    s.read_to_string(&mut reply).unwrap();
                    return reply;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("client never connected");
        });

        let received = run_bootstrap_listener(
            &socket_path,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            expected_uid,
        )
        .unwrap();
        let core_reply = sender.join().unwrap();

        assert_eq!(received.watchdog_fingerprint, "AA:BB:CC:DD:EE:FF");
        assert_eq!(received.watchdog_cert_pem, FAKE_WATCHDOG_CERT_PEM);
        assert_eq!(
            core_reply, FAKE_CORE_CERT_PEM,
            "watchdog must receive core's own certificate back"
        );
        assert_eq!(
            load_pin(&fpr_pin_path).unwrap().as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            load_pin(&cert_pin_path).unwrap().as_deref(),
            Some(FAKE_WATCHDOG_CERT_PEM)
        );
        for path in [&fpr_pin_path, &cert_pin_path] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{path:?} must be 0600");
        }
        assert!(
            !socket_path.exists(),
            "one-shot socket must not linger after success"
        );
    }

    #[test]
    fn a_handoff_from_the_wrong_uid_is_rejected_and_nothing_is_pinned() {
        let dir = scratch_dir("wrong-uid");
        let socket_path = dir.join("handoff.sock");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");

        let wrong_expected_uid = my_uid().wrapping_add(999_999);

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || {

            for _ in 0..200 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {

                    match s.write_all(b"should-never-be-pinned\n") {
                        Ok(()) => {}
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionReset
                            ) => {}
                        Err(e) => panic!("client write failed unexpectedly: {e}"),
                    }
                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("client never connected");
        });

        let result = run_bootstrap_listener(
            &socket_path,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            wrong_expected_uid,
        );
        sender.join().unwrap();

        assert!(matches!(result, Err(PinError::WrongPeer { .. })));
        assert_eq!(
            load_pin(&fpr_pin_path).unwrap(),
            None,
            "a rejected peer must never get pinned"
        );
        assert_eq!(load_pin(&cert_pin_path).unwrap(), None);
    }

    #[test]
    fn a_second_handoff_attempt_is_refused_once_a_pin_already_exists() {
        let dir = scratch_dir("no-silent-rotation");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");
        persist_pin(&fpr_pin_path, "already-pinned-fingerprint").unwrap();

        let unreachable_socket = dir.join("does/not/exist/handoff.sock");
        let result = run_bootstrap_listener(
            &unreachable_socket,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            my_uid(),
        );
        assert!(matches!(result, Err(PinError::AlreadyPinned)));
    }

    #[test]
    fn persist_pin_refuses_to_overwrite_an_existing_pin() {
        let dir = scratch_dir("persist-refuses-overwrite");
        let pin_path = dir.join("watchdog.pin");
        persist_pin(&pin_path, "first").unwrap();
        let result = persist_pin(&pin_path, "second");
        assert!(matches!(result, Err(PinError::AlreadyPinned)));
        assert_eq!(load_pin(&pin_path).unwrap().as_deref(), Some("first"));
    }

    #[test]
    fn load_pin_of_a_missing_file_is_none_not_an_error() {
        let dir = scratch_dir("missing-is-none");
        let pin_path = dir.join("does-not-exist.pin");
        assert_eq!(load_pin(&pin_path).unwrap(), None);
    }

    #[test]
    fn concurrent_persist_pin_racers_for_the_same_path_all_get_a_clean_verdict() {

        for attempt in 0..20 {
            let dir = scratch_dir(&format!("persist-race-{attempt}"));
            let path = dir.join("watchdog.pin");
            const RACERS: usize = 8;
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(RACERS));
            let handles: Vec<_> = (0..RACERS)
                .map(|i| {
                    let path = path.clone();
                    let barrier = std::sync::Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        persist_pin(&path, &format!("racer-{i}"))
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let ok_count = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(
                ok_count, 1,
                "exactly one racer must win and persist (attempt {attempt})"
            );
            for r in &results {
                if let Err(e) = r {
                    assert!(
                        matches!(e, PinError::AlreadyPinned),
                        "every losing racer must get a clean AlreadyPinned verdict, \
                         not {e:?} (attempt {attempt})"
                    );
                }
            }
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn an_oversized_fingerprint_is_rejected() {
        let dir = scratch_dir("oversized");
        let socket_path = dir.join("handoff.sock");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");
        let expected_uid = my_uid();

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || {
            for _ in 0..50 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {
                    let oversized = "a".repeat(MAX_FINGERPRINT_LEN + 100);

                    let _ = s.write_all(format!("{oversized}\n").as_bytes());
                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("client never connected");
        });

        let result = run_bootstrap_listener(
            &socket_path,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            expected_uid,
        );
        sender.join().unwrap();
        assert!(matches!(result, Err(PinError::FingerprintTooLarge(_))));
        assert_eq!(load_pin(&fpr_pin_path).unwrap(), None);
    }

    #[test]
    fn an_oversized_certificate_is_rejected() {
        let dir = scratch_dir("oversized-cert");
        let socket_path = dir.join("handoff.sock");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");
        let expected_uid = my_uid();

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || {
            for _ in 0..50 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {
                    s.write_all(b"AA:BB:CC:DD:EE:FF\n").unwrap();

                    let _ = s.write_all(b"-----BEGIN CERTIFICATE-----\n");
                    let filler = "a".repeat(MAX_CERT_PEM_LEN + 100);
                    let _ = s.write_all(filler.as_bytes());
                    let _ = s.write_all(b"\n-----END CERTIFICATE-----\n");
                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("client never connected");
        });

        let result = run_bootstrap_listener(
            &socket_path,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            expected_uid,
        );
        let _ = sender.join();
        assert!(matches!(result, Err(PinError::CertPemTooLarge(_))));
        assert_eq!(load_pin(&fpr_pin_path).unwrap(), None);
        assert_eq!(load_pin(&cert_pin_path).unwrap(), None);
    }

    #[test]
    fn a_certificate_with_no_end_marker_is_rejected_not_hung_on() {
        let dir = scratch_dir("unterminated-cert");
        let socket_path = dir.join("handoff.sock");
        let fpr_pin_path = dir.join("watchdog.pin");
        let cert_pin_path = dir.join("watchdog-cert.pin");
        let expected_uid = my_uid();

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || {
            for _ in 0..50 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {
                    s.write_all(b"AA:BB:CC:DD:EE:FF\n").unwrap();
                    s.write_all(b"-----BEGIN CERTIFICATE-----\nbm90IGEgcmVhbCBjZXJ0\n")
                        .unwrap();

                    return;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("client never connected");
        });

        let result = run_bootstrap_listener(
            &socket_path,
            &fpr_pin_path,
            &cert_pin_path,
            FAKE_CORE_CERT_PEM,
            expected_uid,
        );
        sender.join().unwrap();
        assert!(matches!(result, Err(PinError::UnterminatedCertPem)));
        assert_eq!(load_pin(&fpr_pin_path).unwrap(), None);
    }

    #[test]
    fn stale_socket_from_a_dead_listener_is_detected_as_safe_to_remove() {
        let dir = scratch_dir("stale-detect");
        let socket_path = dir.join("handoff.sock");
        {

            let _listener = UnixListener::bind(&socket_path).unwrap();
        }
        assert!(socket_path.exists());

        let mut became_safe = false;
        for _ in 0..50 {
            if stale_socket_is_safe_to_remove(&socket_path) {
                became_safe = true;
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            became_safe,
            "a socket with no listener must eventually be detected as safe to remove"
        );
    }

    #[test]
    fn a_live_socket_is_not_reported_as_safe_to_remove() {
        let dir = scratch_dir("live-detect");
        let socket_path = dir.join("handoff.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        assert!(!stale_socket_is_safe_to_remove(&socket_path));
    }
}
