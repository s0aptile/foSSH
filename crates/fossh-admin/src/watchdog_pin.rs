//! §2.4: the one-time bootstrap handoff. `fossh-watchdog` generates a
//! fresh per-install OpenPGP keypair on first start (its own concern,
//! not this module's — used for tamper-detection manifest signing,
//! §3.3) and hands its fingerprint to foSSH core exactly once, over a
//! local Unix domain socket — not QUIC, which §3.4 scopes to
//! steady-state IPC only, after this handoff has already pinned both
//! sides. This module is core's (`fossh-svc`'s) half: listen, verify
//! the connecting peer is really the watchdog (not just "some local
//! process that found the socket path"), and persist what it sends so
//! none of it can ever be silently replaced.
//!
//! **Extended beyond the original OpenPGP-fingerprint-only exchange**
//! (see ADR-0048/ADR-0050): §3.4 requires the QUIC channel's mTLS to
//! be verified in *both* directions, which needs each side to hold
//! the other's actual X.509 certificate content — the OpenPGP
//! fingerprint alone was never enough for that (wrong key, wrong
//! format; quiche/BoringSSL needs a real PEM certificate to load as a
//! trust anchor, not a hash of one). The wire exchange is now:
//! watchdog sends its OpenPGP fingerprint (one line, unchanged), then
//! its X.509 certificate (a PEM block, terminated by its own
//! `-----END CERTIFICATE-----` line — an unambiguous delimiter PEM
//! already defines, not a new framing convention invented here); core
//! verifies the peer via `SO_PEERCRED` exactly as before, persists
//! both, and — new — writes *its own* X.509 certificate back over the
//! same, already-established, already-peer-verified connection before
//! it closes. Still a single Unix-domain-socket round trip, not a
//! new transport.
//!
//! "Regeneration requires a full re-bootstrap handoff, not a silent
//! rotation" (§2.4) is enforced at the one point that actually
//! matters: [`persist_pin`]'s `create_new` open refuses outright if a
//! pin already exists, no matter how many handoff attempts run
//! concurrently or how many times this function is called. An
//! operator must explicitly remove the existing pin file(s) before a
//! new handoff can succeed at all — this module never does that
//! itself. One accepted asymmetry worth stating plainly: this
//! module's own two `persist_pin` calls (fingerprint, then watchdog
//! cert) happen *before* it writes its own reply back, so if that
//! reply write itself fails (the connection dropped a moment early,
//! say), the watchdog's data is still durably pinned on core's side
//! even though the watchdog never received core's half — and because
//! a pin already exists, a retried handoff would then be refused as
//! `AlreadyPinned`, the same manual-recovery situation an operator
//! already has to handle for *any* interrupted handoff, not a new
//! failure mode this extension introduces on its own.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use fossh_ingest::random::read_random_bytes;

/// Real OpenPGP fingerprints are well under this; generous enough to
/// never legitimately reject one, tight enough that a confused or
/// hostile peer can't make this read arbitrarily long.
pub const MAX_FINGERPRINT_LEN: usize = 512;

/// A real EC P-256 self-signed certificate (this project's own shape
/// — ADR-0044/ADR-0048/ADR-0049) PEM-encodes to a few hundred bytes;
/// 8 KiB is generous headroom for a certificate with a longer subject
/// or an unexpectedly large key, while still bounding how much a
/// confused or hostile peer can make this read looking for a
/// terminator line that never arrives.
pub const MAX_CERT_PEM_LEN: usize = 8192;

const CERT_PEM_END_MARKER: &str = "-----END CERTIFICATE-----";

#[derive(Debug)]
pub enum PinError {
    Io(std::io::Error),
    /// Failed to source randomness for a temp filename — see
    /// `persist_pin`'s own doc comment for why that randomness is
    /// load-bearing, not decorative.
    Random(String),
    /// A pin already exists at the target path — see this module's
    /// own header comment. The caller must not remove it automatically;
    /// that is deliberately an operator action, not a code path.
    AlreadyPinned,
    /// The peer that connected was not the expected watchdog process,
    /// per `SO_PEERCRED`'s real (kernel-reported, unspoofable-by-the-
    /// peer) UID — not just "connected to the right socket path".
    WrongPeer {
        expected_uid: u32,
        actual_uid: u32,
    },
    EmptyFingerprint,
    FingerprintTooLarge(usize),
    EmptyCertPem,
    CertPemTooLarge(usize),
    /// The peer's cert data stopped (EOF) before a
    /// `-----END CERTIFICATE-----` line ever arrived — a truncated or
    /// malformed send, not a merely-oversized one (see
    /// `CertPemTooLarge` for that case).
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

/// The pinned fingerprint, if a handoff has already completed —
/// `None` means "not yet bootstrapped", not an error.
pub fn load_pin(path: &Path) -> Result<Option<String>, PinError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PinError::Io(e)),
    }
}

/// Temp file + hard-link into place, matching `data_key.rs`'s own
/// established pattern for this project — except here, unlike
/// `data_key`'s "concurrent first callers all converge on the same
/// value" shape, `AlreadyExists` on the final `hard_link` is exactly
/// the desired outcome (refuse, don't overwrite), not something to
/// fall back past by reading the existing file instead.
///
/// The temp filename folds in a fresh random suffix, not
/// `std::process::id()` alone — the same `Unix.getpid()`-only-temp-
/// path bug class this project's OCaml sibling module found and fixed
/// at the source in `operator_key.ml` (a real, reproduced corruption
/// under a forced-overlap thread race, PID alone being unique per
/// *process*, not per *call*), and separately flagged but left
/// unfixed in `core_pin.ml`. This function has the identical
/// structural gap: two threads inside one process racing to persist
/// the *same* path previously computed the exact same PID-only temp
/// path, so the losing racer's own `create_new` failed with
/// `AlreadyExists` on that shared temp file — mapped straight to a
/// generic `PinError::Io`, not the documented `PinError::AlreadyPinned`
/// this module's header comment promises "no matter how many handoff
/// attempts run concurrently." Reproduced directly (100% of forced-
/// overlap runs, not intermittent — see this module's own regression
/// test) before this fix, matching `data_key::write_via_temp_then_link`'s
/// existing "random, not the PID/thread ID alone" reasoning exactly.
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

/// A stale socket path from a previous, incomplete handoff attempt is
/// safe to remove and rebind; a socket a *live* listener still holds
/// is not — unlinking that out from under it would let a second,
/// concurrent bind silently steal the path mid-handoff. Same class of
/// bug, same fix shape, as `fossh-fcgi`'s own `socket_is_live` (ADR-0036,
/// finding F4): attempt a real connect first, and only treat a
/// connection *refusal* (nobody home) as "safe to remove", not bare
/// file existence.
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

/// Reads lines from `reader` until one trims to exactly
/// `CERT_PEM_END_MARKER`, returning everything read (including that
/// final line). PEM's own `-----BEGIN`/`-----END` delimiters are used
/// as-is as the framing — an unambiguous, already-standard marker,
/// not a new convention invented for this wire protocol. Bounded by
/// `cap`: an oversized block (checked after every line, not only at
/// the end, so one pathologically long single line without its own
/// newline can't read unboundedly either) is `CertPemTooLarge`; EOF
/// before the marker ever appears is `UnterminatedCertPem` — a
/// distinct, more specific error than a generic I/O failure, since a
/// peer that simply stopped sending mid-certificate is a real,
/// expected-to-happen malformed-input case, not a system error.
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

    // Scoped so the BufReader (which only borrows `stream`) is
    // dropped before `stream` itself needs to move into the returned
    // tuple. Any bytes it may have buffered ahead of what these two
    // reads actually consumed are safe to drop with it: the protocol
    // has core reading nothing further from the watchdog after this
    // point, only writing its own reply — see this module's own
    // header comment for the full exchange shape.
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

/// Core's (`fossh-svc`'s) side of the handoff: bind `socket_path`,
/// accept exactly one connection, verify it's really the watchdog via
/// `SO_PEERCRED`, read its OpenPGP fingerprint and X.509 certificate,
/// pin both, and write `own_cert_pem` back over the same connection
/// before it closes. Refuses before ever binding if either pin
/// already exists, and refuses at the final, race-safe persists
/// either way — see this module's own header comment for why
/// regeneration is never silent, and for the one accepted asymmetry
/// (both pins land before the reply is sent, not atomically with it).
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
    let _ = fs::remove_file(socket_path); // one-shot; don't linger listening after either outcome
    let (mut stream, fingerprint, cert_pem) = result?;

    persist_pin(fingerprint_pin_path, &fingerprint)?;
    persist_pin(cert_pin_path, &cert_pem)?;

    // `own_cert_pem` is this same process's own, locally-generated
    // certificate (from `Tls_identity`/`tls_identity::ensure_identity`
    // on whichever side calls this), not peer-controlled input — no
    // length/emptiness validation needed here the way the watchdog's
    // own data got above; only a trailing-newline normalization so
    // the reader on the other end reliably sees the same
    // one-line-per-`read_line` framing this module's own read side
    // depends on.
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
            // Real client-side connect races the listener's bind — a
            // handful of short retries is standard practice for this,
            // not a design smell.
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
        // A real connection, from this same test process — but the
        // listener is told to expect a UID that isn't this process's
        // real one, so SO_PEERCRED's own kernel-reported value must
        // be what causes the rejection, not a bogus/spoofed claim.
        let wrong_expected_uid = my_uid().wrapping_add(999_999);

        let socket_path2 = socket_path.clone();
        let sender = thread::spawn(move || {
            // 200 tries at 10ms (2s total), not the original 50
            // (500ms): confirmed flaky under real load, not
            // theoretically — this crate's own test suite now
            // includes several real, CPU-heavy `openssl` subprocess
            // tests (`tls_identity`) that can legitimately delay this
            // thread's own scheduling past 500ms when run in
            // parallel with them, and a slow scheduler handoff here
            // is not the thing this test exists to check.
            for _ in 0..200 {
                if let Ok(mut s) = UnixStream::connect(&socket_path2) {
                    // A second, distinct race from the connect-retry
                    // one above, also confirmed for real (not just
                    // theorized): once connected, the listener checks
                    // SO_PEERCRED and, on a mismatch, returns
                    // immediately without ever reading — dropping its
                    // side of the stream and closing it. If that
                    // rejection-and-close completes before this write
                    // reaches the kernel (plausible any time, more so
                    // under the same real system load discussed
                    // above), this write legitimately fails with
                    // BrokenPipe/ConnectionReset — which is not a test
                    // failure, it is direct evidence the server
                    // rejected this connection *promptly*, exactly
                    // what this test exists to confirm. Only a write
                    // that fails for some *other* reason indicates an
                    // actual problem.
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

        // Refused before ever touching a socket at all — confirmed by
        // passing a socket path whose parent directory doesn't exist,
        // which would itself error if this function tried to bind.
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
        // Regression test for the same `Unix.getpid()`-only-temp-path
        // bug class this project's OCaml sibling module found and
        // fixed at the source in `operator_key.ml`, and separately
        // flagged (but explicitly left, as out of scope for that pass)
        // in `core_pin.ml` -- see DECISIONS.md's discussion of the
        // `Unix.getpid()` collision. `persist_pin`'s temp filename was
        // built from `std::process::id()` alone: unique per *process*,
        // not per *call*. Every thread inside one process racing to
        // persist the *same* destination path computes the exact same
        // temp path, so `OpenOptions::create_new`'s kernel-level
        // atomicity means at most one racer can ever even begin
        // writing -- every other racer's own `create_new` on that
        // shared temp path fails with `AlreadyExists` before it ever
        // touches the real destination, and the pre-fix code mapped
        // that straight to a generic `PinError::Io`, not the
        // documented, caller-facing `PinError::AlreadyPinned` this
        // module's own header comment promises regardless of "how many
        // handoff attempts run concurrently." A perfectly ordinary
        // concurrent-first-caller race would surface as an opaque I/O
        // failure indistinguishable from a real disk problem, exactly
        // the same "no such promise documented, but a future caller
        // would inherit the gap silently" shape the OCaml finding
        // described. A `Barrier` forces genuinely simultaneous calls
        // (not sleep-staggered ones), matching this project's own
        // countdown-latch pattern for the identical class of race.
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
                    // A real, well-formed newline still has to follow —
                    // otherwise this would also trip the *unterminated*
                    // path (EOF before any newline) rather than
                    // specifically testing the size cap on its own.
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
                    // A real BEGIN line, then a huge body with no END
                    // marker anywhere in the first MAX_CERT_PEM_LEN
                    // bytes -- must trip the size cap specifically,
                    // not the separate "EOF with no marker" case.
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
                    // Deliberately no END marker, then a normal close
                    // (drop) rather than an infinite/hanging send --
                    // this must surface as UnterminatedCertPem, not
                    // block the listener forever.
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
            // Bind and immediately drop -- the path exists on disk but
            // nothing is listening on it anymore, exactly the "stale
            // from a crashed prior attempt" case this guards against.
            let _listener = UnixListener::bind(&socket_path).unwrap();
        }
        assert!(socket_path.exists());
        // Retried, not a single immediate check: confirmed flaky under
        // real, heavy parallel system load (this crate's test suite
        // now includes several CPU-heavy real-`openssl`-subprocess
        // tests running concurrently by default) — reproduced directly
        // with full output: `stale_socket_is_safe_to_remove` observed
        // `false` immediately after the listener's own fd was closed.
        // That is not a correctness gap in the function under test
        // (an immediate `connect()` racing the kernel's own listen-
        // state teardown is not something this project's threat model
        // needs to be instantaneous), and every other place this
        // project polls for an expected-but-not-guaranteed-instant
        // state change already retries rather than checking once (e.g.
        // `Bootstrap.send_fingerprint_with_retry`) — this test should
        // hold itself to the same standard rather than assuming
        // synchronous teardown under load conditions it doesn't
        // control.
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
