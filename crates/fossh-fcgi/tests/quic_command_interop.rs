#![cfg(feature = "quic")]
//! Real cross-language interop check for §3.4's QUIC *command*
//! channel — the one piece `bootstrap_interop.rs` doesn't cover.
//! `crates/fossh-fcgi::quic_client` (core's real Rust client) and
//! `watchdog/quic/quic_command_server.ml` (the watchdog's real OCaml
//! server) were each built and separately tested against themselves
//! only — the OCaml side end-to-end against a real spawned process
//! (`watchdog/test/test_quic_command_server.ml`), the Rust side at
//! the wire-parsing-unit-test level (`command_client.rs`) — but had
//! never actually spoken to each other over a real socket before
//! this test.
//!
//! That gap is not hypothetical: adversarial review of this exact
//! channel (see DECISIONS.md ADR-0050) found a real, reproduced
//! interop-only bug this way (the session hello was sent on QUIC
//! stream 0, which only the *client*-initiated stream space actually
//! grants standing to open — quiche enforced this and refused the
//! server's write outright) that neither side's own same-language
//! test suite could ever have caught, structurally, since each only
//! ever validates itself. This test is what catches that class of
//! bug going forward.
//!
//! Skips (does not fail) if the OCaml binary hasn't been built in
//! this checkout, matching `bootstrap_interop.rs`'s own reasoning
//! exactly: a missing binary means "the OCaml side wasn't built
//! here," not "the interop is broken."

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn watchdog_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../watchdog/_build/default/bin/main.exe")
}

fn find_free_loopback_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral UDP port");
    socket.local_addr().expect("local_addr").port()
}

/// Shells out to the real `sha256sum` binary — the exact same tool
/// `watchdog/lib/manifest.ml`'s own `sha256_hex` uses, so this test
/// produces byte-identical manifest entries to what the real product
/// code would, not a parallel reimplementation of its hashing.
fn sha256_hex(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("failed to run sha256sum");
    assert!(output.status.success(), "sha256sum {path:?} failed");
    let stdout = String::from_utf8(output.stdout).expect("sha256sum output should be UTF-8");
    stdout[..64].to_string()
}

/// `gpg --quick-generate-key` into a fresh homedir — the real
/// `fossh-watchdog` binary's own `Keypair.ensure_keypair` will find
/// and reuse this exact key on first startup rather than generating
/// a second one (already proven by `test_keypair.ml`'s own "calling
/// ensure_keypair again on the same homedir returns the SAME
/// fingerprint" case), which is what lets this test sign a manifest
/// with the *correct* key before the watchdog process ever starts.
fn generate_watchdog_key(gnupghome: &Path) -> String {
    let status = Command::new("gpg")
        .arg("--batch")
        .arg("--homedir")
        .arg(gnupghome)
        .args([
            "--quick-generate-key",
            "fossh-watchdog-interop-test",
            "ed25519",
            "sign",
            "never",
        ])
        .status()
        .expect("failed to run gpg --quick-generate-key");
    assert!(status.success(), "gpg --quick-generate-key failed");

    let output = Command::new("gpg")
        .arg("--batch")
        .arg("--homedir")
        .arg(gnupghome)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .expect("failed to run gpg --list-secret-keys");
    assert!(output.status.success(), "gpg --list-secret-keys failed");
    let stdout = String::from_utf8(output.stdout).expect("gpg output should be UTF-8");
    // `--with-colons` fingerprint record shape: "fpr:::::::::<fingerprint>:"
    stdout
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .expect("gpg --list-secret-keys produced no fpr: line")
        .split(':')
        .nth(9)
        .expect("malformed fpr: line")
        .to_string()
}

/// `gpg --clearsign`, fed the rendered manifest body on stdin —
/// mirrors `watchdog/lib/manifest.ml`'s own `render`/`sign` exactly
/// (`"<sha256hex>  <path>\n"` per entry, then a plain `--clearsign`),
/// not a hand-rolled approximation of its wire format.
fn sign_manifest(gnupghome: &Path, fingerprint: &str, covered_paths: &[&str]) -> String {
    let body: String = covered_paths
        .iter()
        .map(|p| format!("{}  {p}\n", sha256_hex(Path::new(p))))
        .collect();

    let mut child = Command::new("gpg")
        .arg("--batch")
        .arg("--homedir")
        .arg(gnupghome)
        .args(["--local-user", fingerprint, "--clearsign"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn gpg --clearsign");
    child
        .stdin
        .take()
        .expect("gpg stdin")
        .write_all(body.as_bytes())
        .expect("write manifest body to gpg stdin");
    let output = child.wait_with_output().expect("gpg --clearsign wait");
    assert!(
        output.status.success(),
        "gpg --clearsign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("clearsigned manifest should be UTF-8")
}

#[test]
fn core_quic_client_interops_with_the_real_watchdog_command_server() {
    let binary = watchdog_binary_path();
    if !binary.exists() {
        eprintln!(
            "SKIPPED: {} not found — build the OCaml watchdog first (cd watchdog && eval $(opam env) && dune build)",
            binary.display()
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!(
        "fossh-fcgi-quic-command-interop-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let gnupghome = dir.join("gnupghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let watchdog_fingerprint = generate_watchdog_key(&gnupghome);

    // The real watchdog binary needs a real program to supervise —
    // /bin/sleep, exactly like the pure-OCaml
    // test_quic_command_server.ml uses, so a verified reload's
    // SIGTERM has something real to terminate.
    let supervised_program = "/bin/sleep";
    let manifest = sign_manifest(&gnupghome, &watchdog_fingerprint, &[supervised_program]);
    let manifest_path = dir.join("manifest.clearsigned");
    std::fs::write(&manifest_path, &manifest).unwrap();

    let watchdog_tls_dir = dir.join("watchdog-tls");
    let core_tls_dir = dir.join("core-tls");
    let core_cert_pin_path = dir.join("core-cert.pin");

    // Core's own identity, generated via the real product function —
    // not a throwaway openssl-only fixture — the same one
    // quic_client::run itself calls.
    let core_identity =
        fossh_admin::tls_identity::ensure_identity(&core_tls_dir, "fossh-svc-interop-test")
            .expect("ensure_identity for core");

    // Stands in for a completed §2.4 bootstrap handoff: that exchange
    // already has its own dedicated real cross-language test
    // (bootstrap_interop.rs) proving the handoff itself works: this
    // test starts from "the handoff already happened" so it can
    // focus on the QUIC command channel specifically, rather than
    // re-driving the whole handoff dance (which requires the
    // watchdog's own bootstrap-send subcommand as a *separate*
    // process invocation, run *after* this one is already up) just
    // to reach the part this test actually exists to check.
    let core_cert_pem = std::fs::read_to_string(&core_identity.cert_pem_path).unwrap();
    std::fs::write(&core_cert_pin_path, &core_cert_pem).unwrap();

    let port = find_free_loopback_port();
    let listen_addr = format!("127.0.0.1:{port}");

    // A new process group (`process_group(0)`), not the default of
    // inheriting this test's own: `Supervisor.spawn`'s own
    // `Unix.create_process` does a plain fork+exec with no
    // `setpgid`, so /bin/sleep (spawned *by* the watchdog, once it's
    // running) lands in the *same* group as the watchdog itself.
    // Putting the watchdog in its own fresh group here means killing
    // that whole group later (see below) reaches /bin/sleep too —
    // without this, `Child::kill()` on the watchdog alone leaves
    // /bin/sleep running as an orphan holding its inherited copy of
    // this process's stderr pipe open, and `wait_with_output()` below
    // would block for the rest of /bin/sleep's own argument (up to
    // 60s) waiting for that pipe to actually close. Reproduced
    // directly during this test's own development: exactly this hang.
    let watchdog_process = Command::new(&binary)
        .arg(supervised_program)
        .arg(&gnupghome)
        .arg(&manifest_path)
        .arg("60") // /bin/sleep's own argument: stay up long enough for this test
        .env("FOSSH_WATCHDOG_TLS_DIR", &watchdog_tls_dir)
        .env("FOSSH_CORE_CERT_PIN", &core_cert_pin_path)
        .env("FOSSH_QUIC_LISTEN_ADDR", &listen_addr)
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("failed to spawn the real fossh-watchdog binary");

    // Two independently-started processes, no ordering guarantee —
    // the watchdog needs a moment to spawn /bin/sleep, generate its
    // own TLS identity, and start listening. Retried, not a fixed
    // sleep: `send_one_reload` itself reports a plain connect/config
    // error until the watchdog's QUIC server is actually up (e.g.
    // its own cert.pem not existing yet is a real, ordinary transient
    // state here, not a bug).
    let config = fossh_fcgi::quic_client::QuicClientConfig {
        bootstrap_socket: dir.join("unused-bootstrap.sock"),
        tls_dir: core_tls_dir.clone(),
        watchdog_fingerprint_pin: dir.join("unused-fingerprint.pin"),
        watchdog_cert_pin: watchdog_tls_dir.join("cert.pem"),
        watchdog_uid: 0,
        quic_connect_addr: listen_addr.parse().expect("valid loopback address"),
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_error = String::new();
    let mut succeeded = false;
    while Instant::now() < deadline {
        match fossh_fcgi::quic_client::send_one_reload(&core_identity, &config) {
            Ok(()) => {
                succeeded = true;
                break;
            }
            Err(e) => {
                last_error = e;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    // Kill the whole process group (watchdog + its supervised
    // /bin/sleep together) — see the `process_group(0)` comment above
    // for why a plain `Child::kill()` (watchdog only) would hang this
    // test on the orphaned /bin/sleep instead.
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(-(watchdog_process.id() as i32)),
        nix::sys::signal::Signal::SIGKILL,
    );
    let watchdog_output = watchdog_process
        .wait_with_output()
        .expect("wait on the real fossh-watchdog process");

    assert!(
        succeeded,
        "core's real quic_client::send_one_reload never got a verified OK from the real \
         fossh-watchdog binary within 15s (last error: {last_error}); watchdog stderr:\n{}",
        String::from_utf8_lossy(&watchdog_output.stderr)
    );

    // The real, cross-process proof this test exists for: the
    // watchdog's own log line for a dispatched command, not just
    // this side's own belief that it got an OK reply.
    let watchdog_stderr = String::from_utf8_lossy(&watchdog_output.stderr);
    assert!(
        watchdog_stderr.contains("dispatched a verified reload command"),
        "the real watchdog process's own log never confirmed dispatching a verified reload \
         command; stderr:\n{watchdog_stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
