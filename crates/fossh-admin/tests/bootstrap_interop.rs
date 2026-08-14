//! §2.4 real cross-language interop check: the Rust listener
//! (`fossh_admin::watchdog_pin`) and the OCaml sender
//! (`watchdog/lib/bootstrap.ml`, exercised through the real compiled
//! `fossh-watchdog bootstrap-send` binary) were built and unit-tested
//! independently, each against its own understanding of the wire
//! protocol. This test is the one place that actually runs both real
//! implementations against each other, over a real Unix domain
//! socket — the only way to catch a protocol mismatch neither side's
//! own tests could ever see, since each side's tests only ever talk
//! to itself.
//!
//! Skips (does not fail) if the OCaml binary hasn't been built in
//! this checkout — `watchdog/` is a separate dune project with its
//! own opam switch, built by a completely different toolchain
//! (`dune build`, not `cargo build`), and `cargo test` has no way to
//! build it as a side effect. A missing binary here means "the OCaml
//! side wasn't built in this environment", not "the interop is
//! broken" — those are different failures and this test only speaks
//! to the second one.
//!
//! Extended (see ADR-0048/ADR-0050) to exercise the full bidirectional
//! exchange: the OCaml binary now also sends a real X.509 certificate
//! PEM and expects one back over the same connection.

use std::path::PathBuf;
use std::process::Command;
use std::thread;

fn watchdog_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../watchdog/_build/default/bin/main.exe")
}

#[test]
fn ocaml_bootstrap_send_interops_with_the_real_rust_listener() {
    let binary = watchdog_binary_path();
    if !binary.exists() {
        eprintln!(
            "SKIPPED: {} not found — build the OCaml watchdog first (cd watchdog && eval $(opam env) && dune build)",
            binary.display()
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!(
        "fossh-admin-bootstrap-interop-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket_path = dir.join("handoff.sock");
    let fingerprint_pin_path = dir.join("watchdog-fingerprint.pin");
    let cert_pin_path = dir.join("watchdog-cert.pin");
    let gnupghome = dir.join("gnupghome");
    let tls_dir = dir.join("tls");
    let core_cert_pin_path = dir.join("core-cert.pin");
    std::fs::create_dir_all(&gnupghome).unwrap();

    // The real OCaml binary runs as a child of *this* process, so it
    // shares this test's real UID — SO_PEERCRED on the Rust side sees
    // the actual kernel-reported credential of a genuinely separate
    // process, not a same-process stand-in.
    let my_uid = nix::unistd::Uid::current().as_raw();

    // Core's own certificate for this test — same shape a real
    // `fossh-svc` would generate via `fossh_admin::tls_identity`, but
    // this test only needs its bytes to arrive back at the OCaml side
    // unmodified, not a real certificate a TLS stack would accept.
    let own_cert_pem = "-----BEGIN CERTIFICATE-----\nZmFrZS1jb3Jl\n-----END CERTIFICATE-----\n";

    let socket_path_for_listener = socket_path.clone();
    let fingerprint_pin_path_for_listener = fingerprint_pin_path.clone();
    let cert_pin_path_for_listener = cert_pin_path.clone();
    let listener = thread::spawn(move || {
        fossh_admin::watchdog_pin::run_bootstrap_listener(
            &socket_path_for_listener,
            &fingerprint_pin_path_for_listener,
            &cert_pin_path_for_listener,
            own_cert_pem,
            my_uid,
        )
    });

    // The OCaml side's own retry loop handles the listener not being
    // bound yet — no artificial delay needed here. `bootstrap-send`
    // derives its own fingerprint (from `gnupghome`) and its own
    // X.509 identity (under `tls_dir`) rather than taking either as a
    // literal argument — see ADR-0048/ADR-0050 and watchdog/bin/main.ml's
    // own header comment for why a caller-supplied fingerprint was
    // dropped as a footgun. It prints that derived fingerprint to
    // stdout on success, the one piece of this handoff this test has
    // no other way to learn.
    // `main.exe` is dynamically linked against `libquiche.so.0` (§3.4's
    // OCaml/ctypes QUIC channel), which lives in this vendor directory
    // in a dev checkout; on an installed target it is `/usr/lib64/fossh/`
    // registered with `ldconfig`, which a checkout is not. Without this
    // the binary dies in the dynamic linker before its `main` ever runs,
    // and this test fails with a bare non-zero exit that has nothing to
    // do with the bootstrap protocol it exists to exercise. The two
    // interop tests in `fossh-agent` already did this; this one was
    // simply missed, and had been failing for exactly that reason.
    let quic_vendor_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../watchdog/quic/vendor");

    let output = Command::new(&binary)
        .arg("bootstrap-send")
        .arg(&socket_path)
        .arg(&gnupghome)
        .arg(&tls_dir)
        .arg(&core_cert_pin_path)
        .env("LD_LIBRARY_PATH", &quic_vendor_dir)
        .output()
        .expect("failed to run the real fossh-watchdog binary");
    assert!(
        output.status.success(),
        "fossh-watchdog bootstrap-send exited non-zero: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let sent_fingerprint = String::from_utf8(output.stdout)
        .expect("bootstrap-send stdout should be valid UTF-8")
        .trim()
        .to_string();
    assert!(
        !sent_fingerprint.is_empty(),
        "bootstrap-send should have printed its derived fingerprint"
    );

    let received = listener
        .join()
        .expect("listener thread panicked")
        .expect("run_bootstrap_listener returned an error");
    assert_eq!(received.watchdog_fingerprint, sent_fingerprint);

    let pinned_fingerprint = fossh_admin::watchdog_pin::load_pin(&fingerprint_pin_path)
        .unwrap()
        .expect("fingerprint pin file should exist after a successful handoff");
    assert_eq!(pinned_fingerprint, sent_fingerprint);

    let pinned_cert = fossh_admin::watchdog_pin::load_pin(&cert_pin_path)
        .unwrap()
        .expect("cert pin file should exist after a successful handoff");
    assert_eq!(pinned_cert, received.watchdog_cert_pem);
    assert!(pinned_cert.contains("-----BEGIN CERTIFICATE-----"));

    // The reply direction: core's own certificate, sent back over the
    // same connection, should have landed in the OCaml side's own
    // pin file exactly as core sent it.
    let core_pin_on_watchdog_side = std::fs::read_to_string(&core_cert_pin_path)
        .expect("watchdog-side core cert pin file should exist after a successful handoff");
    assert_eq!(core_pin_on_watchdog_side, own_cert_pem);

    let _ = std::fs::remove_dir_all(&dir);
}
