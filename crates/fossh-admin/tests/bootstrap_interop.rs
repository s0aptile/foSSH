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
    let pin_path = dir.join("watchdog.pin");

    // The real OCaml binary runs as a child of *this* process, so it
    // shares this test's real UID — SO_PEERCRED on the Rust side sees
    // the actual kernel-reported credential of a genuinely separate
    // process, not a same-process stand-in.
    let my_uid = nix::unistd::Uid::current().as_raw();

    let socket_path_for_listener = socket_path.clone();
    let pin_path_for_listener = pin_path.clone();
    let listener = thread::spawn(move || {
        fossh_admin::watchdog_pin::run_bootstrap_listener(
            &socket_path_for_listener,
            &pin_path_for_listener,
            my_uid,
        )
    });

    // The OCaml side's own retry loop handles the listener not being
    // bound yet — no artificial delay needed here.
    let status = Command::new(&binary)
        .arg("bootstrap-send")
        .arg(&socket_path)
        .arg("AA:BB:CC:DD:EE:FF:00:11:22:33")
        .status()
        .expect("failed to run the real fossh-watchdog binary");
    assert!(
        status.success(),
        "fossh-watchdog bootstrap-send exited non-zero: {status:?}"
    );

    let fingerprint = listener
        .join()
        .expect("listener thread panicked")
        .expect("run_bootstrap_listener returned an error");
    assert_eq!(fingerprint, "AA:BB:CC:DD:EE:FF:00:11:22:33");

    let pinned = fossh_admin::watchdog_pin::load_pin(&pin_path)
        .unwrap()
        .expect("pin file should exist after a successful handoff");
    assert_eq!(pinned, "AA:BB:CC:DD:EE:FF:00:11:22:33");

    let _ = std::fs::remove_dir_all(&dir);
}
