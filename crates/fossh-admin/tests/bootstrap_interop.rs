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

    let my_uid = nix::unistd::Uid::current().as_raw();

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

    let core_pin_on_watchdog_side = std::fs::read_to_string(&core_cert_pin_path)
        .expect("watchdog-side core cert pin file should exist after a successful handoff");
    assert_eq!(core_pin_on_watchdog_side, own_cert_pem);

    let _ = std::fs::remove_dir_all(&dir);
}
