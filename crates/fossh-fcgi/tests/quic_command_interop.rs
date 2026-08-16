#![cfg(feature = "quic")]

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

fn sha256_hex(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("failed to run sha256sum");
    assert!(output.status.success(), "sha256sum {path:?} failed");
    let stdout = String::from_utf8(output.stdout).expect("sha256sum output should be UTF-8");
    stdout[..64].to_string()
}

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

    stdout
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .expect("gpg --list-secret-keys produced no fpr: line")
        .split(':')
        .nth(9)
        .expect("malformed fpr: line")
        .to_string()
}

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

    let supervised_program = "/bin/sleep";
    let manifest = sign_manifest(&gnupghome, &watchdog_fingerprint, &[supervised_program]);
    let manifest_path = dir.join("manifest.clearsigned");
    std::fs::write(&manifest_path, &manifest).unwrap();

    let watchdog_tls_dir = dir.join("watchdog-tls");
    let core_tls_dir = dir.join("core-tls");
    let core_cert_pin_path = dir.join("core-cert.pin");

    let core_identity =
        fossh_admin::tls_identity::ensure_identity(&core_tls_dir, "fossh-svc-interop-test")
            .expect("ensure_identity for core");

    let core_cert_pem = std::fs::read_to_string(&core_identity.cert_pem_path).unwrap();
    std::fs::write(&core_cert_pin_path, &core_cert_pem).unwrap();

    let port = find_free_loopback_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let watchdog_process = Command::new(&binary)
        .arg(supervised_program)
        .arg(&gnupghome)
        .arg(&manifest_path)
        .arg("60")
        .env("FOSSH_WATCHDOG_TLS_DIR", &watchdog_tls_dir)
        .env("FOSSH_CORE_CERT_PIN", &core_cert_pin_path)
        .env("FOSSH_QUIC_LISTEN_ADDR", &listen_addr)
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("failed to spawn the real fossh-watchdog binary");

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

    let watchdog_stderr = String::from_utf8_lossy(&watchdog_output.stderr);
    assert!(
        watchdog_stderr.contains("dispatched a verified reload command"),
        "the real watchdog process's own log never confirmed dispatching a verified reload \
         command; stderr:\n{watchdog_stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
