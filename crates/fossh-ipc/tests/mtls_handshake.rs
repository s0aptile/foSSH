use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

use fossh_ipc::TlsPaths;

struct GeneratedCert {
    dir: std::path::PathBuf,
    cert_pem: std::path::PathBuf,
    key_pem: std::path::PathBuf,
}

impl Drop for GeneratedCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn generate_self_signed_cert(common_name: &str) -> GeneratedCert {
    let dir = std::env::temp_dir().join(format!(
        "fossh-ipc-test-cert-{common_name}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_pem = dir.join("cert.pem");
    let key_pem = dir.join("key.pem");

    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-days",
            "1",
            "-nodes",
            "-keyout",
        ])
        .arg(&key_pem)
        .arg("-out")
        .arg(&cert_pem)
        .args(["-subj", &format!("/CN={common_name}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to run openssl");
    assert!(status.success(), "openssl req failed for {common_name}");

    GeneratedCert {
        dir,
        cert_pem,
        key_pem,
    }
}

fn find_free_loopback_port() -> u16 {

    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

#[test]
fn a_real_mtls_quic_handshake_completes_and_a_stream_round_trips() {
    let _ = env_logger::builder().is_test(true).try_init();
    let watchdog_cert = generate_self_signed_cert("fossh-watchdog-test");
    let core_cert = generate_self_signed_cert("fossh-core-test");

    let watchdog_cert_str = watchdog_cert.cert_pem.to_str().unwrap().to_string();
    let core_cert_str = core_cert.cert_pem.to_str().unwrap().to_string();
    let core_key_str = core_cert.key_pem.to_str().unwrap().to_string();

    let port = find_free_loopback_port();
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let core_thread = std::thread::spawn(move || {
        let tls = TlsPaths {
            cert_chain_pem: &core_cert_str,
            priv_key_pem: &core_key_str,
            trusted_peer_cert_pem: &watchdog_cert_str,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut conn, socket) =
            fossh_ipc::accept_one(listen_addr, &tls, deadline).expect("accept_one failed");
        assert!(conn.is_established());

        let peer_cert_der = conn.peer_cert().expect("server should see the client cert");
        assert!(!peer_cert_der.is_empty());

        let (msg, fin) = fossh_ipc::recv_from_stream(&mut conn, &socket, 4, deadline)
            .expect("recv_from_stream failed");
        assert_eq!(msg, b"hello from watchdog");
        assert!(fin);

        fossh_ipc::send_on_stream(&mut conn, &socket, 4, b"hello from core", true, deadline)
            .expect("send_on_stream failed");
    });

    let tls = TlsPaths {
        cert_chain_pem: watchdog_cert.cert_pem.to_str().unwrap(),
        priv_key_pem: watchdog_cert.key_pem.to_str().unwrap(),
        trusted_peer_cert_pem: core_cert.cert_pem.to_str().unwrap(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut conn, socket) =
        fossh_ipc::connect(listen_addr, &tls, deadline).expect("connect failed");
    assert!(conn.is_established());

    let peer_cert_der = conn.peer_cert().expect("client should see the server cert");
    assert!(!peer_cert_der.is_empty());

    fossh_ipc::send_on_stream(
        &mut conn,
        &socket,
        4,
        b"hello from watchdog",
        true,
        deadline,
    )
    .expect("send_on_stream failed");

    let (msg, fin) = fossh_ipc::recv_from_stream(&mut conn, &socket, 4, deadline)
        .expect("recv_from_stream failed");
    assert_eq!(msg, b"hello from core");
    assert!(fin);

    core_thread.join().unwrap();
}

#[test]
fn a_client_presenting_the_wrong_certificate_is_rejected() {
    let _ = env_logger::builder().is_test(true).try_init();
    let watchdog_cert = generate_self_signed_cert("fossh-watchdog-wrongcert");
    let core_cert = generate_self_signed_cert("fossh-core-wrongcert");

    let impostor_cert = generate_self_signed_cert("impostor");

    let core_cert_str = core_cert.cert_pem.to_str().unwrap().to_string();
    let core_key_str = core_cert.key_pem.to_str().unwrap().to_string();
    let watchdog_cert_str = watchdog_cert.cert_pem.to_str().unwrap().to_string();

    let port = find_free_loopback_port();
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let core_thread = std::thread::spawn(move || {
        let tls = TlsPaths {
            cert_chain_pem: &core_cert_str,
            priv_key_pem: &core_key_str,

            trusted_peer_cert_pem: &watchdog_cert_str,
        };
        let deadline = Instant::now() + Duration::from_secs(3);

        let result = fossh_ipc::accept_one(listen_addr, &tls, deadline);
        match result {
            Err(_) => {}
            Ok((conn, _)) => panic!(
                "accept_one must not establish a connection with an untrusted client cert, \
                 established={}",
                conn.is_established()
            ),
        }
    });

    let tls = TlsPaths {
        cert_chain_pem: impostor_cert.cert_pem.to_str().unwrap(),
        priv_key_pem: impostor_cert.key_pem.to_str().unwrap(),
        trusted_peer_cert_pem: core_cert.cert_pem.to_str().unwrap(),
    };
    let deadline = Instant::now() + Duration::from_secs(3);

    let result = fossh_ipc::connect(listen_addr, &tls, deadline);
    if let Ok((mut conn, socket)) = result {

        let _ = fossh_ipc::send_on_stream(
            &mut conn,
            &socket,
            4,
            b"should never arrive",
            true,
            deadline,
        );
        let recv_result = fossh_ipc::recv_from_stream(&mut conn, &socket, 4, deadline);
        assert!(
            recv_result.is_err() || conn.is_closed(),
            "a connection using an untrusted client cert must not remain usable: \
             recv_result={recv_result:?}, is_closed={}",
            conn.is_closed()
        );
    }

    core_thread.join().unwrap();
}
