open Fossh_watchdog_lib
open Fossh_watchdog_quic
open Test_helpers

let read_file (path : string) : string = Fileutil.read_all_bytes path

let () =
  let dir_a = mkdtemp () in
  let dir_b = mkdtemp () in
  let dir_corrupt = mkdtemp () in
  let dir_partial = mkdtemp () in

  (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"fossh-watchdog-test-a" with
  | Error e -> check ("ensure_identity failed: " ^ Tls_identity.describe_error e) false
  | Ok id_a ->
      check "cert.pem was created" (Sys.file_exists id_a.cert_pem_path);
      check "key.pem was created" (Sys.file_exists id_a.key_pem_path);
      check "cert.pem contains a real PEM certificate block"
        (let s = read_file id_a.cert_pem_path in
         let contains needle =
           let nlen = String.length needle in
           let rec go i = i + nlen <= String.length s && (String.sub s i nlen = needle || go (i + 1)) in
           go 0
         in
         contains "-----BEGIN CERTIFICATE-----" && contains "-----END CERTIFICATE-----");
      check "key.pem is mode 0600"
        (Unix.((stat id_a.key_pem_path).st_perm) = 0o600);
      check "the containing directory is mode 0700" (Unix.((stat dir_a).st_perm) = 0o700);

      let cert_bytes_before = read_file id_a.cert_pem_path in
      (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"a-different-cn-should-not-matter" with
      | Error e -> check ("second ensure_identity call failed: " ^ Tls_identity.describe_error e) false
      | Ok id_a_again ->
          check "a second call on the same directory returns the identical certificate"
            (String.equal cert_bytes_before (read_file id_a_again.cert_pem_path)));

      let oc = open_out (Filename.concat dir_corrupt "cert.pem") in
      output_string oc "this is not a certificate";
      close_out oc;
      let oc2 = open_out (Filename.concat dir_corrupt "key.pem") in
      output_string oc2 "this is not a key either";
      close_out oc2;
      (match Tls_identity.ensure_identity ~dir:dir_corrupt ~common_name:"fossh-recovers-from-corruption" with
      | Error e -> check ("recovering from a corrupt identity failed: " ^ Tls_identity.describe_error e) false
      | Ok id_corrupt ->
          check "a corrupt cert.pem is regenerated into a real certificate, not left as garbage"
            (let s = read_file id_corrupt.cert_pem_path in
             String.length s > 0 && s <> "this is not a certificate"));

      (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"source-for-partial-test" with
      | Ok source ->
          let cert_content = read_file source.cert_pem_path in
          let oc3 = open_out (Filename.concat dir_partial "cert.pem") in
          output_string oc3 cert_content;
          close_out oc3

      | Error _ -> ());
      (match Tls_identity.ensure_identity ~dir:dir_partial ~common_name:"fossh-recovers-from-partial-state" with
      | Error e -> check ("recovering from a partial identity failed: " ^ Tls_identity.describe_error e) false
      | Ok id_partial ->
          check "key.pem exists after recovering from a cert-only partial state"
            (Sys.file_exists id_partial.key_pem_path);
          check "the regenerated cert.pem and the borrowed leftover cert are different files"
            (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"irrelevant" with
            | Ok id_a_ref -> not (String.equal (read_file id_a_ref.cert_pem_path) (read_file id_partial.cert_pem_path))
            | Error _ -> false));

      (match Tls_identity.ensure_identity ~dir:dir_b ~common_name:"fossh-watchdog-test-b" with
      | Error e -> check ("ensure_identity for dir_b failed: " ^ Tls_identity.describe_error e) false
      | Ok id_b ->
          check "two different directories get two different certificates"
            (not (String.equal cert_bytes_before (read_file id_b.cert_pem_path)));

          let port =
            let probe = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
            Unix.bind probe (Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 0));
            let p = match Unix.getsockname probe with Unix.ADDR_INET (_, p) -> p | _ -> assert false in
            Unix.close probe;
            p
          in
          let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
          let server_ok = ref false in
          let server_thread =
            Thread.create
              (fun () ->
                let tls : Quic.tls_paths =
                  {
                    cert_chain_pem = id_b.cert_pem_path;
                    priv_key_pem = id_b.key_pem_path;
                    trusted_peer_cert_pem = id_a.cert_pem_path;
                  }
                in
                match Quic.accept_one ~listen_addr ~tls ~deadline:(Unix.gettimeofday () +. 5.0) with
                | Ok state ->
                    server_ok := true;
                    Quic.close state
                | Error _ -> ())
              ()
          in
          let tls : Quic.tls_paths =
            {
              cert_chain_pem = id_a.cert_pem_path;
              priv_key_pem = id_a.key_pem_path;
              trusted_peer_cert_pem = id_b.cert_pem_path;
            }
          in
          (match Quic.connect ~peer_addr:listen_addr ~tls ~deadline:(Unix.gettimeofday () +. 5.0) with
          | Ok state -> Quic.close state
          | Error e -> check ("connect using tls_identity-generated certs failed: " ^ Quic.describe_error e) false);
          Thread.join server_thread;
          check "a real mTLS QUIC handshake succeeds using exactly the certificates this module generated"
            !server_ok));

  let dir_concurrent = mkdtemp () in
  let n_racers = 20 in
  let results : (Tls_identity.t, Tls_identity.error) result option array = Array.make n_racers None in
  let threads =
    Array.init n_racers (fun i ->
        Thread.create
          (fun () -> results.(i) <- Some (Tls_identity.ensure_identity ~dir:dir_concurrent ~common_name:"race"))
          ())
  in
  Array.iter Thread.join threads;
  let all_ok =
    Array.for_all
      (function Some (Ok _) -> true | _ -> false)
      results
  in
  check "all 20 concurrent callers succeeded" all_ok;
  (if all_ok then
     let cert_bytes =
       Array.map
         (function Some (Ok (id : Tls_identity.t)) -> read_file id.cert_pem_path | _ -> "")
         results
     in
     let key_bytes =
       Array.map
         (function Some (Ok (id : Tls_identity.t)) -> read_file id.key_pem_path | _ -> "")
         results
     in
     check "every concurrent caller saw the exact same certificate bytes, not an interleaved mix"
       (Array.for_all (String.equal cert_bytes.(0)) cert_bytes);
     check "every concurrent caller saw the exact same key bytes, not an interleaved mix"
       (Array.for_all (String.equal key_bytes.(0)) key_bytes));
  (match Tls_identity.ensure_identity ~dir:dir_concurrent ~common_name:"race" with
  | Error e -> check ("post-race identity is unusable: " ^ Tls_identity.describe_error e) false
  | Ok id_race ->
      let port =
        let probe = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
        Unix.bind probe (Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 0));
        let p = match Unix.getsockname probe with Unix.ADDR_INET (_, p) -> p | _ -> assert false in
        Unix.close probe;
        p
      in
      let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
      let peer_dir = mkdtemp () in
      (match Tls_identity.ensure_identity ~dir:peer_dir ~common_name:"race-peer" with
      | Error _ -> check "peer identity for the post-race handshake should generate cleanly" false
      | Ok id_peer ->
          let server_ok = ref false in
          let server_thread =
            Thread.create
              (fun () ->
                let tls : Quic.tls_paths =
                  {
                    cert_chain_pem = id_peer.cert_pem_path;
                    priv_key_pem = id_peer.key_pem_path;
                    trusted_peer_cert_pem = id_race.cert_pem_path;
                  }
                in
                match Quic.accept_one ~listen_addr ~tls ~deadline:(Unix.gettimeofday () +. 5.0) with
                | Ok state ->
                    server_ok := true;
                    Quic.close state
                | Error _ -> ())
              ()
          in
          let tls : Quic.tls_paths =
            {
              cert_chain_pem = id_race.cert_pem_path;
              priv_key_pem = id_race.key_pem_path;
              trusted_peer_cert_pem = id_peer.cert_pem_path;
            }
          in
          (match Quic.connect ~peer_addr:listen_addr ~tls ~deadline:(Unix.gettimeofday () +. 5.0) with
          | Ok state -> Quic.close state
          | Error e -> check ("post-race handshake connect failed: " ^ Quic.describe_error e) false);
          Thread.join server_thread;
          check "the identity surviving a 20-way concurrent race is a real, matched, working keypair"
            !server_ok;
          rm_rf peer_dir));
  rm_rf dir_concurrent;

  let dir_expired = mkdtemp () in
  let expired_cert = Filename.concat dir_expired "cert.pem" in
  let expired_key = Filename.concat dir_expired "key.pem" in
  (match
     Subprocess.run ~prog:"/usr/bin/openssl"
       ~argv:
         [|
           "openssl"; "req"; "-x509"; "-newkey"; "ec"; "-pkeyopt"; "ec_paramgen_curve:prime256v1"; "-nodes";
           "-not_before"; "20200101000000Z"; "-not_after"; "20210101000000Z"; "-keyout"; expired_key;
           "-out"; expired_cert; "-subj"; "/CN=already-expired";
         |]
       ~stdin_content:""
   with
  | Error e -> check ("could not even generate an expired test certificate: " ^ e) false
  | Ok _ -> (
      let expired_bytes = read_file expired_cert in
      match Tls_identity.ensure_identity ~dir:dir_expired ~common_name:"fossh-should-replace-expired" with
      | Error e -> check ("recovering from an expired identity failed: " ^ Tls_identity.describe_error e) false
      | Ok id_fresh ->
          check "an expired certificate is regenerated, not reused as though still valid"
            (not (String.equal expired_bytes (read_file id_fresh.cert_pem_path)))));
  rm_rf dir_expired;

  List.iter
    (fun bad_cn ->
      let dir = mkdtemp () in
      (match Tls_identity.ensure_identity ~dir ~common_name:bad_cn with
      | Error (Tls_identity.Invalid_common_name _) -> check ("rejects common_name: " ^ bad_cn) true
      | _ -> check ("should reject common_name: " ^ bad_cn) false);
      rm_rf dir)
    [ "innocuous/O=Evil Corp/OU=Fake Unit"; "has=equals"; ""; String.make 65 'a' ];

  rm_rf dir_a;
  rm_rf dir_b;
  rm_rf dir_corrupt;
  rm_rf dir_partial;
  summarize ()
