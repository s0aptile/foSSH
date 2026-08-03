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

      (* Idempotency: calling again on the same directory must return
         the exact same certificate, not silently regenerate — a fresh
         certificate would carry a new fingerprint and orphan whatever
         a peer already pinned, exactly the failure mode
         Keypair.ensure_keypair already guards against for the OpenPGP
         key (see this module's own header comment). *)
      let cert_bytes_before = read_file id_a.cert_pem_path in
      (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"a-different-cn-should-not-matter" with
      | Error e -> check ("second ensure_identity call failed: " ^ Tls_identity.describe_error e) false
      | Ok id_a_again ->
          check "a second call on the same directory returns the identical certificate"
            (String.equal cert_bytes_before (read_file id_a_again.cert_pem_path)));

      (* A directory with a corrupt/truncated cert.pem (simulating a
         previous run interrupted mid-write — openssl req writes
         cert.pem/key.pem directly, with no atomic rename-into-place
         of its own) must be recovered from by regenerating, not
         trusted as-is just because a file happens to exist at that
         path. *)
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

      (* A directory with only a *valid* cert.pem but no key.pem at all
         (simulating an interrupted run that got further, or a key
         accidentally deleted afterward) must also be recovered by
         regenerating both, not left as a half-usable identity. *)
      (match Tls_identity.ensure_identity ~dir:dir_a ~common_name:"source-for-partial-test" with
      | Ok source ->
          let cert_content = read_file source.cert_pem_path in
          let oc3 = open_out (Filename.concat dir_partial "cert.pem") in
          output_string oc3 cert_content;
          close_out oc3
          (* deliberately: no key.pem written into dir_partial at all *)
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

      (* Distinct directories get distinct identities. *)
      (match Tls_identity.ensure_identity ~dir:dir_b ~common_name:"fossh-watchdog-test-b" with
      | Error e -> check ("ensure_identity for dir_b failed: " ^ Tls_identity.describe_error e) false
      | Ok id_b ->
          check "two different directories get two different certificates"
            (not (String.equal cert_bytes_before (read_file id_b.cert_pem_path)));

          (* The real proof: drive an actual mTLS QUIC handshake using
             exactly the files this module produced, through the same
             Quic.connect/accept_one this project's real transport
             layer uses — not a parallel, test-only cert-generation
             path. If tls_identity.ml ever produced a certificate
             quiche/BoringSSL couldn't actually use (a wrong curve, a
             missing field, wrong permissions blocking a read), this
             is what would catch it; `openssl` exiting 0 alone
             wouldn't. *)
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

  (* Regression test for the most severe adversarial-review finding:
     an earlier version had no synchronization at all, and two
     concurrent ensure_identity calls on the same directory could each
     spawn their own `openssl req`, both targeting the same cert.pem/
     key.pem paths — reproduced empirically to land as a *mismatched*
     pair (one invocation's key, a different invocation's cert) in
     10/80 real trials, a state that then parses as individually valid
     forever (cert_is_valid/key_is_valid check each file in isolation)
     while being completely unusable — confirmed separately to fail
     quiche_config_load_priv_key_from_pem_file outright. Fixed with a
     Mutex serializing the whole check-then-generate sequence. This
     spawns a real 20-way race on a fresh directory and checks both
     that every thread agrees on the exact same certificate bytes
     (proving no interleaving happened) and that the result is a real,
     matched, working pair via an actual QUIC handshake — not just
     "openssl didn't error", which is exactly what missed this the
     first time. *)
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

  (* Expired certificates must not be trusted as still valid — a bare
     `openssl x509 -noout` parse exits 0 on a certificate years past
     its own expiry; cert_is_valid must ask more than that. *)
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

  (* common_name containing `/` or `=` must be rejected outright, not
     passed through to build a -subj value that could inject
     additional Subject-DN fields (confirmed real:
     "innocuous/O=Evil Corp/OU=Fake Unit" produced a three-field
     Subject from one string argument, before this validation
     existed). *)
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
