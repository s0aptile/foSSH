open Fossh_watchdog_lib
open Fossh_watchdog_quic

let log fmt = Printf.eprintf ("fossh-watchdog: " ^^ fmt ^^ "\n%!")

let fossh_svc_user = "fossh-svc"

let env_var (key : string) : string option =
  match Sys.getenv_opt key with Some "" -> None | v -> v

let allow_no_privdrop_var = "FOSSH_WATCHDOG_ALLOW_NO_PRIVDROP"

let resolve_privdrop_target () : string option =
  if Unix.geteuid () = 0 then Some fossh_svc_user
  else
    match env_var allow_no_privdrop_var with
    | Some "1" ->
        log
          "WARNING: running without privilege separation — the supervised child will inherit \
           this process's own uid (%d), not %s. This is a development and test mode only; %s \
           must never be set on a real install."
          (Unix.geteuid ()) fossh_svc_user allow_no_privdrop_var;
        None
    | _ ->
        log
          "REFUSING TO START: supervision drops the child's privileges to %s, which requires \
           running as root (euid is %d). Start this via its systemd unit, or set %s=1 to \
           supervise without privilege separation — a development mode that is not safe on a \
           real install."
          fossh_svc_user (Unix.geteuid ()) allow_no_privdrop_var;
        exit 9

let env_var_default (key : string) ~(default : string) : string =
  Option.value (env_var key) ~default

let parse_inet_addr (s : string) : Unix.sockaddr option =
  match String.rindex_opt s ':' with
  | None -> None
  | Some i -> (
      let host = String.sub s 0 i in
      let port_str = String.sub s (i + 1) (String.length s - i - 1) in
      match int_of_string_opt port_str with
      | None -> None
      | Some port -> (
          try Some (Unix.ADDR_INET (Unix.inet_addr_of_string host, port))
          with Failure _ -> None))

let start_quic_command_server (supervisor : Supervisor.t) ~(gnupghome : string)
    ~(expected_key_fingerprint : string) ~(manifest_path : string) : unit =
  match parse_inet_addr (env_var_default "FOSSH_QUIC_LISTEN_ADDR" ~default:"127.0.0.1:7443") with
  | None -> log "FOSSH_QUIC_LISTEN_ADDR is not a valid host:port — QUIC command server disabled"
  | Some listen_addr ->
      let config : Quic_command_server.config =
        {
          tls_dir = env_var_default "FOSSH_WATCHDOG_TLS_DIR" ~default:"/var/lib/fossh-watchdog/tls";
          core_cert_pin_path =
            env_var_default "FOSSH_CORE_CERT_PIN" ~default:"/var/lib/fossh-watchdog/core-cert.pin";
          listen_addr;
          gnupghome;
          expected_key_fingerprint;
          manifest_path;
        }
      in
      let (_ : Thread.t) = Thread.create (fun () -> Quic_command_server.run config supervisor) () in
      ()

let start_operator_auth_server () : unit =
  let socket_path =
    env_var_default "FOSSH_OPERATOR_AUTH_SOCKET"
      ~default:"/var/lib/fossh-watchdog/operator-auth.sock"
  in
  let operator_key_dir =
    env_var_default "FOSSH_OPERATOR_KEY_DIR" ~default:"/var/lib/fossh-watchdog/operator-key"
  in
  let token_path = env_var_default "FOSSH_SETUP_TOKEN_PATH" ~default:"/etc/fossh/setup-token" in

  (match try Setup_token.ensure ~token_path ~operator_key_dir with e -> Error (Setup_token.Io_error (Printexc.to_string e)) with
  | Ok () -> ()
  | Error e ->
      log "setup-token init failed (first-run setup unavailable until this is fixed): %s"
        (Setup_token.describe_error e));
  let config : Operator_auth_server.config = { socket_path; operator_key_dir } in
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        match Operator_auth_server.run config with
        | Ok () -> ()
        | Error e -> log "operator auth server disabled: %s" e)
      ()
  in
  ()

let describe_check_result = function
  | Manifest.Signature_invalid e -> Printf.sprintf "manifest signature invalid: %s" e
  | Manifest.Hash_mismatch { path; expected; actual } ->
      Printf.sprintf "tamper detected in %s (expected %s, got %s)" path expected actual
  | Manifest.Program_replaced msg ->
      Printf.sprintf "refusing to launch: %s" msg
  | Manifest.Program_not_covered p ->
      Printf.sprintf "manifest does not cover the program about to run (%s)" p
  | Manifest.Io_error e -> Printf.sprintf "could not verify manifest: %s" e
  | Manifest.Ok_manifest _ -> assert false

let spawn_or_refuse (supervisor : Supervisor.t) ~gnupghome ~expected_key_fingerprint
    ~manifest_path : int option =
  match Manifest.read_from_path manifest_path with
  | Error e ->
      log "REFUSING TO LAUNCH: %s" (Manifest.describe_read_error e);
      exit 5
  | Ok clearsigned_manifest -> (
      match
        try
          Ok
            (Supervisor.spawn_if_safe supervisor ~gnupghome ~expected_key_fingerprint
               ~clearsigned_manifest)
        with Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
      with
      | Error e ->
          log "REFUSING TO LAUNCH: could not spawn %s: %s" supervisor.program e;
          exit 3
      | Ok (Spawned pid) ->
          log "spawned %s (pid %d)" supervisor.program pid;
          Some pid
      | Ok (Spawn_refused_tamper result) ->
          log "REFUSING TO LAUNCH: %s" (describe_check_result result);
          exit 3)

let () =

  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  match Array.to_list Sys.argv with
  | _ :: "bootstrap-send" :: socket_path :: gnupghome :: tls_dir :: core_cert_pin_path :: _ -> (
      match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
      | Error e ->
          log "BOOTSTRAP HANDOFF FAILED: could not establish watchdog keypair: %s"
            (Keypair.describe_error e);
          exit 6
      | Ok fingerprint -> (
          match Tls_identity.ensure_identity ~dir:tls_dir ~common_name:"fossh-watchdog" with
          | Error e ->
              log "BOOTSTRAP HANDOFF FAILED: could not establish TLS identity: %s"
                (Tls_identity.describe_error e);
              exit 6
          | Ok identity -> (

              match
                try Ok (Fileutil.read_all_bytes identity.cert_pem_path)
                with Sys_error msg -> Error msg
              with
              | Error msg ->
                  log "BOOTSTRAP HANDOFF FAILED: could not read own certificate at %s: %s"
                    identity.cert_pem_path msg;
                  exit 6
              | Ok cert_pem -> (
              match Bootstrap.send_handoff_with_retry ~socket_path ~fingerprint cert_pem with
              | Error e ->
                  log "BOOTSTRAP HANDOFF FAILED: %s" (Bootstrap.describe_error e);
                  exit 6
              | Ok core_cert_pem -> (
                  match Core_pin.persist_pin core_cert_pin_path core_cert_pem with
                  | Error e ->
                      log "BOOTSTRAP HANDOFF FAILED: could not persist core's certificate: %s"
                        (Core_pin.describe_error e);
                      exit 6
                  | Ok () ->
                      log "bootstrap handoff completed with %s" socket_path;

                      print_endline fingerprint;
                      exit 0)))))
  | _ :: "generate-manifest" :: gnupghome :: manifest_path :: paths -> (
      if paths = [] then (
        prerr_endline
          "usage: fossh-watchdog generate-manifest <gnupghome> <manifest-path> <path>...";
        exit 2);
      match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
      | Error e ->
          log "MANIFEST GENERATION FAILED: could not establish watchdog keypair: %s"
            (Keypair.describe_error e);
          exit 8
      | Ok fingerprint -> (
          match Keypair.ensure_passphrase gnupghome with
          | Error e ->
              log "MANIFEST GENERATION FAILED: could not establish keypair passphrase: %s"
                (Keypair.describe_error e);
              exit 8
          | Ok passphrase -> (
              match
                Manifest.generate_and_sign ~gnupghome ~key_id:fingerprint ~passphrase paths
              with
              | Error e ->
                  log "MANIFEST GENERATION FAILED: %s" e;
                  exit 8
              | Ok signed -> (

                  let tmp_path = manifest_path ^ ".tmp" in
                  match
                    try
                      let fd =
                        Unix.openfile tmp_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600
                      in
                      let oc = Unix.out_channel_of_descr fd in
                      output_string oc signed;
                      close_out oc;
                      Unix.rename tmp_path manifest_path;
                      Ok ()
                    with
                    | Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
                    | Sys_error msg -> Error msg
                  with
                  | Error e ->
                      log "MANIFEST GENERATION FAILED: could not write %s: %s" manifest_path e;
                      exit 8
                  | Ok () ->
                      log "wrote signed manifest covering %d path(s) to %s"
                        (List.length paths) manifest_path;
                      exit 0)))
      )
  | _ :: program :: gnupghome :: manifest_path :: rest ->
      let expected_key_fingerprint =
        match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
        | Ok fpr ->
            log "watchdog key fingerprint: %s" fpr;
            log "watchdog key passphrase: %s" (Filename.concat gnupghome "passphrase");
            fpr
        | Error e ->
            log "COULD NOT ESTABLISH WATCHDOG KEYPAIR: %s" (Keypair.describe_error e);
            exit 7
      in
      let args = Array.of_list (program :: rest) in
      let supervisor =
        Supervisor.create ~drop_privileges_to:(resolve_privdrop_target ()) ~program args
      in
      start_quic_command_server supervisor ~gnupghome ~expected_key_fingerprint ~manifest_path;
      start_operator_auth_server ();
      let (_ : int option) =
        spawn_or_refuse supervisor ~gnupghome ~expected_key_fingerprint ~manifest_path
      in
      let running = ref true in
      while !running do
        let outcome = Supervisor.wait_for_exit supervisor in

        let was_requested = Supervisor.take_requested_termination supervisor in
        (match outcome with
        | Exited 0 when not was_requested ->
            log "%s exited 0 (clean shutdown) — not restarting" program;
            running := false
        | Exited 0 -> log "%s exited 0 after a verified restart/reload command" program
        | Exited code -> log "%s exited %d" program code
        | Signaled n when was_requested ->
            log "%s exited via a verified restart/reload command (signal %s)" program
              (Subprocess.describe_signal n)
        | Signaled n -> log "%s killed by signal %s" program (Subprocess.describe_signal n)
        | Stopped n -> log "%s stopped by signal %s" program (Subprocess.describe_signal n));
        if !running then
          match Manifest.read_from_path manifest_path with
          | Error e ->
              log "REFUSING RESTART: %s" (Manifest.describe_read_error e);
              exit 5
          | Ok clearsigned_manifest ->
              if was_requested then
                match
                  try
                    Ok
                      (Supervisor.restart_after_requested_termination supervisor ~gnupghome
                         ~expected_key_fingerprint ~clearsigned_manifest)
                  with
                  | Unix.Unix_error (e, fn, _) ->
                      Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
                with
                | Error e ->
                    log "REFUSING RESTART: could not spawn %s: %s" program e;
                    exit 3
                | Ok (Supervisor.Requested_restart_completed pid) ->
                    log "restarted %s (pid %d) after a verified command" program pid
                | Ok (Supervisor.Requested_restart_refused_tamper result) ->
                    log "REFUSING RESTART: %s" (describe_check_result result);
                    exit 3
              else (
                match
                  try
                    Ok
                      (Supervisor.restart_if_safe supervisor ~gnupghome
                         ~expected_key_fingerprint ~clearsigned_manifest)
                  with
                  | Unix.Unix_error (e, fn, _) ->
                      Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
                with
                | Error e ->
                    log "REFUSING RESTART: could not spawn %s: %s" program e;
                    exit 3
                | Ok (Restarted pid) -> log "restarted %s (pid %d)" program pid
                | Ok (Restart_refused_tamper result) ->
                    log "REFUSING RESTART: %s" (describe_check_result result);
                    exit 3
                | Ok Restart_refused_storm ->
                    log "REFUSING RESTART: too many restarts too fast (policy: %d/%.0fs)"
                      supervisor.policy.max_restarts supervisor.policy.window_seconds;
                    exit 4)
      done
  | _ ->
      prerr_endline
        "usage: fossh-watchdog <program> <gnupghome> <manifest-path> [args...]\n\
        \       fossh-watchdog bootstrap-send <socket-path> <gnupghome> <tls-dir> \
         <core-cert-pin-path>\n\
        \       fossh-watchdog generate-manifest <gnupghome> <manifest-path> <path>...";
      exit 2
