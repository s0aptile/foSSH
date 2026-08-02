(* fossh-watchdog: process supervision + tamper-detection gate for
   `fossh-fcgi` (§3.3, responsibilities 1 and 3).

   Deliberately NOT wired up yet in this binary: the challenge-response
   auth gate's network listener and the QUIC IPC channel to core
   (§2.1/§3.4) — Auth/Session (lib/auth.ml, lib/session.ml) are real,
   tested, standalone modules, but nothing in this file accepts a
   connection and calls them yet. That's the next pass; see
   DECISIONS.md and dev/DURUM.md for exactly what's built versus
   still open. Running this binary today gives you real crash-restart
   plus real tamper detection on every restart, and nothing else.

   Usage: fossh-watchdog <program> <gnupghome> <manifest-path> [args...] *)

open Fossh_watchdog_lib

let log fmt = Printf.eprintf ("fossh-watchdog: " ^^ fmt ^^ "\n%!")

let read_file path =
  let ic = open_in_bin path in
  let len = in_channel_length ic in
  let content = really_input_string ic len in
  close_in ic;
  content

let () =
  match Array.to_list Sys.argv with
  | _ :: program :: gnupghome :: manifest_path :: rest ->
      let args = Array.of_list (program :: rest) in
      let supervisor = Supervisor.create ~program args in
      let read_manifest () = read_file manifest_path in
      let pid = Supervisor.spawn supervisor in
      log "spawned %s (pid %d)" program pid;
      let running = ref true in
      while !running do
        (match Supervisor.wait_for_exit supervisor with
        | Exited 0 ->
            log "%s exited 0 (clean shutdown) — not restarting" program;
            running := false
        | Exited code -> log "%s exited %d" program code
        | Signaled n -> log "%s killed by signal %d" program n
        | Stopped n -> log "%s stopped by signal %d" program n);
        if !running then
          match
            Supervisor.restart_if_safe supervisor ~gnupghome
              ~clearsigned_manifest:(read_manifest ())
          with
          | Restarted pid -> log "restarted %s (pid %d)" program pid
          | Refused_tamper_detected (Signature_invalid e) ->
              log "REFUSING RESTART: manifest signature invalid: %s" e;
              running := false
          | Refused_tamper_detected (Hash_mismatch { path; expected; actual })
            ->
              log
                "REFUSING RESTART: tamper detected in %s (expected %s, got \
                 %s)"
                path expected actual;
              running := false
          | Refused_tamper_detected (Io_error e) ->
              log "REFUSING RESTART: could not verify manifest: %s" e;
              running := false
          | Refused_tamper_detected (Ok_manifest _) ->
              (* Unreachable: restart_if_safe only wraps the failing
                 constructors in Refused_tamper_detected. *)
              assert false
          | Refused_restart_storm ->
              log "REFUSING RESTART: too many restarts too fast (policy: %d/%.0fs)"
                supervisor.policy.max_restarts supervisor.policy.window_seconds;
              running := false
      done
  | _ ->
      prerr_endline
        "usage: fossh-watchdog <program> <gnupghome> <manifest-path> \
         [args...]";
      exit 2
