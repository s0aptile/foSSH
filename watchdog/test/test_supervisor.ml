open Fossh_watchdog_lib
open Test_helpers

let write_file path content =
  let oc = open_out_bin path in
  output_string oc content;
  close_out oc

let () =
  (* spawn / wait_for_exit against a real, short-lived process *)
  let t = Supervisor.create ~program:"/bin/sh" [| "/bin/sh"; "-c"; "exit 7" |] in
  let pid = Supervisor.spawn t in
  check "spawn returns a positive pid" (pid > 0);
  (match Supervisor.wait_for_exit t with
  | Exited 7 -> check "wait_for_exit reports the real exit code" true
  | _ -> check "wait_for_exit reports the real exit code" false);

  (* restart-storm guard: policy allows N within the window, refuses
     the (N+1)th *)
  let policy = { Supervisor.max_restarts = 3; window_seconds = 60.0 } in
  let t2 = Supervisor.create ~policy ~program:"/bin/true" [| "/bin/true" |] in
  let results =
    List.init 5 (fun _ -> Supervisor.record_restart_and_check_storm t2)
  in
  check "first max_restarts (3) attempts are allowed"
    (results = [ true; true; true; false; false ]);

  (* spawn_if_safe / restart_if_safe: real end-to-end gate against a
     real signed manifest that actually covers the supervised
     program's own path, since ADR-0041's fix requires that. *)
  let k = generate_key () in
  let watched_dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      cleanup k;
      rm_rf watched_dir)
    (fun () ->
      let watched_file = Filename.concat watched_dir "core.bin" in
      write_file watched_file "core binary contents (stand-in)";
      let sign_manifest_for paths =
        match Manifest.hash_all paths with
        | Error e -> failwith e
        | Ok entries -> (
            match
              Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint ~passphrase:k.passphrase
                (Manifest.render entries)
            with
            | Error e -> failwith e
            | Ok s -> s)
      in
      let t3 = Supervisor.create ~program:"/bin/true" [| "/bin/true" |] in

      (* Initial spawn now goes through the same gate restarts do
         (ADR-0041, finding #1) — a manifest that doesn't cover
         t3.program at all must refuse even the FIRST spawn. *)
      let manifest_missing_program = sign_manifest_for [ watched_file ] in
      (match
         Supervisor.spawn_if_safe t3 ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_missing_program
       with
      | Spawn_refused_tamper (Program_not_covered _) ->
          check
            "spawn_if_safe refuses the INITIAL spawn when the manifest doesn't cover \
             the program"
            true
      | _ ->
          check
            "spawn_if_safe refuses the INITIAL spawn when the manifest doesn't cover \
             the program"
            false);

      let manifest_covering_program = sign_manifest_for [ watched_file; "/bin/true" ] in
      (match
         Supervisor.spawn_if_safe t3 ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_covering_program
       with
      | Spawned _ ->
          check "spawn_if_safe spawns when the manifest covers the program and is clean"
            true
      | Spawn_refused_tamper _ ->
          check "spawn_if_safe spawns when the manifest covers the program and is clean"
            false);
      (match Supervisor.wait_for_exit t3 with Exited 0 -> () | _ -> ());

      (match
         Supervisor.restart_if_safe t3 ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_covering_program
       with
      | Restarted _ -> check "restart_if_safe restarts on a clean, covering manifest" true
      | _ -> check "restart_if_safe restarts on a clean, covering manifest" false);
      (match Supervisor.wait_for_exit t3 with Exited 0 -> () | _ -> ());

      write_file watched_file "TAMPERED";
      (match
         Supervisor.restart_if_safe t3 ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_covering_program
       with
      | Restart_refused_tamper (Hash_mismatch _) ->
          check "restart_if_safe refuses a restart when a watched file changed" true
      | _ -> check "restart_if_safe refuses a restart when a watched file changed" false);

      (* The time-of-check/time-of-use gap: the manifest verifies the
         file at a path, and the exec reopens that path. Simulated by
         letting verification pass and then replacing the program before
         the launch, which is exactly what an attacker with write access
         to the binary would arrange to happen in between. *)
      let swappable = Filename.concat watched_dir "swappable" in
      write_file swappable "#!/bin/sh\nexit 0\n";
      Unix.chmod swappable 0o755;
      let t_race = Supervisor.create ~program:swappable [| swappable |] in
      let manifest_for_swappable = sign_manifest_for [ swappable ] in

      (match
         Supervisor.spawn_if_safe t_race ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_for_swappable
       with
      | Spawned _ -> check "the unmodified program launches normally" true
      | Spawn_refused_tamper _ -> check "the unmodified program launches normally" false);
      (match Supervisor.wait_for_exit t_race with Exited 0 -> () | _ -> ());

      (* Verify against the real file, then swap it for another one at
         the same path -- unlink and recreate, so the inode changes the
         way a replaced binary's would. *)
      let verified_as =
        match Manifest.identity_of swappable with Ok id -> Some id | Error _ -> None
      in
      check "the program's identity was captured at verification time" (verified_as <> None);
      Unix.unlink swappable;
      write_file swappable "#!/bin/sh\nexit 1\n";
      Unix.chmod swappable 0o755;

      (match Supervisor.spawn ?verified_as t_race with
      | _pid ->
          check "a program swapped after verification is NOT launched" false
      | exception Supervisor.Program_changed_since_verification _ ->
          check "a program swapped after verification is NOT launched" true);

      (* And the refusal must arrive as a decision, never as an
         exception escaping into the supervision loop -- a watchdog that
         dies on tamper detection has stopped watching. *)
      (match
         Supervisor.restart_if_safe t_race ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint
           ~clearsigned_manifest:manifest_for_swappable
       with
      | Restart_refused_tamper (Hash_mismatch _) ->
          check "the swapped file is caught by the hash check on the next cycle" true
      | Restart_refused_tamper (Program_replaced _) ->
          check "the swapped file is caught by the hash check on the next cycle" true
      | _ -> check "the swapped file is caught by the hash check on the next cycle" false);

      (* §3.4: request_termination — the one cross-thread touch the
         real QUIC command server (Quic_command_server) makes on a
         live Supervisor.t, from a thread other than the one running
         the wait_for_exit loop above. *)
      let t4 = Supervisor.create ~program:"/bin/true" [| "/bin/true" |] in
      check "request_termination on a supervisor with no tracked child is a safe no-op"
        (Supervisor.request_termination t4;
         true);

      let t5 = Supervisor.create ~program:"/bin/sleep" [| "/bin/sleep"; "30" |] in
      let (_ : int) = Supervisor.spawn t5 in
      Supervisor.request_termination t5;
      (match Supervisor.wait_for_exit t5 with
      | Signaled n when n = Sys.sigterm ->
          check "request_termination delivers SIGTERM to the real, currently-tracked child" true
      | _ -> check "request_termination delivers SIGTERM to the real, currently-tracked child" false);
      check "take_requested_termination reports true after a real request_termination, then resets"
        (Supervisor.take_requested_termination t5 && not (Supervisor.take_requested_termination t5));

      let t6 = Supervisor.create ~program:"/bin/true" [| "/bin/true" |] in
      check "take_requested_termination is false when nothing has ever requested one"
        (not (Supervisor.take_requested_termination t6));

      (* Adversarial-review regression (ADR-0050, CRITICAL): a real,
         reproduced bug had 6 individually-verified reload commands in
         a row — an ordinary operational pattern, not an attack —
         trip the crash-storm guard and `exit 4` the *entire watchdog
         process*, because a command-triggered restart fed the exact
         same counter a genuine crash loop needs. This drives more
         than `default_policy.max_restarts` command-triggered restart
         cycles through the real dispatch path
         (request_termination -> wait_for_exit ->
         take_requested_termination -> restart_after_requested_termination)
         end to end and asserts every single one succeeds — proving
         the storm guard is structurally bypassed for this path, not
         merely "still passing today by chance."

         A manifest covering *only* /bin/true, signed fresh here — not
         the earlier manifest_covering_program above, which by this
         point in the same test function has been invalidated on
         purpose (the "restart_if_safe refuses a restart when a
         watched file changed" check just above deliberately tampered
         with watched_file, so re-using that same manifest here would
         make every cycle below fail tamper-check for an unrelated
         reason and never actually exercise the storm-guard bypass). *)
      let manifest_for_true_only = sign_manifest_for [ "/bin/true" ] in
      let t8 = Supervisor.create ~program:"/bin/true" [| "/bin/true" |] in
      let (_ : int) = Supervisor.spawn t8 in
      let cycles = Supervisor.default_policy.max_restarts + 3 in
      let all_completed = ref true in
      for _ = 1 to cycles do
        Supervisor.request_termination t8;
        let (_ : Supervisor.wait_outcome) = Supervisor.wait_for_exit t8 in
        let was_requested = Supervisor.take_requested_termination t8 in
        if not was_requested then all_completed := false
        else
          match
            Supervisor.restart_after_requested_termination t8 ~gnupghome:k.gnupghome
              ~expected_key_fingerprint:k.fingerprint ~clearsigned_manifest:manifest_for_true_only
          with
          | Requested_restart_completed _ -> ()
          | Requested_restart_refused_tamper _ -> all_completed := false
      done;
      check
        (Printf.sprintf
           "%d command-triggered restarts (more than the %d-restart crash-storm cap) all completed, \
            none refused"
           cycles Supervisor.default_policy.max_restarts)
        !all_completed;
      let (_ : Supervisor.wait_outcome) = Supervisor.wait_for_exit t8 in

      (* §2.3 regression: `spawn` used to exec fossh-fcgi with no
         privilege drop at all, inheriting fossh-watchdog's own uid.
         See `Supervisor.privdrop_argv`'s doc for the mechanism. *)

      (* Pure: catches a missing flag, especially the three
         capability-clearing ones, whose absence would leak this
         process's own ambient capabilities into the dropped child. *)
      check "privdrop_argv builds the exact expected setpriv invocation"
        (Supervisor.privdrop_argv ~user:"fossh-svc" ~program:"/usr/bin/fossh-fcgi"
           [| "/usr/bin/fossh-fcgi"; "--extra-flag" |]
        = [|
            "/usr/bin/setpriv"; "--reuid=fossh-svc"; "--regid=fossh-svc";
            "--keep-groups"; "--bounding-set=-all"; "--inh-caps=-all";
            "--ambient-caps=-all"; "--no-new-privs"; "--";
            "/usr/bin/fossh-fcgi"; "--extra-flag";
          |]);

      (* Real, executed end to end through the real, installed
         setpriv, not a stub. Unprivileged, this process should see
         setpriv itself refuse (exit 127, confirmed directly against a
         standalone invocation before writing this test) rather than
         silently fall back to running the child as its own identity
         -- fail closed, not open. As real root, expect the drop to
         actually succeed. *)
      let is_root = Unix.geteuid () = 0 in
      let t9 =
        Supervisor.create ~drop_privileges_to:(Some "fossh-svc") ~program:"/bin/true"
          [| "/bin/true" |]
      in
      let (_ : int) = Supervisor.spawn t9 in
      (match Supervisor.wait_for_exit t9 with
      | Exited 127 when not is_root ->
          check
            "spawn with drop_privileges_to refuses closed (setpriv exits 127) rather than \
             silently running the child as this process's own identity, when this process \
             lacks CAP_SETUID/CAP_SETGID"
            true
      | Exited 0 when is_root ->
          check "spawn with drop_privileges_to succeeds when this test process is real root"
            true
      | _ ->
          check
            "spawn with drop_privileges_to refuses closed (setpriv exits 127) rather than \
             silently running the child as this process's own identity, when this process \
             lacks CAP_SETUID/CAP_SETGID"
            false);

      (* Same program, no drop_privileges_to: proves the 127 above is
         caused by the setpriv wrapping, not by /bin/true itself. *)
      let t10 = Supervisor.create ~program:"/bin/true" [| "/bin/true" |] in
      let (_ : int) = Supervisor.spawn t10 in
      (match Supervisor.wait_for_exit t10 with
      | Exited 0 ->
          check
            "the same program without drop_privileges_to still exits 0 as before -- the 127 \
             above is caused by the privilege-drop wrapping, not by /bin/true itself"
            true
      | _ ->
          check
            "the same program without drop_privileges_to still exits 0 as before -- the 127 \
             above is caused by the privilege-drop wrapping, not by /bin/true itself"
            false);

      (* Real root only: inspect the live child's /proc/<pid>/status
         to confirm it's really running as fossh-svc's uid/gid, and
         that CapEff is all zero (mirrors privdrop.rs's own "verify
         the drop stuck by trying to reclaim" -- there's no single
         syscall to retry here, so "holds no capability at all" is the
         equivalent property). Genuinely can't run without real root
         or CAP_SETUID/CAP_SETGID -- see the hardening report for what
         was and wasn't verified in the environment this actually ran
         in. *)
      if is_root then (
        let t11 =
          Supervisor.create ~drop_privileges_to:(Some "fossh-svc") ~program:"/bin/sleep"
            [| "/bin/sleep"; "5" |]
        in
        let pid = Supervisor.spawn t11 in
        let comm_path = Printf.sprintf "/proc/%d/comm" pid in
        let rec wait_for_exec attempts_left =
          if attempts_left <= 0 then ()
          else
            match Fileutil.read_all_bytes comm_path with
            | s when String.trim s = "sleep" -> ()
            | _ | (exception Sys_error _) ->
                Unix.sleepf 0.05;
                wait_for_exec (attempts_left - 1)
        in
        wait_for_exec 100;
        let status = Fileutil.read_all_bytes (Printf.sprintf "/proc/%d/status" pid) in
        let field_values prefix =
          String.split_on_char '\n' status
          |> List.find_opt (fun line ->
                 String.length line >= String.length prefix
                 && String.sub line 0 (String.length prefix) = prefix)
          |> Option.map (fun line ->
                 String.sub line (String.length prefix) (String.length line - String.length prefix)
                 |> String.split_on_char '\t'
                 |> List.filter (fun s -> String.trim s <> ""))
        in
        let fossh_svc = Unix.getpwnam "fossh-svc" in
        let expect_all_uid_gid_fields prefix expected_id =
          match field_values prefix with
          | Some values when values <> [] ->
              List.for_all (fun v -> int_of_string_opt (String.trim v) = Some expected_id) values
          | _ -> false
        in
        check
          (Printf.sprintf
             "the real spawned child's /proc/%d/status Uid line is fossh-svc's uid (%d) across \
              real/effective/saved/fs, not fossh-watchdog's"
             pid fossh_svc.Unix.pw_uid)
          (expect_all_uid_gid_fields "Uid:" fossh_svc.Unix.pw_uid);
        check
          (Printf.sprintf
             "the real spawned child's /proc/%d/status Gid line is fossh-svc's gid (%d) across \
              real/effective/saved/fs, not fossh-watchdog's"
             pid fossh_svc.Unix.pw_gid)
          (expect_all_uid_gid_fields "Gid:" fossh_svc.Unix.pw_gid);
        check
          "the real spawned child holds no effective capabilities (CapEff all zero) -- it \
           cannot regain any identity, fossh-watchdog's or otherwise"
          (match field_values "CapEff:" with
          | Some [ hex ] -> String.trim hex = String.make (String.length (String.trim hex)) '0'
          | _ -> false);
        Supervisor.request_termination t11;
        let (_ : Supervisor.wait_outcome) = Supervisor.wait_for_exit t11 in
        ())
      else
        Printf.eprintf
          "skip: real /proc/<pid>/status uid/gid + capability verification of a dropped child \
           needs this test process to itself run as root (or hold CAP_SETUID/CAP_SETGID) -- not \
           available in this environment; the argv-construction and refuses-closed-without-\
           privilege checks above still ran for real.\n\
           %!";

      summarize ())
