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

  (* restart_if_safe: real end-to-end gate against a real signed
     manifest, using generate_key/detach helpers from Test_helpers *)
  let k = generate_key () in
  let watched_dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      cleanup k;
      rm_rf watched_dir)
    (fun () ->
      let watched_file = Filename.concat watched_dir "core.bin" in
      write_file watched_file "core binary contents (stand-in)";
      let good_manifest =
        match Manifest.hash_all [ watched_file ] with
        | Error e -> failwith e
        | Ok entries -> (
            match
              Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.key_id
                (Manifest.render entries)
            with
            | Error e -> failwith e
            | Ok s -> s)
      in
      let t3 =
        Supervisor.create ~program:"/bin/true" [| "/bin/true" |]
      in
      (match
         Supervisor.restart_if_safe t3 ~gnupghome:k.gnupghome
           ~clearsigned_manifest:good_manifest
       with
      | Restarted _ -> check "restart_if_safe restarts on a clean manifest" true
      | _ -> check "restart_if_safe restarts on a clean manifest" false);

      write_file watched_file "TAMPERED";
      (match
         Supervisor.restart_if_safe t3 ~gnupghome:k.gnupghome
           ~clearsigned_manifest:good_manifest
       with
      | Refused_tamper_detected (Hash_mismatch _) ->
          check "restart_if_safe refuses a restart when a watched file changed"
            true
      | _ ->
          check "restart_if_safe refuses a restart when a watched file changed"
            false);

      summarize ())
