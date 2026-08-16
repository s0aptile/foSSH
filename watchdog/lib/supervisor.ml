type restart_policy = { max_restarts : int; window_seconds : float }

let default_policy = { max_restarts = 5; window_seconds = 60.0 }

type t = {
  program : string;
  args : string array;
  mutable child_pid : int option;
  mutable restart_times : float list;
  policy : restart_policy;
  drop_privileges_to : string option;

  mutable termination_was_requested : bool;
}

let create ?(policy = default_policy) ?(drop_privileges_to : string option = None)
    ~(program : string) (args : string array) : t =
  {
    program;
    args;
    child_pid = None;
    restart_times = [];
    policy;
    drop_privileges_to;
    termination_was_requested = false;
  }

let setpriv_path = "/usr/bin/setpriv"

let privdrop_argv ~(user : string) ~(program : string) (args : string array) :
    string array =
  Array.concat
    [
      [|
        setpriv_path;
        "--reuid=" ^ user;
        "--regid=" ^ user;
        "--keep-groups";
        "--bounding-set=-all";
        "--inh-caps=-all";
        "--ambient-caps=-all";
        "--no-new-privs";
        "--";
        program;
      |];
      Array.sub args 1 (Array.length args - 1);
    ]

exception Program_changed_since_verification of string

let ensure_unchanged (t : t) (verified_as : Manifest.file_identity option) : unit =
  match verified_as with
  | None -> ()
  | Some expected -> (
      match Manifest.identity_of t.program with
      | Error msg ->
          raise
            (Program_changed_since_verification
               (Printf.sprintf "%s could not be re-stat'ed after verification: %s" t.program msg))
      | Ok actual ->
          if actual <> expected then
            raise
              (Program_changed_since_verification
                 (Printf.sprintf "%s was replaced between verification and launch" t.program)))

let spawn ?(verified_as : Manifest.file_identity option) (t : t) : int =
  ensure_unchanged t verified_as;
  let real_prog, real_args =
    match t.drop_privileges_to with
    | None -> (t.program, t.args)
    | Some user -> (setpriv_path, privdrop_argv ~user ~program:t.program t.args)
  in
  let pid = Unix.create_process real_prog real_args Unix.stdin Unix.stdout Unix.stderr in
  t.child_pid <- Some pid;
  pid

let record_restart_and_check_storm (t : t) : bool =
  let now = Unix.gettimeofday () in
  let cutoff = now -. t.policy.window_seconds in
  let recent = now :: List.filter (fun ts -> ts >= cutoff) t.restart_times in
  t.restart_times <- recent;
  List.length recent <= t.policy.max_restarts

type wait_outcome = Exited of int | Signaled of int | Stopped of int

let wait_for_exit (t : t) : wait_outcome =
  match t.child_pid with
  | None -> invalid_arg "Supervisor.wait_for_exit: nothing spawned yet"
  | Some pid -> (
      let _, status = Unix.waitpid [] pid in
      t.child_pid <- None;
      match status with
      | Unix.WEXITED code -> Exited code
      | Unix.WSIGNALED n -> Signaled n
      | Unix.WSTOPPED n -> Stopped n)

let tamper_check (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) :
    (Manifest.file_identity option, Manifest.check_result) result =
  match
    Manifest.check ~gnupghome ~expected_key_fingerprint ~program:t.program
      ~clearsigned_manifest
  with

  | Ok_manifest _ -> Ok (Result.to_option (Manifest.identity_of t.program))
  | (Signature_invalid _ | Hash_mismatch _ | Program_not_covered _ | Io_error _
    | Program_replaced _) as result ->
      Error result

type spawn_decision =
  | Spawned of int
  | Spawn_refused_tamper of Manifest.check_result

let spawn_if_safe (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) : spawn_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Spawn_refused_tamper result
  | Ok verified_as -> (
      match spawn ?verified_as t with
      | pid -> Spawned pid
      | exception Program_changed_since_verification msg ->
          Spawn_refused_tamper (Manifest.Program_replaced msg))

type restart_decision =
  | Restarted of int
  | Restart_refused_tamper of Manifest.check_result
  | Restart_refused_storm

let restart_if_safe (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) : restart_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Restart_refused_tamper result
  | Ok verified_as ->
      if not (record_restart_and_check_storm t) then Restart_refused_storm
      else (
        match spawn ?verified_as t with
        | pid -> Restarted pid
        | exception Program_changed_since_verification msg ->
            Restart_refused_tamper (Manifest.Program_replaced msg))

let request_termination (t : t) : unit =
  match t.child_pid with
  | None -> ()
  | Some pid ->
      t.termination_was_requested <- true;
      (try Unix.kill pid Sys.sigterm with Unix.Unix_error _ -> ())

let take_requested_termination (t : t) : bool =
  let was_requested = t.termination_was_requested in
  t.termination_was_requested <- false;
  was_requested

type requested_restart_decision =
  | Requested_restart_completed of int
  | Requested_restart_refused_tamper of Manifest.check_result

let restart_after_requested_termination (t : t) ~(gnupghome : string)
    ~(expected_key_fingerprint : string) ~(clearsigned_manifest : string) :
    requested_restart_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Requested_restart_refused_tamper result
  | Ok verified_as -> (
      match spawn ?verified_as t with
      | pid -> Requested_restart_completed pid
      | exception Program_changed_since_verification msg ->
          Requested_restart_refused_tamper (Manifest.Program_replaced msg))
