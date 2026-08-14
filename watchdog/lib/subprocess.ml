(* Shared helper for shelling out to `gpgv`/`gpg`/`sha256sum` via an
   argv array, never a shell string — every caller in this codebase
   passes untrusted or semi-trusted data (file paths, key IDs, nonce
   bytes) as separate argv/stdin elements, so there is no shell
   metacharacter injection surface, matching the same discipline the
   Rust side of this project holds itself to for SQL/shell contexts. *)

(* Live-run finding (real repro): `Unix.WSIGNALED`/`WSTOPPED` carry
   OCaml's own portable internal signal encoding (small negative ints,
   e.g. `Sys.sigkill = -7`), not the real OS signal number -- a real
   `kill -9` logged as "killed by signal -7", not "9", confusing for
   an operator or an alerting rule grepping log output. Translates the
   common process-supervision-relevant signals back to their real
   Linux numbers by matching against OCaml's own named `Sys.sig*`
   constants (portable across OCaml versions/platforms by
   construction, since those constants are whatever this runtime
   actually uses) rather than hardcoding assumed values; anything not
   in this short list still shows the raw OCaml int, labeled as such
   rather than presented as if it were the real number. *)
let describe_signal (n : int) : string =
  let named =
    [
      (Sys.sigkill, "SIGKILL", 9); (Sys.sigterm, "SIGTERM", 15);
      (Sys.sigsegv, "SIGSEGV", 11); (Sys.sigabrt, "SIGABRT", 6);
      (Sys.sigint, "SIGINT", 2); (Sys.sigquit, "SIGQUIT", 3);
      (Sys.sighup, "SIGHUP", 1); (Sys.sigpipe, "SIGPIPE", 13);
      (Sys.sigbus, "SIGBUS", 7); (Sys.sigfpe, "SIGFPE", 8);
      (Sys.sigill, "SIGILL", 4);
    ]
  in
  match List.find_opt (fun (ocaml_n, _, _) -> ocaml_n = n) named with
  | Some (_, name, real_n) -> Printf.sprintf "%s (%d)" name real_n
  | None -> Printf.sprintf "OCaml internal signal %d" n

(* Every pipe end not explicitly handed to the child is close-on-exec.
   `gpg` spawns `gpg-agent`, a lingering background daemon, as a side
   effect of some operations; without this, `gpg-agent` inherits our
   pipe fds across `gpg`'s own exec and holds them open indefinitely
   even after `gpg` itself exits, hanging any read loop waiting for
   EOF on that pipe. `Unix.create_process` still gets a correctly
   open, non-cloexec fd 0/1/2 in the child either way, since a
   `dup2`'d descriptor never inherits `CLOEXEC` from its source fd.
   Reproduced this exact hang (and confirmed the fix with `pgrep`)
   while building this module — see DECISIONS.md's ADR-0040. *)
let pipe () = Unix.pipe ~cloexec:true ()

(* stdin is written from a dedicated thread rather than sequentially
   before reading stdout/stderr — writing everything first and only
   then reading, as an earlier version of this function did, is an
   unconditional deadlock risk for any input near or past the OS pipe
   buffer size (traditionally 64KiB on Linux) once the child starts
   producing output before it has fully drained stdin, which `gpg
   --decrypt`/`--verify` genuinely does on real, plausibly-sized
   manifests. Reproduced the hang for real (a few hundred KB against
   `/bin/cat`, and again against real `gpg --decrypt` on a
   several-hundred-KB clearsigned manifest) before switching to this
   shape — see ADR-0041. *)
let write_stdin_in_background (fd : Unix.file_descr) (content : string) : unit
    =
  let oc = Unix.out_channel_of_descr fd in
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        try
          output_string oc content;
          close_out oc
        with Sys_error _ ->
          (* The child may exit (bad args, etc.) before reading all of
             stdin — a broken pipe here is not this function's error
             to report; the child's exit status is. *)
          ())
      ()
  in
  ()

let read_all (fd : Unix.file_descr) : string =
  let ic = Unix.in_channel_of_descr fd in
  let bufsize = 4096 in
  let chunk = Bytes.create bufsize in
  let buf = Buffer.create bufsize in
  let rec loop () =
    let n = input ic chunk 0 bufsize in
    if n > 0 then (
      Buffer.add_subbytes buf chunk 0 n;
      loop ())
  in
  loop ();
  close_in ic;
  Buffer.contents buf

type outcome = { stdout : string; stderr : string; exit_status : Unix.process_status }

let run_raw ~(prog : string) ~(argv : string array) ~(stdin_content : string) :
    outcome =
  let in_read, in_write = pipe () in
  let out_read, out_write = pipe () in
  let err_read, err_write = pipe () in
  let pid =
    try Unix.create_process prog argv in_read out_write err_write
    with e ->
      List.iter
        (fun fd -> try Unix.close fd with Unix.Unix_error _ -> ())
        [ in_read; in_write; out_read; out_write; err_read; err_write ];
      raise e
  in
  Unix.close in_read;
  Unix.close out_write;
  Unix.close err_write;
  write_stdin_in_background in_write stdin_content;
  let stdout = read_all out_read in
  let stderr = read_all err_read in
  let _, exit_status = Unix.waitpid [] pid in
  { stdout; stderr; exit_status }

(* Convenience wrapper for the common "I just want stdout on success,
   an error message otherwise" case (`sha256sum`, plain signing). *)
let run ~(prog : string) ~(argv : string array) ~(stdin_content : string) :
    (string, string) result =
  let o = run_raw ~prog ~argv ~stdin_content in
  match o.exit_status with
  | Unix.WEXITED 0 -> Ok o.stdout
  | Unix.WEXITED code ->
      Error
        (Printf.sprintf "%s exited %d: %s" (Filename.basename prog) code
           (String.trim o.stderr))
  | Unix.WSIGNALED n ->
      Error (Printf.sprintf "%s killed by signal %s" (Filename.basename prog) (describe_signal n))
  | Unix.WSTOPPED n ->
      Error (Printf.sprintf "%s stopped by signal %s" (Filename.basename prog) (describe_signal n))
