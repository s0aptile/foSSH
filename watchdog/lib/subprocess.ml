(* Shared helper for shelling out to `gpgv`/`gpg`/`sha256sum` via an
   argv array, never a shell string — every caller in this codebase
   passes untrusted or semi-trusted data (file paths, key IDs, nonce
   bytes) as separate argv/stdin elements, so there is no shell
   metacharacter injection surface, matching the same discipline the
   Rust side of this project holds itself to for SQL/shell contexts. *)

(* Bounded content only (a manifest or a nonce is at most a few KB) —
   sequential write-then-read cannot deadlock against the OS pipe
   buffer at this size. A general-purpose subprocess helper would need
   concurrent read/write via [select]; this one deliberately doesn't,
   because nothing in this codebase ever calls it with large input. *)
let run ~(prog : string) ~(argv : string array) ~(stdin_content : string) :
    (string, string) result =
  (* [~cloexec:true] on every pipe fd matters here specifically
     because `gpg` (this module's only real caller) spawns
     `gpg-agent`, a lingering background daemon, as a side effect of
     some operations. Without close-on-exec, `gpg-agent` inherits our
     `out_write`/`err_write` fds across gpg's own exec and keeps them
     open indefinitely (`Unix.create_process` still gets a correctly
     open, non-cloexec fd 0/1/2 in the child either way, since dup2'd
     descriptors never inherit CLOEXEC from their source) — the read
     loop below then blocks forever waiting for an EOF that only
     happens once *every* holder of the write end has closed it, not
     just the gpg process we actually waited for. Confirmed by
     reproducing the hang with this set to [false] before fixing it,
     not assumed. *)
  let in_read, in_write = Unix.pipe ~cloexec:true () in
  let out_read, out_write = Unix.pipe ~cloexec:true () in
  let err_read, err_write = Unix.pipe ~cloexec:true () in
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
  let oc = Unix.out_channel_of_descr in_write in
  (try
     output_string oc stdin_content;
     close_out oc
   with Sys_error _ ->
     (* The child may have exited (e.g. bad args) before reading all
        of stdin — a broken pipe here is not this function's error to
        report; the exit status below is. *)
     ());
  let read_all fd =
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
  in
  let stdout_content = read_all out_read in
  let stderr_content = read_all err_read in
  let _, status = Unix.waitpid [] pid in
  match status with
  | Unix.WEXITED 0 -> Ok stdout_content
  | Unix.WEXITED code ->
      Error
        (Printf.sprintf "%s exited %d: %s" (Filename.basename prog) code
           (String.trim stderr_content))
  | Unix.WSIGNALED n ->
      Error (Printf.sprintf "%s killed by signal %d" (Filename.basename prog) n)
  | Unix.WSTOPPED n ->
      Error (Printf.sprintf "%s stopped by signal %d" (Filename.basename prog) n)
