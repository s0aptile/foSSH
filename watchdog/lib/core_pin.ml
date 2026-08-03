(* §2.4, extended (see ADR-0048/ADR-0050): the watchdog's own record of
   core's X.509 certificate, received once over the bootstrap handoff
   and never silently replaced afterward — the mirror image, on this
   side, of `fossh_admin::watchdog_pin`'s pin files on core's side.
   Same atomicity shape as that Rust module's `persist_pin`: write to a
   pid-suffixed temp file first, then `link` it into place — `link`
   fails outright if the destination already exists, which is what
   actually enforces "regeneration requires a full re-bootstrap, not a
   silent rotation" (§2.4) at the write itself, not just in a comment.
   A crash between the temp write and the link leaves only an orphaned
   temp file behind, never a partially-written file under the real pin
   path. *)

type error = Already_pinned | Io_error of string

let describe_error = function
  | Already_pinned -> "a core certificate is already pinned"
  | Io_error e -> Printf.sprintf "core pin I/O error: %s" e

let persist_pin (path : string) (contents : string) : (unit, error) result =
  let tmp_path = Printf.sprintf "%s.tmp-%d" path (Unix.getpid ()) in
  match
    let fd = Unix.openfile tmp_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
    Fun.protect
      ~finally:(fun () -> try Sys.remove tmp_path with Sys_error _ -> ())
      (fun () ->
        let oc = Unix.out_channel_of_descr fd in
        output_string oc contents;
        close_out oc;
        Unix.link tmp_path path)
  with
  | () -> Ok ()
  | exception Unix.Unix_error (Unix.EEXIST, "link", _) -> Error Already_pinned
  | exception Unix.Unix_error (e, fn, _) ->
      Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  (* Adversarial-review finding (HIGH): `output_string`/`close_out` are
     `Stdlib` channel operations, which raise `Sys_error`, not
     `Unix.Unix_error` — the exact same footgun already found and
     fixed once this same pass in `bootstrap.ml`'s `read_pem_block`
     (a reset connection there), reproduced here too via a forced
     `EFBIG`/`Sys_error "File too large"` (`ulimit -f 1`) standing in
     for any real disk-full/quota condition. Without this, the one
     real caller (`bootstrap-send`, immediately after a successful
     handoff) would crash with a generic uncaught-exception message
     instead of the documented, distinct exit code 6 `main.ml`'s own
     header comment promises specifically so a systemd unit/alerting
     hook has something to key off. *)
  | exception Sys_error msg -> Error (Io_error msg)

let load_pin (path : string) : (string option, error) result =
  (* `Sys.file_exists` first, not a bare `Fileutil.read_all_bytes`
     with every `Sys_error` mapped to `Ok None`: adversarial review
     noted the original version misreported a real permissions/IO
     failure on an *existing* pin file as "not yet pinned" — a
     misleading diagnostic for an operator, not just a missing-file
     case. Mirrors `fossh_admin::watchdog_pin::load_pin`'s own Rust-
     side semantics, which only maps `ErrorKind::NotFound` (not every
     `io::Error`) to `Ok(None)`. *)
  if not (Sys.file_exists path) then Ok None
  else
    match Fileutil.read_all_bytes path with
    | contents -> Ok (Some contents)
    | exception Sys_error msg -> Error (Io_error msg)
