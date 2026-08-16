type error = Already_pinned | Io_error of string

let describe_error = function
  | Already_pinned -> "a core certificate is already pinned"
  | Io_error e -> Printf.sprintf "core pin I/O error: %s" e

let persist_pin (path : string) (contents : string) : (unit, error) result =
  let tmp_path = Printf.sprintf "%s.tmp-%d-%s" path (Unix.getpid ()) (Nonce.generate ()) in
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

  | exception Sys_error msg -> Error (Io_error msg)

let load_pin (path : string) : (string option, error) result =

  if not (Sys.file_exists path) then Ok None
  else
    match Fileutil.read_all_bytes path with
    | contents -> Ok (Some contents)
    | exception Sys_error msg -> Error (Io_error msg)
