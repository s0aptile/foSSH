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

let pipe () = Unix.pipe ~cloexec:true ()

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
