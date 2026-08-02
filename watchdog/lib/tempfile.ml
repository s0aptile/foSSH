(* [gpgv]/[gpg] take file paths, not stdin, for keyrings and detached
   signatures — this writes [contents] to a fresh temp file and runs
   [f] against its path, removing it afterward whether [f] raises or
   not. [Filename.temp_file] creates the file at mode 0600 from the
   [open()] call itself (documented stdlib behavior, and covered by
   this lib's own test suite rather than just trusted) — there is no
   separate chmod step to get right or forget. *)
let with_contents (contents : string) (f : string -> 'a) : 'a =
  let path = Filename.temp_file "fossh-watchdog-" ".tmp" in
  Fun.protect
    ~finally:(fun () -> try Sys.remove path with Sys_error _ -> ())
    (fun () ->
      let oc = open_out_bin path in
      output_string oc contents;
      close_out oc;
      f path)
