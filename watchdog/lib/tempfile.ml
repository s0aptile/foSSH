let with_contents (contents : string) (f : string -> 'a) : 'a =
  let path = Filename.temp_file "fossh-watchdog-" ".tmp" in
  Fun.protect
    ~finally:(fun () -> try Sys.remove path with Sys_error _ -> ())
    (fun () ->
      let oc = open_out_bin path in
      output_string oc contents;
      close_out oc;
      f path)
