open Fossh_watchdog_lib
open Test_helpers

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      let pin_path = Filename.concat dir "core.pin" in

      check "load_pin of a file that doesn't exist yet is None, not an error"
        (Core_pin.load_pin pin_path = Ok None);

      check "persist_pin succeeds the first time"
        (Core_pin.persist_pin pin_path "fake-cert-pem" = Ok ());

      check "load_pin then returns exactly what was persisted"
        (Core_pin.load_pin pin_path = Ok (Some "fake-cert-pem"));

      check "persist_pin refuses to overwrite an existing pin"
        (match Core_pin.persist_pin pin_path "different-cert-pem" with
        | Error Core_pin.Already_pinned -> true
        | _ -> false);

      check "the original pin content is untouched after a refused overwrite"
        (Core_pin.load_pin pin_path = Ok (Some "fake-cert-pem"));

      check "no leftover temp file survives a successful persist"
        (Sys.readdir dir |> Array.to_list |> List.filter (fun f -> f <> "core.pin") = []);

      check "the pin file is written at mode 0600"
        (let st = Unix.stat pin_path in
         st.Unix.st_perm = 0o600);

      summarize ())
