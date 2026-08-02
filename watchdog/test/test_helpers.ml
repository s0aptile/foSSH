(* Shared test scaffolding: a fresh, throwaway GNUPGHOME per test with
   a real Ed25519 signing key generated in it — every test in this
   suite exercises the real `gpg`/`gpgv` binaries against real keys,
   not a mock or a hand-rolled stand-in for OpenPGP semantics. *)

open Fossh_watchdog_lib

let mkdtemp () =
  let base = Filename.temp_file "fossh-watchdog-test-" "" in
  Sys.remove base;
  Unix.mkdir base 0o700;
  base

let rec rm_rf path =
  match Unix.((lstat path).st_kind) with
  | Unix.S_DIR ->
      Sys.readdir path
      |> Array.iter (fun name -> rm_rf (Filename.concat path name));
      Unix.rmdir path
  | _ -> Sys.remove path
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ()

type key = { gnupghome : string; key_id : string; pubkey_binary : string }

let generate_key ?(uid = "test <test@example.invalid>") () : key =
  let gnupghome = mkdtemp () in
  (match
     Subprocess.run ~prog:"/usr/bin/gpg"
       ~argv:
         [|
           "gpg";
           "--batch";
           "--homedir";
           gnupghome;
           "--passphrase";
           "";
           "--quick-generate-key";
           uid;
           "ed25519";
           "sign";
           "0";
         |]
       ~stdin_content:""
   with
  | Ok _ -> ()
  | Error e -> failwith ("test key generation failed: " ^ e));
  let key_id =
    match
      Subprocess.run ~prog:"/usr/bin/gpg"
        ~argv:
          [|
            "gpg";
            "--batch";
            "--homedir";
            gnupghome;
            "--with-colons";
            "--list-secret-keys";
          |]
        ~stdin_content:""
    with
    | Error e -> failwith ("listing test key failed: " ^ e)
    | Ok listing ->
        (* --with-colons "fpr" lines: fpr:::::::::<FINGERPRINT>::: *)
        let found =
          String.split_on_char '\n' listing
          |> List.find_map (fun line ->
                 if String.length line > 4 && String.sub line 0 4 = "fpr:" then
                   match String.split_on_char ':' line with
                   | _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: fpr :: _ ->
                       Some fpr
                   | _ -> None
                 else None)
        in
        (* NB: `Option.value ~default:(failwith ...) found` would call
           `failwith` unconditionally — `~default` is a plain, eagerly
           evaluated argument, not a lazy thunk, in OCaml. A real match
           is required to make the failure conditional. *)
        match found with
        | Some fpr -> fpr
        | None -> failwith "could not find fingerprint in gpg listing"
  in
  let pubkey_binary =
    match
      Subprocess.run ~prog:"/usr/bin/gpg"
        ~argv:[| "gpg"; "--batch"; "--homedir"; gnupghome; "--export"; key_id |]
        ~stdin_content:""
    with
    | Ok bin -> bin
    | Error e -> failwith ("exporting test pubkey failed: " ^ e)
  in
  { gnupghome; key_id; pubkey_binary }

let detach_sign (k : key) (data : string) : string =
  Tempfile.with_contents data (fun data_path ->
      let sig_path = Filename.temp_file "fossh-watchdog-test-" ".sig" in
      Fun.protect
        ~finally:(fun () -> try Sys.remove sig_path with Sys_error _ -> ())
        (fun () ->
          match
            Subprocess.run ~prog:"/usr/bin/gpg"
              ~argv:
                [|
                  "gpg";
                  "--batch";
                  "--homedir";
                  k.gnupghome;
                  "--local-user";
                  k.key_id;
                  "--yes";
                  "--detach-sign";
                  "--output";
                  sig_path;
                  data_path;
                |]
              ~stdin_content:""
          with
          | Error e -> failwith ("detached sign failed: " ^ e)
          | Ok _ ->
              let ic = open_in_bin sig_path in
              let len = in_channel_length ic in
              let content = really_input_string ic len in
              close_in ic;
              content))

let cleanup (k : key) : unit = rm_rf k.gnupghome

let checks_run = ref 0
let checks_failed = ref 0

let check name cond =
  incr checks_run;
  if not cond then (
    incr checks_failed;
    Printf.eprintf "FAIL: %s\n%!" name)
  else Printf.eprintf "ok:   %s\n%!" name

let summarize () =
  Printf.eprintf "\n%d/%d checks passed\n%!"
    (!checks_run - !checks_failed)
    !checks_run;
  if !checks_failed > 0 then exit 1
