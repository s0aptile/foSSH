open Fossh_watchdog_lib
open Test_helpers

let scratch_token_path (name : string) : string =
  Filename.concat (mkdtemp ()) (Printf.sprintf "setup-token-%s" name)

let () =

  let dir_a = mkdtemp () in
  let token_path_a = scratch_token_path "a" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_a;
      (try Sys.remove token_path_a with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_a))
    (fun () ->
      (match Setup_token.ensure ~token_path:token_path_a ~operator_key_dir:dir_a with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      check "ensure with no file and nothing enrolled generates a token file" (Sys.file_exists token_path_a);
      check "the generated token file is mode 0600"
        (let st = Unix.stat token_path_a in
         st.Unix.st_perm = 0o600);
      let plaintext = String.trim (Fileutil.read_all_bytes token_path_a) in
      check "the generated token verifies" (Setup_token.verify plaintext);
      check "a wrong token does not verify" (not (Setup_token.verify "definitely-not-the-token"));

      (match Setup_token.ensure ~token_path:token_path_a ~operator_key_dir:dir_a with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let plaintext_again = String.trim (Fileutil.read_all_bytes token_path_a) in
      check "a second ensure() call does not regenerate the token file" (plaintext = plaintext_again);
      check "the original token still verifies after a second ensure() call" (Setup_token.verify plaintext));

  let dir_c = mkdtemp () in
  let token_path_c = scratch_token_path "c" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_c;
      (try Sys.remove token_path_c with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_c))
    (fun () ->
      let fd = Unix.openfile token_path_c [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
      let oc = Unix.out_channel_of_descr fd in
      output_string oc "a-token-written-by-someone-else";
      close_out oc;
      (match Setup_token.ensure ~token_path:token_path_c ~operator_key_dir:dir_c with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      check "ensure() recovers (not regenerates) an existing token file"
        (String.trim (Fileutil.read_all_bytes token_path_c) = "a-token-written-by-someone-else");
      check "the recovered token verifies" (Setup_token.verify "a-token-written-by-someone-else");
      check "a different token does not verify against a recovered file" (not (Setup_token.verify "something-else")));

  let dir_d = mkdtemp () in
  let token_path_d = scratch_token_path "d" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_d;
      (try Sys.remove token_path_d with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_d))
    (fun () ->
      let operator = generate_key ~uid:"operator <operator@example.invalid>" () in
      (match Operator_key.enroll ~dir:dir_d (export_pubkey operator) with
      | Ok _ -> ()
      | Error e -> failwith (Operator_key.describe_error e));
      (match Setup_token.ensure ~token_path:token_path_d ~operator_key_dir:dir_d with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      check "ensure() does not generate a token file once a key is already enrolled"
        (not (Sys.file_exists token_path_d));
      check "nothing verifies once a key is already enrolled" (not (Setup_token.verify ""));

      (match Setup_token.burn () with
      | Ok () -> check "burn() with nothing live is a no-op success" true
      | Error e -> failwith ("burn() with nothing live should succeed: " ^ Setup_token.describe_error e));
      cleanup operator);

  let dir_f = mkdtemp () in
  let token_path_f = scratch_token_path "f" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_f;
      (try Sys.remove token_path_f with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_f))
    (fun () ->
      (match Setup_token.ensure ~token_path:token_path_f ~operator_key_dir:dir_f with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let plaintext = String.trim (Fileutil.read_all_bytes token_path_f) in
      check "token verifies before burn" (Setup_token.verify plaintext);
      (match Setup_token.burn () with
      | Ok () -> ()
      | Error e -> failwith ("burn() failed: " ^ Setup_token.describe_error e));
      check "burn() deletes the token file" (not (Sys.file_exists token_path_f));
      check "the token no longer verifies after burn()" (not (Setup_token.verify plaintext));
      (match Setup_token.burn () with
      | Ok () -> check "a second burn() call is still a harmless no-op" true
      | Error e -> failwith ("a second burn() call should still succeed: " ^ Setup_token.describe_error e)));

  let dir_g = mkdtemp () in
  let token_path_g = scratch_token_path "g" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_g;
      (try Sys.remove token_path_g with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_g))
    (fun () ->
      (match Setup_token.ensure ~token_path:token_path_g ~operator_key_dir:dir_g with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let plaintext = String.trim (Fileutil.read_all_bytes token_path_g) in
      let thread_count = 20 in
      let failures = Array.make thread_count None in
      let threads =
        Array.init thread_count (fun i ->
            Thread.create
              (fun () ->
                try
                  match Setup_token.burn () with
                  | Ok () -> ()
                  | Error e -> failures.(i) <- Some (Setup_token.describe_error e)
                with e -> failures.(i) <- Some (Printexc.to_string e))
              ())
      in
      Array.iter Thread.join threads;
      check "no racing burn() call raised or returned an error"
        (Array.for_all (fun f -> f = None) failures);
      check "the token file is gone after the race" (not (Sys.file_exists token_path_g));
      check "the token no longer verifies after the race" (not (Setup_token.verify plaintext)));

  let dir_h = mkdtemp () in
  let token_path_h = scratch_token_path "h" in
  Fun.protect
    ~finally:(fun () ->
      rm_rf dir_h;
      (try Sys.remove token_path_h with Sys_error _ -> ());
      rm_rf (Filename.dirname token_path_h))
    (fun () ->
      (match Setup_token.ensure ~token_path:token_path_h ~operator_key_dir:dir_h with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let plaintext = String.trim (Fileutil.read_all_bytes token_path_h) in

      let contestant_count = 6 in
      let contestants =
        List.init contestant_count (fun i ->
            generate_key ~uid:(Printf.sprintf "h-racer%d <h-racer%d@example.invalid>" i i) ())
      in
      let pubkeys = List.map export_pubkey contestants in
      let outcomes = Array.make contestant_count `Not_run in
      let latch = make_latch () in
      let threads =
        List.mapi
          (fun i pubkey ->
            Thread.create
              (fun () ->

                let token_is_valid = Setup_token.verify plaintext in
                arrive_and_wait latch contestant_count;
                if not token_is_valid then outcomes.(i) <- `Verify_failed
                else
                  match Operator_key.enroll ~dir:dir_h pubkey with
                  | Error Operator_key.Already_enrolled -> outcomes.(i) <- `Already_enrolled
                  | Error e -> outcomes.(i) <- `Other_error (Operator_key.describe_error e)
                  | Ok fingerprint -> (
                      match Setup_token.burn () with
                      | Ok () -> outcomes.(i) <- `Enrolled fingerprint
                      | Error e -> outcomes.(i) <- `Enrolled_but_burn_failed (fingerprint, Setup_token.describe_error e)))
              ())
          pubkeys
      in
      List.iter Thread.join threads;

      let winners =
        Array.to_list outcomes
        |> List.filter_map (function
             | `Enrolled fp -> Some fp
             | `Enrolled_but_burn_failed (fp, _) -> Some fp
             | _ -> None)
      in
      let losers =
        Array.to_list outcomes |> List.filter (function `Already_enrolled -> true | _ -> false)
      in
      check "every thread saw the token as valid before the latch released"
        (Array.for_all (fun o -> o <> `Verify_failed) outcomes);
      check "no unexpected error occurred under forced overlap"
        (Array.for_all (function `Other_error _ -> false | _ -> true) outcomes);
      check "exactly one thread wins the real, forced-overlap enrollment race" (List.length winners = 1);
      check "every other thread is refused as already_enrolled, not silently dropped or duplicated"
        (List.length losers = contestant_count - 1);
      check "the winning fingerprint matches one of the real contestant keys"
        (match winners with
        | [ fp ] -> List.exists (fun k -> k.fingerprint = fp) contestants
        | _ -> false);
      check "the token is burned after the forced-overlap race" (not (Sys.file_exists token_path_h));
      check "the token no longer verifies after the forced-overlap race" (not (Setup_token.verify plaintext));

      List.iter cleanup contestants);

  summarize ()
