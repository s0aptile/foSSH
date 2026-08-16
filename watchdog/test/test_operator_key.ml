open Fossh_watchdog_lib
open Test_helpers

let add_encryption_subkey (k : key) : unit =
  let (_ : string) =
    run_gpg_ok ~gnupghome:k.gnupghome
      [
        "--pinentry-mode"; "loopback"; "--passphrase"; k.passphrase; "--quick-add-key"; k.fingerprint;
        "cv25519"; "encr"; "0";
      ]
  in
  ()

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      check "nothing enrolled yet" (Operator_key.enrolled_fingerprint ~dir = Ok None);

      let operator = generate_key ~uid:"operator <operator@example.invalid>" () in
      let pubkey = export_pubkey operator in

      (match Operator_key.enroll ~dir pubkey with
      | Error e -> failwith (Operator_key.describe_error e)
      | Ok fpr -> check "enroll returns the real fingerprint" (fpr = operator.fingerprint));

      check "enrolled_fingerprint reflects the enrollment"
        (Operator_key.enrolled_fingerprint ~dir = Ok (Some operator.fingerprint));

      check "enrolling a second time is refused, not silently replaced"
        (match Operator_key.enroll ~dir pubkey with
        | Error Operator_key.Already_enrolled -> true
        | _ -> false);

      let other_dir = mkdtemp () in
      Fun.protect
        ~finally:(fun () -> rm_rf other_dir)
        (fun () ->
          let second = generate_key ~uid:"second <second@example.invalid>" () in
          check "importing more than one key at once is rejected, not silently picking one"
            (match Operator_key.enroll ~dir:other_dir (pubkey ^ export_pubkey second) with
            | Error Operator_key.Multiple_keys_imported -> true
            | _ -> false);
          check "the rejected import did not partially enroll" (Operator_key.enrolled_fingerprint ~dir:other_dir = Ok None);

          (match Operator_key.enroll ~dir:other_dir (export_pubkey second) with
          | Error e ->
              failwith
                ("enrolling a single valid key after an earlier rejected multi-key attempt should \
                  succeed, not carry over poisoned state: " ^ Operator_key.describe_error e)
          | Ok fpr ->
              check "a clean single-key enroll succeeds even after an earlier rejected attempt on the same dir"
                (fpr = second.fingerprint));

          cleanup second);

      let with_subkey_dir = mkdtemp () in
      Fun.protect
        ~finally:(fun () -> rm_rf with_subkey_dir)
        (fun () ->
          let keyed = generate_key ~uid:"has-subkey <has-subkey@example.invalid>" () in
          add_encryption_subkey keyed;
          (match Operator_key.enroll ~dir:with_subkey_dir (export_pubkey keyed) with
          | Error e -> failwith ("a real key with a subkey should enroll cleanly: " ^ Operator_key.describe_error e)
          | Ok fpr -> check "a key with a subkey enrolls using its PRIMARY fingerprint" (fpr = keyed.fingerprint));
          cleanup keyed);

      let garbage_dir = mkdtemp () in
      Fun.protect
        ~finally:(fun () -> rm_rf garbage_dir)
        (fun () ->
          check "garbage input is a clean error, not a crash"
            (match Operator_key.enroll ~dir:garbage_dir "this is not key material" with
            | Error _ -> true
            | Ok _ -> false));

      let racing_dir = mkdtemp () in
      Fun.protect
        ~finally:(fun () -> rm_rf racing_dir)
        (fun () ->
          let contestant_count = 6 in
          let contestants =
            List.init contestant_count (fun i ->
                generate_key ~uid:(Printf.sprintf "racer%d <racer%d@example.invalid>" i i) ())
          in
          let pubkeys = List.map export_pubkey contestants in
          let outcomes : (string, Operator_key.error) result option array =
            Array.make contestant_count None
          in
          let latch = make_latch () in
          let threads =
            List.mapi
              (fun i pubkey ->
                Thread.create
                  (fun () ->
                    arrive_and_wait latch contestant_count;
                    outcomes.(i) <- Some (Operator_key.enroll ~dir:racing_dir pubkey))
                  ())
              pubkeys
          in
          List.iter Thread.join threads;
          let winners =
            Array.to_list outcomes |> List.filter_map (function Some (Ok fp) -> Some fp | _ -> None)
          in
          let clean_losers =
            Array.to_list outcomes
            |> List.filter (function Some (Error Operator_key.Already_enrolled) -> true | _ -> false)
          in
          check "under real, forced-overlap thread concurrency, exactly one enroll call wins"
            (List.length winners = 1);
          check "every other concurrent thread is cleanly refused as Already_enrolled, not a garbled gpg error"
            (List.length clean_losers = contestant_count - 1);
          List.iter cleanup contestants);

      cleanup operator;
      summarize ())
