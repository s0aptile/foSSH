let openssl_path = "/usr/bin/openssl"

let validity_days = 3650

type error =
  | Generate_failed of string
  | Invalid_common_name of string
  | Io_error of string

let describe_error = function
  | Generate_failed e -> Printf.sprintf "generating TLS identity: %s" e
  | Invalid_common_name cn -> Printf.sprintf "invalid common name %S" cn
  | Io_error e -> Printf.sprintf "TLS identity I/O error: %s" e

type t = { cert_pem_path : string; key_pem_path : string }

let valid_common_name_re =
  let is_ok c =
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c = '-' || c = '.'
  in
  fun s -> String.length s > 0 && String.length s <= 64 && String.for_all is_ok s

let cert_is_valid (path : string) : bool =
  Sys.file_exists path
  &&
  match
    Subprocess.run ~prog:openssl_path
      ~argv:[| "openssl"; "x509"; "-in"; path; "-noout"; "-checkend"; "0" |]
      ~stdin_content:""
  with
  | Ok _ -> true
  | Error _ -> false

let key_is_valid (path : string) : bool =
  Sys.file_exists path
  &&
  match
    Subprocess.run ~prog:openssl_path ~argv:[| "openssl"; "pkey"; "-in"; path; "-noout" |]
      ~stdin_content:""
  with
  | Ok _ -> true
  | Error _ -> false

let generation_lock = Mutex.create ()

let ensure_identity ~(dir : string) ~(common_name : string) : (t, error) result =
  if not (valid_common_name_re common_name) then Error (Invalid_common_name common_name)
  else
    Mutex.protect generation_lock (fun () ->
        try
          (try Unix.mkdir dir 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
          let cert_pem_path = Filename.concat dir "cert.pem" in
          let key_pem_path = Filename.concat dir "key.pem" in
          if cert_is_valid cert_pem_path && key_is_valid key_pem_path then
            Ok { cert_pem_path; key_pem_path }
          else
            match
              Subprocess.run ~prog:openssl_path
                ~argv:
                  [|
                    "openssl"; "req"; "-x509"; "-newkey"; "ec"; "-pkeyopt";
                    "ec_paramgen_curve:prime256v1"; "-days"; string_of_int validity_days; "-nodes";
                    "-keyout"; key_pem_path; "-out"; cert_pem_path; "-subj";
                    Printf.sprintf "/CN=%s" common_name;
                  |]
                ~stdin_content:""
            with
            | Error e -> Error (Generate_failed e)
            | Ok _ ->

                Unix.chmod key_pem_path 0o600;
                Ok { cert_pem_path; key_pem_path }
        with Unix.Unix_error (e, fn, _) -> Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e))))
