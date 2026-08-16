exception Entropy_unavailable of string

let read_random_bytes (n : int) : string =
  match open_in_bin "/dev/urandom" with
  | exception Sys_error msg ->
      raise (Entropy_unavailable ("opening /dev/urandom: " ^ msg))
  | ic ->
      Fun.protect
        ~finally:(fun () -> try close_in ic with Sys_error _ -> ())
        (fun () ->
          let buf = Bytes.create n in
          (try really_input ic buf 0 n with
          | End_of_file ->
              raise (Entropy_unavailable "/dev/urandom returned short read")
          | Sys_error msg ->
              raise (Entropy_unavailable ("reading /dev/urandom: " ^ msg)));
          Bytes.unsafe_to_string buf)

let hex_of_bytes (s : string) : string =
  let hex_digit c =
    if c < 10 then Char.chr (Char.code '0' + c)
    else Char.chr (Char.code 'a' + c - 10)
  in
  let n = String.length s in
  let out = Bytes.create (n * 2) in
  for i = 0 to n - 1 do
    let byte = Char.code s.[i] in
    Bytes.set out (2 * i) (hex_digit (byte lsr 4));
    Bytes.set out ((2 * i) + 1) (hex_digit (byte land 0x0f))
  done;
  Bytes.unsafe_to_string out

let generate_n (n : int) : string = hex_of_bytes (read_random_bytes n)

let generate () : string = generate_n 32

let constant_time_equal (a : string) (b : string) : bool =
  if String.length a <> String.length b then false
  else (
    let diff = ref 0 in
    for i = 0 to String.length a - 1 do
      diff := !diff lor (Char.code a.[i] lxor Char.code b.[i])
    done;
    !diff = 0)
