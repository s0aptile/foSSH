(* Cryptographically secure nonces read directly from the kernel CSPRNG
   ([/dev/urandom] on Linux) rather than OCaml's [Random] module, which
   is not cryptographically secure, and rather than pulling in a
   dedicated RNG library — §3.3 asks for this component's own
   dependency tree to stay as small as possible, since it is the last
   line of defense if foSSH core is compromised. [/dev/urandom], not
   [/dev/random], is deliberate: on any Linux kernel this project
   targets, it is backed by the same CSPRNG and never blocks. *)

let read_random_bytes (n : int) : string =
  let ic = open_in_bin "/dev/urandom" in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.unsafe_to_string buf

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

(* 32 bytes (256 bits) of entropy, hex-encoded — a single-use,
   short-lived challenge nonce (§2.1) or session token (Session). *)
let generate () : string = hex_of_bytes (read_random_bytes 32)
