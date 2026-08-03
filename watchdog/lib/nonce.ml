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

(* Compares two secret-derived strings (session tokens, in practice)
   without an early-exit on the first differing byte, so how many
   leading bytes matched isn't observable via response timing —
   ordinary `String.equal`/`=` short-circuit as soon as they find a
   mismatch, which is exactly the property a naive credential
   comparison must not have. Flagged as a real gap in ADR-0041 (§3.3's
   adversarial review) and left unfixed there specifically because
   nothing reachable at the time actually compared a session token
   against attacker-influenced input over a network — §3.4's own
   command protocol is that first reachable path.

   The one early-exit this function does have — differing lengths
   return `false` immediately — does not reintroduce that gap: unlike
   the token's actual *content*, its length is not a secret (every
   token this project issues is a fixed, public 64 hex characters,
   `generate`'s own output shape), so an attacker learning "that
   wasn't even the right length" learns nothing about the token
   itself. Constant-time comparison libraries elsewhere (e.g. Python's
   `hmac.compare_digest`) make the exact same trade-off for the exact
   same reason.

   That trade-off is safe *only* because every call site today
   compares two values whose length is public — this function does
   not itself enforce or check that assumption for whatever gets
   compared. If a future caller ever reaches for this to compare
   something whose *length itself* is sensitive (a password, as
   opposed to a fixed-shape generated token), the length short-circuit
   above would leak exactly the thing that caller needed protected —
   this function's name promises "constant-time" but its actual
   contract is narrower than that name suggests. Confirm the same
   fixed-length-and-not-secret property holds before adding a new call
   site, don't assume it from the name alone. *)
let constant_time_equal (a : string) (b : string) : bool =
  if String.length a <> String.length b then false
  else (
    let diff = ref 0 in
    for i = 0 to String.length a - 1 do
      diff := !diff lor (Char.code a.[i] lxor Char.code b.[i])
    done;
    !diff = 0)
