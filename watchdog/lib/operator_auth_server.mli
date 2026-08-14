(* §2.1: the human-operator challenge-response network listener.
   main.ml's own header comment has documented this as missing since
   §3.3's first pass -- Auth/Session/Nonce/Operator_key are real,
   tested, standalone modules; this is what actually accepts a
   connection and calls them.

   Wire protocol, one line at a time over a Unix domain socket
   (client -> server marked *, otherwise server -> client):
     * connect
     server: "NOT_ENROLLED\n" (no key enrolled yet — see the first-run
       setup flow below, reachable only from here), or
     server: "NONCE <64 lowercase hex chars>\n"

   -- challenge-response flow (an operator key is already enrolled):
     * client signs exactly the nonce's hex characters (not the
       trailing newline, not the "NONCE " prefix) with their enrolled
       private key: `gpg --armor --detach-sign`
     * client sends the resulting armored signature block verbatim,
       ending with its own "-----END PGP SIGNATURE-----" line
     server: "OK <session token>\n", or "DENIED\n"

   -- first-run setup flow (§2.6/§3.11 steps 1-2; only reachable
      immediately after "NOT_ENROLLED" — once a key is enrolled this
      flow is never entered again, so it is not a standing bypass of
      the challenge-response flow above, just the one-time path that
      populates what that flow later authenticates against):
     * client sends "SETUP <token>\n", the plaintext read verbatim
       from /etc/fossh/setup-token (or wherever this install's
       FOSSH_SETUP_TOKEN_PATH points)
     server: "SETUP_OK\n" if Setup_token.verify accepts it right now,
       or "SETUP_DENIED\n" otherwise (wrong token, or nothing currently
       live — never generated, generation failed, already burned by an
       earlier successful setup, or a key is already enrolled by some
       other means)
     * on SETUP_OK, client sends the operator's own armored public key
       material verbatim (§3.11 step 2: pasted from an existing key, or
       freshly generated), ending with its own
       "-----END PGP PUBLIC KEY BLOCK-----" line
     server: "ENROLLED <fingerprint>\n" on success — which also burns
       the setup token in the same call (Setup_token.burn, invalidate-
       then-delete order per §2.6) so it cannot be replayed into a
       second enrollment attempt from any later connection — or
       "ENROLL_FAILED <reason code>\n" (the token is deliberately NOT
       burned on failure, so a bad paste can be retried with the same
       still-valid token; reason codes are a small fixed vocabulary —
       see enroll_failure_code in the .ml — never raw internal error
       text, which is logged server-side instead)
   Every read in this flow is bounded by the same connection-wide wall-
   clock [deadline] as the rest of this listener; there is no server-
   side state for this flow that outlives one connection, which is
   what actually rules out a captured SETUP_OK being replayed into a
   second connection's enrollment attempt, not merely a convention.

   Unix domain socket, not QUIC: unlike §3.4's core<->watchdog
   channel, an operator client has no X.509 identity to pin via mTLS
   and never will -- this gate authenticates by signature, not by
   transport-level certificate. Socket directory permissions are the
   local-access boundary; the signature check is the actual
   authentication. Satisfies §3.9/§3.11's requirement that the TUI use
   "the same local QUIC/Unix-socket channels already defined", not a
   new transport. *)

type config = { socket_path : string; operator_key_dir : string }

(* Binds [config.socket_path] and accepts connections forever, one at
   a time. Returns an error only if binding itself fails; a
   misbehaving individual connection never ends the loop -- bounded by
   [connection_timeout_seconds] (default 10s, overridable for tests)
   so a client that connects and never writes can't hang every
   connection queued behind it. *)
val run : ?connection_timeout_seconds:float -> config -> (unit, string) result
