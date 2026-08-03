//! §3.4's app-level command protocol — core's (`fossh-svc`'s) side.
//! `watchdog/lib/command_protocol.ml` is the responder (issues and
//! verifies session tokens, dispatches to `Supervisor`); this module
//! is the initiator's counterpart, wire-compatible with it but far
//! smaller, since core never issues or verifies a session — it only
//! ever echoes back the token the watchdog already handed it. No Rust
//! equivalent of this existed anywhere before ADR-0050: tracing task
//! #31's wiring found the wire protocol built and tested on the OCaml
//! side only, with nothing on core's side able to speak it at all.
//!
//! Deliberately QUIC-independent pure logic, exactly like its OCaml
//! counterpart — this module has no `fossh-ipc`/`quiche` dependency
//! and is tested without a live connection. The caller (gated behind
//! `fossh-fcgi`'s own `quic` feature, since that's where `fossh-ipc`
//! actually lives) is responsible for getting these encoded lines
//! onto and off of a real stream.

#![forbid(unsafe_code)]

pub const MAX_LINE_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Restart,
    Reload,
}

impl Command {
    fn name(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Reload => "reload",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Ok,
    Error(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Malformed(String),
    LineTooLarge(usize),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(line) => write!(f, "malformed message: {line:?}"),
            Self::LineTooLarge(n) => write!(f, "line exceeded the {MAX_LINE_LEN}-byte cap (got {n})"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Same 64-lowercase-hex shape `command_protocol.ml`'s own
/// `looks_like_a_token` enforces (`Nonce.generate`'s output shape) —
/// kept in lockstep with that function rather than re-derived, since
/// a mismatch here would silently make every real session token this
/// side ever receives fail its own syntax check.
fn looks_like_a_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// OCaml's `String.trim` (used throughout `command_protocol.ml`'s own
/// `decode_session_hello`/`decode_command`/`decode_response`) strips
/// exactly `' '`, `'\x0c'`, `'\n'`, `'\r'`, `'\t'` — a fixed ASCII
/// set, per its own documented behavior. Rust's `str::trim` strips
/// every Unicode-whitespace codepoint instead (confirmed empirically:
/// it removes a trailing U+00A0 NBSP; OCaml's `String.trim` does
/// not). Adversarial review flagged this divergence directly: two
/// parsers meant to accept the identical wire text were not actually
/// doing the identical thing, even though currently inert (neither
/// side's own `encode_*` ever produces non-ASCII whitespace) — real
/// protocol drift a same-language unit test on either side alone
/// could never surface. This trims exactly OCaml's set so both sides
/// parse byte-for-byte identically, not just "close enough" on the
/// inputs each side's own tests happen to try.
fn ocaml_compatible_trim(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t'))
}

/// Parses a `SESSION <token>` line (the responder's first message on
/// a fresh connection) and returns the token, unvalidated beyond
/// syntax — this side has no way to independently verify a session
/// token's *validity*, only its shape; the token is only ever
/// meaningful to whichever side issued it.
pub fn decode_session_hello(line: &str) -> Result<String, ProtocolError> {
    if line.len() > MAX_LINE_LEN {
        return Err(ProtocolError::LineTooLarge(line.len()));
    }
    let trimmed = ocaml_compatible_trim(line);
    match trimmed.split(' ').collect::<Vec<_>>().as_slice() {
        ["SESSION", token] if looks_like_a_token(token) => Ok((*token).to_string()),
        _ => Err(ProtocolError::Malformed(trimmed.to_string())),
    }
}

/// Encodes a `COMMAND <token> <name>` line — the wire-exact
/// counterpart to `command_protocol.ml`'s own `encode_command`.
pub fn encode_command(session_token: &str, cmd: Command) -> String {
    format!("COMMAND {session_token} {}\n", cmd.name())
}

/// Parses an `OK` / `ERROR <reason>` reply line.
pub fn decode_response(line: &str) -> Result<Response, ProtocolError> {
    if line.len() > MAX_LINE_LEN {
        return Err(ProtocolError::LineTooLarge(line.len()));
    }
    let trimmed = ocaml_compatible_trim(line);
    if trimmed == "OK" {
        Ok(Response::Ok)
    } else if let Some(reason) = trimmed.strip_prefix("ERROR ") {
        Ok(Response::Error(reason.to_string()))
    } else {
        Err(ProtocolError::Malformed(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nonce.generate's own output shape: 64 lowercase hex chars. Built
    // by repeating a 16-char unit rather than hand-typed, after a
    // hand-typed version of this string silently landed 2 characters
    // short and only surfaced as a confusing "malformed" test failure.
    fn real_token() -> String {
        let token = "0123456789abcdef".repeat(4);
        assert_eq!(token.len(), 64);
        token
    }

    #[test]
    fn a_well_formed_session_hello_round_trips() {
        let token = real_token();
        let line = format!("SESSION {token}\n");
        assert_eq!(decode_session_hello(&line), Ok(token));
    }

    #[test]
    fn trimming_matches_ocaml_string_trim_exactly_not_rust_str_trim() {
        // A trailing NBSP (U+00A0): Rust's `str::trim` strips it
        // (Unicode-whitespace-aware); OCaml's `String.trim` does not
        // (fixed ASCII set only). Kept attached here — matching
        // OCaml, not Rust's own default — is the whole point of
        // `ocaml_compatible_trim`; this pins that choice down as a
        // real regression test, not just a doc comment's claim.
        assert_eq!(ocaml_compatible_trim("OK\u{a0}"), "OK\u{a0}");
        assert_eq!(ocaml_compatible_trim(" OK \n"), "OK");
        assert_eq!(ocaml_compatible_trim("\x0cOK\x0c"), "OK");
    }

    #[test]
    fn a_session_hello_with_a_non_hex_token_is_malformed() {
        assert!(decode_session_hello("SESSION not-a-real-token\n").is_err());
    }

    #[test]
    fn a_session_hello_missing_its_keyword_is_malformed() {
        assert!(decode_session_hello(&format!("{}\n", real_token())).is_err());
    }

    #[test]
    fn an_oversized_line_is_line_too_large_not_a_panic() {
        let huge = "SESSION ".to_string() + &"a".repeat(MAX_LINE_LEN + 100);
        assert_eq!(
            decode_session_hello(&huge),
            Err(ProtocolError::LineTooLarge(huge.len()))
        );
    }

    #[test]
    fn encode_command_matches_the_ocaml_side_wire_shape_exactly() {
        let token = real_token();
        assert_eq!(
            encode_command(&token, Command::Restart),
            format!("COMMAND {token} restart\n")
        );
        assert_eq!(
            encode_command(&token, Command::Reload),
            format!("COMMAND {token} reload\n")
        );
    }

    #[test]
    fn an_ok_response_decodes_cleanly() {
        assert_eq!(decode_response("OK\n"), Ok(Response::Ok));
    }

    #[test]
    fn an_error_response_carries_its_reason_text() {
        assert_eq!(
            decode_response("ERROR session token missing, expired, revoked, or not this connection's own\n"),
            Ok(Response::Error(
                "session token missing, expired, revoked, or not this connection's own".to_string()
            ))
        );
    }

    #[test]
    fn a_garbage_response_line_is_rejected_not_misparsed() {
        assert!(matches!(
            decode_response("garbage\n"),
            Err(ProtocolError::Malformed(_))
        ));
    }
}
