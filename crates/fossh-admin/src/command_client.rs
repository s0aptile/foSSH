#![forbid(unsafe_code)]

pub const MAX_LINE_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Restart,
    Reload,
    Status,
}

impl Command {
    fn name(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Reload => "reload",
            Self::Status => "status",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    Running,
    Stopped,
}

impl ChildState {
    fn from_name(s: &str) -> Option<Self> {
        match s {
            "running" => Some(Self::Running),
            "stopped" => Some(Self::Stopped),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperState {
    Clean,
    Tampered,
    Unknown,
}

impl TamperState {
    fn from_name(s: &str) -> Option<Self> {
        match s {
            "clean" => Some(Self::Clean),
            "tampered" => Some(Self::Tampered),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Ok,
    Error(String),
    Status {
        child: ChildState,
        tamper: TamperState,
    },
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
            Self::LineTooLarge(n) => {
                write!(f, "line exceeded the {MAX_LINE_LEN}-byte cap (got {n})")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

fn looks_like_a_token(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ocaml_compatible_trim(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t'))
}

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

pub fn encode_command(session_token: &str, cmd: Command) -> String {
    format!("COMMAND {session_token} {}\n", cmd.name())
}

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
        match trimmed.split(' ').collect::<Vec<_>>().as_slice() {
            ["STATUS", child_tok, tamper_tok] => {
                match (
                    ChildState::from_name(child_tok),
                    TamperState::from_name(tamper_tok),
                ) {
                    (Some(child), Some(tamper)) => Ok(Response::Status { child, tamper }),
                    _ => Err(ProtocolError::Malformed(trimmed.to_string())),
                }
            }
            _ => Err(ProtocolError::Malformed(trimmed.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            encode_command(&token, Command::Status),
            format!("COMMAND {token} status\n")
        );
    }

    #[test]
    fn a_status_response_decodes_every_child_tamper_combination() {
        for (line, child, tamper) in [
            (
                "STATUS running clean\n",
                ChildState::Running,
                TamperState::Clean,
            ),
            (
                "STATUS running tampered\n",
                ChildState::Running,
                TamperState::Tampered,
            ),
            (
                "STATUS stopped unknown\n",
                ChildState::Stopped,
                TamperState::Unknown,
            ),
        ] {
            assert_eq!(
                decode_response(line),
                Ok(Response::Status { child, tamper })
            );
        }
    }

    #[test]
    fn a_status_response_with_an_unrecognized_field_is_malformed() {
        for line in [
            "STATUS running\n",
            "STATUS not-a-real-state clean\n",
            "STATUS running not-a-real-state\n",
            "STATUS running clean extra\n",
            "STATUS\n",
        ] {
            assert!(
                matches!(decode_response(line), Err(ProtocolError::Malformed(_))),
                "expected {line:?} to be rejected as malformed"
            );
        }
    }

    #[test]
    fn an_ok_response_decodes_cleanly() {
        assert_eq!(decode_response("OK\n"), Ok(Response::Ok));
    }

    #[test]
    fn an_error_response_carries_its_reason_text() {
        assert_eq!(
            decode_response(
                "ERROR session token missing, expired, revoked, or not this connection's own\n"
            ),
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
