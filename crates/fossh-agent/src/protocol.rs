//! The wire types `fossh-console` and this binary agree on.
//!
//! One JSON object per line, in both directions, over the agent's own
//! stdin/stdout — no socket, no port, no listener. The console spawns
//! this process as a child and owns both pipes for its lifetime, which
//! is the entire access-control story: there is nothing here to
//! authenticate to, because there is no way for a second process to
//! reach it in the first place.
//!
//! Why a bridge process at all rather than reimplementing these
//! surfaces in Python: every protocol this exposes already has exactly
//! one hardened implementation (`operator_auth_client.rs`'s SETUP and
//! challenge-response flows, `watchdog_status.rs`'s QUIC/mTLS status
//! query, `fossh-store`'s k-anonymity fold), and this project's own
//! history is unusually clear about what a *second* implementation of
//! an already-working wire protocol costs — see ADR-0050's stream-ID
//! bug and its `trim()` divergence, both interop-only bugs that
//! neither side's own same-language test suite could ever have caught.
//! A Python reimplementation would have been a third. See ADR-0061.
//!
//! ## Error codes
//!
//! `code` is a small, closed, stable set specifically so the console
//! can branch on it without matching on human-readable text. `message`
//! is for humans and may change freely; `code` may not.

use serde::{Deserialize, Serialize};

/// Bumped only on a breaking change to the shapes in this file. The
/// console checks this at handshake time and refuses to run against a
/// mismatch rather than guessing — a version-skewed pair (a
/// freshly-updated console against an agent still on disk from the
/// previous RPM, mid-upgrade) is a real situation, and failing it
/// loudly is much cheaper than debugging a silently absent field.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct Request {
    /// Echoed back verbatim on the matching response. The console
    /// correlates by this rather than by arrival order, since it is
    /// free to have several requests outstanding.
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

/// The closed set referenced in this module's own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Malformed frame, unknown method, or parameters that don't fit
    /// the method's shape. Always the caller's fault, never retryable
    /// unchanged.
    BadRequest,
    /// The thing named exists in the protocol but not on this install.
    NotFound,
    /// Reachable in principle, not right now: watchdog down, feature
    /// not compiled into this build, database not initialised yet.
    /// The console shows these as a state, not as a failure.
    Unavailable,
    /// A real, deliberate refusal by something that checked: a denied
    /// setup token, a rejected signature. Distinct from `Unavailable`
    /// because retrying identically will not help, and distinct from
    /// `BadRequest` because the request itself was well-formed.
    Denied,
    /// The operation would clobber or duplicate existing state.
    Conflict,
    /// Anything this process failed to do for its own reasons.
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Denied => "denied",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Internal => "internal",
        }
    }
}

#[derive(Debug)]
pub struct MethodError {
    pub code: ErrorCode,
    pub message: String,
}

impl MethodError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

pub type MethodResult = Result<serde_json::Value, MethodError>;

impl Response {
    pub fn success(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: u64, err: MethodError) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: err.code.as_str(),
                message: err.message,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_frame_carries_no_error_key_at_all() {
        // The console distinguishes the two shapes by `ok`, but a
        // stray `"error": null` would still be a lie in the transcript
        // and in any log an operator pastes into a bug report.
        let line = serde_json::to_string(&Response::success(7, serde_json::json!({"a": 1}))).unwrap();
        assert!(line.contains("\"ok\":true"));
        assert!(!line.contains("error"));
    }

    #[test]
    fn a_failure_frame_carries_no_result_key_at_all() {
        let line = serde_json::to_string(&Response::failure(
            9,
            MethodError::unavailable("watchdog is not running"),
        ))
        .unwrap();
        assert!(line.contains("\"ok\":false"));
        assert!(line.contains("\"code\":\"unavailable\""));
        assert!(!line.contains("result"));
    }

    #[test]
    fn every_error_code_has_a_distinct_stable_string() {
        let all = [
            ErrorCode::BadRequest,
            ErrorCode::NotFound,
            ErrorCode::Unavailable,
            ErrorCode::Denied,
            ErrorCode::Conflict,
            ErrorCode::Internal,
        ];
        let mut seen: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two error codes serialise identically");
    }

    #[test]
    fn a_request_without_params_still_parses() {
        // The console omits `params` entirely for no-argument methods
        // rather than sending `{}`; `#[serde(default)]` is what makes
        // that legal, and this pins it.
        let req: Request = serde_json::from_str(r#"{"id":1,"method":"agent.hello"}"#).unwrap();
        assert_eq!(req.id, 1);
        assert!(req.params.is_null());
    }

    #[test]
    fn a_response_serialises_to_exactly_one_line() {
        // The whole framing depends on this: `serde_json` does not
        // emit newlines in compact mode, and every string it writes is
        // escaped, so no field value can smuggle a frame boundary.
        let line = serde_json::to_string(&Response::failure(
            1,
            MethodError::internal("first line\nsecond line"),
        ))
        .unwrap();
        assert!(!line.contains('\n'), "a response must never contain a raw newline");
    }
}
