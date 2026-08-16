use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct Request {

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {

    BadRequest,

    NotFound,

    Unavailable,

    Denied,

    Conflict,

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

        let line =
            serde_json::to_string(&Response::success(7, serde_json::json!({"a": 1}))).unwrap();
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

        let req: Request = serde_json::from_str(r#"{"id":1,"method":"agent.hello"}"#).unwrap();
        assert_eq!(req.id, 1);
        assert!(req.params.is_null());
    }

    #[test]
    fn a_response_serialises_to_exactly_one_line() {

        let line = serde_json::to_string(&Response::failure(
            1,
            MethodError::internal("first line\nsecond line"),
        ))
        .unwrap();
        assert!(
            !line.contains('\n'),
            "a response must never contain a raw newline"
        );
    }
}
