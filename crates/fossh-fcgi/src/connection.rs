//! Reads one complete FastCGI request off a stream (`BEGIN_REQUEST`,
//! `PARAMS*`, `STDIN*`, in the canonical order every real FastCGI
//! client — nginx included — actually sends them) and converts it into
//! `fossh_ingest::ingest::IngestEnv` plus a body buffer. Assumes no
//! request multiplexing (`FCGI_MPXS_CONNS` is never advertised as
//! supported): a second `BEGIN_REQUEST` before the first one finishes
//! is refused, not queued.

use std::io::{Read, Write};

use fossh_core::validate::BODY_MAX;
use fossh_ingest::ingest::IngestEnv;

use crate::protocol::{self, ProtocolStatus, RecordType, Role};

#[derive(Debug)]
pub struct IngestRequest {
    pub request_id: u16,
    pub env: IngestEnv,
    pub body: Vec<u8>,
    pub keep_conn: bool,
}

#[derive(Debug)]
pub enum RequestOutcome {
    Ingest(Box<IngestRequest>),
    /// The peer closed the connection cleanly before sending anything
    /// — the ordinary way a FastCGI connection ends, not an error.
    ConnectionClosed,
}

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    Protocol(protocol::ProtocolError),
    /// A role other than `RESPONDER`, or a second concurrent
    /// `BEGIN_REQUEST` — refused with the given `request_id` and the
    /// status the caller should report back before closing.
    Unsupported {
        request_id: u16,
        status: ProtocolStatus,
    },
    /// Accumulated `STDIN` exceeded S4's body cap before the stream
    /// signaled its own end.
    BodyTooLarge {
        request_id: u16,
    },
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<protocol::ProtocolError> for ReadError {
    fn from(e: protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Reads exactly one byte first via a plain `read` (not `read_exact`)
/// so a clean `Ok(0)` — the peer closing the connection between
/// requests, the normal end of a `keep_conn` session — is
/// distinguishable from a connection that dies mid-header, which is a
/// real I/O error, not a graceful close.
fn read_header_or_eof<R: Read>(r: &mut R) -> std::io::Result<Option<protocol::Header>> {
    let mut first = [0u8; 1];
    let n = r.read(&mut first)?;
    if n == 0 {
        return Ok(None);
    }
    let mut rest = [0u8; protocol::HEADER_LEN - 1];
    r.read_exact(&mut rest)?;
    let mut buf = [0u8; protocol::HEADER_LEN];
    buf[0] = first[0];
    buf[1..].copy_from_slice(&rest);
    Ok(Some(protocol::read_header(&mut &buf[..])?))
}

fn build_env(params: &protocol::NameValuePairs, trust_forwarded_for: bool) -> IngestEnv {
    let mut get = std::collections::HashMap::with_capacity(params.len());
    for (k, v) in params {
        get.insert(
            String::from_utf8_lossy(k).into_owned(),
            String::from_utf8_lossy(v).into_owned(),
        );
    }
    let mut get = move |key: &str| get.remove(key);

    let remote_addr = fossh_ingest::forwarded::resolve_client_ip(
        &get("REMOTE_ADDR").unwrap_or_default(),
        get("HTTP_X_FORWARDED_FOR").as_deref(),
        trust_forwarded_for,
    );

    IngestEnv {
        method: get("REQUEST_METHOD").unwrap_or_default(),
        path_info: get("PATH_INFO").unwrap_or_default(),
        query_string: get("QUERY_STRING").unwrap_or_default(),
        remote_addr,
        user_agent: get("HTTP_USER_AGENT").unwrap_or_default(),
        referer: get("HTTP_REFERER"),
        dnt: get("HTTP_DNT").as_deref() == Some("1"),
        gpc: get("HTTP_SEC_GPC").as_deref() == Some("1"),
        key_id: get("HTTP_X_FOSSH_KEY_ID"),
        ts_header: get("HTTP_X_FOSSH_TS"),
        nonce_header: get("HTTP_X_FOSSH_NONCE"),
        sig_header: get("HTTP_X_FOSSH_SIG"),
        authorization: get("HTTP_AUTHORIZATION"),
        origin: get("HTTP_ORIGIN"),
    }
}

pub fn read_request<R: Read>(
    r: &mut R,
    trust_forwarded_for: bool,
) -> Result<RequestOutcome, ReadError> {
    let Some(begin_header) = read_header_or_eof(r)? else {
        return Ok(RequestOutcome::ConnectionClosed);
    };
    let request_id = begin_header.request_id;

    if begin_header.kind != RecordType::BeginRequest {
        return Err(ReadError::Unsupported {
            request_id,
            status: ProtocolStatus::UnknownRole,
        });
    }
    let begin_body = protocol::read_record_body(r, &begin_header)?;
    let Some(begin) = protocol::parse_begin_request_body(&begin_body) else {
        return Err(ReadError::Unsupported {
            request_id,
            status: ProtocolStatus::UnknownRole,
        });
    };
    if begin.role != Role::Responder {
        return Err(ReadError::Unsupported {
            request_id,
            status: ProtocolStatus::UnknownRole,
        });
    }

    let mut params_bytes = Vec::new();
    loop {
        let header = protocol::read_header(r)?;
        if header.request_id != request_id {
            // No multiplexing support: a second request's records
            // interleaved with the first's is exactly the case
            // FCGI_MPXS_CONNS=0 (never advertised otherwise) tells a
            // well-behaved client not to do.
            return Err(ReadError::Unsupported {
                request_id: header.request_id,
                status: ProtocolStatus::CantMpxConn,
            });
        }
        if header.kind != RecordType::Params {
            return Err(ReadError::Unsupported {
                request_id,
                status: ProtocolStatus::UnknownRole,
            });
        }
        let body = protocol::read_record_body(r, &header)?;
        if body.is_empty() {
            break; // end-of-stream marker
        }
        // Checked *before* appending, not after (adversarial-review
        // finding — this loop originally checked post-append, the
        // STDIN loop below already checked pre-append; bounded either
        // way by one record's own 65535-byte cap, but worth being
        // consistent with the documented "bounded before it's ever
        // retained" intent).
        if params_bytes.len() + body.len() > protocol::MAX_PARAMS_BYTES {
            return Err(ReadError::Protocol(protocol::ProtocolError::ParamsTooLarge));
        }
        params_bytes.extend_from_slice(&body);
    }
    let params = protocol::decode_name_value_pairs(&params_bytes)?;

    let mut body = Vec::new();
    loop {
        let header = protocol::read_header(r)?;
        if header.request_id != request_id {
            return Err(ReadError::Unsupported {
                request_id: header.request_id,
                status: ProtocolStatus::CantMpxConn,
            });
        }
        if header.kind != RecordType::Stdin {
            return Err(ReadError::Unsupported {
                request_id,
                status: ProtocolStatus::UnknownRole,
            });
        }
        let chunk = protocol::read_record_body(r, &header)?;
        if chunk.is_empty() {
            break; // end-of-stream marker
        }
        if body.len() + chunk.len() > BODY_MAX {
            return Err(ReadError::BodyTooLarge { request_id });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(RequestOutcome::Ingest(Box::new(IngestRequest {
        request_id,
        env: build_env(&params, trust_forwarded_for),
        body,
        keep_conn: begin.keep_conn,
    })))
}

/// Writes the CGI-style status header block this application's
/// response always is (§7.1: never a body, ever) as one `FCGI_STDOUT`
/// record plus its terminator and `FCGI_END_REQUEST` — the same fixed
/// shape `fossh-cgi::main`'s `write_response` produces, just framed for
/// FastCGI instead of a real process stdout.
pub fn write_ingest_response<W: Write>(
    w: &mut W,
    request_id: u16,
    status: u16,
    allow_origin: Option<&str>,
) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("Status: ");
    out.push_str(status_line(status));
    out.push_str("\r\n");
    out.push_str("Cache-Control: no-store\r\n");
    out.push_str("Content-Length: 0\r\n");
    if let Some(origin) = allow_origin {
        out.push_str("Access-Control-Allow-Origin: ");
        out.push_str(origin);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    protocol::write_response(w, request_id, out.as_bytes(), 0)
}

fn status_line(code: u16) -> &'static str {
    match code {
        204 => "204 No Content",
        401 => "401 Unauthorized",
        413 => "413 Payload Too Large",
        422 => "422 Unprocessable Entity",
        429 => "429 Too Many Requests",
        _ => "500 Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encode_params(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in pairs {
            out.push(k.len() as u8);
            out.push(v.len() as u8);
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn write_record<W: Write>(w: &mut W, kind: RecordType, request_id: u16, content: &[u8]) {
        protocol::write_header(
            w,
            &protocol::Header {
                version: protocol::VERSION_1,
                kind,
                request_id,
                content_length: content.len() as u16,
                padding_length: 0,
            },
        )
        .unwrap();
        w.write_all(content).unwrap();
    }

    fn full_request(params: &[(&str, &str)], body: &[u8], keep_conn: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        let begin_body = {
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&1u16.to_be_bytes()); // Responder
            b[2] = if keep_conn { 1 } else { 0 };
            b
        };
        write_record(&mut buf, RecordType::BeginRequest, 1, &begin_body);
        let encoded = encode_params(params);
        if !encoded.is_empty() {
            write_record(&mut buf, RecordType::Params, 1, &encoded);
        }
        write_record(&mut buf, RecordType::Params, 1, &[]); // end of PARAMS
        if !body.is_empty() {
            write_record(&mut buf, RecordType::Stdin, 1, body);
        }
        write_record(&mut buf, RecordType::Stdin, 1, &[]); // end of STDIN
        buf
    }

    #[test]
    fn a_clean_connection_close_before_any_request_is_not_an_error() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let outcome = read_request(&mut cursor, false).unwrap();
        assert!(matches!(outcome, RequestOutcome::ConnectionClosed));
    }

    #[test]
    fn a_full_request_round_trips_into_an_ingest_env_and_body() {
        let data = full_request(
            &[
                ("REQUEST_METHOD", "POST"),
                ("PATH_INFO", "/e"),
                ("REMOTE_ADDR", "203.0.113.9"),
                ("HTTP_AUTHORIZATION", "Bearer fossh_blog_AAAA"),
            ],
            br#"{"name":"pageview"}"#,
            true,
        );
        let mut cursor = Cursor::new(data);
        let outcome = read_request(&mut cursor, false).unwrap();
        let RequestOutcome::Ingest(req) = outcome else {
            panic!("expected Ingest");
        };
        assert_eq!(req.request_id, 1);
        assert_eq!(req.env.method, "POST");
        assert_eq!(req.env.path_info, "/e");
        assert_eq!(req.env.remote_addr, "203.0.113.9");
        assert_eq!(
            req.env.authorization.as_deref(),
            Some("Bearer fossh_blog_AAAA")
        );
        assert_eq!(req.body, br#"{"name":"pageview"}"#);
        assert!(req.keep_conn);
    }

    #[test]
    fn remote_addr_honors_trust_forwarded_for_exactly_like_cgi_does() {
        let data = full_request(
            &[
                ("REMOTE_ADDR", "127.0.0.1"),
                ("HTTP_X_FORWARDED_FOR", "198.51.100.1, 127.0.0.1"),
            ],
            b"",
            false,
        );
        let mut cursor = Cursor::new(data);
        let RequestOutcome::Ingest(req) = read_request(&mut cursor, true).unwrap() else {
            panic!("expected Ingest");
        };
        assert_eq!(req.env.remote_addr, "198.51.100.1");
    }

    #[test]
    fn non_responder_role_is_refused() {
        let mut buf = Vec::new();
        let mut begin_body = [0u8; 8];
        begin_body[0..2].copy_from_slice(&2u16.to_be_bytes()); // Authorizer
        write_record(&mut buf, RecordType::BeginRequest, 1, &begin_body);
        let mut cursor = Cursor::new(buf);
        let err = read_request(&mut cursor, false).unwrap_err();
        assert!(matches!(
            err,
            ReadError::Unsupported {
                status: ProtocolStatus::UnknownRole,
                ..
            }
        ));
    }

    #[test]
    fn a_second_interleaved_request_id_is_refused_not_multiplexed() {
        let mut buf = Vec::new();
        let mut begin_body = [0u8; 8];
        begin_body[0..2].copy_from_slice(&1u16.to_be_bytes());
        write_record(&mut buf, RecordType::BeginRequest, 1, &begin_body);
        // A PARAMS record under a *different* request_id shows up
        // before request 1's PARAMS stream even finishes.
        write_record(
            &mut buf,
            RecordType::Params,
            2,
            &encode_params(&[("A", "1")]),
        );
        let mut cursor = Cursor::new(buf);
        let err = read_request(&mut cursor, false).unwrap_err();
        assert!(matches!(
            err,
            ReadError::Unsupported {
                request_id: 2,
                status: ProtocolStatus::CantMpxConn,
            }
        ));
    }

    #[test]
    fn stdin_over_the_body_cap_is_refused() {
        let big = vec![b'x'; BODY_MAX + 1];
        let data = full_request(&[("REQUEST_METHOD", "POST")], &big, false);
        let mut cursor = Cursor::new(data);
        let err = read_request(&mut cursor, false).unwrap_err();
        assert!(matches!(err, ReadError::BodyTooLarge { request_id: 1 }));
    }

    #[test]
    fn params_over_the_bound_is_rejected_before_being_retained() {
        // Adversarial-review finding (F2): this loop originally checked
        // its size bound *after* appending each record's content to the
        // accumulator, unlike the STDIN loop just above, which already
        // checked before. Bounded either way by a single record's own
        // 65535-byte wire cap, so this needs *two* records' worth of raw
        // filler to cross MAX_PARAMS_BYTES at all (content doesn't need
        // to be well-formed name/value pairs — the bound check runs
        // before `decode_name_value_pairs` is ever called). The first
        // record is exactly 65535 bytes — a single FastCGI record's
        // content length is a wire `u16`, so anything larger would
        // silently wrap (65536usize as u16 == 0), turning an intended
        // "huge record" into an empty end-of-stream marker instead; an
        // earlier draft of this exact test hit precisely that bug.
        let mut buf = Vec::new();
        let mut begin_body = [0u8; 8];
        begin_body[0..2].copy_from_slice(&1u16.to_be_bytes());
        write_record(&mut buf, RecordType::BeginRequest, 1, &begin_body);
        let filler = vec![b'x'; u16::MAX as usize]; // 65535, the max one record can carry
        write_record(&mut buf, RecordType::Params, 1, &filler);
        write_record(&mut buf, RecordType::Params, 1, &[b'y', b'y']); // 65535 + 2 > MAX_PARAMS_BYTES (65536)

        let mut cursor = Cursor::new(buf);
        let err = read_request(&mut cursor, false).unwrap_err();
        assert!(matches!(
            err,
            ReadError::Protocol(protocol::ProtocolError::ParamsTooLarge)
        ));
    }

    #[test]
    fn write_ingest_response_matches_the_fixed_cgi_style_shape() {
        let mut buf = Vec::new();
        write_ingest_response(&mut buf, 1, 204, Some("https://blog.example.com")).unwrap();

        let mut cursor = Cursor::new(buf);
        let h = protocol::read_header(&mut cursor).unwrap();
        assert_eq!(h.kind, RecordType::Stdout);
        let content = protocol::read_record_body(&mut cursor, &h).unwrap();
        let text = String::from_utf8(content).unwrap();
        assert!(text.starts_with("Status: 204 No Content\r\n"));
        assert!(text.contains("Cache-Control: no-store\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.contains("Access-Control-Allow-Origin: https://blog.example.com\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
