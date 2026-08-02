//! Hand-rolled FastCGI record framing (the wire protocol originally
//! defined by Open Market's FastCGI spec, still what nginx/every real
//! webserver speaks) — pure, `#![forbid(unsafe_code)]`, no I/O of its
//! own beyond generic `Read`/`Write` bounds, so every byte-parsing path
//! is unit-testable and fuzzable without a real socket. Hand-rolled
//! rather than pulling a `fastcgi` crate for the same reason this
//! project already hand-rolls CRC-32/base32/HLL: the wire format is
//! small (an 8-byte header plus two simple sub-encodings), and parsing
//! untrusted bytes from a socket is exactly the kind of narrow,
//! security-relevant surface this project prefers to own and review
//! directly rather than trust to an unaudited third-party crate.
//!
//! Deliberately implements only what this application's single
//! `RESPONDER`-role, request/response-only use actually needs: no
//! `FCGI_AUTHORIZER`/`FCGI_FILTER` roles, no `FCGI_DATA` stream, no
//! request multiplexing beyond rejecting anything that would need it.
//! Values not recognized (an unknown record type, a non-`RESPONDER`
//! role) are refused explicitly rather than guessed at — S2's "fail
//! closed" applies to wire parsing exactly as it does to the request
//! pipeline above it.

use std::io::{self, Read, Write};

pub const VERSION_1: u8 = 1;

/// Every record this application either reads or writes. `Other(u8)`
/// exists so a genuinely unrecognized type byte on the wire can be
/// represented and rejected explicitly, never silently reinterpreted
/// as one of the known variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    BeginRequest,
    AbortRequest,
    EndRequest,
    Params,
    Stdin,
    Stdout,
    Stderr,
    Data,
    GetValues,
    GetValuesResult,
    UnknownType,
    Other(u8),
}

impl RecordType {
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::BeginRequest,
            2 => Self::AbortRequest,
            3 => Self::EndRequest,
            4 => Self::Params,
            5 => Self::Stdin,
            6 => Self::Stdout,
            7 => Self::Stderr,
            8 => Self::Data,
            9 => Self::GetValues,
            10 => Self::GetValuesResult,
            11 => Self::UnknownType,
            other => Self::Other(other),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::BeginRequest => 1,
            Self::AbortRequest => 2,
            Self::EndRequest => 3,
            Self::Params => 4,
            Self::Stdin => 5,
            Self::Stdout => 6,
            Self::Stderr => 7,
            Self::Data => 8,
            Self::GetValues => 9,
            Self::GetValuesResult => 10,
            Self::UnknownType => 11,
            Self::Other(b) => b,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub kind: RecordType,
    pub request_id: u16,
    pub content_length: u16,
    pub padding_length: u8,
}

pub const HEADER_LEN: usize = 8;

/// Role carried in an `FCGI_BEGIN_REQUEST` body. Only `Responder` is
/// ever accepted — see the module doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Responder,
    Authorizer,
    Filter,
    Other(u16),
}

impl Role {
    fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Responder,
            2 => Self::Authorizer,
            3 => Self::Filter,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BeginRequestBody {
    pub role: Role,
    pub keep_conn: bool,
}

pub const BEGIN_REQUEST_BODY_LEN: usize = 8;
const FCGI_KEEP_CONN: u8 = 1;

/// `FCGI_UNKNOWN_TYPE`'s `Overloaded` protocol status exists in the
/// wire spec but has no variant here: emitting it needs a real
/// overload signal (a bounded queue rejecting work, specifically) that
/// this application doesn't implement — its connection/event channels
/// are deliberately unbounded, backpressure via blocking rather than
/// rejection (see `main.rs`). Not worth a status this app can never
/// actually produce; add it back if that changes.
#[derive(Debug, Clone, Copy)]
pub enum ProtocolStatus {
    RequestComplete,
    CantMpxConn,
    UnknownRole,
}

impl ProtocolStatus {
    fn to_byte(self) -> u8 {
        match self {
            Self::RequestComplete => 0,
            Self::CantMpxConn => 1,
            Self::UnknownRole => 3,
        }
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    /// A length-prefixed name/value pair's encoded length pointed
    /// past the end of the record's own content — either a
    /// misbehaving client or a deliberately malformed stream.
    Truncated,
    /// Decoded name/value content exceeded `MAX_PARAMS_BYTES` before
    /// finishing — S4's "bounded everything" applied to this stream
    /// specifically, since nothing upstream caps it otherwise.
    ParamsTooLarge,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated name/value length prefix or content"),
            Self::ParamsTooLarge => write!(f, "PARAMS stream exceeds {MAX_PARAMS_BYTES} bytes"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn read_header<R: Read>(r: &mut R) -> io::Result<Header> {
    let mut buf = [0u8; HEADER_LEN];
    r.read_exact(&mut buf)?;
    Ok(Header {
        version: buf[0],
        kind: RecordType::from_byte(buf[1]),
        request_id: u16::from_be_bytes([buf[2], buf[3]]),
        content_length: u16::from_be_bytes([buf[4], buf[5]]),
        padding_length: buf[6],
        // buf[7] ("reserved") is intentionally ignored, per spec.
    })
}

pub fn write_header<W: Write>(w: &mut W, h: &Header) -> io::Result<()> {
    let [cl1, cl0] = h.content_length.to_be_bytes();
    let [id1, id0] = h.request_id.to_be_bytes();
    let buf = [
        h.version,
        h.kind.to_byte(),
        id1,
        id0,
        cl1,
        cl0,
        h.padding_length,
        0,
    ];
    w.write_all(&buf)
}

/// Reads exactly one record's content (after its header) plus its
/// trailing padding, discarding the padding. Bounds the read to
/// `content_length` — never more, regardless of what a caller's
/// buffer capacity might otherwise allow.
pub fn read_record_body<R: Read>(r: &mut R, header: &Header) -> io::Result<Vec<u8>> {
    let mut content = vec![0u8; header.content_length as usize];
    r.read_exact(&mut content)?;
    if header.padding_length > 0 {
        let mut pad = [0u8; 255]; // padding_length is a u8, so this always fits
        r.read_exact(&mut pad[..header.padding_length as usize])?;
    }
    Ok(content)
}

pub fn parse_begin_request_body(content: &[u8]) -> Option<BeginRequestBody> {
    if content.len() != BEGIN_REQUEST_BODY_LEN {
        return None;
    }
    let role = Role::from_u16(u16::from_be_bytes([content[0], content[1]]));
    let keep_conn = content[2] & FCGI_KEEP_CONN != 0;
    Some(BeginRequestBody { role, keep_conn })
}

/// Total decoded name+value bytes a single PARAMS stream may carry —
/// generous for real CGI meta-variables (which this application's own
/// wire protocol already bounds far more tightly per S4: 4 KiB per env
/// var value) but still a hard, finite ceiling rather than "whatever
/// fits in memory," so a misbehaving or malicious client can't grow
/// this stream unboundedly before this application ever gets a chance
/// to validate anything about the request.
pub const MAX_PARAMS_BYTES: usize = 64 * 1024;

fn decode_length(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let first = *bytes.get(*pos)?;
    if first & 0x80 == 0 {
        *pos += 1;
        Some(first as u32)
    } else {
        let b = bytes.get(*pos..*pos + 4)?;
        *pos += 4;
        Some(u32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]))
    }
}

/// A decoded FastCGI name/value stream: raw bytes, not yet interpreted
/// as UTF-8 — `connection::build_env` does that lossily, matching how
/// CGI meta-variables have always been treated on the `fossh-cgi` side.
pub type NameValuePairs = Vec<(Vec<u8>, Vec<u8>)>;

/// Decodes one FastCGI name-value pair stream (the encoding
/// `FCGI_PARAMS` and `FCGI_GET_VALUES`/`_RESULT` all share): each
/// name/value length is either one byte (high bit clear, value
/// `0..=127`) or four bytes big-endian with the first byte's high bit
/// set and cleared before use. Content may span multiple concatenated
/// `FCGI_PARAMS` records — callers accumulate all of them into one
/// buffer (see `connection.rs`) before calling this once on the whole
/// thing, since a name/value pair is permitted to straddle a record
/// boundary.
pub fn decode_name_value_pairs(bytes: &[u8]) -> Result<NameValuePairs, ProtocolError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut total_len = 0usize;

    while pos < bytes.len() {
        let name_len = decode_length(bytes, &mut pos).ok_or(ProtocolError::Truncated)? as usize;
        let val_len = decode_length(bytes, &mut pos).ok_or(ProtocolError::Truncated)? as usize;

        total_len = total_len
            .checked_add(name_len)
            .and_then(|t| t.checked_add(val_len))
            .ok_or(ProtocolError::ParamsTooLarge)?;
        if total_len > MAX_PARAMS_BYTES {
            return Err(ProtocolError::ParamsTooLarge);
        }

        let name = bytes
            .get(pos..pos + name_len)
            .ok_or(ProtocolError::Truncated)?
            .to_vec();
        pos += name_len;
        let value = bytes
            .get(pos..pos + val_len)
            .ok_or(ProtocolError::Truncated)?
            .to_vec();
        pos += val_len;

        out.push((name, value));
    }

    Ok(out)
}

/// Writes `content` as one or more `FCGI_STDOUT` records (a single
/// record's content is capped at 65535 bytes by the header's own
/// `u16` field — chunking is what the spec expects for anything
/// larger, though in practice this application's responses are always
/// small fixed headers), followed by the empty-content record that
/// signals end-of-stream, then `FCGI_END_REQUEST`. One call covers the
/// whole response — there is no partial-write API here on purpose,
/// mirroring `fossh-cgi::main`'s own single buffered write and the same
/// reasoning: nothing should be able to leave a response half-sent.
pub fn write_response<W: Write>(
    w: &mut W,
    request_id: u16,
    content: &[u8],
    app_status: u32,
) -> io::Result<()> {
    // `[].chunks(n)` yields zero chunks for empty content — correct on
    // its own, no special-casing needed: the unconditional terminator
    // record below is *always* the one and only empty marker, for
    // both empty and non-empty content. (An earlier draft added a
    // `.chain()` here to "handle" the empty case explicitly, which
    // actually caused a *second* empty record to be written before
    // `EndRequest` — caught by this function's own
    // `..._still_emits_exactly_one_stdout_terminator` test actually
    // failing, not by inspection.)
    for chunk in content.chunks(u16::MAX as usize) {
        write_header(
            w,
            &Header {
                version: VERSION_1,
                kind: RecordType::Stdout,
                request_id,
                content_length: chunk.len() as u16,
                padding_length: 0,
            },
        )?;
        w.write_all(chunk)?;
    }
    // Empty-content STDOUT record: end-of-stream marker.
    write_header(
        w,
        &Header {
            version: VERSION_1,
            kind: RecordType::Stdout,
            request_id,
            content_length: 0,
            padding_length: 0,
        },
    )?;

    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&app_status.to_be_bytes());
    body[4] = ProtocolStatus::RequestComplete.to_byte();
    write_header(
        w,
        &Header {
            version: VERSION_1,
            kind: RecordType::EndRequest,
            request_id,
            content_length: 8,
            padding_length: 0,
        },
    )?;
    w.write_all(&body)
}

/// A minimal `FCGI_END_REQUEST` with no `FCGI_STDOUT` at all — used to
/// refuse a request outright (wrong role, unsupported record) without
/// ever having produced a meaningful response body.
pub fn write_end_request_only<W: Write>(
    w: &mut W,
    request_id: u16,
    status: ProtocolStatus,
) -> io::Result<()> {
    let mut body = [0u8; 8];
    body[4] = status.to_byte();
    write_header(
        w,
        &Header {
            version: VERSION_1,
            kind: RecordType::EndRequest,
            request_id,
            content_length: 8,
            padding_length: 0,
        },
    )?;
    w.write_all(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn header_round_trips() {
        let h = Header {
            version: VERSION_1,
            kind: RecordType::Params,
            request_id: 42,
            content_length: 1000,
            padding_length: 3,
        };
        let mut buf = Vec::new();
        write_header(&mut buf, &h).unwrap();
        assert_eq!(buf.len(), HEADER_LEN);

        let parsed = read_header(&mut Cursor::new(buf)).unwrap();
        assert_eq!(parsed.version, VERSION_1);
        assert_eq!(parsed.kind, RecordType::Params);
        assert_eq!(parsed.request_id, 42);
        assert_eq!(parsed.content_length, 1000);
        assert_eq!(parsed.padding_length, 3);
    }

    #[test]
    fn unrecognized_record_type_byte_round_trips_as_other_not_a_panic() {
        let h = Header {
            version: VERSION_1,
            kind: RecordType::Other(200),
            request_id: 1,
            content_length: 0,
            padding_length: 0,
        };
        let mut buf = Vec::new();
        write_header(&mut buf, &h).unwrap();
        let parsed = read_header(&mut Cursor::new(buf)).unwrap();
        assert_eq!(parsed.kind, RecordType::Other(200));
    }

    #[test]
    fn read_record_body_reads_content_and_discards_padding() {
        let mut data = b"hello!!!".to_vec(); // 8 bytes content
        data.extend_from_slice(&[0u8; 5]); // 5 bytes padding
        data.extend_from_slice(b"NEXT"); // what follows must be untouched
        let header = Header {
            version: VERSION_1,
            kind: RecordType::Stdin,
            request_id: 1,
            content_length: 8,
            padding_length: 5,
        };
        let mut cursor = Cursor::new(data);
        let content = read_record_body(&mut cursor, &header).unwrap();
        assert_eq!(content, b"hello!!!");

        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"NEXT");
    }

    #[test]
    fn begin_request_body_parses_role_and_keep_conn() {
        let content = [0x00, 0x01, 0x01, 0, 0, 0, 0, 0]; // role=Responder(1), keep_conn set
        let parsed = parse_begin_request_body(&content).unwrap();
        assert_eq!(parsed.role, Role::Responder);
        assert!(parsed.keep_conn);
    }

    #[test]
    fn begin_request_body_without_keep_conn_flag() {
        let content = [0x00, 0x02, 0x00, 0, 0, 0, 0, 0]; // role=Authorizer(2), no keep_conn
        let parsed = parse_begin_request_body(&content).unwrap();
        assert_eq!(parsed.role, Role::Authorizer);
        assert!(!parsed.keep_conn);
    }

    #[test]
    fn begin_request_body_wrong_length_is_none_not_a_panic() {
        assert!(parse_begin_request_body(&[0, 1, 2]).is_none());
        assert!(parse_begin_request_body(&[0u8; 9]).is_none());
    }

    #[test]
    fn name_value_short_form_round_trips() {
        // name="REQUEST_METHOD" (14 bytes), value="POST" (4 bytes), both < 128.
        let mut bytes = vec![14u8, 4u8];
        bytes.extend_from_slice(b"REQUEST_METHOD");
        bytes.extend_from_slice(b"POST");
        let pairs = decode_name_value_pairs(&bytes).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, b"REQUEST_METHOD");
        assert_eq!(pairs[0].1, b"POST");
    }

    #[test]
    fn name_value_long_form_length_is_used_when_high_bit_set() {
        // A 200-byte value needs the 4-byte long form (200 > 127).
        let name = b"X";
        let value = vec![b'v'; 200];
        let mut bytes = vec![1u8]; // name length: short form, 1
        let len_bytes = (200u32 | 0x8000_0000).to_be_bytes();
        bytes.extend_from_slice(&len_bytes); // value length: long form
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&value);

        let pairs = decode_name_value_pairs(&bytes).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, b"X");
        assert_eq!(pairs[0].1.len(), 200);
    }

    #[test]
    fn name_value_multiple_pairs_in_one_stream() {
        let mut bytes = Vec::new();
        for (name, value) in [("A", "1"), ("BB", "22"), ("CCC", "333")] {
            bytes.push(name.len() as u8);
            bytes.push(value.len() as u8);
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        let pairs = decode_name_value_pairs(&bytes).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[2].0, b"CCC");
        assert_eq!(pairs[2].1, b"333");
    }

    #[test]
    fn name_value_empty_stream_is_zero_pairs_not_an_error() {
        assert_eq!(decode_name_value_pairs(&[]).unwrap(), vec![]);
    }

    #[test]
    fn name_value_truncated_length_prefix_is_an_error_not_a_panic() {
        // Claims a 4-byte long-form length but supplies only 2 more bytes.
        let bytes = vec![0x80, 0x00];
        assert!(matches!(
            decode_name_value_pairs(&bytes),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn name_value_length_claims_more_content_than_is_actually_present() {
        let bytes = vec![200u8, 0u8, b'x']; // claims a 200-byte name, gives 1 byte
        assert!(matches!(
            decode_name_value_pairs(&bytes),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn name_value_stream_over_the_bound_is_rejected() {
        // One pair whose declared lengths alone exceed MAX_PARAMS_BYTES.
        let over = (MAX_PARAMS_BYTES + 1) as u32;
        let mut bytes = vec![0x80, 0x00, 0x00, 0x00]; // name length: long form
        bytes.extend_from_slice(&over.to_be_bytes());
        bytes[0..4].copy_from_slice(&(over | 0x8000_0000).to_be_bytes());
        bytes.push(0); // value length: 0, short form
        // Content is never actually supplied — the bound must be caught
        // from the declared lengths alone, before any content read.
        assert!(matches!(
            decode_name_value_pairs(&bytes),
            Err(ProtocolError::ParamsTooLarge)
        ));
    }

    #[test]
    fn write_response_produces_stdout_then_empty_stdout_then_end_request() {
        let mut buf = Vec::new();
        write_response(&mut buf, 7, b"hello", 0).unwrap();

        let mut cursor = Cursor::new(buf);
        let h1 = read_header(&mut cursor).unwrap();
        assert_eq!(h1.kind, RecordType::Stdout);
        assert_eq!(h1.request_id, 7);
        assert_eq!(h1.content_length, 5);
        let body1 = read_record_body(&mut cursor, &h1).unwrap();
        assert_eq!(body1, b"hello");

        let h2 = read_header(&mut cursor).unwrap();
        assert_eq!(h2.kind, RecordType::Stdout);
        assert_eq!(h2.content_length, 0, "end-of-stream marker must be empty");

        let h3 = read_header(&mut cursor).unwrap();
        assert_eq!(h3.kind, RecordType::EndRequest);
        assert_eq!(h3.content_length, 8);
        let body3 = read_record_body(&mut cursor, &h3).unwrap();
        assert_eq!(&body3[0..4], &0u32.to_be_bytes(), "app_status");
        assert_eq!(body3[4], ProtocolStatus::RequestComplete.to_byte());

        let mut trailing = Vec::new();
        cursor.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty(), "nothing must follow END_REQUEST");
    }

    #[test]
    fn write_response_with_empty_content_still_emits_exactly_one_stdout_terminator() {
        let mut buf = Vec::new();
        write_response(&mut buf, 1, b"", 0).unwrap();
        let mut cursor = Cursor::new(buf);

        let h1 = read_header(&mut cursor).unwrap();
        assert_eq!(h1.kind, RecordType::Stdout);
        assert_eq!(h1.content_length, 0);

        let h2 = read_header(&mut cursor).unwrap();
        assert_eq!(h2.kind, RecordType::EndRequest);
        // Confirms exactly one STDOUT record was written for empty
        // content, not zero (missing the terminator) or two.
    }

    #[test]
    fn write_end_request_only_emits_no_stdout_at_all() {
        let mut buf = Vec::new();
        write_end_request_only(&mut buf, 3, ProtocolStatus::UnknownRole).unwrap();
        let mut cursor = Cursor::new(buf);
        let h = read_header(&mut cursor).unwrap();
        assert_eq!(h.kind, RecordType::EndRequest);
        let body = read_record_body(&mut cursor, &h).unwrap();
        assert_eq!(body[4], ProtocolStatus::UnknownRole.to_byte());
        let mut trailing = Vec::new();
        cursor.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty());
    }
}
