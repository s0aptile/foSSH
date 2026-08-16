use std::io::{self, Read, Write};

pub const VERSION_1: u8 = 1;

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

    Truncated,

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

pub fn read_record_body<R: Read>(r: &mut R, header: &Header) -> io::Result<Vec<u8>> {
    let mut content = vec![0u8; header.content_length as usize];
    r.read_exact(&mut content)?;
    if header.padding_length > 0 {
        let mut pad = [0u8; 255];
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

pub type NameValuePairs = Vec<(Vec<u8>, Vec<u8>)>;

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

pub fn write_response<W: Write>(
    w: &mut W,
    request_id: u16,
    content: &[u8],
    app_status: u32,
) -> io::Result<()> {

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
        let mut data = b"hello!!!".to_vec();
        data.extend_from_slice(&[0u8; 5]);
        data.extend_from_slice(b"NEXT");
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
        let content = [0x00, 0x01, 0x01, 0, 0, 0, 0, 0];
        let parsed = parse_begin_request_body(&content).unwrap();
        assert_eq!(parsed.role, Role::Responder);
        assert!(parsed.keep_conn);
    }

    #[test]
    fn begin_request_body_without_keep_conn_flag() {
        let content = [0x00, 0x02, 0x00, 0, 0, 0, 0, 0];
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

        let name = b"X";
        let value = vec![b'v'; 200];
        let mut bytes = vec![1u8];
        let len_bytes = (200u32 | 0x8000_0000).to_be_bytes();
        bytes.extend_from_slice(&len_bytes);
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

        let bytes = vec![0x80, 0x00];
        assert!(matches!(
            decode_name_value_pairs(&bytes),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn name_value_length_claims_more_content_than_is_actually_present() {
        let bytes = vec![200u8, 0u8, b'x'];
        assert!(matches!(
            decode_name_value_pairs(&bytes),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn name_value_stream_over_the_bound_is_rejected() {

        let over = (MAX_PARAMS_BYTES + 1) as u32;
        let mut bytes = vec![0x80, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&over.to_be_bytes());
        bytes[0..4].copy_from_slice(&(over | 0x8000_0000).to_be_bytes());
        bytes.push(0);

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
