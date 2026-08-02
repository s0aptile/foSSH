//! §3.7: fuzzes the hand-rolled FastCGI wire parser — `read_header` and
//! `read_record_body` (the two functions `connection::read_request`
//! calls for every record on the wire), then, for a `Params` record,
//! `decode_name_value_pairs` on the body those two produce. This is
//! the least-trusted input in the whole binary: bytes straight off a
//! Unix socket, from whatever sits in front of it (nginx, Apache,
//! etc.), before any of foSSH's own auth or validation runs.

#![no_main]

use fossh_fcgi::protocol::{RecordType, decode_name_value_pairs, read_header, read_record_body};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let Ok(header) = read_header(&mut cursor) else {
        return;
    };
    let Ok(body) = read_record_body(&mut cursor, &header) else {
        return;
    };
    if header.kind == RecordType::Params {
        let _ = decode_name_value_pairs(&body);
    }
});
