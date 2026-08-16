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
