#![no_main]

use fossh_ingest::spool::decode_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_event(data);
});
