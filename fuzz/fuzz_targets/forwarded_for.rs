#![no_main]

use arbitrary::Arbitrary;
use fossh_ingest::forwarded::resolve_client_ip;
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

#[derive(Debug, Arbitrary)]
struct Input {
    remote_addr: String,
    forwarded_for: Option<String>,
    trusted_hops: u8,
}

fuzz_target!(|input: Input| {
    let result = resolve_client_ip(
        &input.remote_addr,
        input.forwarded_for.as_deref(),
        input.trusted_hops,
    );

    if input.trusted_hops == 0 {
        assert_eq!(
            result, input.remote_addr,
            "with no trusted hops, forwarded_for must never override remote_addr"
        );
    }

    if result != input.remote_addr {
        assert!(
            result.parse::<IpAddr>().is_ok(),
            "returned {result:?}, which is neither remote_addr nor a valid IP address"
        );
    }
});
