//! §3.7: fuzzes `resolve_client_ip`, the one function that decides
//! whether a request's logged IP comes from the socket peer or from a
//! client-supplied `X-Forwarded-For` header.
//!
//! Pure string handling, so this is less about finding a crash than
//! about holding the two properties the rest of the system leans on:
//! with no trusted hops the header can never influence the answer, and
//! whatever comes back is always either `remote_addr` verbatim or a
//! syntactically valid IP address. That second one is what keeps
//! arbitrary client-supplied bytes out of the visitor hash, the
//! rate-limit key, and the country lookup.

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

    // Either we fell back, or we returned something that parses. There
    // is no third outcome, and if there were, the unparseable value
    // would go on to be hashed and stored.
    if result != input.remote_addr {
        assert!(
            result.parse::<IpAddr>().is_ok(),
            "returned {result:?}, which is neither remote_addr nor a valid IP address"
        );
    }
});
