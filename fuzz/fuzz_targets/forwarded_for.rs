//! §3.7: fuzzes `resolve_client_ip`, the one function that decides
//! whether a request's logged IP comes from the socket peer or from a
//! client-supplied `X-Forwarded-For` header. It's pure string handling
//! (no unsafe, no parsing that can panic on its own), so this target
//! exists mainly as a cheap correctness net — `trust: false` must
//! never let `forwarded_for` leak into the result — rather than an
//! expectation of finding a crash.

#![no_main]

use arbitrary::Arbitrary;
use fossh_ingest::forwarded::resolve_client_ip;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    remote_addr: String,
    forwarded_for: Option<String>,
    trust: bool,
}

fuzz_target!(|input: Input| {
    let result = resolve_client_ip(
        &input.remote_addr,
        input.forwarded_for.as_deref(),
        input.trust,
    );
    if !input.trust {
        assert_eq!(
            result, input.remote_addr,
            "trust=false must never let forwarded_for override remote_addr"
        );
    }
});
