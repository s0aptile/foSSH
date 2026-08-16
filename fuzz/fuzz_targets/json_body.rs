#![no_main]

use fossh_core::types::{Country, SiteId};
use fossh_ingest::pipeline::{RequestContext, from_json_body};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let allowlist = vec![
        "pageview".to_string(),
        "click".to_string(),
        "prop1".to_string(),
        "prop2".to_string(),
    ];
    let salt = [0x42u8; 32];
    let ctx = RequestContext {
        site_id: SiteId::new(1),
        site_allowlist: &allowlist,
        client_ip: "203.0.113.1",
        user_agent: "Mozilla/5.0 (fuzz)",
        referrer_header: None,
        dnt: false,
        gpc: false,
        respect_optout_signals: true,
        now: 1_700_000_000,
        daily_salt: &salt,
        country: Country::UNKNOWN,
    };
    let _ = from_json_body(data, &ctx);
});
