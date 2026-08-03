//! Library half of `fossh-fcgi`, split out from the binary specifically
//! so `fuzz/`'s `cargo-fuzz` targets (§3.7) can drive the hand-rolled
//! FastCGI wire parser (`protocol`) and request assembly (`connection`)
//! directly, from outside this crate, without duplicating either. The
//! binary (`main.rs`) is a thin wrapper around this — same modules,
//! same code, just reachable as a dependency too.

#![forbid(unsafe_code)]

pub mod connection;
pub mod protocol;
#[cfg(feature = "quic")]
pub mod quic_client;
pub mod writer;
