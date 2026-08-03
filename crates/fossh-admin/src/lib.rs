#![forbid(unsafe_code)]
//! Watchdog-adjacent security primitives, shared by `fossh-tui` (a
//! direct Rust dependency — no boundary to cross) and, once chapter
//! §3.3/§3.4's OCaml watchdog exists, its FFI surface (the same "push
//! crypto into an already-audited Rust crate rather than growing the
//! watchdog's own dependency tree" pattern `fossh-ffi` already
//! established for the telemetry ingest path).
//!
//! No `unsafe` anywhere in this crate (`#![forbid(unsafe_code)]` — S1).
//! Currently: the first-run setup-token model (§2.6). Tamper-detection
//! manifest signing/verification (§3.6) and challenge-response
//! keypair/session logic (§2.1) land here as those sub-chapters are
//! implemented.

pub mod command_client;
pub mod data_key;
pub mod setup_token;
pub mod tls_identity;
pub mod watchdog_pin;
