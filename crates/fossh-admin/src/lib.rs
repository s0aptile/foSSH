#![forbid(unsafe_code)]
//! Watchdog-adjacent security primitives, shared by `fossh-tui` (a
//! direct Rust dependency — no boundary to cross). The OCaml watchdog
//! (§3.3/§3.4) exists now, but ended up pure OCaml + `gpg` shell-outs
//! for its own manifest signing/verification (§3.6) and
//! challenge-response keypair/session logic (§2.1) — neither landed
//! here as this comment originally expected; see `dev/DURUM.md`'s §3.6
//! row for why. This crate's own §3.4 piece is `command_client.rs`
//! (core's side of the QUIC command protocol) and `tls_identity`
//! (core's X.509 identity for the mTLS channel).
//!
//! No `unsafe` anywhere in this crate (`#![forbid(unsafe_code)]` — S1).
//! Currently: the first-run setup-token model (§2.6), core's QUIC
//! command-protocol client and X.509 identity generation (§3.4).

pub mod command_client;
pub mod data_key;
pub mod integrations;
pub mod providers;
pub mod setup_token;
pub mod tls_identity;
pub mod watchdog_pin;
