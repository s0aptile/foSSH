#![forbid(unsafe_code)]
//! Pure logic for foSSH: domain types, allowlist/grammar validation, path
//! sanitization (P9), UA bucketing (P4), HyperLogLog cardinality estimation,
//! rotating-salt visitor hashing (P2), and config loading (§10).
//!
//! No `unsafe` anywhere in this crate (`#![forbid(unsafe_code)]` — S1).
//! No I/O except `config::Config::load`, which reads a TOML file from disk;
//! see ADR-0004 in `DECISIONS.md` for why that lives here rather than in a
//! dedicated crate. Everything else is deterministic, allocation-bounded,
//! 100% unit-testable logic with no side effects.

pub mod config;
pub mod hist;
pub mod hll;
pub mod sanitize_path;
pub mod types;
pub mod ua;
pub mod validate;
pub mod visitor;

pub use sanitize_path::sanitize_path;
