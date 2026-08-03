//! Never built directly — see `scripts/build-quiche-ffi.sh`. This
//! crate exists solely so `Cargo.toml`/`Cargo.lock` pin an exact,
//! auditable `quiche` version for that script to vendor and build.

#![forbid(unsafe_code)]
