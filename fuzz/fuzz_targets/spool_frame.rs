//! §3.7: fuzzes `decode_event`, the plaintext spool-frame parser.
//! Deliberately targets this layer, not the ChaCha20-Poly1305-sealed
//! container around it (§3.8) — random bytes fail AEAD authentication
//! almost immediately, so fuzzing the outer layer would spend nearly
//! all its cycles on that single rejection instead of exercising this
//! parser, which is what actually walks attacker-shaped length-prefixed
//! fields. This is what runs on an already-decrypted, but still
//! untrusted-until-parsed, frame.

#![no_main]

use fossh_ingest::spool::decode_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_event(data);
});
