//! S10: per-site rate limiting. Token bucket, default 60 events/s burst
//! 600, keyed by `site_id` via one state file per site. Same file-backed
//! (not mmap'd) approach as `auth::NonceCache` — see the crate-level doc
//! comment for why. A plain read-then-write-back under concurrent CGI
//! processes gives exactly the "no lock, tolerate ±1 slop" behavior S10
//! asks for.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::IngestError;

const STATE_BYTES: usize = 16; // 8-byte f64 token count + 8-byte i64 last-refill timestamp

pub struct TokenBucket {
    path: PathBuf,
    per_sec: u32,
    burst: u32,
}

impl TokenBucket {
    pub fn new(path: PathBuf, per_sec: u32, burst: u32) -> Self {
        Self {
            path,
            per_sec,
            burst,
        }
    }

    /// Attempts to consume one token. `Ok(true)` = allowed; `Ok(false)` =
    /// bucket empty (caller responds `429`, drops the event, and counts
    /// it in an internal `dropped_ratelimit` counter — S10's exact
    /// wording — which is the ingest pipeline's job, not this type's).
    pub fn try_consume(&self, now: i64) -> Result<bool, IngestError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;

        let mut buf = [0u8; STATE_BYTES];
        let read = file.read(&mut buf)?;
        let (tokens, last_refill) = if read == STATE_BYTES {
            (
                f64::from_le_bytes(buf[0..8].try_into().expect("8 bytes")),
                i64::from_le_bytes(buf[8..16].try_into().expect("8 bytes")),
            )
        } else {
            (self.burst as f64, now)
        };

        let elapsed = (now - last_refill).max(0) as f64;
        let refilled = (tokens + elapsed * self.per_sec as f64).min(self.burst as f64);
        let (allowed, remaining) = if refilled >= 1.0 {
            (true, refilled - 1.0)
        } else {
            (false, refilled)
        };

        let mut out = [0u8; STATE_BYTES];
        out[0..8].copy_from_slice(&remaining.to_le_bytes());
        out[8..16].copy_from_slice(&now.to_le_bytes());
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&out)?;

        Ok(allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fossh-ratelimit-test-{name}-{}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn fresh_bucket_starts_full_and_allows() {
        let path = scratch_path("fresh");
        let bucket = TokenBucket::new(path.clone(), 60, 600);
        assert!(bucket.try_consume(1_700_000_000).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn burst_capacity_is_enforced() {
        let path = scratch_path("burst");
        let bucket = TokenBucket::new(path.clone(), 60, 5);
        let now = 1_700_000_000;
        for i in 0..5 {
            assert!(
                bucket.try_consume(now).unwrap(),
                "token {i} within burst should be allowed"
            );
        }
        assert!(
            !bucket.try_consume(now).unwrap(),
            "burst exhausted, same instant, must be denied"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tokens_refill_over_time() {
        let path = scratch_path("refill");
        let bucket = TokenBucket::new(path.clone(), 10, 5); // 10/s, burst 5
        let now = 1_700_000_000;
        for _ in 0..5 {
            assert!(bucket.try_consume(now).unwrap());
        }
        assert!(!bucket.try_consume(now).unwrap());
        // One second later, 10 tokens worth of refill (capped at burst=5) should be available.
        assert!(bucket.try_consume(now + 1).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refill_never_exceeds_burst_cap() {
        let path = scratch_path("cap");
        let bucket = TokenBucket::new(path.clone(), 1_000_000, 3); // huge refill rate, tiny burst
        let now = 1_700_000_000;
        assert!(bucket.try_consume(now).unwrap());
        // A long time later, the bucket must still be capped at `burst`,
        // not overflow to something absurd.
        for i in 0..3 {
            assert!(
                bucket.try_consume(now + 1_000_000).unwrap(),
                "token {i} after long idle should be allowed"
            );
        }
        assert!(
            !bucket.try_consume(now + 1_000_000).unwrap(),
            "still capped at burst even after a long idle period"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn different_sites_have_independent_buckets() {
        let path_a = scratch_path("site-a");
        let path_b = scratch_path("site-b");
        let a = TokenBucket::new(path_a.clone(), 60, 1);
        let b = TokenBucket::new(path_b.clone(), 60, 1);
        assert!(a.try_consume(1_700_000_000).unwrap());
        assert!(!a.try_consume(1_700_000_000).unwrap());
        assert!(
            b.try_consume(1_700_000_000).unwrap(),
            "a separate state file must have its own full bucket"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }
}
