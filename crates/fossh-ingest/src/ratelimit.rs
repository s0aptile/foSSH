use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::IngestError;

const STATE_BYTES: usize = 16;

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

    pub fn try_consume(&self, now: i64) -> Result<bool, IngestError> {
        let open_opts = || {
            let mut o = OpenOptions::new();
            o.read(true).write(true).create(true).truncate(false);
            o
        };
        let mut file = match open_opts().open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                open_opts().open(&self.path)?
            }
            Err(e) => return Err(e.into()),
        };

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

const IP_FAIL_PER_SEC: f64 = 1.0;
const IP_FAIL_BURST: f64 = 20.0;

pub struct IpFailBucket {
    path: PathBuf,
}

const IP_FAIL_SLOTS: u64 = 65_536;
const IP_FAIL_SLOT_BYTES: usize = 24;

impl IpFailBucket {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn fingerprint(source: &str) -> u64 {
        let hash = blake3::hash(source.as_bytes());
        u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("8 bytes"))
    }

    pub fn record_failure(&self, source: &str, now: i64) -> Result<bool, IngestError> {
        let open_opts = || {
            let mut o = OpenOptions::new();
            o.read(true).write(true).create(true).truncate(false);
            o
        };
        let mut file = match open_opts().open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                open_opts().open(&self.path)?
            }
            Err(e) => return Err(e.into()),
        };

        let fingerprint = Self::fingerprint(source);
        let slot = fingerprint % IP_FAIL_SLOTS;
        let offset = slot * IP_FAIL_SLOT_BYTES as u64;

        let needed_len = IP_FAIL_SLOTS * IP_FAIL_SLOT_BYTES as u64;
        if file.metadata()?.len() < needed_len {
            file.set_len(needed_len)?;
        }

        file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; IP_FAIL_SLOT_BYTES];
        file.read_exact(&mut buf)?;
        let stored_fp = u64::from_le_bytes(buf[0..8].try_into().expect("8 bytes"));
        let stored_tokens = f64::from_le_bytes(buf[8..16].try_into().expect("8 bytes"));
        let stored_last_refill = i64::from_le_bytes(buf[16..24].try_into().expect("8 bytes"));

        let (tokens, last_refill) = if stored_fp == fingerprint {
            (stored_tokens, stored_last_refill)
        } else {
            (IP_FAIL_BURST, now)
        };

        let elapsed = (now - last_refill).max(0) as f64;
        let refilled = (tokens + elapsed * IP_FAIL_PER_SEC).min(IP_FAIL_BURST);
        let (allowed, remaining) = if refilled >= 1.0 {
            (true, refilled - 1.0)
        } else {
            (false, refilled)
        };

        let mut out = [0u8; IP_FAIL_SLOT_BYTES];
        out[0..8].copy_from_slice(&fingerprint.to_le_bytes());
        out[8..16].copy_from_slice(&remaining.to_le_bytes());
        out[16..24].copy_from_slice(&now.to_le_bytes());
        file.seek(SeekFrom::Start(offset))?;
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
        let bucket = TokenBucket::new(path.clone(), 10, 5);
        let now = 1_700_000_000;
        for _ in 0..5 {
            assert!(bucket.try_consume(now).unwrap());
        }
        assert!(!bucket.try_consume(now).unwrap());

        assert!(bucket.try_consume(now + 1).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refill_never_exceeds_burst_cap() {
        let path = scratch_path("cap");
        let bucket = TokenBucket::new(path.clone(), 1_000_000, 3);
        let now = 1_700_000_000;
        assert!(bucket.try_consume(now).unwrap());

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

    #[test]
    fn a_sustained_run_of_failures_from_one_source_eventually_gets_throttled() {
        let path = scratch_path("ip-fail-sustained");
        let bucket = IpFailBucket::new(path.clone());
        let now = 1_700_000_000;

        for i in 0..20 {
            assert!(
                bucket.record_failure("203.0.113.9", now).unwrap(),
                "failure {i} within the burst allowance must still be 'allowed' (401, not yet 429)"
            );
        }
        assert!(
            !bucket.record_failure("203.0.113.9", now).unwrap(),
            "burst exhausted: a sustained flood of auth failures from one source must eventually throttle"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn failures_refill_over_time_same_as_token_bucket() {
        let path = scratch_path("ip-fail-refill");
        let bucket = IpFailBucket::new(path.clone());
        let now = 1_700_000_000;
        for _ in 0..20 {
            assert!(bucket.record_failure("203.0.113.9", now).unwrap());
        }
        assert!(!bucket.record_failure("203.0.113.9", now).unwrap());
        assert!(bucket.record_failure("203.0.113.9", now + 1).unwrap());
        assert!(!bucket.record_failure("203.0.113.9", now + 1).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn different_sources_get_independent_allowances() {
        let path = scratch_path("ip-fail-independent");
        let bucket = IpFailBucket::new(path.clone());
        let now = 1_700_000_000;
        for _ in 0..20 {
            assert!(bucket.record_failure("203.0.113.9", now).unwrap());
        }
        assert!(
            !bucket.record_failure("203.0.113.9", now).unwrap(),
            "first source must now be throttled"
        );
        assert!(
            bucket.record_failure("198.51.100.7", now).unwrap(),
            "a genuinely different source must have its own, untouched allowance"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fingerprint_is_stable_and_source_sensitive() {
        assert_eq!(
            IpFailBucket::fingerprint("203.0.113.9"),
            IpFailBucket::fingerprint("203.0.113.9")
        );
        assert_ne!(
            IpFailBucket::fingerprint("203.0.113.9"),
            IpFailBucket::fingerprint("198.51.100.7")
        );
    }
}
