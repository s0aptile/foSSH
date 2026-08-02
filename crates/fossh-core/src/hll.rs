//! Hand-rolled HyperLogLog (p = 12 → 4096 registers, 1 byte each = 4 KiB),
//! used to estimate unique `visitor` counts in rollups without retaining
//! individual visitor hashes past the retention window (§6 "Uniques").
//! ~100 lines, no dependency — justified in DECISIONS.md over pulling in a
//! crate for something this size and this central to the privacy story.
//!
//! Callers pass an already-hashed 64-bit value — the `visitor` id produced
//! by [`crate::visitor::hash_visitor`]. HyperLogLog always assumes its
//! input is uniformly distributed, so no additional hashing happens here.
//!
//! Only the 64-bit-hash-space variant is implemented (no "large range"
//! correction from the original paper, which exists for 32-bit hash
//! spaces): cardinalities in this product are visitor counts per
//! site-per-hour, nowhere near approaching 2^64.

pub const PRECISION: u32 = 12;
pub const NUM_REGISTERS: usize = 1 << PRECISION; // 4096

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hll {
    registers: Vec<u8>, // len == NUM_REGISTERS
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl Hll {
    pub fn new() -> Self {
        Self {
            registers: vec![0u8; NUM_REGISTERS],
        }
    }

    /// Folds one already-hashed 64-bit value into the sketch.
    pub fn add(&mut self, hash: u64) {
        let idx = (hash >> (64 - PRECISION)) as usize;
        let rest = hash << PRECISION; // discard the top PRECISION bits used as idx
        // 1-indexed position of the leftmost 1-bit among the remaining
        // (64-PRECISION) bits; an all-zero remainder saturates at
        // (64-PRECISION+1), the standard HLL convention.
        let rho = (rest.leading_zeros() + 1).min(64 - PRECISION + 1) as u8;
        if rho > self.registers[idx] {
            self.registers[idx] = rho;
        }
    }

    /// Merges another sketch of the same precision into this one
    /// (register-wise max — mathematically identical to having processed
    /// the union of both input multisets into a single sketch).
    pub fn merge(&mut self, other: &Hll) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
    }

    /// Estimated cardinality (standard HLL estimator with small-range /
    /// linear-counting correction; ~1.6% standard error at p=12).
    pub fn estimate(&self) -> f64 {
        let m = NUM_REGISTERS as f64;
        let alpha_m = 0.7213 / (1.0 + 1.079 / m);

        let sum_inv: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let raw = alpha_m * m * m / sum_inv;

        let zeros = self.registers.iter().filter(|&&r| r == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }

    /// Serializes to the fixed-size (`NUM_REGISTERS`-byte) BLOB form stored
    /// in `rollup_hourly` (see the M2 ADR on why that column is a BLOB, not
    /// the `INTEGER` shown in §6's illustrative `CREATE TABLE`).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.registers.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != NUM_REGISTERS {
            return None;
        }
        Some(Self {
            registers: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic, dependency-free PRNG (SplitMix64) for generating
    /// test hash values without pulling in `rand`.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn empty_estimates_near_zero() {
        let hll = Hll::new();
        assert!(hll.estimate() < 1.0, "estimate = {}", hll.estimate());
    }

    #[test]
    fn small_count_is_roughly_right() {
        let mut hll = Hll::new();
        let mut state = 42u64;
        for _ in 0..5 {
            hll.add(splitmix64(&mut state));
        }
        let est = hll.estimate();
        assert!((0.0..=15.0).contains(&est), "estimate = {est}");
    }

    #[test]
    fn large_count_within_error_budget() {
        let mut hll = Hll::new();
        let mut state = 7u64;
        let n = 100_000u64;
        for _ in 0..n {
            hll.add(splitmix64(&mut state));
        }
        let est = hll.estimate();
        let rel_error = (est - n as f64).abs() / n as f64;
        // Spec quotes ~1.6% standard error for p=12; allow generous slack
        // (10%, several sigma) so the test isn't flaky under a fixed seed.
        assert!(rel_error < 0.10, "n={n} est={est} rel_error={rel_error}");
    }

    #[test]
    fn duplicates_do_not_inflate_count() {
        let mut hll = Hll::new();
        for _ in 0..10_000 {
            hll.add(0xDEAD_BEEF_CAFE_BABE);
        }
        let est = hll.estimate();
        assert!(est < 10.0, "estimate = {est}");
    }

    #[test]
    fn merge_matches_direct_union_exactly() {
        let mut a = Hll::new();
        let mut b = Hll::new();
        let mut state = 99u64;
        for _ in 0..5_000 {
            a.add(splitmix64(&mut state));
        }
        for _ in 0..5_000 {
            b.add(splitmix64(&mut state));
        }
        let mut merged = a.clone();
        merged.merge(&b);

        let mut direct = Hll::new();
        let mut state2 = 99u64;
        for _ in 0..10_000 {
            direct.add(splitmix64(&mut state2));
        }

        assert_eq!(
            merged, direct,
            "register-wise max-merge must equal processing the union directly"
        );
    }

    #[test]
    fn merge_is_commutative() {
        let mut state = 123u64;
        let vals: Vec<u64> = (0..2_000).map(|_| splitmix64(&mut state)).collect();
        let (left, right) = vals.split_at(1000);

        let mut a = Hll::new();
        for &v in left {
            a.add(v);
        }
        let mut b = Hll::new();
        for &v in right {
            b.add(v);
        }

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn bytes_roundtrip() {
        let mut hll = Hll::new();
        let mut state = 5u64;
        for _ in 0..1_000 {
            hll.add(splitmix64(&mut state));
        }
        let bytes = hll.to_bytes();
        assert_eq!(bytes.len(), NUM_REGISTERS);
        let restored = Hll::from_bytes(&bytes).expect("valid length");
        assert_eq!(hll, restored);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Hll::from_bytes(&[0u8; 10]).is_none());
        assert!(Hll::from_bytes(&[]).is_none());
        assert!(Hll::from_bytes(&[0u8; NUM_REGISTERS + 1]).is_none());
    }

    #[test]
    fn new_serializes_to_all_zero_registers() {
        let bytes = Hll::new().to_bytes();
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
