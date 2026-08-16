pub const PRECISION: u32 = 12;
pub const NUM_REGISTERS: usize = 1 << PRECISION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hll {
    registers: Vec<u8>,
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

    pub fn add(&mut self, hash: u64) {
        let idx = (hash >> (64 - PRECISION)) as usize;
        let rest = hash << PRECISION;

        let rho = (rest.leading_zeros() + 1).min(64 - PRECISION + 1) as u8;
        if rho > self.registers[idx] {
            self.registers[idx] = rho;
        }
    }

    pub fn merge(&mut self, other: &Hll) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
    }

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
