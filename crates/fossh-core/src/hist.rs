pub const NUM_BUCKETS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    buckets: [u32; NUM_BUCKETS],
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        Self {
            buckets: [0u32; NUM_BUCKETS],
        }
    }

    fn bucket_index(value: u64) -> usize {
        let bit_length = 64 - value.leading_zeros() as usize;
        bit_length.min(NUM_BUCKETS - 1)
    }

    pub fn add(&mut self, value: i64) {
        if value < 0 {
            return;
        }
        let idx = Self::bucket_index(value as u64);
        self.buckets[idx] = self.buckets[idx].saturating_add(1);
    }

    pub fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a = a.saturating_add(*b);
        }
    }

    pub fn total(&self) -> u64 {
        self.buckets.iter().map(|&c| c as u64).sum()
    }

    pub fn percentile(&self, p: f64) -> i64 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        let target = ((total as f64) * p).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            cumulative += c as u64;
            if cumulative >= target {
                return if i == 0 { 0 } else { 1i64 << (i - 1) };
            }
        }
        1i64 << (NUM_BUCKETS - 2)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buckets.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != NUM_BUCKETS * 4 {
            return None;
        }
        let mut buckets = [0u32; NUM_BUCKETS];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            buckets[i] = u32::from_le_bytes(chunk.try_into().expect("chunk of 4"));
        }
        Some(Self { buckets })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_percentile_is_zero() {
        let h = Histogram::new();
        assert_eq!(h.percentile(0.5), 0);
        assert_eq!(h.percentile(0.95), 0);
    }

    #[test]
    fn single_zero_value() {
        let mut h = Histogram::new();
        h.add(0);
        assert_eq!(h.percentile(0.5), 0);
    }

    #[test]
    fn all_same_value_bucket_lower_bound() {
        let mut h = Histogram::new();
        for _ in 0..100 {
            h.add(100);
        }

        let p = h.percentile(0.5);
        assert_eq!(p, 64);
    }

    #[test]
    fn p95_at_least_p50() {
        let mut h = Histogram::new();
        for v in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1000, 5000] {
            h.add(v);
        }
        assert!(h.percentile(0.95) >= h.percentile(0.5));
    }

    #[test]
    fn monotonic_in_p() {
        let mut h = Histogram::new();
        for v in 0..1000 {
            h.add(v);
        }
        let mut last = 0;
        for p in [0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99] {
            let cur = h.percentile(p);
            assert!(cur >= last, "percentile must be non-decreasing in p");
            last = cur;
        }
    }

    #[test]
    fn merge_matches_direct_union_exactly() {
        let mut a = Histogram::new();
        let mut b = Histogram::new();
        for v in 0..500 {
            a.add(v);
        }
        for v in 500..1000 {
            b.add(v);
        }
        let mut merged = a.clone();
        merged.merge(&b);

        let mut direct = Histogram::new();
        for v in 0..1000 {
            direct.add(v);
        }
        assert_eq!(merged, direct);
    }

    #[test]
    fn negative_values_are_ignored_not_panicking() {
        let mut h = Histogram::new();
        h.add(-1);
        h.add(-1000);
        assert_eq!(h.total(), 0);
    }

    #[test]
    fn bytes_roundtrip() {
        let mut h = Histogram::new();
        for v in [1, 10, 100, 1000, 10_000] {
            h.add(v);
        }
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), NUM_BUCKETS * 4);
        let restored = Histogram::from_bytes(&bytes).unwrap();
        assert_eq!(h, restored);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Histogram::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn large_values_do_not_panic() {
        let mut h = Histogram::new();
        h.add(i64::MAX);
        assert!(h.percentile(0.5) > 0);
    }
}
