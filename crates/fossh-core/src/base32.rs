const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = (bits >> bit_count) & 0x1F;
            out.push(ALPHABET[idx as usize] as char);
        }
    }
    if bit_count > 0 {
        let idx = (bits << (5 - bit_count)) & 0x1F;
        out.push(ALPHABET[idx as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(val);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (input, expected) in cases {
            assert_eq!(encode(input), *expected, "encoding {input:?}");
            assert_eq!(decode(expected).unwrap(), *input, "decoding {expected:?}");
        }
    }

    #[test]
    fn decode_accepts_lowercase() {
        assert_eq!(decode("mzxw6ytboi"), decode("MZXW6YTBOI"));
    }

    #[test]
    fn decode_rejects_invalid_characters() {
        assert!(decode("MZXW6YTBOI!").is_none());
        assert!(decode("01").is_none());
    }

    #[test]
    fn round_trip_random_lengths() {

        let mut state = 0xC0FFEEu64;
        let mut next = || {
            state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            (z ^ (z >> 27)) as u8
        };
        for len in 0..=64 {
            let bytes: Vec<u8> = (0..len).map(|_| next()).collect();
            let encoded = encode(&bytes);
            assert!(encoded.bytes().all(|b| ALPHABET.contains(&b)), "len={len}");
            assert_eq!(decode(&encoded).unwrap(), bytes, "len={len}");
        }
    }

    #[test]
    fn key_length_round_trips() {

        let key = [0xAB_u8; 32];
        let encoded = encode(&key);
        assert_eq!(decode(&encoded).unwrap(), key.to_vec());
    }
}
