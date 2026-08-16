use std::fs::File;
use std::io::Read;

use zeroize::Zeroizing;

use crate::IngestError;

pub fn read_random_bytes(n: usize) -> Result<Zeroizing<Vec<u8>>, IngestError> {
    let mut f = File::open("/dev/urandom").map_err(IngestError::Random)?;
    let mut buf = Zeroizing::new(vec![0u8; n]);
    f.read_exact(&mut buf).map_err(IngestError::Random)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_requested_length() {
        let bytes = read_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn two_calls_are_not_identical() {

        let a = read_random_bytes(32).unwrap();
        let b = read_random_bytes(32).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn zero_length_is_fine() {
        let bytes = read_random_bytes(0).unwrap();
        assert!(bytes.is_empty());
    }
}
