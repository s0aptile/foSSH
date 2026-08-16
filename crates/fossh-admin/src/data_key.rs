use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use fossh_ingest::random::read_random_bytes;

pub const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum DataKeyError {
    Random(String),
    Io(std::io::Error),

    Corrupt,
}

impl std::fmt::Display for DataKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Random(e) => write!(f, "generating data key: {e}"),
            Self::Io(e) => write!(f, "data key file I/O: {e}"),
            Self::Corrupt => write!(f, "data key file is not exactly {KEY_LEN} bytes"),
        }
    }
}

impl std::error::Error for DataKeyError {}

fn parse(bytes: Vec<u8>) -> Result<Zeroizing<[u8; KEY_LEN]>, DataKeyError> {
    let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| DataKeyError::Corrupt)?;
    Ok(Zeroizing::new(arr))
}

fn write_via_temp_then_link(path: &Path, key: &[u8; KEY_LEN]) -> Result<(), DataKeyError> {

    let suffix = read_random_bytes(8).map_err(|e| DataKeyError::Random(e.to_string()))?;
    let suffix_hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp_name = format!(
        "{}.tmp-{}-{suffix_hex}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
        std::process::id(),
    );
    let tmp_path = path.with_file_name(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    {
        let mut file = opts.open(&tmp_path).map_err(DataKeyError::Io)?;
        file.write_all(key).map_err(DataKeyError::Io)?;
        file.sync_all().map_err(DataKeyError::Io)?;
    }

    let result = fs::hard_link(&tmp_path, path);
    fs::remove_file(&tmp_path).ok();
    result.map_err(DataKeyError::Io)
}

fn generate_and_write(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, DataKeyError> {
    let raw = read_random_bytes(KEY_LEN).map_err(|e| DataKeyError::Random(e.to_string()))?;
    let key: [u8; KEY_LEN] = raw
        .as_slice()
        .try_into()
        .expect("read exactly KEY_LEN bytes");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(DataKeyError::Io)?;
    }
    write_via_temp_then_link(path, &key)?;
    Ok(Zeroizing::new(key))
}

pub fn load_or_generate(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, DataKeyError> {
    match fs::read(path) {
        Ok(bytes) => parse(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match generate_and_write(path) {
            Ok(key) => Ok(key),
            Err(DataKeyError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::read(path).map_err(DataKeyError::Io).and_then(parse)
            }
            Err(e) => Err(e),
        },
        Err(e) => Err(DataKeyError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fossh-admin-data-key-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn first_load_generates_a_key_file_with_0600() {
        let path = scratch_path("fresh");
        let _ = fs::remove_file(&path);
        let key = load_or_generate(&path).unwrap();
        assert_eq!(key.len(), KEY_LEN);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn second_load_returns_the_same_key_as_the_first() {
        let path = scratch_path("stable");
        let _ = fs::remove_file(&path);
        let first = load_or_generate(&path).unwrap();
        let second = load_or_generate(&path).unwrap();
        assert_eq!(*first, *second);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn two_different_paths_get_different_keys() {
        let a = scratch_path("a");
        let b = scratch_path("b");
        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);
        let key_a = load_or_generate(&a).unwrap();
        let key_b = load_or_generate(&b).unwrap();
        assert_ne!(*key_a, *key_b);
        fs::remove_file(&a).ok();
        fs::remove_file(&b).ok();
    }

    #[test]
    fn corrupt_key_file_is_refused_not_silently_reinterpreted() {
        let path = scratch_path("corrupt");
        let _ = fs::remove_file(&path);
        fs::write(&path, b"too short").unwrap();
        assert!(matches!(
            load_or_generate(&path),
            Err(DataKeyError::Corrupt)
        ));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn concurrent_first_callers_all_converge_on_the_same_key() {
        let path = scratch_path("concurrent");
        let _ = fs::remove_file(&path);
        let path = std::sync::Arc::new(path);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = std::sync::Arc::clone(&path);
                std::thread::spawn(move || load_or_generate(&path).unwrap())
            })
            .collect();

        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for k in &keys[1..] {
            assert_eq!(
                **k, *keys[0],
                "every concurrent first-caller must converge on one key"
            );
        }
        fs::remove_file(&*path).ok();
    }
}
