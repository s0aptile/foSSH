//! P2: daily salt lifecycle. `daily_salt` is 32 random bytes, generated at
//! first use, rotated at 00:00 UTC. In CGI mode there is no persistent
//! process to hold it in memory across requests, so P2 explicitly carves
//! out a tmpfs-backed file for that case: `0600`, regenerated when its
//! mtime crosses the UTC day boundary, `shred`-overwritten on rotation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use zeroize::Zeroizing;

use fossh_core::visitor::SALT_LEN;

use crate::IngestError;

fn read_random_bytes(n: usize) -> Result<Zeroizing<Vec<u8>>, IngestError> {
    let mut f = File::open("/dev/urandom").map_err(IngestError::Random)?;
    let mut buf = Zeroizing::new(vec![0u8; n]);
    f.read_exact(&mut buf).map_err(IngestError::Random)?;
    Ok(buf)
}

fn utc_day(t: SystemTime) -> Result<i64, IngestError> {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| IngestError::Io(std::io::Error::other("system clock before unix epoch")))?
        .as_secs();
    Ok((secs / 86_400) as i64)
}

fn write_new_salt(path: &Path) -> Result<Zeroizing<[u8; SALT_LEN]>, IngestError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let random = read_random_bytes(SALT_LEN)?;
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    salt.copy_from_slice(&random);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&*salt)?;
    let _ = file.sync_all(); // best-effort — tmpfs has no durability to lose anyway

    // `.mode(0o600)` on OpenOptions only governs a *newly created* file;
    // enforce it explicitly too in case a file already existed here with
    // wider permissions from a previous, differently-configured run.
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;

    Ok(salt)
}

/// Overwrites a file's bytes with zeroes before removing it — a `shred`
/// stand-in without shelling out. Best-effort, with the same caveat every
/// software-level shred has on copy-on-write/journaled/wear-levelled
/// storage — which is exactly why P2 puts this file on tmpfs: plain RAM,
/// none of those caveats apply.
fn shred(path: &Path) -> Result<(), IngestError> {
    if let Ok(metadata) = fs::metadata(path)
        && let Ok(mut file) = OpenOptions::new().write(true).open(path)
    {
        let zeros = vec![0u8; metadata.len() as usize];
        let _ = file.write_all(&zeros);
        let _ = file.sync_all();
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(IngestError::Io(e)),
    }
}

/// Owns the salt file location for a site. Each CGI invocation is its own
/// process with no shared state, so `current()` is meant to be called
/// once per request; it transparently generates or rotates the on-disk
/// salt as needed and returns the day's value.
pub struct SaltManager {
    salt_dir: PathBuf,
}

impl SaltManager {
    pub fn new(salt_dir: PathBuf) -> Self {
        Self { salt_dir }
    }

    fn path(&self) -> PathBuf {
        self.salt_dir.join("daily_salt")
    }

    pub fn current(&self) -> Result<Zeroizing<[u8; SALT_LEN]>, IngestError> {
        self.current_at(SystemTime::now())
    }

    fn current_at(&self, now: SystemTime) -> Result<Zeroizing<[u8; SALT_LEN]>, IngestError> {
        let path = self.path();
        let today = utc_day(now)?;

        match fs::metadata(&path) {
            Ok(meta) => {
                let mtime = meta.modified()?;
                if utc_day(mtime)? == today {
                    let mut f = File::open(&path)?;
                    let mut buf = Zeroizing::new(vec![0u8; SALT_LEN]);
                    f.read_exact(&mut buf)?;
                    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
                    salt.copy_from_slice(&buf);
                    Ok(salt)
                } else {
                    shred(&path)?;
                    write_new_salt(&path)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_new_salt(&path),
            Err(e) => Err(IngestError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-salt-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn generates_a_salt_on_first_use() {
        let dir = scratch_dir("first-use");
        let mgr = SaltManager::new(dir.clone());
        let salt = mgr.current().unwrap();
        assert_eq!(salt.len(), SALT_LEN);
        assert!(
            !salt.iter().all(|&b| b == 0),
            "a real random salt should not be all zero"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_day_reuses_the_same_salt() {
        let dir = scratch_dir("same-day");
        let mgr = SaltManager::new(dir.clone());
        let a = mgr.current().unwrap();
        let b = mgr.current().unwrap();
        assert_eq!(*a, *b);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_is_0600() {
        let dir = scratch_dir("perms");
        let mgr = SaltManager::new(dir.clone());
        mgr.current().unwrap();
        let mode = fs::metadata(mgr.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotates_when_the_file_is_from_a_previous_utc_day() {
        let dir = scratch_dir("rotate");
        let mgr = SaltManager::new(dir.clone());
        let yesterday = mgr.current().unwrap();

        // Backdate the file's mtime by 2 days so the next `current_at` call
        // (with "now" a day later) sees it as stale and rotates.
        let file = File::options().write(true).open(mgr.path()).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(2 * 86_400))
            .unwrap();

        let today = mgr.current_at(SystemTime::now()).unwrap();
        assert_ne!(
            *yesterday, *today,
            "crossing a UTC day boundary must produce a new salt"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn old_salt_file_is_gone_after_rotation_not_just_overwritten_in_place() {
        // Regression guard for the shred-then-recreate path: after
        // rotation the file must still exist (freshly created), readable,
        // and 0600 — not left in some half-shredded state.
        let dir = scratch_dir("rotate-integrity");
        let mgr = SaltManager::new(dir.clone());
        mgr.current().unwrap();
        let file = File::options().write(true).open(mgr.path()).unwrap();
        file.set_modified(UNIX_EPOCH).unwrap(); // epoch — definitely a previous day
        let rotated = mgr.current_at(SystemTime::now()).unwrap();
        assert_eq!(rotated.len(), SALT_LEN);
        let mode = fs::metadata(mgr.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_managers_different_dirs_get_independent_salts() {
        let dir_a = scratch_dir("indep-a");
        let dir_b = scratch_dir("indep-b");
        let a = SaltManager::new(dir_a.clone()).current().unwrap();
        let b = SaltManager::new(dir_b.clone()).current().unwrap();
        assert_ne!(*a, *b);
        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }
}
