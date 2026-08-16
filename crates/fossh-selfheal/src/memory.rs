use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const FILE_NAME: &str = "advisor-memory.enc";

pub const MAX_OBSERVATIONS: usize = 256;

pub const RETENTION_DAYS: i64 = 30;

const MAX_FILE_LEN: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {

    Detected,

    Remedied,

    RemedyDidNotHold,

    RolledBack,

    Recurred,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Detected => "detected",
            Outcome::Remedied => "remedied",
            Outcome::RemedyDidNotHold => "remedy did not hold",
            Outcome::RolledBack => "rolled back",
            Outcome::Recurred => "recurred",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {

    pub finding_id: String,
    pub at: i64,
    pub outcome: Outcome,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Memory {
    #[serde(default)]
    entries: Vec<Observation>,
}

#[derive(Debug)]
pub enum MemoryError {
    Io(String),

    Unusable,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::Io(m) => write!(f, "{m}"),
            MemoryError::Unusable => write!(
                f,
                "the advisory layer's memory could not be read and has been discarded; \
                 self-healing is unaffected"
            ),
        }
    }
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

fn is_finding_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl Memory {
    pub fn entries(&self) -> &[Observation] {
        &self.entries
    }

    pub fn record(&mut self, finding_id: &str, outcome: Outcome, now: i64) {
        if !is_finding_id(finding_id) {

            return;
        }
        self.entries.push(Observation {
            finding_id: finding_id.to_string(),
            at: now,
            outcome,
        });
        self.prune(now);
    }

    pub fn prune(&mut self, now: i64) {
        let cutoff = now - RETENTION_DAYS * 86_400;
        self.entries.retain(|e| e.at >= cutoff);
        if self.entries.len() > MAX_OBSERVATIONS {
            let excess = self.entries.len() - MAX_OBSERVATIONS;
            self.entries.drain(0..excess);
        }
    }

    pub fn count(&self, finding_id: &str) -> usize {
        self.entries
            .iter()
            .filter(|e| e.finding_id == finding_id)
            .count()
    }

    pub fn context_for(&self, finding_id: &str) -> Option<String> {
        let mine: Vec<&Observation> = self
            .entries
            .iter()
            .filter(|e| e.finding_id == finding_id)
            .collect();
        if mine.len() < 2 {
            return None;
        }
        let failures = mine
            .iter()
            .filter(|e| matches!(e.outcome, Outcome::RemedyDidNotHold | Outcome::RolledBack))
            .count();
        let recurrences = mine
            .iter()
            .filter(|e| e.outcome == Outcome::Recurred)
            .count();

        let mut parts = vec![format!(
            "seen {} times in the last {RETENTION_DAYS} days",
            mine.len()
        )];
        if recurrences > 0 {
            parts.push(format!("came back {recurrences} time(s) after being fixed"));
        }
        if failures > 0 {
            parts.push(format!("an automatic fix failed {failures} time(s)"));
        }
        Some(parts.join("; "))
    }

    pub fn load_or_forget(data_dir: &Path, key: &[u8; 32]) -> Self {
        let p = path(data_dir);
        let Ok(meta) = std::fs::metadata(&p) else {
            return Self::default();
        };
        if meta.len() > MAX_FILE_LEN {
            return Self::default();
        }
        let Ok(sealed) = std::fs::read(&p) else {
            return Self::default();
        };
        let Ok(plain) = fossh_ingest::crypto::open(key, &sealed) else {
            return Self::default();
        };
        let plain = Zeroizing::new(plain);
        let Ok(mut memory) = serde_json::from_slice::<Self>(&plain) else {
            return Self::default();
        };

        memory.entries.retain(|e| is_finding_id(&e.finding_id));
        memory
    }

    pub fn save(&self, data_dir: &Path, key: &[u8; 32]) -> Result<(), MemoryError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let plain =
            Zeroizing::new(serde_json::to_vec(self).map_err(|e| MemoryError::Io(e.to_string()))?);
        let sealed =
            fossh_ingest::crypto::seal(key, &plain).map_err(|e| MemoryError::Io(e.to_string()))?;

        let final_path = path(data_dir);
        let tmp = final_path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| MemoryError::Io(format!("{}: {e}", tmp.display())))?;
            f.write_all(&sealed)
                .map_err(|e| MemoryError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| MemoryError::Io(e.to_string()))?;
        }
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(MemoryError::Io(format!("{}: {e}", final_path.display())));
        }
        Ok(())
    }

    pub fn forget_all(data_dir: &Path) {
        let _ = std::fs::remove_file(path(data_dir));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fossh-memory-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn an_observation_has_nowhere_to_put_a_sentence() {

        let o = Observation {
            finding_id: "data_key_permissions".to_string(),
            at: NOW,
            outcome: Outcome::Detected,
        };
        let json = serde_json::to_value(&o).unwrap();
        let fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            fields.len(),
            3,
            "a field was added to Observation: {fields:?}"
        );
        for f in &fields {
            assert!(
                ["finding_id", "at", "outcome"].contains(f),
                "unexpected field {f:?} — could it hold model output?"
            );
        }
    }

    #[test]
    fn prose_cannot_be_smuggled_in_through_the_id() {
        let mut m = Memory::default();

        m.record(
            "The model thinks this is probably fine",
            Outcome::Detected,
            NOW,
        );
        m.record("data_key_permissions", Outcome::Detected, NOW);
        assert_eq!(m.entries().len(), 1);
        assert_eq!(m.entries()[0].finding_id, "data_key_permissions");
    }

    #[test]
    fn memory_is_bounded() {
        let mut m = Memory::default();
        for i in 0..(MAX_OBSERVATIONS + 50) {
            m.record("data_key_permissions", Outcome::Detected, NOW + i as i64);
        }
        assert_eq!(m.entries().len(), MAX_OBSERVATIONS);
    }

    #[test]
    fn old_observations_expire() {
        let mut m = Memory::default();
        m.record("data_key_permissions", Outcome::Detected, NOW - 40 * 86_400);
        m.record("data_key_permissions", Outcome::Detected, NOW);
        m.prune(NOW);
        assert_eq!(
            m.entries().len(),
            1,
            "an entry older than retention survived"
        );
        assert_eq!(m.entries()[0].at, NOW);
    }

    #[test]
    fn context_says_nothing_until_there_is_a_pattern() {
        let mut m = Memory::default();
        assert_eq!(m.context_for("data_key_permissions"), None);
        m.record("data_key_permissions", Outcome::Detected, NOW);
        assert_eq!(
            m.context_for("data_key_permissions"),
            None,
            "one occurrence is not a pattern"
        );
        m.record("data_key_permissions", Outcome::Recurred, NOW + 60);
        let c = m.context_for("data_key_permissions").unwrap();
        assert!(c.contains("seen 2 times"));
        assert!(c.contains("came back"));
    }

    #[test]
    fn context_is_assembled_from_counts_not_from_stored_text() {

        let mut m = Memory::default();
        for i in 0..3 {
            m.record("watchdog_unreachable", Outcome::RolledBack, NOW + i);
        }
        let c = m.context_for("watchdog_unreachable").unwrap();
        assert!(c.contains("3 times"));
        assert!(c.contains("automatic fix failed 3 time(s)"));
    }

    #[test]
    fn memory_round_trips_through_the_sealed_file() {
        let dir = scratch("roundtrip");
        let key = [21u8; 32];
        let mut m = Memory::default();
        m.record("data_key_permissions", Outcome::Detected, NOW);
        m.record("data_key_permissions", Outcome::Remedied, NOW + 10);
        m.save(&dir, &key).unwrap();

        let back = Memory::load_or_forget(&dir, &key);
        assert_eq!(back.entries().len(), 2);
        assert_eq!(back.count("data_key_permissions"), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_file_is_sealed_not_plaintext() {
        let dir = scratch("sealed");
        let key = [22u8; 32];
        let mut m = Memory::default();
        m.record("watchdog_unreachable", Outcome::Recurred, NOW);
        m.save(&dir, &key).unwrap();
        let raw = fs::read(path(&dir)).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("watchdog_unreachable"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_wrong_key_forgets_rather_than_failing() {

        let dir = scratch("wrongkey");
        let mut m = Memory::default();
        m.record("data_key_permissions", Outcome::Detected, NOW);
        m.save(&dir, &[23u8; 32]).unwrap();
        assert!(
            Memory::load_or_forget(&dir, &[24u8; 32])
                .entries()
                .is_empty()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tampered_file_forgets_rather_than_failing() {
        let dir = scratch("tampered");
        let key = [25u8; 32];
        let mut m = Memory::default();
        m.record("data_key_permissions", Outcome::Detected, NOW);
        m.save(&dir, &key).unwrap();
        let p = path(&dir);
        let mut raw = fs::read(&p).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        fs::write(&p, raw).unwrap();
        assert!(Memory::load_or_forget(&dir, &key).entries().is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_simply_an_empty_memory() {
        let dir = scratch("absent");
        assert!(
            Memory::load_or_forget(&dir, &[26u8; 32])
                .entries()
                .is_empty()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forgetting_is_available_and_complete() {
        let dir = scratch("forget");
        let key = [27u8; 32];
        let mut m = Memory::default();
        m.record("data_key_permissions", Outcome::Detected, NOW);
        m.save(&dir, &key).unwrap();
        Memory::forget_all(&dir);
        assert!(!path(&dir).exists());
        assert!(Memory::load_or_forget(&dir, &key).entries().is_empty());
        fs::remove_dir_all(&dir).ok();
    }
}
