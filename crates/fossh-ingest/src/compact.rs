//! Draining spool files into the store — shared by `fossh-cli maintain`
//! and (M7) `fossh-fcgi`'s background compactor thread. `rename()` alone
//! is not sufficient for safety against a concurrent writer holding an
//! already-open fd across the rename: a write through that stale fd,
//! landing after this module's own read-to-EOF but before (or during)
//! its `remove_file`, would be silently lost once the fd closes. The
//! rotate-read-drain sequence below therefore holds `spool::lock_path`'s
//! `spool.lock` exclusively for exactly that sequence; `append_frame`
//! holds the same lock file shared for its own open-and-write. See
//! DECISIONS.md for the incident this closed.

use std::fs;
use std::path::Path;

use fossh_store::Store;

use crate::IngestError;
use crate::spool::{self, DrainedFrame};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompactStats {
    pub events_recorded: u64,
    pub frames_corrupt: u64,
    pub files_processed: u64,
}

/// Drains every spool file in `spool_dir` (the live `current.bin`,
/// staged aside first, plus any already-rotated `spool-*.bin` files from
/// `spool::append_frame`'s own 8 MiB rotation) into `store`.
///
/// `key` (§3.8) must be the same per-install data-encryption key the
/// spool was written under (`fossh_admin::data_key`) — see
/// `spool::read_frames` for what happens to a frame written under a
/// different key.
pub fn drain_site_spool(
    store: &mut Store,
    spool_dir: &Path,
    key: &[u8; 32],
) -> Result<CompactStats, IngestError> {
    let mut stats = CompactStats::default();
    if !spool_dir.is_dir() {
        return Ok(stats);
    }

    let current = spool_dir.join("current.bin");
    if current.is_file() {
        let lock = spool::open_lock_file(spool_dir)?;
        lock.lock()?;
        let staged = spool_dir.join(format!(
            "draining-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if fs::rename(&current, &staged).is_ok() {
            drain_file(store, &staged, &mut stats, key)?;
            fs::remove_file(&staged).ok();
        }
        drop(lock);
    }

    if let Ok(entries) = fs::read_dir(spool_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("spool-") && name.ends_with(".bin") {
                let path = entry.path();
                drain_file(store, &path, &mut stats, key)?;
                fs::remove_file(&path).ok();
            }
        }
    }

    Ok(stats)
}

fn drain_file(
    store: &mut Store,
    path: &Path,
    stats: &mut CompactStats,
    key: &[u8; 32],
) -> Result<(), IngestError> {
    let frames = spool::read_frames(path, key)?;
    stats.files_processed += 1;
    for frame in frames {
        match frame {
            DrainedFrame::Event(event) => {
                // S2, fail closed: a store-level rejection (e.g. the spool
                // held a frame that predates a since-tightened allowlist)
                // is dropped exactly like a corrupt frame, not retried
                // forever or allowed to halt the rest of the drain.
                if store.record_event(&event).is_ok() {
                    stats.events_recorded += 1;
                } else {
                    stats.frames_corrupt += 1;
                }
            }
            DrainedFrame::Corrupt => stats.frames_corrupt += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::types::{Country, Event, EventKind, SiteId};
    use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
    use fossh_core::validate::Name;
    use std::io::Write;
    use std::path::PathBuf;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-compact-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn sample_event(ts: i64) -> Event {
        Event {
            site_id: SiteId::new(1),
            ts,
            kind: EventKind::Pageview,
            name: Name::parse("pageview").unwrap(),
            path: None,
            referrer: None,
            country: Country::parse("TR").unwrap(),
            browser: BrowserFamily::Chrome,
            os: OsFamily::Linux,
            device: DeviceClass::Desktop,
            visitor: Some(42),
            value: None,
            props: vec![],
        }
    }

    #[test]
    fn missing_spool_dir_is_a_no_op() {
        let dir = scratch_dir("missing");
        let mut store = Store::open_in_memory().unwrap();
        let stats = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();
        assert_eq!(stats, CompactStats::default());
    }

    #[test]
    fn drains_current_bin_and_records_events() {
        let dir = scratch_dir("basic");
        spool::append_frame(&dir, &sample_event(1_700_000_000), &TEST_KEY).unwrap();
        spool::append_frame(&dir, &sample_event(1_700_000_100), &TEST_KEY).unwrap();

        let mut store = Store::open_in_memory().unwrap();
        let stats = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();
        assert_eq!(stats.events_recorded, 2);
        assert_eq!(stats.frames_corrupt, 0);
        assert_eq!(store.count_events(SiteId::new(1)).unwrap(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn current_bin_is_gone_after_a_successful_drain() {
        let dir = scratch_dir("cleanup");
        spool::append_frame(&dir, &sample_event(1_700_000_000), &TEST_KEY).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();
        assert!(!dir.join("current.bin").exists());
        // And no leftover "draining-*.bin" files either.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("draining-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drains_rotated_spool_files_too() {
        let dir = scratch_dir("rotated");
        fs::create_dir_all(&dir).unwrap();
        // Simulate a file already rotated by `append_frame`'s 8 MiB logic.
        let mut frame = Vec::new();
        let payload = crate::crypto::seal(
            &TEST_KEY,
            &spool::encode_event(&sample_event(1_700_000_000)),
        )
        .unwrap();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&spool::crc32(&payload).to_le_bytes());
        frame.extend_from_slice(&payload);
        fs::write(dir.join("spool-123.bin"), &frame).unwrap();

        let mut store = Store::open_in_memory().unwrap();
        let stats = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();
        assert_eq!(stats.events_recorded, 1);
        assert!(!dir.join("spool-123.bin").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_frames_are_counted_and_do_not_abort_the_drain() {
        let dir = scratch_dir("corrupt");
        spool::append_frame(&dir, &sample_event(1_700_000_000), &TEST_KEY).unwrap();
        let path = dir.join("current.bin");
        let mut bytes = fs::read(&path).unwrap();
        let flip_at = bytes.len() - 2;
        bytes[flip_at] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        spool::append_frame(&dir, &sample_event(1_700_000_100), &TEST_KEY).unwrap(); // a good frame after

        let mut store = Store::open_in_memory().unwrap();
        let stats = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();
        assert_eq!(stats.events_recorded, 1);
        assert_eq!(stats.frames_corrupt, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rename_does_not_disturb_a_still_open_writer() {
        // The safety property `drain_site_spool` relies on: renaming a
        // file out from under an open, already-appending file descriptor
        // does not redirect its writes or truncate what's already there.
        let dir = scratch_dir("rename-safety");
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("current.bin");

        let payload_a =
            crate::crypto::seal(&TEST_KEY, &spool::encode_event(&sample_event(1))).unwrap();
        let mut frame_a = Vec::new();
        frame_a.extend_from_slice(&(payload_a.len() as u32).to_le_bytes());
        frame_a.extend_from_slice(&spool::crc32(&payload_a).to_le_bytes());
        frame_a.extend_from_slice(&payload_a);

        let mut open_writer = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&current)
            .unwrap();
        open_writer.write_all(&frame_a).unwrap();

        let staged = dir.join("draining-test.bin");
        fs::rename(&current, &staged).unwrap();

        let payload_b =
            crate::crypto::seal(&TEST_KEY, &spool::encode_event(&sample_event(2))).unwrap();
        let mut frame_b = Vec::new();
        frame_b.extend_from_slice(&(payload_b.len() as u32).to_le_bytes());
        frame_b.extend_from_slice(&spool::crc32(&payload_b).to_le_bytes());
        frame_b.extend_from_slice(&payload_b);
        open_writer.write_all(&frame_b).unwrap(); // written via the pre-rename fd

        let frames = spool::read_frames(&staged, &TEST_KEY).unwrap();
        assert_eq!(
            frames.len(),
            2,
            "both the pre- and post-rename writes must land in the staged file"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_append_and_drain_forced_start_never_loses_an_event() {
        for attempt in 0..100u64 {
            let dir = scratch_dir(&format!("lock-race-{attempt}"));
            spool::append_frame(&dir, &sample_event(1_000 + attempt as i64), &TEST_KEY).unwrap();

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let dir_w = dir.clone();
            let barrier_w = std::sync::Arc::clone(&barrier);
            let second_ts = 2_000_000 + attempt as i64;
            let writer = std::thread::spawn(move || {
                let ev = sample_event(second_ts);
                barrier_w.wait();
                spool::append_frame(&dir_w, &ev, &TEST_KEY)
            });

            let mut store = Store::open_in_memory().unwrap();
            barrier.wait();
            let first_pass = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();

            let append_result = writer.join().unwrap();
            assert!(
                append_result.is_ok(),
                "attempt {attempt}: concurrent append must not fail: {append_result:?}"
            );

            let second_pass = drain_site_spool(&mut store, &dir, &TEST_KEY).unwrap();

            let total_recorded = first_pass.events_recorded + second_pass.events_recorded;
            let total_corrupt = first_pass.frames_corrupt + second_pass.frames_corrupt;
            assert_eq!(
                total_recorded, 2,
                "attempt {attempt}: both the pre-existing and the concurrently-appended \
                 event must be recovered, none lost (first pass {first_pass:?}, \
                 second pass {second_pass:?})"
            );
            assert_eq!(
                total_corrupt, 0,
                "attempt {attempt}: no frame should be corrupt"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }
}
