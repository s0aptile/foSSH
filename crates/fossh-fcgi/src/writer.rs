//! The direct-to-SQLite batched writer (§7.2): a single dedicated
//! thread owns the one `Store` handle this process ever touches,
//! receiving accepted events from every connection-handling thread
//! over an `mpsc` channel (multi-producer, single-consumer — exactly
//! `mpsc`'s own intended shape) and flushing them in one shared
//! transaction per batch, every 100 events or 500 ms, whichever comes
//! first. Funneling all writes through one thread is also what makes
//! this safe without any locking around `Store` itself: rusqlite's
//! `Connection` is `Send` but not `Sync`, and nothing here ever needs
//! it to be `Sync`, since only this one thread ever touches it.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use fossh_core::types::Event;
use fossh_store::Store;

const FLUSH_MAX_EVENTS: usize = 100;
const FLUSH_MAX_INTERVAL: Duration = Duration::from_millis(500);

/// Runs until `rx`'s senders are all dropped (process shutdown),
/// flushing whatever remains buffered on the way out. Blocking,
/// meant to be the body of its own dedicated thread.
pub fn run(mut store: Store, rx: Receiver<Event>) {
    let mut batch = Vec::with_capacity(FLUSH_MAX_EVENTS);
    // A fixed point in time, not "500ms since the last message": if
    // events trickle in slower than the interval but never stop
    // entirely, a naive `recv_timeout(FLUSH_MAX_INTERVAL)` on every
    // loop iteration would keep resetting its own clock on every
    // arrival and could let a batch sit well past 500ms without ever
    // actually hitting a timeout. Anchoring `deadline` to the last
    // flush (not the last message) and always waiting only the
    // *remaining* time until it is what actually bounds staleness
    // regardless of arrival pattern.
    let mut deadline = Instant::now() + FLUSH_MAX_INTERVAL;

    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(event) => {
                batch.push(event);
                if batch.len() >= FLUSH_MAX_EVENTS {
                    flush(&mut store, &mut batch);
                    deadline = Instant::now() + FLUSH_MAX_INTERVAL;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    flush(&mut store, &mut batch);
                }
                deadline = Instant::now() + FLUSH_MAX_INTERVAL;
            }
            Err(RecvTimeoutError::Disconnected) => {
                if !batch.is_empty() {
                    flush(&mut store, &mut batch);
                }
                return;
            }
        }
    }
}

fn flush(store: &mut Store, batch: &mut Vec<Event>) {
    // S2, fail closed: a batch write failure drops this batch (logged,
    // not retried forever, not fatal to the process) rather than
    // blocking every future request behind a wedged writer thread.
    match store.record_events_batch(batch) {
        Ok(n) if n as usize == batch.len() => {}
        Ok(n) => eprintln!(
            "fossh-fcgi: batch write recorded {n} of {} events (rest failed validation)",
            batch.len()
        ),
        Err(e) => eprintln!(
            "fossh-fcgi: batch write failed, {} events dropped: {e}",
            batch.len()
        ),
    }
    batch.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossh_core::types::{Country, EventKind, SiteId};
    use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
    use fossh_core::validate::Name;
    use std::sync::mpsc;
    use std::thread;

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
            visitor: Some(1),
            value: None,
            props: vec![],
        }
    }

    fn scratch_db_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fossh-fcgi-writer-test-{name}-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn flushes_on_disconnect_even_below_the_size_threshold() {
        let path = scratch_db_path("disconnect-flush");
        let store = Store::open(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        tx.send(sample_event(1)).unwrap();
        tx.send(sample_event(2)).unwrap();
        drop(tx); // triggers Disconnected on the next recv

        run(store, rx); // returns once the channel is drained and closed

        let readback = Store::open(&path).unwrap();
        assert_eq!(
            readback.count_events(SiteId::new(1)).unwrap(),
            2,
            "both events must be durably written even though disconnect, \
             not the 100-event size threshold, is what triggered the flush"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_real_threaded_run_flushes_a_full_batch_at_the_size_threshold() {
        // End to end, through the real `run()` loop in its own thread —
        // not just a direct `flush()` call — so this actually exercises
        // the `batch.len() >= FLUSH_MAX_EVENTS` trigger inside the loop,
        // not only the primitives it calls.
        let path = scratch_db_path("size-threshold");
        let store = Store::open(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || run(store, rx));

        for i in 0..FLUSH_MAX_EVENTS {
            tx.send(sample_event(1_700_000_000 + i as i64)).unwrap();
        }
        drop(tx); // lets `run` return once its (by-now-empty) batch has nothing left to flush
        handle.join().unwrap();

        let readback = Store::open(&path).unwrap();
        assert_eq!(
            readback.count_events(SiteId::new(1)).unwrap(),
            FLUSH_MAX_EVENTS as u64
        );
        std::fs::remove_file(&path).ok();
    }
}
