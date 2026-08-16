use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use fossh_core::types::Event;
use fossh_store::Store;

const FLUSH_MAX_EVENTS: usize = 100;
const FLUSH_MAX_INTERVAL: Duration = Duration::from_millis(500);

pub fn run(mut store: Store, rx: Receiver<Event>) {
    let mut batch = Vec::with_capacity(FLUSH_MAX_EVENTS);

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
        drop(tx);

        run(store, rx);

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

        let path = scratch_db_path("size-threshold");
        let store = Store::open(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || run(store, rx));

        for i in 0..FLUSH_MAX_EVENTS {
            tx.send(sample_event(1_700_000_000 + i as i64)).unwrap();
        }
        drop(tx);
        handle.join().unwrap();

        let readback = Store::open(&path).unwrap();
        assert_eq!(
            readback.count_events(SiteId::new(1)).unwrap(),
            FLUSH_MAX_EVENTS as u64
        );
        std::fs::remove_file(&path).ok();
    }
}
