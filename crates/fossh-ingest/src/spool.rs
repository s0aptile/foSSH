use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use fossh_core::types::{Country, Event, EventKind, Host, Path as SanitizedPath, SiteId};
use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
use fossh_core::validate::{Key, Name, Val};

use crate::IngestError;

pub const SPOOL_ROTATE_BYTES: u64 = 8 * 1024 * 1024;

const HEADER_LEN: usize = 8;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_str(buf: &[u8], pos: &mut usize) -> Result<String, IngestError> {
    if *pos + 2 > buf.len() {
        return Err(IngestError::CorruptFrame);
    }
    let len = u16::from_le_bytes(buf[*pos..*pos + 2].try_into().expect("2 bytes")) as usize;
    *pos += 2;
    if *pos + len > buf.len() {
        return Err(IngestError::CorruptFrame);
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|_| IngestError::CorruptFrame)?
        .to_string();
    *pos += len;
    Ok(s)
}

fn need(pos: usize, n: usize, len: usize) -> Result<(), IngestError> {
    if pos + n > len {
        Err(IngestError::CorruptFrame)
    } else {
        Ok(())
    }
}

pub fn encode_event(event: &Event) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&event.site_id.get().to_le_bytes());
    out.extend_from_slice(&event.ts.to_le_bytes());
    out.push(event.kind.as_i64() as u8);
    write_str(&mut out, event.name.as_str());

    match &event.path {
        Some(p) => {
            out.push(1);
            write_str(&mut out, p.as_str());
        }
        None => out.push(0),
    }
    match &event.referrer {
        Some(h) => {
            out.push(1);
            write_str(&mut out, h.as_str());
        }
        None => out.push(0),
    }

    out.extend_from_slice(event.country.as_str().as_bytes());
    out.push(event.browser.as_u8());
    out.push(event.os.as_u8());
    out.push(event.device.as_u8());

    match event.visitor {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
    match event.value {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }

    out.push(event.props.len() as u8);
    for (k, v) in &event.props {
        write_str(&mut out, k.as_str());
        write_str(&mut out, v.as_str());
    }
    out
}

pub fn decode_event(buf: &[u8]) -> Result<Event, IngestError> {
    let mut pos = 0usize;

    need(pos, 4, buf.len())?;
    let site_id = u32::from_le_bytes(buf[pos..pos + 4].try_into().expect("4 bytes"));
    pos += 4;

    need(pos, 8, buf.len())?;
    let ts = i64::from_le_bytes(buf[pos..pos + 8].try_into().expect("8 bytes"));
    pos += 8;

    need(pos, 1, buf.len())?;
    let kind = EventKind::from_i64(i64::from(buf[pos])).ok_or(IngestError::CorruptFrame)?;
    pos += 1;

    let name = Name::parse(read_str(buf, &mut pos)?).map_err(IngestError::Validation)?;

    need(pos, 1, buf.len())?;
    let has_path = buf[pos] != 0;
    pos += 1;
    let path = if has_path {
        Some(SanitizedPath::from_raw(&read_str(buf, &mut pos)?))
    } else {
        None
    };

    need(pos, 1, buf.len())?;
    let has_ref = buf[pos] != 0;
    pos += 1;
    let referrer = if has_ref {
        Some(Host::from_trusted(read_str(buf, &mut pos)?))
    } else {
        None
    };

    need(pos, 2, buf.len())?;
    let country = Country::parse(
        std::str::from_utf8(&buf[pos..pos + 2]).map_err(|_| IngestError::CorruptFrame)?,
    )
    .ok_or(IngestError::CorruptFrame)?;
    pos += 2;

    need(pos, 3, buf.len())?;
    let browser = BrowserFamily::from_u8(buf[pos]);
    let os = OsFamily::from_u8(buf[pos + 1]);
    let device = DeviceClass::from_u8(buf[pos + 2]);
    pos += 3;

    need(pos, 1, buf.len())?;
    let has_visitor = buf[pos] != 0;
    pos += 1;
    let visitor = if has_visitor {
        need(pos, 8, buf.len())?;
        let v = u64::from_le_bytes(buf[pos..pos + 8].try_into().expect("8 bytes"));
        pos += 8;
        Some(v)
    } else {
        None
    };

    need(pos, 1, buf.len())?;
    let has_value = buf[pos] != 0;
    pos += 1;
    let value = if has_value {
        need(pos, 8, buf.len())?;
        let v = i64::from_le_bytes(buf[pos..pos + 8].try_into().expect("8 bytes"));
        pos += 8;
        Some(v)
    } else {
        None
    };

    need(pos, 1, buf.len())?;
    let prop_count = buf[pos] as usize;
    pos += 1;
    let mut props = Vec::with_capacity(prop_count);
    for _ in 0..prop_count {
        let k = Key::parse(read_str(buf, &mut pos)?).map_err(IngestError::Validation)?;
        let v = Val::parse(read_str(buf, &mut pos)?).map_err(IngestError::Validation)?;
        props.push((k, v));
    }

    Ok(Event {
        site_id: SiteId::new(site_id),
        ts,
        kind,
        name,
        path,
        referrer,
        country,
        browser,
        os,
        device,
        visitor,
        value,
        props,
    })
}

fn lock_path(dir: &Path) -> std::path::PathBuf {
    dir.join("spool.lock")
}

pub(crate) fn open_lock_file(dir: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(lock_path(dir))
}

pub fn append_frame(dir: &Path, event: &Event, key: &[u8; 32]) -> Result<(), IngestError> {
    fs::create_dir_all(dir)?;
    let lock = open_lock_file(dir)?;
    lock.lock_shared()?;
    let current = dir.join("current.bin");

    if let Ok(meta) = fs::metadata(&current)
        && meta.len() >= SPOOL_ROTATE_BYTES
    {
        let rotated_name = format!(
            "spool-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        match fs::rename(&current, dir.join(rotated_name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(IngestError::Io(e)),
        }
    }

    let payload = crate::crypto::seal(key, &encode_event(event))?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);

    let is_new = !current.exists();
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&current)?;
    if !is_new {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let written = file.write(&frame)?;
    if written != frame.len() {
        return Err(IngestError::Io(std::io::Error::other(format!(
            "short spool write: {written} of {} bytes",
            frame.len()
        ))));
    }
    Ok(())
}

pub enum DrainedFrame {
    Event(Event),
    Corrupt,
}

pub fn read_frames(path: &Path, key: &[u8; 32]) -> Result<Vec<DrainedFrame>, IngestError> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(IngestError::Io(e)),
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos + HEADER_LEN <= buf.len() {
        let payload_len =
            u32::from_le_bytes(buf[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        let expected_crc = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().expect("4 bytes"));
        let payload_start = pos + HEADER_LEN;
        let payload_end = payload_start + payload_len;
        if payload_end > buf.len() {
            break;
        }
        let payload = &buf[payload_start..payload_end];
        if crc32(payload) != expected_crc {
            frames.push(DrainedFrame::Corrupt);
        } else {
            match crate::crypto::open(key, payload).and_then(|pt| decode_event(&pt)) {
                Ok(event) => frames.push(DrainedFrame::Event(event)),
                Err(_) => frames.push(DrainedFrame::Corrupt),
            }
        }
        pos = payload_end;
    }

    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x42; 32];
    use std::path::PathBuf;

    #[test]
    fn crc32_matches_standard_conformance_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_empty_input() {
        assert_eq!(crc32(b""), 0);
    }

    fn sample_event() -> Event {
        Event {
            site_id: SiteId::new(42),
            ts: 1_700_000_000,
            kind: EventKind::Pageview,
            name: Name::parse("pageview").unwrap(),
            path: Some(SanitizedPath::from_raw("/blog/hello")),
            referrer: Host::from_referrer_url("https://www.google.com/search?q=x"),
            country: Country::parse("TR").unwrap(),
            browser: BrowserFamily::Chrome,
            os: OsFamily::Linux,
            device: DeviceClass::Desktop,
            visitor: Some(0x0123_4567_89AB_CDEF),
            value: None,
            props: vec![(Key::parse("plan").unwrap(), Val::parse("pro").unwrap())],
        }
    }

    fn assert_events_eq(a: &Event, b: &Event) {
        assert_eq!(a.site_id, b.site_id);
        assert_eq!(a.ts, b.ts);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.name, b.name);
        assert_eq!(a.path, b.path);
        assert_eq!(a.referrer, b.referrer);
        assert_eq!(a.country, b.country);
        assert_eq!(a.browser, b.browser);
        assert_eq!(a.os, b.os);
        assert_eq!(a.device, b.device);
        assert_eq!(a.visitor, b.visitor);
        assert_eq!(a.value, b.value);
        assert_eq!(a.props, b.props);
    }

    #[test]
    fn encode_decode_round_trip_full_event() {
        let ev = sample_event();
        let decoded = decode_event(&encode_event(&ev)).unwrap();
        assert_events_eq(&ev, &decoded);
    }

    #[test]
    fn encode_decode_round_trip_minimal_event() {
        let mut ev = sample_event();
        ev.path = None;
        ev.referrer = None;
        ev.visitor = None;
        ev.value = None;
        ev.props = vec![];
        let decoded = decode_event(&encode_event(&ev)).unwrap();
        assert_events_eq(&ev, &decoded);
    }

    #[test]
    fn encode_decode_round_trip_full_16_props() {
        let mut ev = sample_event();
        ev.props = (0..16)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v".repeat(200)).unwrap(),
                )
            })
            .collect();
        let decoded = decode_event(&encode_event(&ev)).unwrap();
        assert_events_eq(&ev, &decoded);
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let ev = sample_event();
        let full = encode_event(&ev);
        for cut in [0, 1, 4, 10, full.len() / 2, full.len() - 1] {
            assert!(
                decode_event(&full[..cut]).is_err(),
                "truncating to {cut} bytes must not decode"
            );
        }
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-spool-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn append_then_drain_round_trips() {
        let dir = scratch_dir("append-drain");
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        let frames = read_frames(&dir.join("current.bin"), &TEST_KEY).unwrap();
        assert_eq!(frames.len(), 2);
        for f in frames {
            match f {
                DrainedFrame::Event(ev) => assert_events_eq(&ev, &sample_event()),
                DrainedFrame::Corrupt => panic!("unexpected corrupt frame"),
            }
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_file_on_disk_does_not_contain_the_plaintext_path_or_name() {

        let dir = scratch_dir("at-rest");
        let mut ev = sample_event();
        ev.path = Some(SanitizedPath::from_raw("/a-very-distinctive-path-marker"));
        append_frame(&dir, &ev, &TEST_KEY).unwrap();

        let on_disk = fs::read(dir.join("current.bin")).unwrap();
        let on_disk_str = String::from_utf8_lossy(&on_disk);
        assert!(
            !on_disk_str.contains("a-very-distinctive-path-marker"),
            "the plaintext path must not appear anywhere in the on-disk spool file"
        );
        assert!(
            !on_disk_str.contains("pageview"),
            "nor the plaintext event name"
        );

        let frames = read_frames(&dir.join("current.bin"), &TEST_KEY).unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            DrainedFrame::Event(decoded) => assert_events_eq(decoded, &ev),
            DrainedFrame::Corrupt => panic!("unexpected corrupt frame"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn draining_with_the_wrong_key_reports_corrupt_not_a_panic_or_silent_wrong_data() {
        let dir = scratch_dir("wrong-key");
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        let wrong_key = [0x99u8; 32];
        let frames = read_frames(&dir.join("current.bin"), &wrong_key).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], DrainedFrame::Corrupt));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_file_is_0600() {
        let dir = scratch_dir("perms-fresh");
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();
        let mode = fs::metadata(dir.join("current.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_file_permissions_are_tightened_if_found_wider() {
        let dir = scratch_dir("perms-tighten");
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("current.bin");
        fs::write(&current, b"").unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o644)).unwrap();

        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        let mode = fs::metadata(&current).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "an existing, wider-permission spool file must be tightened, not refused"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_spool_file_drains_to_empty() {
        let dir = scratch_dir("missing");
        let frames = read_frames(&dir.join("current.bin"), &TEST_KEY).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn truncated_trailing_frame_is_left_for_next_drain() {
        let dir = scratch_dir("truncated-tail");
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();
        let path = dir.join("current.bin");
        let full = fs::read(&path).unwrap();
        fs::write(&path, &full[..full.len() - 5]).unwrap();

        let frames = read_frames(&path, &TEST_KEY).unwrap();
        assert_eq!(
            frames.len(),
            1,
            "only the first, complete frame should be returned"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_frame_is_flagged_not_fatal_to_the_rest_of_the_drain() {
        let dir = scratch_dir("corrupt-middle");
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();
        let path = dir.join("current.bin");
        let mut bytes = fs::read(&path).unwrap();

        let flip_at = bytes.len() - 3;
        bytes[flip_at] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        let frames = read_frames(&path, &TEST_KEY).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0], DrainedFrame::Corrupt));
        assert!(matches!(frames[1], DrainedFrame::Event(_)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_moves_current_bin_aside_once_it_reaches_the_threshold() {
        let dir = scratch_dir("rotate");
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("current.bin");
        fs::write(&current, vec![0u8; SPOOL_ROTATE_BYTES as usize]).unwrap();

        append_frame(&dir, &sample_event(), &TEST_KEY).unwrap();

        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            entries
                .iter()
                .any(|n| n.starts_with("spool-") && n.ends_with(".bin"))
        );
        assert!(fs::metadata(&current).unwrap().len() < SPOOL_ROTATE_BYTES);
        fs::remove_dir_all(&dir).ok();
    }
}
