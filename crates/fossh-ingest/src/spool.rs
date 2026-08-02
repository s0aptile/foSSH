//! §7.1 spool: length-prefixed, CRC32'd frames appended to a spool file
//! with a single `write()` call, atomic across concurrent CGI processes up
//! to the size POSIX/Linux actually guarantee that for. Frame layout
//! (little-endian): `[u32 payload_len][u32 crc32(payload)][payload]`.
//! `payload` is a compact hand-rolled binary encoding of an `Event` — not
//! JSON, since a frame is written on every request and read back by the
//! compactor, and JSON's self-describing overhead buys nothing here.
//!
//! POSIX only guarantees a single `write()` to be atomic (indivisible
//! against other writers) up to `PIPE_BUF` (4 KiB on Linux) — and even
//! that guarantee is written for pipes/FIFOs; Linux extends the same
//! practical behavior to a regular file opened `O_APPEND` for writes this
//! small. A single event's frame is comfortably inside that bound. S4's
//! batch cap (64 events, each up to ~5 KB with a full 16-property
//! payload) is not, and nothing can make an above-`PIPE_BUF` write
//! atomic against POSIX's own rules. This module always issues exactly
//! one `write()` regardless of frame size — best atomicity for the
//! overwhelmingly common single-small-event case, and a short write
//! surfaces as `IngestError::Io`, never a silently truncated frame.
//!
//! `write()` (not `write_all()`) is what makes this a single syscall:
//! `std::fs::File`'s `Write::write` on Unix is a thin wrapper over one
//! `write(2)` call, whereas `write_all` loops until the buffer is
//! exhausted. That's the whole reason to call `write` directly here and
//! treat a short return as an error instead of retrying it away.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use fossh_core::types::{Country, Event, EventKind, Host, Path as SanitizedPath, SiteId};
use fossh_core::ua::{BrowserFamily, DeviceClass, OsFamily};
use fossh_core::validate::{Key, Name, Val};

use crate::IngestError;

/// §7.1: "Spool files rotate at 8 MiB."
pub const SPOOL_ROTATE_BYTES: u64 = 8 * 1024 * 1024;

const HEADER_LEN: usize = 8; // u32 payload_len + u32 crc32, both little-endian

/// Standard reflected CRC-32 (IEEE 802.3 polynomial, `0xEDB88320`) —
/// bit-by-bit, no lookup table. Frames are small (a handful of KB at
/// most) and written/read once each, so the ~8x slowdown against a
/// table-driven implementation is irrelevant; the table would be the only
/// "dependency-shaped" chunk of this module, and it's not needed. Verified
/// against the standard `"123456789"` → `0xCBF4_3926` conformance vector.
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

/// Encodes one already-validated `Event` into a spool payload (the part
/// after the `[len][crc]` header — `append_frame` adds that).
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

    out.extend_from_slice(event.country.as_str().as_bytes()); // always exactly 2 ASCII bytes
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

    out.push(event.props.len() as u8); // S4 bounds this to <= 16 well before encoding
    for (k, v) in &event.props {
        write_str(&mut out, k.as_str());
        write_str(&mut out, v.as_str());
    }
    out
}

/// Inverse of `encode_event`. Fails closed (S2) on any structural
/// inconsistency — a spool frame that doesn't decode cleanly is treated
/// the same as a CRC mismatch, not partially trusted.
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

/// Appends one event to `dir/current.bin` as a single `write()` call
/// (see the module doc comment). Rotates `current.bin` to a
/// timestamp-named file first if it's already at or past
/// `SPOOL_ROTATE_BYTES` — rotation itself is a `rename()`, not a write to
/// the file being appended, so it doesn't affect this call's atomicity.
pub fn append_frame(dir: &Path, event: &Event) -> Result<(), IngestError> {
    fs::create_dir_all(dir)?;
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
        fs::rename(&current, dir.join(rotated_name))?;
    }

    let payload = encode_event(event);
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&current)?;
    let written = file.write(&frame)?;
    if written != frame.len() {
        return Err(IngestError::Io(std::io::Error::other(format!(
            "short spool write: {written} of {} bytes",
            frame.len()
        ))));
    }
    Ok(())
}

/// One decoded frame from a drained spool file, or a note that a frame
/// was corrupt (dropped, not fatal to the rest of the drain — a single
/// torn frame, e.g. from a crash mid-append, must not lose every event
/// after it).
pub enum DrainedFrame {
    Event(Event),
    Corrupt,
}

/// Reads every complete frame out of `path` in order. Stops (without
/// erroring) at the first incomplete trailing frame — the tail end of a
/// write still in progress when the compactor runs looks exactly like
/// that, and it'll be picked up whole on the next drain.
pub fn read_frames(path: &Path) -> Result<Vec<DrainedFrame>, IngestError> {
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
            break; // incomplete trailing frame — leave it for the next drain
        }
        let payload = &buf[payload_start..payload_end];
        if crc32(payload) != expected_crc {
            frames.push(DrainedFrame::Corrupt);
        } else {
            match decode_event(payload) {
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
        append_frame(&dir, &sample_event()).unwrap();
        append_frame(&dir, &sample_event()).unwrap();

        let frames = read_frames(&dir.join("current.bin")).unwrap();
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
    fn missing_spool_file_drains_to_empty() {
        let dir = scratch_dir("missing");
        let frames = read_frames(&dir.join("current.bin")).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn truncated_trailing_frame_is_left_for_next_drain() {
        let dir = scratch_dir("truncated-tail");
        append_frame(&dir, &sample_event()).unwrap();
        // Simulate a write that was cut off mid-frame (e.g. process killed
        // mid-append) by chopping bytes off the end of a second, otherwise
        // well-formed append.
        append_frame(&dir, &sample_event()).unwrap();
        let path = dir.join("current.bin");
        let full = fs::read(&path).unwrap();
        fs::write(&path, &full[..full.len() - 5]).unwrap();

        let frames = read_frames(&path).unwrap();
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
        append_frame(&dir, &sample_event()).unwrap();
        let path = dir.join("current.bin");
        let mut bytes = fs::read(&path).unwrap();
        // Flip a byte inside the payload (well past the header) to break the CRC.
        let flip_at = bytes.len() - 3;
        bytes[flip_at] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        append_frame(&dir, &sample_event()).unwrap(); // a good frame after the corrupt one

        let frames = read_frames(&path).unwrap();
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

        append_frame(&dir, &sample_event()).unwrap();

        // The oversized file must have been renamed aside, and a fresh
        // (small) current.bin holds just the new frame.
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
