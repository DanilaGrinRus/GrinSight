//! Frames and the reader of their contents, without any process.
use fly_paycore_pipe_link::{plain_text, read_frame, write_frame, Cut};
use std::io::Cursor;

#[test]
fn handshake_budget_includes_writing_the_configuration() -> Result<(), Box<dyn std::error::Error>> {
    use fly_paycore_pipe_link::{Link, READY};
    use std::io::{self, Write};
    use std::time::{Duration, Instant};
    struct SlowFlush;
    impl Write for SlowFlush {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> { Ok(b.len()) }
        fn flush(&mut self) -> io::Result<()> {
            std::thread::sleep(Duration::from_millis(400));
            Ok(())
        }
    }
    let mut reply = Vec::new();
    write_frame(&mut reply, READY, &[1], 16)?;
    let start = Instant::now();
    let opening = Link::connect_begin(Cursor::new(reply), SlowFlush, &mut [7], 1, Duration::from_millis(25), 16)?;
    assert!(opening.wait().is_err());
    assert!(start.elapsed() < Duration::from_millis(350));
    Ok(())
}

#[test]
fn a_frame_crosses_whole_or_not_at_all() {
    let mut wire = Vec::new();
    write_frame(&mut wire, 0x42, b"hello", 64).unwrap();
    write_frame(&mut wire, 0x43, b"", 64).unwrap();
    assert_eq!(wire, [6, 0, 0, 0, 0x42, b'h', b'e', b'l', b'l', b'o', 1, 0, 0, 0, 0x43]);
    let mut r = Cursor::new(wire.clone());
    assert_eq!(read_frame(&mut r, 64).unwrap(), Some((0x42, b"hello".to_vec())));
    assert_eq!(read_frame(&mut r, 64).unwrap(), Some((0x43, Vec::new())));
    // the other side closed between two frames: an end, not an error
    assert_eq!(read_frame(&mut r, 64).unwrap(), None);
    // closed inside a frame: an error, never a shorter frame
    for cut in 1..wire.len() - 5 {
        assert!(read_frame(&mut Cursor::new(&wire[..cut]), 64).is_err(), "cut at {cut}");
    }

    // nothing larger than agreed is written, and nothing larger is read:
    // the length is refused before anything is allocated for it
    let mut out = Vec::new();
    assert!(write_frame(&mut out, 1, &[0; 64], 64).is_err());
    assert!(out.is_empty());
    write_frame(&mut out, 1, &[0; 63], 64).unwrap();
    assert!(read_frame(&mut Cursor::new(&out), 63).is_err());
    assert!(read_frame(&mut Cursor::new(&out), 64).unwrap().is_some());
    assert!(read_frame(&mut Cursor::new(u32::MAX.to_le_bytes()), 64).is_err());
    // a frame without even a tag
    assert!(read_frame(&mut Cursor::new([0u8; 4]), 64).is_err());
}

#[test]
fn contents_are_read_exactly() {
    let bytes = [7, 1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'o', b'k', 3, 0, 0, 0, 9, 9, 9];
    let mut c = Cut(&bytes);
    assert_eq!(c.u8(), Some(7));
    assert_eq!(c.u16(), Some(0x0201));
    assert_eq!(c.array::<2>(), Some([3, 0]));
    assert_eq!(c.u64(), Some(4));
    assert_eq!(c.short_text().as_deref(), Some("ok"));
    assert!(!c.done());
    // a field longer than allowed is not taken, and nothing is consumed past it
    assert_eq!(Cut(&bytes[17..]).bytes(2), None);
    assert_eq!(c.bytes(3), Some(&[9u8, 9, 9][..]));
    assert!(c.done());
    // nothing is ever read past the end
    assert_eq!((c.u8(), c.u16(), c.u32(), c.u64(), c.take(1)), (None, None, None, None, None));
    assert_eq!(Cut(&[1, 2, 3]).u32(), None);
    assert_eq!(Cut(&[5, 0, b'a']).short_text(), None, "a text that promises more than there is");
    assert_eq!(Cut(&[2, 0, 0xff, 0xfe]).short_text(), None, "a text that is not text");
}

#[test]
fn text_from_the_other_side_is_made_plain() {
    assert_eq!(plain_text("no peer answers", 200), "no peer answers");
    assert_eq!(plain_text("a\nb\tc\u{1b}[31m\u{202e}d", 200), "a?b?c?[31m?d");
    assert_eq!(plain_text(&"x".repeat(500), 200).len(), 200);
    assert_eq!(plain_text("привет", 3), "???");
}
