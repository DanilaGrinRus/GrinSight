//! A QR code of what the window already shows as text: the wallet's own
//! address and a Slatepack text to pass on (decision of the author, 24.11).
//!
//! The code holds the text itself, byte for byte, so any reader gets the
//! same characters a copy would give. Nothing secret is drawn: the callers
//! are the address line and the read-only Slatepack box, and the words of
//! the wallet never come here.
use qrcodegen::{QrCode, QrCodeEcc};

/// Light modules around the code, as the standard asks.
pub(crate) const QUIET: usize = 4;
/// The longest text one code holds (version 40, the lowest correction).
pub(crate) const MAX_BYTES: usize = 2953;

/// A code with its light border: `side` modules each way, dark or light.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grid {
    side: usize,
    dark: Vec<bool>,
}

impl Grid {
    /// Modules along one side, the border included.
    pub(crate) fn side(&self) -> usize {
        self.side
    }

    /// Whether the module is dark. Outside the picture everything is light.
    #[cfg(test)]
    pub(crate) fn dark(&self, x: usize, y: usize) -> bool {
        if x >= self.side || y >= self.side {
            return false;
        }
        y.checked_mul(self.side).and_then(|row| row.checked_add(x)).and_then(|i| self.dark.get(i).copied()).unwrap_or(false)
    }

    /// O61: the picture as a PNG file, `zoom` pixels a module: grey, eight
    /// bits a pixel, not compressed. Written here by hand: a QR code needs
    /// nothing of a picture library. `None`: a zoom of nought, or a
    /// picture too large to describe.
    pub(crate) fn png(&self, zoom: usize) -> Option<Vec<u8>> {
        if zoom == 0 || self.side == 0 {
            return None;
        }
        let px = self.side.checked_mul(zoom)?;
        let width = u32::try_from(px).ok()?;
        // the picture's bytes: every line begins with the filter "none"
        let mut raw = Vec::with_capacity(px.checked_add(1)?.checked_mul(px)?);
        for row in self.dark.chunks(self.side) {
            let mut line = Vec::with_capacity(px.checked_add(1)?);
            line.push(0u8);
            for dark in row {
                line.extend(std::iter::repeat_n(if *dark { 0u8 } else { 255u8 }, zoom));
            }
            for _ in 0..zoom {
                raw.extend_from_slice(&line);
            }
        }
        // zlib: a header, stored blocks of at most 65535 bytes, the Adler sum
        let mut packed = vec![0x78, 0x01];
        let mut blocks = raw.chunks(65_535).peekable();
        while let Some(block) = blocks.next() {
            let len = u16::try_from(block.len()).ok()?;
            packed.push(u8::from(blocks.peek().is_none()));
            packed.extend_from_slice(&len.to_le_bytes());
            packed.extend_from_slice(&(!len).to_le_bytes());
            packed.extend_from_slice(block);
        }
        packed.extend_from_slice(&adler32(&raw).to_be_bytes());
        let mut header = Vec::with_capacity(13);
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&width.to_be_bytes());
        // eight bits, grey, the one compression and filter there are, not interlaced
        header.extend_from_slice(&[8, 0, 0, 0, 0]);
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        for (name, data) in [(b"IHDR", header.as_slice()), (b"IDAT", packed.as_slice()), (b"IEND", [].as_slice())] {
            out.extend_from_slice(&u32::try_from(data.len()).ok()?.to_be_bytes());
            let mut summed = name.to_vec();
            summed.extend_from_slice(data);
            out.extend_from_slice(&summed);
            out.extend_from_slice(&crc32(&summed).to_be_bytes());
        }
        Some(out)
    }

    /// The picture, one pixel a module: black on white, four bytes a pixel.
    pub(crate) fn rgba(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.dark.len().saturating_mul(4));
        for dark in &self.dark {
            let shade = if *dark { 0 } else { 255 };
            out.extend_from_slice(&[shade, shade, shade, 255]);
        }
        out
    }
}

/// The check sum of a PNG chunk (CRC-32, as in zlib and Ethernet).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// The check sum of a zlib stream (Adler-32).
fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in bytes {
        a = a.wrapping_add(u32::from(*byte)).checked_rem(65_521).unwrap_or(0);
        b = b.wrapping_add(a).checked_rem(65_521).unwrap_or(0);
    }
    (b << 16) | a
}

/// The code of `text`, or nothing when there is no text or it is longer
/// than one code holds.
pub(crate) fn grid(text: &str) -> Option<Grid> {
    if text.is_empty() || text.len() > MAX_BYTES {
        return None;
    }
    // the bytes as they are: a reader gives back exactly this text
    let code = QrCode::encode_binary(text.as_bytes(), QrCodeEcc::Low).ok()?;
    let inner = usize::try_from(code.size()).ok()?;
    let side = inner.checked_add(QUIET.checked_mul(2)?)?;
    let mut dark = Vec::with_capacity(side.checked_mul(side)?);
    for y in 0..side {
        for x in 0..side {
            let within = |v: usize| v.checked_sub(QUIET).filter(|m| *m < inner).and_then(|m| i32::try_from(m).ok());
            dark.push(match (within(x), within(y)) {
                (Some(mx), Some(my)) => code.get_module(mx, my),
                _ => false,
            });
        }
    }
    Some(Grid { side, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three corner marks every reader looks for: a dark 7x7 frame, a
    /// light ring, a dark 3x3 middle.
    fn mark_at(g: &Grid, left: usize, top: usize) -> bool {
        (0..7usize).all(|dy| {
            (0..7usize).all(|dx| {
                let frame = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                let middle = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                g.dark(left.saturating_add(dx), top.saturating_add(dy)) == (frame || middle)
            })
        })
    }

    /// O61: the saved picture is a PNG any viewer opens: the signature,
    /// the size, the sums of each part - and, read back, the same dark and
    /// light modules, `zoom` pixels each.
    #[test]
    fn the_code_is_written_as_a_png() -> Result<(), String> {
        // the sums against values known from elsewhere
        assert_eq!((crc32(b"IEND"), adler32(b"Wikipedia")), (0xAE42_6082, 0x11E6_0398));
        let g = grid("grin1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7zyv4m").ok_or("no code")?;
        assert_eq!(g.png(0), None);
        let zoom = 8usize;
        let png = g.png(zoom).ok_or("no picture")?;
        let px = g.side().checked_mul(zoom).ok_or("size")?;
        assert_eq!(png.get(..8), Some([0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A].as_slice()));
        // walk the parts: length, name, data, sum
        let (mut at, mut names, mut packed, mut header) = (8usize, Vec::new(), Vec::new(), Vec::new());
        while at < png.len() {
            let len = usize::try_from(u32::from_be_bytes(png.get(at..at.saturating_add(4)).ok_or("length")?.try_into().map_err(|_| "length")?)).map_err(|_| "length")?;
            let body = png.get(at.saturating_add(4)..at.saturating_add(8).saturating_add(len)).ok_or("body")?;
            let sum = png.get(at.saturating_add(8).saturating_add(len)..at.saturating_add(12).saturating_add(len)).ok_or("sum")?;
            assert_eq!(sum, crc32(body).to_be_bytes().as_slice());
            let (name, data) = body.split_at(4);
            names.push(String::from_utf8_lossy(name).into_owned());
            match name {
                b"IHDR" => header = data.to_vec(),
                b"IDAT" => packed = data.to_vec(),
                _ => {}
            }
            at = at.saturating_add(12).saturating_add(len);
        }
        assert_eq!(names, ["IHDR", "IDAT", "IEND"]);
        let side = u32::try_from(px).map_err(|_| "size")?.to_be_bytes();
        assert_eq!(header, [side.as_slice(), side.as_slice(), &[8, 0, 0, 0, 0]].concat());
        // the stored blocks back into the picture's bytes
        let (mut raw, mut at) = (Vec::new(), 2usize);
        loop {
            let last = *packed.get(at).ok_or("block")? == 1;
            let len = usize::from(u16::from_le_bytes(packed.get(at.saturating_add(1)..at.saturating_add(3)).ok_or("len")?.try_into().map_err(|_| "len")?));
            raw.extend_from_slice(packed.get(at.saturating_add(5)..at.saturating_add(5).saturating_add(len)).ok_or("data")?);
            at = at.saturating_add(5).saturating_add(len);
            if last {
                break;
            }
        }
        assert_eq!(packed.get(at..), Some(adler32(&raw).to_be_bytes().as_slice()));
        assert_eq!(raw.len(), px.saturating_add(1).saturating_mul(px));
        for (y, line) in raw.chunks(px.saturating_add(1)).enumerate() {
            assert_eq!(line.first(), Some(&0));
            for (x, shade) in line.iter().skip(1).enumerate() {
                let dark = g.dark(x.checked_div(zoom).unwrap_or(0), y.checked_div(zoom).unwrap_or(0));
                assert_eq!(*shade, if dark { 0 } else { 255 }, "{x} {y}");
            }
        }
        Ok(())
    }

    #[test]
    fn an_address_becomes_a_code_with_its_marks_and_border() {
        let g = grid("grin1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7zyv4m").unwrap_or_else(|| Grid { side: 0, dark: Vec::new() });
        let inner = g.side().saturating_sub(QUIET.saturating_mul(2));
        // a version of the standard: 21, 25, 29 ... modules
        assert!(inner >= 21);
        assert_eq!(inner.saturating_sub(21) % 4, 0);
        // the border the standard asks for is four modules, by number and not by the constant
        assert_eq!(g.side(), inner.saturating_add(8));
        let far = inner.saturating_add(4).saturating_sub(7);
        assert!(mark_at(&g, 4, 4));
        assert!(mark_at(&g, far, 4));
        assert!(mark_at(&g, 4, far));
        // the border is light all the way round
        for i in 0..g.side() {
            for b in 0..4usize {
                let last = g.side().saturating_sub(1).saturating_sub(b);
                assert!(!g.dark(i, b) && !g.dark(b, i) && !g.dark(i, last) && !g.dark(last, i));
            }
        }
        // the picture is one pixel a module, opaque, black or white
        let px = g.rgba();
        assert_eq!(px.len(), g.side().saturating_mul(g.side()).saturating_mul(4));
        assert!(px.chunks(4).all(|p| matches!(p, [0, 0, 0, 255] | [255, 255, 255, 255])));
    }

    #[test]
    fn the_same_text_gives_the_same_code_and_another_text_another() {
        let a = grid("BEGINSLATEPACK. one two three. ENDSLATEPACK.");
        assert!(a.is_some());
        assert_eq!(a, grid("BEGINSLATEPACK. one two three. ENDSLATEPACK."));
        assert_ne!(a, grid("BEGINSLATEPACK. one two threE. ENDSLATEPACK."));
    }

    #[test]
    fn no_text_and_too_long_a_text_give_no_code() {
        assert!(grid("").is_none());
        assert!(grid(&"a".repeat(MAX_BYTES)).is_some());
        assert!(grid(&"a".repeat(MAX_BYTES.saturating_add(1))).is_none());
        // letters of two bytes count as two
        assert!(grid(&"я".repeat(MAX_BYTES / 2)).is_some());
        assert!(grid(&"я".repeat((MAX_BYTES / 2).saturating_add(1))).is_none());
    }

    #[test]
    fn outside_the_picture_all_is_light() {
        let g = grid("x").unwrap_or_else(|| Grid { side: 0, dark: Vec::new() });
        assert!(g.side() > 0);
        assert!(!g.dark(g.side(), 0) && !g.dark(0, g.side()) && !g.dark(usize::MAX, usize::MAX));
    }
}
