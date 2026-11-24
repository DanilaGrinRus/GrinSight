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
