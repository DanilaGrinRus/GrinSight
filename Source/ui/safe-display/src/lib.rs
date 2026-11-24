//! How the wallet shows what it did not write itself, how much money and to
//! whom (rules О1–О8 of «Интерфейс — правила отображения»).
//!
//! Everything a contact, a relay or a node can put on the screen goes
//! through [`foreign_line`] or [`foreign_text`] first: names, messages, notes
//! on invoices, reasons a node gave. Amounts are turned into text only by
//! [`amount`]; addresses are shown only after [`address`] has checked them.
//! The interface draws the results; it never formats these things itself.
//!
//! What this does not do: it cannot tell a real contact from someone who
//! chose the same name. [`recipient`] names a contact only when the address
//! is the very one stored for that contact.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

/// Longest contact name shown, in characters (О5).
pub const NAME_CHARS: usize = 32;
/// Longest note on an invoice or a payment, in characters (О5).
pub const NOTE_CHARS: usize = 140;
/// Longest message shown in a conversation, in characters (О5).
pub const MESSAGE_CHARS: usize = 2000;
/// Longest reason from a node or a relay, in characters (О5).
pub const REASON_CHARS: usize = 240;
/// Most combining marks kept on one letter (О3).
pub const MARKS_PER_LETTER: usize = 2;

/// Text from someone else, ready to be drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// What to draw.
    pub text: String,
    /// Something was removed or replaced: invisible, direction-changing or
    /// control characters, or extra combining marks (О1–О3). The interface
    /// says «текст изменён».
    pub changed: bool,
    /// A word mixes letters of different scripts, such as Latin and Cyrillic
    /// (О4). The interface says «похожие буквы».
    pub mixed_scripts: bool,
    /// The text was longer than allowed and ends with «…» (О5).
    pub cut: bool,
}

/// One line of someone else's text: a name, a note, a reason (О1, О3–О5).
/// Line breaks become spaces.
pub fn foreign_line(input: &str, max_chars: usize) -> Shown {
    clean(input, max_chars, false)
}

/// Someone else's text that may have several lines: a message (О2–О5).
/// Line breaks stay, but never more than two in a row.
pub fn foreign_text(input: &str, max_chars: usize) -> Shown {
    clean(input, max_chars, true)
}

/// Characters that are never drawn: they change direction, hide, join or
/// tag text, so what is seen is not what is there (О1).
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0000}'..='\u{E007F}')
}

fn combining(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{FE20}'..='\u{FE2F}')
}

fn line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn clean(input: &str, max_chars: usize, keep_lines: bool) -> Shown {
    let mut text = String::with_capacity(input.len().min(max_chars.saturating_mul(4)));
    let mut changed = false;
    let mut marks = 0usize;
    let mut breaks = 0usize;
    let mut space = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            continue;
        }
        if invisible(c) {
            changed = true;
            continue;
        }
        if combining(c) {
            if text.is_empty() || space || breaks > 0 || marks >= MARKS_PER_LETTER {
                changed = true;
                continue;
            }
            marks = marks.saturating_add(1);
            text.push(c);
            continue;
        }
        marks = 0;
        if line_break(c) {
            if c != '\n' {
                changed = true;
            }
            if keep_lines {
                if text.ends_with(' ') {
                    text.pop();
                }
                if !text.is_empty() && breaks < 2 {
                    text.push('\n');
                }
                breaks = breaks.saturating_add(1);
                space = false;
            } else if !text.is_empty() {
                space = true;
            }
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            if c != ' ' {
                changed = true;
            }
            if !text.is_empty() && breaks == 0 {
                space = true;
            }
            continue;
        }
        if space {
            text.push(' ');
            space = false;
        }
        breaks = 0;
        text.push(c);
    }
    while text.ends_with('\n') || text.ends_with(' ') {
        text.pop();
    }
    let mixed_scripts = text.split(|c: char| !c.is_alphanumeric() && !combining(c)).any(mixed_word);
    let (text, cut) = cut_to(text, max_chars);
    Shown { text, changed, mixed_scripts, cut }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    FullWidth,
}

fn script(c: char) -> Option<Script> {
    match c {
        'a'..='z' | 'A'..='Z' | '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => Some(Script::Latin),
        '\u{0400}'..='\u{052F}' | '\u{1C80}'..='\u{1C8F}' | '\u{2DE0}'..='\u{2DFF}' | '\u{A640}'..='\u{A69F}' => {
            Some(Script::Cyrillic)
        }
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}' => Some(Script::FullWidth),
        _ => None,
    }
}

fn mixed_word(word: &str) -> bool {
    let mut seen: Option<Script> = None;
    for s in word.chars().filter_map(script) {
        match seen {
            None => seen = Some(s),
            Some(first) if first != s => return true,
            Some(_) => {}
        }
    }
    false
}

/// Cuts on a character boundary and marks the cut with «…» (О5).
fn cut_to(text: String, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        return (text, false);
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    // A combining mark left at the end would sit on the ellipsis.
    while out.chars().last().is_some_and(combining) {
        out.pop();
    }
    while out.ends_with(' ') || out.ends_with('\n') {
        out.pop();
    }
    out.push('…');
    (out, true)
}

/// Nanogrin in one grin.
pub const NANO: u64 = 1_000_000_000;

/// An amount in grin, from nanogrin, exactly (О6): no rounding, at least two
/// digits after the point, trailing zeros beyond two dropped, groups of
/// three in the whole part from 10 000 on, joined by a narrow no-break space.
pub fn amount(nanogrin: u64) -> String {
    let whole = nanogrin.checked_div(NANO).unwrap_or(0);
    let part = nanogrin.checked_rem(NANO).unwrap_or(0);
    let mut fraction = format!("{part:09}");
    while fraction.len() > 2 && fraction.ends_with('0') {
        fraction.pop();
    }
    let digits = whole.to_string();
    let grouped = if whole >= 10_000 {
        let mut out = String::with_capacity(digits.len().saturating_mul(2));
        let len = digits.len();
        for (i, d) in digits.chars().enumerate() {
            if i > 0 && len.saturating_sub(i) % 3 == 0 {
                out.push('\u{202F}');
            }
            out.push(d);
        }
        out
    } else {
        digits
    };
    format!("{grouped}.{fraction}")
}

/// The human part of a wallet address on Mainnet.
pub const ADDRESS_PREFIX: &str = "grin";
/// The human part of a wallet address on Testnet.
pub const TEST_ADDRESS_PREFIX: &str = "tgrin";
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Characters of the shortest and the longest address accepted.
pub const ADDRESS_LEN: std::ops::RangeInclusive<usize> = 50..=90;

/// An address that passed every check, split for reading (О7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The whole address, as it was given (lower case).
    pub full: String,
    /// A Testnet address (`tgrin1…`).
    pub testnet: bool,
    /// `grin1`, then the rest in groups of four; the last group may be shorter.
    pub groups: Vec<String>,
}

impl Address {
    /// Groups drawn stronger at the start: `grin1` and the first group.
    pub const STRONG_FIRST: usize = 2;
    /// Groups drawn stronger at the end.
    pub const STRONG_LAST: usize = 2;

    /// Short form for lists only: six characters after `grin1`, «…», the
    /// last six. Never in the window where a payment is signed (О7).
    pub fn short(&self) -> String {
        let prefix = if self.testnet { TEST_ADDRESS_PREFIX } else { ADDRESS_PREFIX };
        let data: Vec<char> = self.full.chars().skip(prefix.len().saturating_add(1)).collect();
        let head: String = data.iter().take(6).collect();
        let tail: String = data.iter().skip(data.len().saturating_sub(6)).collect();
        format!("{prefix}1{head}…{tail}")
    }
}

/// Why an address is not shown as an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Not `grin1…`.
    Prefix,
    /// Too short or too long.
    Length,
    /// Upper and lower case mixed, or a character an address cannot have.
    Characters,
    /// The check sum does not match: a character is wrong or missing.
    Checksum,
}

/// Checks a wallet address (bech32, `grin1…`) and splits it (О7). An address
/// that does not pass is not shown as an address and cannot be paid to.
pub fn address(input: &str) -> Result<Address, AddressError> {
    let len = input.chars().count();
    if !ADDRESS_LEN.contains(&len) {
        return Err(AddressError::Length);
    }
    if !input.is_ascii() {
        return Err(AddressError::Characters);
    }
    let lower = input.to_ascii_lowercase();
    if lower != input && input.to_ascii_uppercase() != input {
        return Err(AddressError::Characters);
    }
    let Some((hrp, data)) = lower.rsplit_once('1') else {
        return Err(AddressError::Prefix);
    };
    let testnet = match hrp {
        ADDRESS_PREFIX => false,
        TEST_ADDRESS_PREFIX => true,
        _ => return Err(AddressError::Prefix),
    };
    let mut values = Vec::with_capacity(data.len());
    for b in data.bytes() {
        match CHARSET.iter().position(|c| *c == b) {
            Some(v) => values.push(u8::try_from(v).map_err(|_| AddressError::Characters)?),
            None => return Err(AddressError::Characters),
        }
    }
    if values.len() < 6 || !checksum_ok(hrp, &values) {
        return Err(AddressError::Checksum);
    }
    let mut groups = vec![format!("{hrp}1")];
    let chars: Vec<char> = data.chars().collect();
    groups.extend(chars.chunks(4).map(|c| c.iter().collect::<String>()));
    Ok(Address { full: lower, testnet, groups })
}

/// The address of a wallet key (32 bytes of an ed25519 public key), as
/// Slatepack writes it: bech32 with `grin` or `tgrin` (О7).
pub fn address_of_key(key: &[u8; 32], testnet: bool) -> String {
    let hrp = if testnet { TEST_ADDRESS_PREFIX } else { ADDRESS_PREFIX };
    // Eight-bit bytes to five-bit groups, the last one padded with zeros.
    let mut data = Vec::with_capacity(52);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in key {
        acc = (acc << 8) | u32::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            data.push(u8::try_from((acc >> bits) & 31).unwrap_or(0));
        }
        acc &= (1u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        data.push(u8::try_from((acc << 5u32.saturating_sub(bits)) & 31).unwrap_or(0));
    }
    let expanded = hrp.bytes().map(|b| b >> 5).chain(std::iter::once(0)).chain(hrp.bytes().map(|b| b & 31));
    let pm = polymod(expanded.chain(data.iter().copied()).chain([0u8; 6])) ^ 1;
    let mut out = format!("{hrp}1");
    for i in 0..6u32 {
        data.push(u8::try_from((pm >> (5u32.saturating_mul(5u32.saturating_sub(i)))) & 31).unwrap_or(0));
    }
    for v in data {
        out.push(char::from(*CHARSET.get(usize::from(v)).unwrap_or(&b'q')));
    }
    out
}

/// The wallet key an address carries (О11): the reverse of
/// [`address_of_key`], for an address that already passed [`address`].
/// `None` when the address holds anything but exactly 32 bytes.
pub fn key_of_address(a: &Address) -> Option<[u8; 32]> {
    let prefix = if a.testnet { TEST_ADDRESS_PREFIX } else { ADDRESS_PREFIX };
    let data = a.full.get(prefix.len().saturating_add(1)..)?;
    let values: Vec<u32> = data
        .bytes()
        .map(|b| CHARSET.iter().position(|c| *c == b).and_then(|v| u32::try_from(v).ok()))
        .collect::<Option<Vec<u32>>>()?;
    // 52 five-bit groups make 260 bits: 32 bytes and four zero bits; then the
    // six groups of the check sum.
    if values.len() != 58 {
        return None;
    }
    let mut out = [0u8; 32];
    let mut filled = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for v in values.iter().take(52) {
        acc = (acc << 5) | v;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            *out.get_mut(filled)? = u8::try_from((acc >> bits) & 0xff).ok()?;
            filled = filled.saturating_add(1);
            acc &= (1u32 << bits).wrapping_sub(1);
        }
    }
    (filled == 32 && acc == 0).then_some(out)
}

/// Why typed text is not an amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountError {
    /// Nothing typed.
    Empty,
    /// Something other than digits, one point or comma, and group spaces.
    Characters,
    /// More than nine digits after the point: finer than a nanogrin.
    TooPrecise,
    /// More than fits.
    TooLarge,
    /// Zero.
    Zero,
}

/// An amount typed by a person, in grin, to nanogrin exactly (О12): a point
/// or a comma before the fraction, spaces between groups allowed, no
/// rounding — finer than a nanogrin is refused, not cut.
pub fn parse_amount(input: &str) -> Result<u64, AmountError> {
    let text: String = input.trim().chars().filter(|c| !matches!(c, ' ' | '\u{00A0}' | '\u{202F}')).collect();
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    let (whole, fraction) = match text.find(['.', ',']) {
        Some(i) => (text.get(..i).unwrap_or(""), text.get(i.saturating_add(1)..).unwrap_or("")),
        None => (text.as_str(), ""),
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || !digits(fraction) || (whole.is_empty() && fraction.is_empty()) {
        return Err(AmountError::Characters);
    }
    if fraction.len() > 9 {
        return Err(AmountError::TooPrecise);
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::TooLarge)? };
    let mut part: u64 = if fraction.is_empty() { 0 } else { fraction.parse().map_err(|_| AmountError::Characters)? };
    for _ in fraction.len()..9 {
        part = part.checked_mul(10).ok_or(AmountError::TooLarge)?;
    }
    let total = whole.checked_mul(NANO).and_then(|w| w.checked_add(part)).ok_or(AmountError::TooLarge)?;
    if total == 0 {
        return Err(AmountError::Zero);
    }
    Ok(total)
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn checksum_ok(hrp: &str, data: &[u8]) -> bool {
    let expanded = hrp.bytes().map(|b| b >> 5).chain(std::iter::once(0)).chain(hrp.bytes().map(|b| b & 31));
    polymod(expanded.chain(data.iter().copied())) == 1
}

/// Who a payment goes to, as the signing window says it (О8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// The address is the very one stored for this contact.
    Contact(Shown),
    /// No contact has this address: «адрес не из ваших контактов».
    Unknown,
}

/// Names the contact only when the checked address equals the stored one
/// exactly; a similar name or a similar address names nobody (О8).
pub fn recipient<'a>(to: &Address, contacts: impl IntoIterator<Item = (&'a str, &'a str)>) -> Recipient {
    for (name, stored) in contacts {
        if let Ok(stored) = address(stored) {
            if stored.full == to.full {
                return Recipient::Contact(foreign_line(name, NAME_CHARS));
            }
        }
    }
    Recipient::Unknown
}

#[cfg(test)]
mod tests;
