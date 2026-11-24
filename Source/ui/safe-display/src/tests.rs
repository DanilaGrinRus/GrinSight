#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use super::*;

// ---- О1: one line of someone else's text

#[test]
fn direction_and_invisible_characters_are_removed_and_said() {
    // "аннa" + right-to-left override + "exe.txt": seen as something else.
    let shown = foreign_line("Аня\u{202E}txt.exe", NAME_CHARS);
    assert_eq!(shown.text, "Аняtxt.exe");
    assert!(shown.changed);
    for c in ['\u{200B}', '\u{200D}', '\u{2066}', '\u{2069}', '\u{FEFF}', '\u{061C}', '\u{E0041}', '\u{00AD}', '\u{3164}'] {
        let shown = foreign_line(&format!("Па{c}вел"), NAME_CHARS);
        assert_eq!(shown.text, "Павел", "{:?}", c);
        assert!(shown.changed, "{:?}", c);
    }
}

#[test]
fn plain_text_is_not_marked_changed() {
    let shown = foreign_line("Кофейня «Утро», 2 этаж", NOTE_CHARS);
    assert_eq!(shown.text, "Кофейня «Утро», 2 этаж");
    assert!(!shown.changed && !shown.mixed_scripts && !shown.cut);
}

#[test]
fn a_line_has_no_line_breaks_or_controls() {
    let shown = foreign_line("  Счёт\nза\r\nкофе\tи\u{0007}чай  ", NOTE_CHARS);
    assert_eq!(shown.text, "Счёт за кофе и чай");
    assert!(shown.changed, "tab and bell are not plain spaces");
    let shown = foreign_line("одна\u{2028}строка", NOTE_CHARS);
    assert_eq!(shown.text, "одна строка");
    assert!(shown.changed);
    let shown = foreign_line("два\n\nабзаца", NOTE_CHARS);
    assert_eq!(shown.text, "два абзаца");
    assert!(!shown.changed, "a plain line break is not hidden text");
}

// ---- О2: several lines

#[test]
fn a_message_keeps_lines_but_not_more_than_two_breaks() {
    let shown = foreign_text("привет\n\n\n\n\nкак дела?\n", MESSAGE_CHARS);
    assert_eq!(shown.text, "привет\n\nкак дела?");
    let shown = foreign_text("\n\n  первая  \n вторая", MESSAGE_CHARS);
    assert_eq!(shown.text, "первая\nвторая");
    let shown = foreign_text("строка\r\nещё", MESSAGE_CHARS);
    assert_eq!(shown.text, "строка\nещё");
    assert!(!shown.changed);
}

// ---- О3: combining marks

#[test]
fn piles_of_combining_marks_are_cut_to_two() {
    let zalgo = "а\u{0301}\u{0302}\u{0303}\u{0304}б";
    let shown = foreign_line(zalgo, NAME_CHARS);
    assert_eq!(shown.text, "а\u{0301}\u{0302}б");
    assert!(shown.changed);
    let ok = foreign_line("е\u{0308}лка", NAME_CHARS);
    assert_eq!(ok.text, "е\u{0308}лка");
    assert!(!ok.changed);
    let lone = foreign_line("\u{0301}имя", NAME_CHARS);
    assert_eq!(lone.text, "имя");
    assert!(lone.changed);
}

// ---- О4: mixed scripts

#[test]
fn a_word_of_latin_and_cyrillic_letters_is_marked() {
    // Latin "a" and "o" inside a Cyrillic name.
    assert!(foreign_line("Пaвел", NAME_CHARS).mixed_scripts);
    assert!(foreign_line("Kофейня", NAME_CHARS).mixed_scripts);
    assert!(foreign_line("Ρavel", NAME_CHARS).mixed_scripts, "Greek capital rho");
    assert!(foreign_line("ｐavel", NAME_CHARS).mixed_scripts, "full width p");
    assert!(!foreign_line("Павел Pavel", NAME_CHARS).mixed_scripts, "two words, each in one script");
    assert!(!foreign_line("Grin Coffee 24", NAME_CHARS).mixed_scripts);
}

// ---- О5: length

#[test]
fn long_text_is_cut_on_a_character_with_an_ellipsis() {
    let long = "щ".repeat(40);
    let shown = foreign_line(&long, NAME_CHARS);
    assert_eq!(shown.text.chars().count(), NAME_CHARS);
    assert!(shown.text.ends_with('…'));
    assert!(shown.cut);
    let exact = "щ".repeat(NAME_CHARS);
    let shown = foreign_line(&exact, NAME_CHARS);
    assert_eq!(shown.text, exact);
    assert!(!shown.cut);
    // A combining mark is never left on the ellipsis.
    let marks = format!("{}е\u{0301}хвост", "ы".repeat(NAME_CHARS - 3));
    let shown = foreign_line(&marks, NAME_CHARS);
    assert!(!shown.text.contains("\u{0301}…"), "{:?}", shown.text);
    assert!(shown.cut);
}

// ---- О6: amounts

#[test]
fn amounts_are_exact_and_formatted_one_way() {
    assert_eq!(amount(0), "0.00");
    assert_eq!(amount(1), "0.000000001");
    assert_eq!(amount(23_000_000), "0.023");
    assert_eq!(amount(500_000_000), "0.50");
    assert_eq!(amount(24_137_000_000), "24.137");
    assert_eq!(amount(9_999_990_000_000), "9999.99");
    assert_eq!(amount(10_000 * NANO), "10\u{202F}000.00");
    assert_eq!(amount(1_234_567 * NANO + 1), "1\u{202F}234\u{202F}567.000000001");
    assert_eq!(amount(u64::MAX), "18\u{202F}446\u{202F}744\u{202F}073.709551615");
}

// ---- О7: addresses

fn encode(hrp: &str, data: &[u8]) -> String {
    let expanded: Vec<u8> = hrp.bytes().map(|b| b >> 5).chain([0]).chain(hrp.bytes().map(|b| b & 31)).collect();
    let pm = polymod(expanded.iter().copied().chain(data.iter().copied()).chain([0; 6])) ^ 1;
    let mut out = format!("{hrp}1");
    for v in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
        out.push(CHARSET[v as usize] as char);
    }
    out
}

fn sample_address(seed: u8) -> String {
    let data: Vec<u8> = (0..52u8).map(|i| (i.wrapping_mul(7).wrapping_add(seed)) % 32).collect();
    encode(ADDRESS_PREFIX, &data)
}

#[test]
fn the_check_sum_is_bech32() {
    // Vectors from BIP 173.
    let vector = |s: &str| {
        let (hrp, data) = s.rsplit_once('1').unwrap();
        let values: Vec<u8> = data.bytes().map(|b| CHARSET.iter().position(|c| *c == b).unwrap() as u8).collect();
        checksum_ok(hrp, &values)
    };
    assert!(vector("a12uel5l"));
    assert!(vector("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"));
    assert!(vector("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"));
    assert!(!vector("a12uel5m"));
}

#[test]
fn a_good_address_is_split_into_groups() {
    let text = sample_address(3);
    let a = address(&text).unwrap();
    assert_eq!(a.full, text);
    assert_eq!(a.groups[0], "grin1");
    assert!(a.groups.iter().skip(1).rev().skip(1).all(|g| g.len() == 4));
    assert_eq!(a.groups.concat(), text);
    let short = a.short();
    assert!(short.starts_with(&text[..11]) && short.ends_with(&text[text.len() - 6..]), "{short}");
    assert_eq!(address(&text.to_ascii_uppercase()).unwrap().full, text, "all upper case is the same address");
}

#[test]
fn a_wrong_address_is_refused() {
    let text = sample_address(5);
    // One character changed.
    let mut chars: Vec<char> = text.chars().collect();
    let i = 20;
    chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
    let typo: String = chars.into_iter().collect();
    assert_eq!(address(&typo), Err(AddressError::Checksum));
    // Two neighbours swapped.
    let mut chars: Vec<char> = text.chars().collect();
    let j = (6..chars.len() - 1).find(|j| chars[*j] != chars[*j + 1]).unwrap();
    chars.swap(j, j + 1);
    assert_eq!(address(&chars.into_iter().collect::<String>()), Err(AddressError::Checksum));
    // Mixed case, foreign letters, other prefix, length.
    let k = text.char_indices().skip(5).find(|(_, c)| c.is_ascii_lowercase()).unwrap().0;
    let mut mixed = text.clone();
    mixed.replace_range(k..k + 1, &text[k..k + 1].to_ascii_uppercase());
    assert_ne!(mixed, text);
    assert_eq!(address(&mixed), Err(AddressError::Characters));
    assert_eq!(address(&text.replacen('q', "о", 1)), Err(AddressError::Characters), "Cyrillic о");
    assert_eq!(address(&text.replacen('q', "b", 1)), Err(AddressError::Characters), "b is not in the set");
    assert_eq!(address(&encode("xgrin", &[1; 52])), Err(AddressError::Prefix));
    assert_eq!(address(&encode("grin", &[1; 20])), Err(AddressError::Length));
    assert_eq!(address(&format!("{text}{}", "q".repeat(40))), Err(AddressError::Length));
}

// ---- О8: recipient

#[test]
fn a_contact_is_named_only_for_the_very_same_address() {
    let anya = sample_address(7);
    let other = sample_address(8);
    let to = address(&anya).unwrap();
    let contacts = [("Павел", other.as_str()), ("Аня", anya.as_str())];
    match recipient(&to, contacts) {
        Recipient::Contact(name) => assert_eq!(name.text, "Аня"),
        Recipient::Unknown => panic!("Аня is a contact"),
    }
    let stranger = address(&sample_address(9)).unwrap();
    assert_eq!(recipient(&stranger, contacts), Recipient::Unknown);
    // A stored address that does not pass the check names nobody.
    assert_eq!(recipient(&to, [("Аня", "grin1broken")]), Recipient::Unknown);
    // The contact's name is someone else's text too.
    let tricky = [("Аня\u{202E}", anya.as_str())];
    match recipient(&to, tricky) {
        Recipient::Contact(name) => assert!(name.changed && name.text == "Аня"),
        Recipient::Unknown => panic!("still the same address"),
    }
}

#[test]
fn a_key_becomes_its_slatepack_address() {
    // Reference values from an independent encoder (BIP 173 bit grouping).
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let main = address_of_key(&key, false);
    assert_eq!(main, "grin1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s90zndu");
    let test = address_of_key(&[255; 32], true);
    assert_eq!(test, "tgrin1llllllllllllllllllllllllllllllllllllllllllllllllllls3s80rl");
    let a = address(&main).unwrap();
    assert!(!a.testnet && a.groups[0] == "grin1");
    let t = address(&test).unwrap();
    assert!(t.testnet && t.groups[0] == "tgrin1");
    assert!(t.short().starts_with("tgrin1llllll…"), "{}", t.short());
}

// ---- О11: the key inside an address

/// Any five-bit values as an address with a valid check sum (for tests).
fn encode_values(hrp: &str, values: &[u8]) -> String {
    let expanded = hrp.bytes().map(|b| b >> 5).chain(std::iter::once(0)).chain(hrp.bytes().map(|b| b & 31));
    let pm = polymod(expanded.chain(values.iter().copied()).chain([0u8; 6])) ^ 1;
    let mut all = values.to_vec();
    for i in 0..6u32 {
        all.push(((pm >> (5 * (5 - i))) & 31) as u8);
    }
    let mut out = format!("{hrp}1");
    for v in all {
        out.push(CHARSET[usize::from(v)] as char);
    }
    out
}

#[test]
fn an_address_gives_back_its_key() {
    for (seed, testnet) in [(0u8, false), (7, true), (0xff, false), (0x5a, true)] {
        let key: [u8; 32] = std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add((i as u8).wrapping_mul(13)));
        let text = address_of_key(&key, testnet);
        let checked = address(&text).unwrap();
        assert_eq!(key_of_address(&checked), Some(key));
    }
    // a Mainnet key read from the Testnet form is the same key, the network differs
    let key = [9u8; 32];
    assert_eq!(key_of_address(&address(&address_of_key(&key, true)).unwrap()), Some(key));
}

#[test]
fn an_address_that_holds_something_else_gives_no_key() {
    // 53 groups: a clean 32-byte key and one group more
    let mut extra = vec![0u8; 53];
    extra[52] = 3;
    let long = encode_values("grin", &extra);
    assert_eq!(key_of_address(&address(&long).unwrap()), None);
    // 51 groups: fewer
    let short = encode_values("grin", &[1u8; 51]);
    assert_eq!(key_of_address(&address(&short).unwrap()), None);
    // 52 groups, but the four spare bits are not zero
    let mut values = vec![0u8; 52];
    values[51] = 1;
    let padded = encode_values("grin", &values);
    assert_eq!(key_of_address(&address(&padded).unwrap()), None);
    values[51] = 16;
    let fine = encode_values("grin", &values);
    assert!(key_of_address(&address(&fine).unwrap()).is_some());
}

// ---- О12: an amount typed by a person

#[test]
fn typed_amounts_are_read_exactly() {
    assert_eq!(parse_amount("1.5"), Ok(1_500_000_000));
    assert_eq!(parse_amount("1,5"), Ok(1_500_000_000));
    assert_eq!(parse_amount(" 2 "), Ok(2 * NANO));
    assert_eq!(parse_amount(".5"), Ok(500_000_000));
    assert_eq!(parse_amount("5."), Ok(5 * NANO));
    assert_eq!(parse_amount("0.000000001"), Ok(1));
    assert_eq!(parse_amount("1 000"), Ok(1000 * NANO));
    assert_eq!(parse_amount("12\u{202F}345,6"), Ok(12_345_600_000_000));
    assert_eq!(parse_amount("18446744073.709551615"), Ok(u64::MAX));
    // what the screen shows can be typed back
    assert_eq!(parse_amount(&amount(24_137_000_000)), Ok(24_137_000_000));
}

#[test]
fn typed_amounts_are_refused_rather_than_guessed() {
    assert_eq!(parse_amount(""), Err(AmountError::Empty));
    assert_eq!(parse_amount("   "), Err(AmountError::Empty));
    assert_eq!(parse_amount("0.0000000001"), Err(AmountError::TooPrecise));
    assert_eq!(parse_amount("1.0000000005"), Err(AmountError::TooPrecise));
    assert_eq!(parse_amount("18446744073.709551616"), Err(AmountError::TooLarge));
    assert_eq!(parse_amount("99999999999999999999"), Err(AmountError::TooLarge));
    assert_eq!(parse_amount("0"), Err(AmountError::Zero));
    assert_eq!(parse_amount("0,000"), Err(AmountError::Zero));
    for bad in ["1.2.3", "1,2.3", "-1", "+1", "1e3", ".", ",", "１", "1 . 5x", "0x10", "1_000"] {
        assert_eq!(parse_amount(bad), Err(AmountError::Characters), "{bad}");
    }
}
