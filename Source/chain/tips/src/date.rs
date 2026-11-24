//! The time a server wrote on its answer.
//!
//! Every HTTP answer carries a `Date` line, and over TLS that line is as
//! much the named operator's word as the rest of the answer. Only the one
//! form servers are required to write is read (`Sun, 06 Nov 1994 08:49:37
//! GMT`); anything else is no time at all.

/// Seconds since 1970 of a `Date` value, or nothing if it is not written
/// the required way, names a day that does not exist or names the wrong
/// day of the week.
pub fn parse(value: &str) -> Option<u64> {
    let mut parts = value.split(' ');
    let weekday = parts.next()?;
    let day = number(parts.next()?, 2)?;
    let month = month(parts.next()?)?;
    let year = number(parts.next()?, 4)?;
    let clock = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    let mut clock = clock.split(':');
    let hour = number(clock.next()?, 2)?;
    let minute = number(clock.next()?, 2)?;
    let second = number(clock.next()?, 2)?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    if year < 1970 || day == 0 || day > days_in(year, month) {
        return None;
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days = days.checked_add(if leap(y) { 366 } else { 365 })?;
    }
    for m in 1..month {
        days = days.checked_add(days_in(year, m))?;
    }
    days = days.checked_add(day.checked_sub(1)?)?;
    // The first day of 1970 was a Thursday.
    let names = ["Thu,", "Fri,", "Sat,", "Sun,", "Mon,", "Tue,", "Wed,"];
    let name = names.get(usize::try_from(days.checked_rem(7)?).ok()?)?;
    if weekday != *name {
        return None;
    }
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// Writes `seconds` since 1970 the way [`parse`] reads it. Nothing for a
/// time past the year 9999.
pub fn write(seconds: u64) -> Option<String> {
    let mut days = seconds.checked_div(86_400)?;
    let clock = seconds.checked_rem(86_400)?;
    let names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = names.get(usize::try_from(days.checked_rem(7)?).ok()?)?;
    let mut year = 1970u64;
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days = days.checked_sub(length)?;
        year = year.checked_add(1)?;
        if year > 9999 {
            return None;
        }
    }
    let mut month = 1u64;
    while days >= days_in(year, month) {
        days = days.checked_sub(days_in(year, month))?;
        month = month.checked_add(1)?;
    }
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let name = months.get(usize::try_from(month.checked_sub(1)?).ok()?)?;
    Some(format!(
        "{weekday}, {:02} {name} {year:04} {:02}:{:02}:{:02} GMT",
        days.checked_add(1)?,
        clock.checked_div(3_600)?,
        clock.checked_rem(3_600)?.checked_div(60)?,
        clock.checked_rem(60)?,
    ))
}

fn number(text: &str, digits: usize) -> Option<u64> {
    if text.len() != digits || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn month(name: &str) -> Option<u64> {
    let names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let at = names.iter().position(|n| *n == name)?;
    u64::try_from(at).ok()?.checked_add(1)
}

fn leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in(year: u64, month: u64) -> u64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if leap(year) => 29,
        2 => 28,
        _ => 31,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::{parse, write};

    #[test]
    fn known_moments() {
        assert_eq!(parse("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse("Tue, 29 Feb 2000 12:00:00 GMT"), Some(951_825_600));
        assert_eq!(parse("Mon, 23 Nov 2026 02:09:33 GMT"), Some(1_795_399_773));
        // 2100 is not a leap year.
        assert_eq!(parse("Mon, 01 Mar 2100 00:00:00 GMT"), Some(4_107_542_400));
        assert_eq!(parse("Fri, 31 Dec 9999 23:59:59 GMT"), Some(253_402_300_799));
    }

    #[test]
    fn written_and_read_back() {
        assert_eq!(write(784_111_777).as_deref(), Some("Sun, 06 Nov 1994 08:49:37 GMT"));
        assert_eq!(write(0).as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(write(253_402_300_799).as_deref(), Some("Fri, 31 Dec 9999 23:59:59 GMT"));
        assert_eq!(write(253_402_300_800), None);
        // Every 9973rd minute and 7 seconds from 1970 into 2200: each
        // comes back as it went, and no two are written alike.
        let mut last = String::new();
        let mut seconds = 0u64;
        while seconds < 7_258_118_400 {
            let text = write(seconds).unwrap();
            assert_eq!(parse(&text), Some(seconds), "{text}");
            assert_ne!(text, last);
            last = text;
            seconds += 9973 * 60 + 7;
        }
    }

    #[test]
    fn what_is_not_a_time() {
        for bad in [
            "",
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:60:00 GMT",
            "Sun, 06 Nov 1994 08:49:61 GMT",
            "Sun, 06 Nov 1994 08:49 GMT",
            "Wed, 30 Feb 2000 12:00:00 GMT",
            "Thu, 29 Feb 2001 12:00:00 GMT",
            "Mon, 29 Feb 2100 00:00:00 GMT",
            "Tue, 31 Apr 2026 00:00:00 GMT",
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 nov 1994 08:49:37 GMT",
            "Sun, +6 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
