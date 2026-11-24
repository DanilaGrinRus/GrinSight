//! The time the program believes.
//!
//! The clock of the computer is whatever its owner or its network last set
//! it to. The operators of the list write the time on every answer; each
//! such time, with the two moments it was written between, is an interval
//! the true time lies in if that operator's clock is right. The time is
//! *confirmed* when the intervals of independent operators agree, are not
//! too wide and the computer's own clock is not far from them. What comes
//! out is itself an interval, and whatever depends on the time has to hold
//! for the whole of it.
//!
//! Two agreeing operators do not prove the time: it is right if one of
//! them is honest and its clock is right.

use crate::source::Source;
use std::time::{Duration, Instant};

/// An answer that took longer than this between question and end says
/// nothing about the time.
pub const RTT_MAX: Duration = Duration::from_secs(30);

/// No two intervals may lie further apart than this. With the limit on
/// how long an answer may take, this also bounds how wide all of them
/// together can be: two intervals of at most 31 s, at most 30 s apart.
pub const APART_MAX_MS: u64 = 30_000;

/// The computer's clock may not be further than this from the interval.
pub const CLOCK_MAX_MS: u64 = 300_000;

/// A confirmed time is used no longer than this before it is confirmed
/// again.
pub const KEPT_FOR: Duration = Duration::from_secs(6 * 3600);

/// The time one source wrote on its answer and the two moments it wrote
/// it between.
#[derive(Debug, Clone, Copy)]
pub struct Stamp {
    /// The place of the source in the list.
    pub source: usize,
    /// The time written, in seconds since 1970.
    pub date: u64,
    /// The moment the question was written.
    pub sent: Instant,
    /// The moment the answer was read to its end.
    pub got: Instant,
}

/// Why the time is not confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unconfirmed {
    /// Fewer than two independent sources gave a time.
    TooFew,
    /// Two sources name times further apart than is allowed.
    Disagree,
    /// The computer's clock is far from the time the sources name.
    Clock,
    /// The time lies wholly before a time that was confirmed earlier.
    Before,
}

/// A confirmed time: at the moment `at` the time was between `low_ms` and
/// `high_ms`, in milliseconds since 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    /// The earliest the time can have been at `at`.
    pub low_ms: u64,
    /// The latest the time can have been at `at`.
    pub high_ms: u64,
    /// The moment the two bounds are for.
    pub at: Instant,
}

/// Confirms the time from the stamps of one generation. `at` is a moment
/// not before any of the answers; `clock_ms` is the computer's clock at
/// that moment; `floor_ms` is the lower bound of the last time confirmed
/// before, or zero.
pub fn confirm(
    stamps: &[Stamp],
    sources: &[Source],
    at: Instant,
    clock_ms: u64,
    floor_ms: u64,
) -> Result<Time, Unconfirmed> {
    // What each stamp says the time is at `at`.
    let mut spans: Vec<(usize, u64, u64)> = Vec::new();
    for stamp in stamps {
        if stamp.got.saturating_duration_since(stamp.sent) > RTT_MAX || stamp.got > at {
            continue;
        }
        let written = stamp.date.saturating_mul(1000);
        let low = written.saturating_add(millis(at.saturating_duration_since(stamp.got)));
        // The server wrote a whole second and may have been at its very
        // end; the durations are cut to whole milliseconds.
        let high = written
            .saturating_add(1000)
            .saturating_add(millis(at.saturating_duration_since(stamp.sent)))
            .saturating_add(1);
        spans.push((stamp.source, low, high));
    }
    let mut independent = false;
    for (place, (first, ..)) in spans.iter().enumerate() {
        for (second, ..) in spans.iter().skip(place.saturating_add(1)) {
            if let (Some(a), Some(b)) = (sources.get(*first), sources.get(*second)) {
                independent |= a.independent_of(b);
            }
        }
    }
    if !independent {
        return Err(Unconfirmed::TooFew);
    }
    for (place, (_, low_a, high_a)) in spans.iter().enumerate() {
        for (_, low_b, high_b) in spans.iter().skip(place.saturating_add(1)) {
            let apart = low_a.saturating_sub(*high_b).max(low_b.saturating_sub(*high_a));
            if apart > APART_MAX_MS {
                return Err(Unconfirmed::Disagree);
            }
        }
    }
    let low = spans.iter().map(|(_, low, _)| *low).min().unwrap_or(0);
    let high = spans.iter().map(|(_, _, high)| *high).max().unwrap_or(0);
    if away(clock_ms, low, high) > CLOCK_MAX_MS {
        return Err(Unconfirmed::Clock);
    }
    if high < floor_ms {
        return Err(Unconfirmed::Before);
    }
    Ok(Time {
        low_ms: low,
        high_ms: high,
        at,
    })
}

impl Time {
    /// The bounds of the time at the moment `now`, or nothing if the time
    /// can no longer be relied on: it was confirmed too long ago, or the
    /// computer's clock (`clock_ms` at `now`) has since moved away from
    /// it, as it does when the clock is set or the computer has slept.
    pub fn at(&self, now: Instant, clock_ms: u64) -> Option<(u64, u64)> {
        let passed = now.saturating_duration_since(self.at);
        if passed > KEPT_FOR {
            return None;
        }
        let passed = millis(passed);
        // A clock without a way back still runs a little fast or slow.
        let drift = passed.checked_div(10_000).unwrap_or(0).saturating_add(1);
        let low = self.low_ms.saturating_add(passed).saturating_sub(drift);
        let high = self.high_ms.saturating_add(passed).saturating_add(drift);
        if away(clock_ms, low, high) > CLOCK_MAX_MS {
            return None;
        }
        Some((low, high))
    }
}

/// How far `point` lies outside `low..=high`.
fn away(point: u64, low: u64, high: u64) -> u64 {
    low.saturating_sub(point).max(point.saturating_sub(high))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const NOON: u64 = 1_795_392_000; // seconds: 23 November 2026, 00:00 UTC

    fn list() -> Vec<Source> {
        vec![
            Source::listed("A", Some(1), "a.example"),
            Source::listed("B", Some(2), "b.example"),
            Source::listed("C", Some(3), "c.example"),
            Source::listed("D", Some(3), "d.example"),
            Source::own("https://mine.example").unwrap(),
        ]
    }

    struct At {
        start: Instant,
    }

    impl At {
        fn new() -> At {
            At { start: Instant::now() }
        }
        fn ms(&self, ms: u64) -> Instant {
            self.start + Duration::from_millis(ms)
        }
        /// A stamp: asked at `sent` ms, answered at `got` ms, the server
        /// wrote `date` seconds after noon.
        fn stamp(&self, source: usize, date: u64, sent: u64, got: u64) -> Stamp {
            Stamp {
                source,
                date: NOON + date,
                sent: self.ms(sent),
                got: self.ms(got),
            }
        }
    }

    const CLOCK: u64 = NOON * 1000;

    #[test]
    fn two_independent_sources_that_agree() {
        let t = At::new();
        // Both asked at 0 and answered within 200 and 300 ms; the true
        // time at the start was noon and 100 ms.
        let stamps = [t.stamp(0, 0, 0, 200), t.stamp(1, 0, 0, 300)];
        let time = confirm(&stamps, &list(), t.ms(1000), CLOCK, 0).unwrap();
        // At 1000 ms: not before noon + 700 ms (the slower answer was
        // read 700 ms ago and its second had begun), not after noon +
        // 2001 ms (written at the end of its second, at the very start).
        assert_eq!(time.low_ms, NOON * 1000 + 700);
        assert_eq!(time.high_ms, NOON * 1000 + 2001);
        assert_eq!(time.at, t.ms(1000));
        // The true time, noon + 1100 ms, is inside.
        assert!(time.low_ms <= NOON * 1000 + 1100 && NOON * 1000 + 1100 <= time.high_ms);
    }

    #[test]
    fn who_can_confirm_the_time() {
        let t = At::new();
        let at = t.ms(1000);
        let ok = |stamps: &[Stamp]| confirm(stamps, &list(), at, CLOCK, 0);
        assert_eq!(ok(&[]).err(), Some(Unconfirmed::TooFew));
        assert_eq!(ok(&[t.stamp(0, 0, 0, 100)]).err(), Some(Unconfirmed::TooFew));
        // Two sources of one network, a source of the user, a source the
        // list does not have.
        assert_eq!(ok(&[t.stamp(2, 0, 0, 100), t.stamp(3, 0, 0, 100)]).err(), Some(Unconfirmed::TooFew));
        assert_eq!(ok(&[t.stamp(0, 0, 0, 100), t.stamp(4, 0, 0, 100)]).err(), Some(Unconfirmed::TooFew));
        assert_eq!(ok(&[t.stamp(0, 0, 0, 100), t.stamp(9, 0, 0, 100)]).err(), Some(Unconfirmed::TooFew));
        assert!(ok(&[t.stamp(0, 0, 0, 100), t.stamp(2, 0, 0, 100)]).is_ok());
        // An answer that took too long says nothing about the time, and
        // neither does one from after the moment asked about.
        let slow = Stamp {
            source: 1,
            date: NOON,
            sent: t.ms(0),
            got: t.ms(0) + RTT_MAX + Duration::from_millis(1),
        };
        let late_at = t.ms(0) + RTT_MAX + Duration::from_secs(1);
        assert_eq!(
            confirm(&[t.stamp(0, 0, 0, 100), slow], &list(), late_at, CLOCK + 31_000, 0).err(),
            Some(Unconfirmed::TooFew)
        );
        let just = Stamp { got: t.ms(0) + RTT_MAX, ..slow };
        assert!(confirm(&[t.stamp(0, 0, 0, 100), just], &list(), late_at, CLOCK + 31_000, 0).is_ok());
        assert_eq!(ok(&[t.stamp(0, 0, 0, 100), t.stamp(1, 0, 0, 1001)]).err(), Some(Unconfirmed::TooFew));
    }

    #[test]
    fn sources_that_disagree() {
        let t = At::new();
        let at = t.ms(1000);
        let ok = |stamps: &[Stamp]| confirm(stamps, &list(), at, CLOCK, 0);
        // The second source is ahead. Its interval starts 1000 - 100 ms
        // after its second, the first one's ends 2001 ms after noon: they
        // are 30 s apart when the dates differ by 31 s and 101 ms.
        assert!(ok(&[t.stamp(0, 0, 0, 100), t.stamp(1, 31, 0, 100)]).is_ok());
        assert_eq!(
            ok(&[t.stamp(0, 0, 0, 100), t.stamp(1, 32, 0, 100)]).err(),
            Some(Unconfirmed::Disagree)
        );
        // One source out of step spoils the time even among three that
        // agree, and whoever it is.
        let three = [t.stamp(0, 0, 0, 100), t.stamp(1, 0, 0, 100), t.stamp(2, 1, 0, 100)];
        assert!(ok(&three).is_ok());
        for odd in [3usize, 4] {
            let mut four = three.to_vec();
            four.push(t.stamp(odd, 600, 0, 100));
            assert_eq!(ok(&four).err(), Some(Unconfirmed::Disagree));
        }
        // Behind is as far as ahead.
        assert_eq!(
            ok(&[t.stamp(0, 32, 0, 100), t.stamp(1, 0, 0, 100)]).err(),
            Some(Unconfirmed::Disagree)
        );
    }

    #[test]
    fn the_widest_time_there_can_be() {
        let t = At::new();
        // The slowest answers allowed, as far apart as allowed, and a
        // third between them: every pair agrees.
        let slow = |source, date| Stamp {
            source,
            date: NOON + date,
            sent: t.ms(0),
            got: t.ms(0) + RTT_MAX,
        };
        let at = t.ms(0) + RTT_MAX;
        let widest = [slow(0, 0), slow(1, 61), slow(2, 30)];
        let time = confirm(&widest, &list(), at, CLOCK + 60_000, 0).unwrap();
        // [noon, noon + 31.001 s] and [noon + 61 s, noon + 92.001 s].
        assert_eq!((time.low_ms, time.high_ms), (CLOCK, CLOCK + 92_001));
        // A second further and the two ends disagree.
        let apart = [slow(0, 0), slow(1, 62), slow(2, 30)];
        assert_eq!(
            confirm(&apart, &list(), at, CLOCK + 60_000, 0).err(),
            Some(Unconfirmed::Disagree)
        );
    }

    #[test]
    fn the_clock_of_the_computer_and_the_time_before() {
        let t = At::new();
        let stamps = [t.stamp(0, 0, 0, 100), t.stamp(1, 0, 0, 100)];
        let at = t.ms(1000);
        // The interval is [noon + 900 ms, noon + 2001 ms].
        let ok = |clock: u64, floor: u64| confirm(&stamps, &list(), at, clock, floor);
        assert!(ok(CLOCK + 900 - CLOCK_MAX_MS, 0).is_ok());
        assert_eq!(ok(CLOCK + 899 - CLOCK_MAX_MS, 0).err(), Some(Unconfirmed::Clock));
        assert!(ok(CLOCK + 2001 + CLOCK_MAX_MS, 0).is_ok());
        assert_eq!(ok(CLOCK + 2002 + CLOCK_MAX_MS, 0).err(), Some(Unconfirmed::Clock));
        assert_eq!(ok(0, 0).err(), Some(Unconfirmed::Clock));
        // A time confirmed earlier is not gone back behind.
        assert!(ok(CLOCK, CLOCK + 2001).is_ok());
        assert_eq!(ok(CLOCK, CLOCK + 2002).err(), Some(Unconfirmed::Before));
    }

    #[test]
    fn a_confirmed_time_goes_on_with_the_clock_that_has_no_way_back() {
        let start = Instant::now();
        let time = Time {
            low_ms: CLOCK,
            high_ms: CLOCK + 1000,
            at: start,
        };
        assert_eq!(time.at(start, CLOCK), Some((CLOCK - 1, CLOCK + 1001)));
        // An hour on: an hour later, wider by what a clock may drift.
        let hour = Duration::from_secs(3600);
        assert_eq!(
            time.at(start + hour, CLOCK + 3_600_000),
            Some((CLOCK + 3_600_000 - 361, CLOCK + 3_601_000 + 361))
        );
        // Not relied on for longer than it is kept.
        assert!(time.at(start + KEPT_FOR, CLOCK + 6 * 3_600_000).is_some());
        assert_eq!(time.at(start + KEPT_FOR + Duration::from_millis(1), CLOCK + 6 * 3_600_000), None);
        // The computer slept for an hour: its clock went on, the clock
        // without a way back did not. The time is no longer relied on.
        assert_eq!(time.at(start + Duration::from_secs(10), CLOCK + 3_610_000), None);
        // The clock was set back by ten minutes.
        assert_eq!(time.at(start + Duration::from_secs(10), CLOCK - 590_000), None);
        // A moment before the confirmation is the confirmation's moment.
        assert_eq!(time.at(start - Duration::from_secs(1), CLOCK), Some((CLOCK - 1, CLOCK + 1001)));
    }
}
