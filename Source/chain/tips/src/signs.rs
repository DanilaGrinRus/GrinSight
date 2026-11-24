//! Signs that the program's chain may not be the network's.
//!
//! The program follows the heaviest valid chain it is shown, and it is
//! shown only what its connections bring. A chain made to deceive it has
//! to be mined, and whoever mines with a fraction of the network's power
//! leaves traces a clock can see: the tip grows old, blocks come slowly,
//! the chain falls behind where it should be by now, the difficulty
//! sinks. None of these proves anything, and each has an innocent
//! cause. A sign does one thing: it makes the program ask the operators
//! of the list before it believes its tip. So a sign may be quick to
//! fire - a false alarm costs one round of questions.
//!
//! Everything here is arithmetic on what the program has verified and on
//! the confirmed time. Where the time is an interval, the end of it that
//! makes the sign fire is used.

use std::net::IpAddr;

/// What a sign says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign {
    /// Nothing to see.
    Clear,
    /// The operators have to be asked.
    Fired,
}

/// The tip may be this old, in seconds.
pub const LAG_MAX_S: u64 = 30 * 60;

/// The chain may be this many blocks short of a block a minute since the
/// starting point - or a twentieth of the blocks expected, if that is more.
pub const DEFICIT_MIN: u64 = 720;

/// The difficulty is compared over two spans of this many blocks.
pub const DROP_WINDOW: usize = 1440;

/// An hour has to bring at least this many blocks. Sixty are expected;
/// three days of the main network never brought fewer than 36.
pub const HOUR_MIN: usize = 30;

/// The program has to be connected to nodes in at least this many
/// different networks.
pub const PEER_GROUPS_MIN: usize = 3;

/// The tip is older than half an hour.
pub fn lag(tip_time_s: u64, now_ms: (u64, u64)) -> Sign {
    let latest = tip_time_s.saturating_add(LAG_MAX_S).saturating_mul(1000);
    if now_ms.1 <= latest {
        Sign::Clear
    } else {
        Sign::Fired
    }
}

/// The chain is far short of a block a minute since the starting point.
pub fn deficit(start_height: u64, start_time_s: u64, tip_height: u64, now_ms: (u64, u64)) -> Sign {
    let now_s = now_ms.1.div_ceil(1000);
    // A time before the starting point's own, or a tip below it, is not
    // something to reason from.
    let (Some(passed), Some(gained)) = (
        now_s.checked_sub(start_time_s),
        tip_height.checked_sub(start_height),
    ) else {
        return Sign::Fired;
    };
    let expected = passed.checked_div(60).unwrap_or(0);
    let short = expected.saturating_sub(gained);
    let allowed = DEFICIT_MIN.max(expected.checked_div(20).unwrap_or(0));
    if short > allowed {
        Sign::Fired
    } else {
        Sign::Clear
    }
}

/// The work of the last 1440 blocks is under three fifths of the work of
/// the 1440 before them. `work` is the total work of consecutive blocks,
/// the tip last; nothing can be said from fewer than 2881 of them.
pub fn drop(work: &[u64]) -> Option<Sign> {
    let span = DROP_WINDOW.checked_mul(2)?.checked_add(1)?;
    let recent = work.get(work.len().checked_sub(span)?..)?;
    let first = *recent.first()?;
    let middle = *recent.get(DROP_WINDOW)?;
    let last = *recent.last()?;
    // On a verified chain the work only grows; anything else fires.
    let (Some(old), Some(new)) = (middle.checked_sub(first), last.checked_sub(middle)) else {
        return Some(Sign::Fired);
    };
    let fired = u128::from(new).saturating_mul(5) < u128::from(old).saturating_mul(3);
    Some(if fired { Sign::Fired } else { Sign::Clear })
}

/// Fewer than thirty blocks carry a time within the last hour. `times`
/// are the times of consecutive blocks, the tip last; nothing can be said
/// if they do not reach an hour back and are too few to clear the sign.
pub fn slow_hour(times: &[u64], now_ms: (u64, u64)) -> Option<Sign> {
    let now_s = now_ms.1.div_ceil(1000);
    let within = |time: &&u64| time.saturating_add(3600) > now_s;
    if times.iter().filter(within).count() >= HOUR_MIN {
        return Some(Sign::Clear);
    }
    let reaches_back = times.first().is_some_and(|oldest| !within(&oldest));
    reaches_back.then_some(Sign::Fired)
}

/// The nodes the program is connected to are in fewer than three
/// networks. A network is the first 16 bits of an IPv4 address or the
/// first 32 of an IPv6 one; addresses that are not public - this
/// computer, a home or office network - are nobody's network.
pub fn peers(addresses: &[IpAddr]) -> Sign {
    let mut groups: Vec<(bool, [u8; 4])> = addresses.iter().filter_map(group).collect();
    groups.sort_unstable();
    groups.dedup();
    if groups.len() >= PEER_GROUPS_MIN {
        Sign::Clear
    } else {
        Sign::Fired
    }
}

fn group(address: &IpAddr) -> Option<(bool, [u8; 4])> {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            let shared = a == 100 && (64..128).contains(&b);
            let public = !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || shared);
            public.then_some((false, [a, b, 0, 0]))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return group(&IpAddr::V4(v4));
            }
            let [a, b, c, d, ..] = v6.octets();
            let local = a & 0xfe == 0xfc || (a == 0xfe && b & 0xc0 == 0x80);
            let public = !(v6.is_loopback() || v6.is_unspecified() || local);
            public.then_some((true, [a, b, c, d]))
        }
    }
}

/// All the signs at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signs {
    /// The tip is old.
    pub lag: Sign,
    /// The chain is short of where it should be.
    pub deficit: Sign,
    /// The difficulty sank; nothing if there is too little history.
    pub drop: Option<Sign>,
    /// The last hour brought few blocks; nothing if there is too little
    /// history.
    pub slow_hour: Option<Sign>,
    /// The connections are to too few networks.
    pub peers: Sign,
}

impl Signs {
    /// Whether any sign fired. A sign that cannot be told does not fire.
    pub fn fired(&self) -> bool {
        [Some(self.lag), Some(self.deficit), self.drop, self.slow_hour, Some(self.peers)]
            .contains(&Some(Sign::Fired))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const T: u64 = 1_795_392_000;

    fn at(seconds: u64) -> (u64, u64) {
        (seconds * 1000 - 900, seconds * 1000)
    }

    #[test]
    fn a_tip_half_an_hour_old() {
        assert_eq!(lag(T, at(T)), Sign::Clear);
        assert_eq!(lag(T, at(T + LAG_MAX_S)), Sign::Clear);
        // The later end of the time decides.
        assert_eq!(lag(T, ((T + LAG_MAX_S) * 1000, (T + LAG_MAX_S) * 1000 + 1)), Sign::Fired);
        assert_eq!(lag(T, at(T + LAG_MAX_S + 1)), Sign::Fired);
        // A tip with a time ahead of now is not old.
        assert_eq!(lag(T + 600, at(T)), Sign::Clear);
    }

    #[test]
    fn a_chain_short_of_a_block_a_minute() {
        let day = 86_400;
        // Ten days from the start: 14 400 blocks expected; 720 short is
        // allowed, 721 is not.
        let now = at(T + 10 * day);
        assert_eq!(deficit(1000, T, 1000 + 14_400, now), Sign::Clear);
        assert_eq!(deficit(1000, T, 1000 + 14_400 - 720, now), Sign::Clear);
        assert_eq!(deficit(1000, T, 1000 + 14_400 - 721, now), Sign::Fired);
        // More blocks than a minute each is no sign.
        assert_eq!(deficit(1000, T, 1000 + 20_000, now), Sign::Clear);
        // A hundred days: 144 000 expected, a twentieth of that allowed.
        let now = at(T + 100 * day);
        assert_eq!(deficit(1000, T, 1000 + 144_000 - 7200, now), Sign::Clear);
        assert_eq!(deficit(1000, T, 1000 + 144_000 - 7201, now), Sign::Fired);
        // Right at the start nothing is expected yet.
        assert_eq!(deficit(1000, T, 1000, at(T)), Sign::Clear);
        assert_eq!(deficit(1000, T, 1000, at(T + 720 * 60 + 59)), Sign::Clear);
        assert_eq!(deficit(1000, T, 1000, at(T + 721 * 60)), Sign::Fired);
        // A part of a second counts as begun.
        assert_eq!(deficit(1000, T, 1000, ((T + 721 * 60) * 1000 - 1500, (T + 721 * 60) * 1000 - 999)), Sign::Fired);
        // What cannot be reasoned from.
        assert_eq!(deficit(1000, T, 1000, at(T - 1)), Sign::Fired);
        assert_eq!(deficit(1000, T, 999, at(T)), Sign::Fired);
    }

    /// The total work of 2881 blocks: `old` a block for the first 1440
    /// steps, `new` a block for the last 1440.
    fn work(old: u64, new: u64) -> Vec<u64> {
        let mut total = 1_000_000u64;
        let mut all = vec![total];
        for step in 0..2 * DROP_WINDOW {
            total += if step < DROP_WINDOW { old } else { new };
            all.push(total);
        }
        all
    }

    #[test]
    fn the_difficulty_sinks() {
        assert_eq!(drop(&work(100, 100)), Some(Sign::Clear));
        assert_eq!(drop(&work(100, 150)), Some(Sign::Clear));
        // Three fifths exactly is still clear; less is not.
        assert_eq!(drop(&work(100, 60)), Some(Sign::Clear));
        assert_eq!(drop(&work(1000, 599)), Some(Sign::Fired));
        assert_eq!(drop(&work(100, 10)), Some(Sign::Fired));
        // Only the last 2881 blocks are looked at.
        let mut longer = vec![1, 2, 3];
        longer.extend(work(100, 100));
        assert_eq!(drop(&longer), Some(Sign::Clear));
        let mut sunk_before = work(1000, 100);
        let base = *sunk_before.last().unwrap() - 1_000_000;
        sunk_before.extend(work(100, 100).iter().skip(1).map(|w| w + base));
        assert_eq!(drop(&sunk_before), Some(Sign::Clear));
        // Too little history says nothing.
        let all = work(100, 10);
        assert_eq!(drop(&all[1..]), None);
        assert_eq!(drop(&[]), None);
        // Work that does not grow is not a verified chain's.
        let mut odd = work(100, 100);
        odd[2880] = 0;
        assert_eq!(drop(&odd), Some(Sign::Fired));
        let mut odd = work(100, 100);
        odd[0] = u64::MAX;
        assert_eq!(drop(&odd), Some(Sign::Fired));
        // Numbers as large as they get.
        let huge = [0u64, u64::MAX / 2, u64::MAX];
        let mut all = vec![huge[0]; 1];
        all.extend(std::iter::repeat_n(huge[1], DROP_WINDOW));
        all.extend(std::iter::repeat_n(huge[2], DROP_WINDOW));
        assert_eq!(drop(&all), Some(Sign::Clear));
        // Half of everything, then a quarter: a drop by half.
        let mut all = vec![0u64; 1];
        all.extend(std::iter::repeat_n(u64::MAX / 2, DROP_WINDOW));
        all.extend(std::iter::repeat_n(u64::MAX / 2 + u64::MAX / 4, DROP_WINDOW));
        assert_eq!(drop(&all), Some(Sign::Fired));
    }

    #[test]
    fn an_hour_with_few_blocks() {
        // A block a minute up to now.
        let steady: Vec<u64> = (0..200).map(|i| T - (199 - i) * 60).collect();
        assert_eq!(slow_hour(&steady, at(T)), Some(Sign::Clear));
        // A block every two minutes: thirty in the hour, just enough.
        let half: Vec<u64> = (0..200).map(|i| T - (199 - i) * 120).collect();
        assert_eq!(slow_hour(&half, at(T)), Some(Sign::Clear));
        // Until the oldest of the thirty is an hour old.
        assert_eq!(slow_hour(&half, at(T + 119)), Some(Sign::Clear));
        assert_eq!(slow_hour(&half, at(T + 120)), Some(Sign::Fired));
        // A block every ten minutes.
        let slow: Vec<u64> = (0..200).map(|i| T - (199 - i) * 600).collect();
        assert_eq!(slow_hour(&slow, at(T)), Some(Sign::Fired));
        // The chain went on as usual and then stopped forty minutes ago.
        assert_eq!(slow_hour(&steady, at(T + 40 * 60)), Some(Sign::Fired));
        assert_eq!(slow_hour(&steady, at(T + 30 * 60)), Some(Sign::Clear));
        // History that does not reach an hour back: enough blocks clear
        // the sign, too few say nothing.
        assert_eq!(slow_hour(&steady[170..], at(T)), Some(Sign::Clear));
        assert_eq!(slow_hour(&steady[171..], at(T)), None);
        assert_eq!(slow_hour(&[], at(T)), None);
        // The later end of the time decides.
        let then = (T + 119) * 1000;
        assert_eq!(slow_hour(&half, (then - 5000, then + 1)), Some(Sign::Fired));
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn nodes_in_three_networks() {
        let three = [ip("195.201.2.51"), ip("90.153.126.182"), ip("51.83.197.245")];
        assert_eq!(peers(&three), Sign::Clear);
        assert_eq!(peers(&three[..2]), Sign::Fired);
        assert_eq!(peers(&[]), Sign::Fired);
        // Many nodes of one network are one; the second number of the
        // address tells networks apart, the third does not.
        let one = [ip("51.83.1.1"), ip("51.83.2.2"), ip("51.83.197.245"), ip("51.83.0.9")];
        assert_eq!(peers(&one), Sign::Fired);
        assert_eq!(peers(&[ip("51.83.1.1"), ip("51.79.1.1"), ip("51.80.1.1")]), Sign::Clear);
        assert_eq!(peers(&[ip("51.83.1.1"), ip("51.83.2.1"), ip("90.153.1.1")]), Sign::Fired);
        // Addresses that are nobody's network.
        for local in ["127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.7", "169.254.1.1", "0.0.0.0", "255.255.255.255", "100.64.0.1", "100.127.255.255", "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "::ffff:192.168.1.7"] {
            let with = [three[0], three[1], ip(local)];
            assert_eq!(peers(&with), Sign::Fired, "{local}");
        }
        // Public addresses next to those ranges are networks.
        for public in ["100.63.0.1", "100.128.0.1", "172.32.0.1", "11.0.0.1", "fec0::1", "fe00::1", "2a01:4f8::1", "::ffff:8.8.8.8"] {
            let with = [three[0], three[1], ip(public)];
            assert_eq!(peers(&with), Sign::Clear, "{public}");
        }
        // IPv6: the first 32 bits. An IPv4 address written as IPv6 is
        // the IPv4 address.
        assert_eq!(peers(&[ip("2a01:4f8:1::1"), ip("2a01:4f8:2::1"), ip("2a01:4f9::1")]), Sign::Fired);
        assert_eq!(peers(&[ip("2a01:4f8::1"), ip("2a01:4f9::1"), ip("2a02:4f8::1")]), Sign::Clear);
        assert_eq!(peers(&[three[0], three[1], ip("::ffff:195.201.9.9")]), Sign::Fired);
        // The same first numbers in IPv4 and in IPv6 are not one network.
        assert_eq!(peers(&[ip("42.1.0.1"), ip("2a01::1"), ip("2a01:0:1::1"), ip("90.153.1.1")]), Sign::Clear);
        assert_eq!(peers(&[ip("42.1.0.1"), ip("2a01::1")]), Sign::Fired);
        assert_eq!(peers(&[ip("42.1.0.1"), ip("2a01::1"), ip("2a01:0:1::1")]), Sign::Fired);
    }

    #[test]
    fn any_sign_fires_and_what_cannot_be_told_does_not() {
        let clear = Signs {
            lag: Sign::Clear,
            deficit: Sign::Clear,
            drop: None,
            slow_hour: None,
            peers: Sign::Clear,
        };
        assert!(!clear.fired());
        assert!(!Signs { drop: Some(Sign::Clear), slow_hour: Some(Sign::Clear), ..clear }.fired());
        assert!(Signs { lag: Sign::Fired, ..clear }.fired());
        assert!(Signs { deficit: Sign::Fired, ..clear }.fired());
        assert!(Signs { drop: Some(Sign::Fired), ..clear }.fired());
        assert!(Signs { slow_hour: Some(Sign::Fired), ..clear }.fired());
        assert!(Signs { peers: Sign::Fired, ..clear }.fired());
    }
}
