//! The signs on three days of the main network: 4446 consecutive headers
//! from the development starting point, as the program verified them on
//! 22 November 2026 (height, time, total work). No sign fires at any
//! moment of those days; then the same chain is cut over to what somebody
//! with a part of the network's power could have mined, and the signs
//! fire within the hour.
use fly_chain_tips::signs::{deficit, drop, lag, slow_hour, Sign, DROP_WINDOW};

struct Block {
    height: u64,
    time: u64,
    work: u64,
}

fn chain() -> Vec<Block> {
    include_str!("data/mainnet-4113930-4118375.csv")
        .lines()
        .map(|line| {
            let mut fields = line.split(',').map(|field| field.parse::<u64>().unwrap());
            Block {
                height: fields.next().unwrap(),
                time: fields.next().unwrap(),
                work: fields.next().unwrap(),
            }
        })
        .collect()
}

fn at(seconds: u64) -> (u64, u64) {
    (seconds * 1000 - 2000, seconds * 1000)
}

#[test]
fn three_days_of_the_main_network_fire_nothing() {
    let chain = chain();
    assert_eq!(chain.len(), 4446);
    assert_eq!((chain[0].height, chain[4445].height), (4_113_930, 4_118_375));
    let start = &chain[0];
    let times: Vec<u64> = chain.iter().map(|b| b.time).collect();
    let work: Vec<u64> = chain.iter().map(|b| b.work).collect();
    let mut told = (0usize, 0usize);
    for tip in 0..chain.len() {
        // Every tip is looked at twice: the moment it came, and the last
        // second before the next block - when it was oldest.
        let next = chain.get(tip + 1).map_or(chain[tip].time + 60, |b| b.time);
        for now in [chain[tip].time, next.max(chain[tip].time + 1) - 1] {
            let now = at(now);
            assert_eq!(lag(chain[tip].time, now), Sign::Clear, "lag at {tip}");
            assert_eq!(deficit(start.height, start.time, chain[tip].height, now), Sign::Clear, "deficit at {tip}");
            match slow_hour(&times[..=tip], now) {
                Some(sign) => {
                    assert_eq!(sign, Sign::Clear, "hour at {tip}");
                    told.0 += 1;
                }
                None => assert!(tip < 60),
            }
            match drop(&work[..=tip]) {
                Some(sign) => {
                    assert_eq!(sign, Sign::Clear, "drop at {tip}");
                    told.1 += 1;
                }
                None => assert!(tip < 2 * DROP_WINDOW),
            }
        }
    }
    // The signs that need history had it for most of the three days.
    assert!(told.0 > 8700 && told.1 == 2 * (4446 - 2 * DROP_WINDOW));
}

#[test]
fn a_chain_mined_with_a_tenth_of_the_power() {
    // From some block on, the program is shown blocks of somebody with a
    // tenth of the network's power: one in ten minutes, same difficulty.
    let chain = chain();
    let start = &chain[0];
    let fork_at = 3000;
    let mut times: Vec<u64> = chain[..=fork_at].iter().map(|b| b.time).collect();
    let mut height = chain[fork_at].height;
    let mut fired_after = None;
    for block in 1..=40u64 {
        let time = chain[fork_at].time + block * 600;
        times.push(time);
        height += 1;
        let now = at(time);
        // The tip is never old and the chain is not yet far behind...
        assert_eq!(lag(time, now), Sign::Clear);
        assert_eq!(deficit(start.height, start.time, height, now), Sign::Clear);
        // ...but the hour is thin.
        if fired_after.is_none() && slow_hour(&times, now) == Some(Sign::Fired) {
            fired_after = Some(block);
        }
    }
    // Before the fourth block of the other chain - forty minutes in.
    assert_eq!(fired_after, Some(4));

    // With half the power: a block in two minutes. An hour of those is
    // just enough, and the sign stays clear; what gives this chain away
    // is that it falls behind - twelve hours short after a day.
    let mut times: Vec<u64> = chain[..=fork_at].iter().map(|b| b.time).collect();
    let mut height = chain[fork_at].height;
    let mut short_after = None;
    for block in 1..=1000u64 {
        let time = chain[fork_at].time + block * 120;
        times.push(time);
        height += 1;
        if block > 30 {
            assert_eq!(slow_hour(&times, at(time)), Some(Sign::Clear));
        }
        if short_after.is_none() && deficit(start.height, start.time, height, at(time)) == Sign::Fired {
            short_after = Some(block);
        }
    }
    assert!(matches!(short_after, Some(700..=760)), "{short_after:?}");
}

#[test]
fn a_chain_that_stops() {
    // The program is shown nothing more: half an hour later the tip is
    // old, and two minutes after that the hour has thinned out too.
    let chain = chain();
    let times: Vec<u64> = chain.iter().map(|b| b.time).collect();
    let tip = chain.last().unwrap().time;
    let mut hour = None;
    let mut old = None;
    for minute in 0..=40u64 {
        let now = at(tip + minute * 60);
        if hour.is_none() && slow_hour(&times, now) == Some(Sign::Fired) {
            hour = Some(minute);
        }
        if old.is_none() && lag(tip, now) == Sign::Fired {
            old = Some(minute);
        }
    }
    assert_eq!(old, Some(31));
    assert_eq!(hour, Some(33));
}
