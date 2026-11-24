//! Asks every source of the built-in list what its tip is and prints what
//! came back: a check of the list itself, run by hand before a release and
//! whenever the list is in doubt. It decides nothing and writes nothing.
//!
//! `fly-tips-check [--network main|test] [--within SECONDS] [https://a-node-of-your-own ...]`
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use fly_chain_tips::generation::Generation;
use fly_chain_tips::source::{mainnet, testnet, LIST_VERSION, MAINNET_GROUPS, TESTNET_GROUPS};
use fly_chain_tips::time::{confirm, Stamp};
use fly_chain_tips::verdict::classify;
use fly_chain_tips::{Answer, Asker, Failure, Source};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// What one source gave: its addresses, and the answer with this
/// computer's clock at the moment it was read.
type Outcome = (Vec<SocketAddr>, Result<(Answer, u64), Failure>);

fn main() -> ExitCode {
    let mut within = Duration::from_secs(20);
    let mut network = "main".to_string();
    let mut own = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--network" {
            match arguments.next() {
                Some(name) if name == "main" || name == "test" => network = name,
                _ => return usage("--network takes main or test"),
            }
        } else if argument == "--within" {
            match arguments.next().and_then(|s| s.parse::<u64>().ok()) {
                Some(seconds) if (1..=300).contains(&seconds) => within = Duration::from_secs(seconds),
                _ => return usage("--within takes seconds, 1 to 300"),
            }
        } else if let Some(source) = Source::own(&argument) {
            own.push(source);
        } else {
            return usage("a node of your own is named as https://host[:port][/path]");
        }
    }
    let mut sources = if network == "test" { testnet() } else { mainnet() };
    sources.append(&mut own);
    let Ok(asker) = Asker::new() else {
        println!("tips: the secure channel could not be set up");
        return ExitCode::from(2);
    };
    println!(
        "tips: network {network}, list version {LIST_VERSION}, {} sources, {} s each",
        sources.len(),
        within.as_secs()
    );

    let started = Instant::now();
    let (tell, told) = channel::<(usize, Outcome)>();
    for (index, source) in sources.iter().cloned().enumerate() {
        let tell = tell.clone();
        let asker = asker.clone();
        thread::spawn(move || {
            let addresses = fly_chain_tips::ask::addresses(&source);
            let answer = asker
                .ask_at(&source, &addresses, within)
                .map(|answer| (answer, clock()));
            let _ = tell.send((index, (addresses, answer)));
        });
    }
    drop(tell);

    let mut outcomes: Vec<Option<Outcome>> = sources.iter().map(|_| None).collect();
    // Finding a name's address is not bounded by the asker, so the wait
    // for all of them is.
    let patience = within.saturating_add(Duration::from_secs(15));
    while outcomes.iter().any(Option::is_none) {
        let left = patience.saturating_sub(started.elapsed());
        let Ok((index, outcome)) = told.recv_timeout(left) else { break };
        if let Some(slot) = outcomes.get_mut(index) {
            *slot = Some(outcome);
        }
    }

    let mut answered: Vec<(&Source, Answer)> = Vec::new();
    for (source, outcome) in sources.iter().zip(&outcomes) {
        let who = format!(
            "tips: source={} group={:?} asn={}",
            source.host,
            source.group,
            source.asn.map_or("unknown".to_string(), |n| n.to_string())
        );
        match outcome {
            None => println!("{who} failed: the name's address was not found in time"),
            Some((addresses, Err(failure))) => {
                println!("{who} addresses={} failed: {failure}", list(addresses));
            }
            Some((addresses, Ok((answer, clock)))) => {
                let took = answer.got.saturating_duration_since(answer.sent).as_millis();
                let date = match answer.date {
                    Some(date) => format!("date={date} date_minus_clock_s={}", difference(date, *clock)),
                    None => "date=none".to_string(),
                };
                println!(
                    "{who} address={} of={} height={} hash={} total_difficulty={} {date} took_ms={took}",
                    answer.peer,
                    list(addresses),
                    answer.said.height,
                    hex(&answer.said.hash),
                    answer.said.total_difficulty,
                );
                answered.push((source, *answer));
            }
        }
    }

    // What follows is arithmetic on the answers, for the eye: no rule of
    // the program is applied here.
    let needed = sources.len().div_ceil(2);
    let mut best = 0usize;
    let mut pair = false;
    for (source, answer) in &answered {
        let same: Vec<&Source> = answered
            .iter()
            .filter(|(_, other)| other.said.height == answer.said.height && other.said.hash == answer.said.hash)
            .map(|(other, _)| *other)
            .collect();
        best = best.max(same.len());
        pair |= same.iter().any(|other| source.independent_of(other));
    }
    let dates: Vec<u64> = answered.iter().filter_map(|(_, a)| a.date).collect();
    let spread = match (dates.iter().min(), dates.iter().max()) {
        (Some(low), Some(high)) => high.saturating_sub(*low).to_string(),
        _ => "none".to_string(),
    };
    println!(
        "tips: answered={}/{} needed={needed} most_on_one_tip={best} independent_pair_on_one_tip={pair} dates={} date_spread_s={spread}",
        answered.len(),
        sources.len(),
        dates.len(),
    );

    // The program's own rules, with one thing borrowed: this check has no
    // verified chain, so the heaviest answer stands in for the program's
    // tip. A source one block behind cannot be told from one on another
    // branch here, and counts as not having answered.
    let stand_in = answered
        .iter()
        .map(|(_, answer)| answer.said)
        .max_by(|a, b| a.total_difficulty.cmp(&b.total_difficulty).then(b.hash.cmp(&a.hash)));
    if let Some(tip) = stand_in {
        let least = if network == "test" { TESTNET_GROUPS } else { MAINNET_GROUPS };
        let mut generation = Generation::open(0, tip, sources.clone(), started, within, least);
        let mut stamps = Vec::new();
        for (index, outcome) in outcomes.iter().enumerate() {
            match outcome {
                Some((_, Ok((answer, _)))) => {
                    let class = classify(&answer.said, &tip, |_| None);
                    generation.record(index, Some((class, answer.said)), answer.got);
                    if let Some(date) = answer.date {
                        stamps.push(Stamp {
                            source: index,
                            date,
                            sent: answer.sent,
                            got: answer.got,
                        });
                    }
                }
                _ => {
                    generation.record(index, None, Instant::now());
                }
            }
        }
        println!(
            "tips: against the heaviest answer, not against a verified chain: {:?}",
            generation.verdict()
        );
        let clock_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        match confirm(&stamps, &sources, Instant::now(), clock_ms, 0) {
            Ok(time) => println!(
                "tips: time confirmed: low_ms={} high_ms={} width_ms={} clock_ms={clock_ms}",
                time.low_ms,
                time.high_ms,
                time.high_ms.saturating_sub(time.low_ms)
            ),
            Err(why) => println!("tips: time not confirmed: {why:?}"),
        }
    }
    if answered.len() >= needed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn usage(why: &str) -> ExitCode {
    println!("tips: {why}");
    println!("usage: fly-tips-check [--network main|test] [--within SECONDS] [https://a-node-of-your-own ...]");
    ExitCode::from(2)
}

/// This computer's clock, in seconds since 1970.
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn difference(date: u64, clock: u64) -> String {
    if date >= clock {
        format!("+{}", date.saturating_sub(clock))
    } else {
        format!("-{}", clock.saturating_sub(date))
    }
}

fn list(addresses: &[SocketAddr]) -> String {
    if addresses.is_empty() {
        return "none".to_string();
    }
    let all: Vec<String> = addresses.iter().map(|a| a.ip().to_string()).collect();
    all.join(",")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
