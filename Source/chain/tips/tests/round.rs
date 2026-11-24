//! A whole generation against servers that listen on this computer: five
//! sources asked at once, their answers placed next to the program's tip,
//! the quorum, a claim of more and what settles it, answers that come too
//! late, and the time confirmed from what the servers wrote.
mod kit;

use fly_chain_tips::claims::{Claims, Noted};
use fly_chain_tips::generation::{Generation, Pace, Verdict};
use fly_chain_tips::survey::{Survey, GRACE};
use fly_chain_tips::time::{confirm, Unconfirmed};
use fly_chain_tips::{Said, Source};
use kit::{asker, gone, serve, serve_after, Then};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The program's chain in these tests: block `h` has the hash made of
/// the mark `h` and the work `10 h`.
fn ours(height: u64) -> Said {
    Said {
        height,
        hash: [u8::try_from(height).unwrap(); 32],
        total_difficulty: height * 10,
    }
}

const TIP: u64 = 100;

fn recent() -> Vec<Said> {
    (TIP - 8..TIP).map(ours).collect()
}

fn clock() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

/// What a test server says: the program's block at `height`, with the
/// time of the moment it answers.
fn our(height: u64) -> Then {
    let block = ours(height);
    tip(block.height, block.hash[0], block.total_difficulty)
}

fn tip(height: u64, mark: u8, work: u64) -> Then {
    Then::Tip {
        height,
        mark,
        work,
        ahead: 0,
    }
}

/// Five sources on this computer, each with an operator and a network of
/// its own but the last two, which share one.
fn sources(ports: &[u16]) -> Vec<Source> {
    let networks = [1u32, 2, 3, 4, 4];
    ports
        .iter()
        .zip(networks)
        .enumerate()
        .map(|(i, (port, network))| {
            let mut source = Source::own(&format!("https://localhost:{port}")).unwrap();
            source.group = format!("Operator {i}");
            source.asn = Some(network);
            source
        })
        .collect()
}

fn run(survey: &mut Survey) {
    while survey.step(Duration::from_millis(100)) {}
}

const WITHIN: Duration = Duration::from_secs(20);

#[test]
fn five_sources_and_a_quorum() {
    let servers = [our(TIP), our(TIP), our(TIP - 1), our(TIP), our(TIP)].map(|then| serve("localhost", then));
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let started = Instant::now();
    let generation = Generation::open(1, ours(TIP), sources(&ports), started, WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    // Everyone was heard long before the deadline.
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(survey.failures().is_empty());
    assert_eq!(survey.generation().verdict(), Verdict::Confirmed { by: (0, 1) });
    assert!(survey.generation().claims().is_empty() && !survey.generation().late());
    assert!(survey.generation().over(Instant::now()));

    // The time: five servers wrote this computer's own time.
    assert_eq!(survey.stamps().len(), 5);
    let at = Instant::now();
    let now = clock();
    let time = confirm(survey.stamps(), survey.generation().sources(), at, now, 0).unwrap();
    assert!(time.low_ms <= now && now <= time.high_ms);
    assert!(time.high_ms - time.low_ms < 15_000);
    // Not before a time that was confirmed already.
    let later = time.high_ms + 1;
    assert_eq!(
        confirm(survey.stamps(), survey.generation().sources(), at, now, later).err(),
        Some(Unconfirmed::Before)
    );
}

#[test]
fn sources_that_are_gone_and_the_two_that_share_a_network() {
    // Two of five hang up on everyone; the three that are left answer, and two
    // of them are independent.
    let servers = [our(TIP), our(TIP - 3), our(TIP)].map(|then| serve("localhost", then));
    let ports = [servers[0].at.port(), gone(), servers[1].at.port(), gone(), servers[2].at.port()];
    let started = Instant::now();
    let generation = Generation::open(1, ours(TIP), sources(&ports), started, WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(survey.generation().verdict(), Verdict::Confirmed { by: (0, 4) });
    // The two are known to have failed: nothing more is waited for.
    assert!(survey.generation().over(Instant::now()));
    assert_eq!(survey.failures().len(), 2);
    assert_eq!(survey.stamps().len(), 3);

    // The same, but the two that confirm are the two of one network.
    let servers = [our(TIP - 1), our(TIP), our(TIP)].map(|then| serve("localhost", then));
    let ports = [servers[0].at.port(), gone(), gone(), servers[1].at.port(), servers[2].at.port()];
    let generation = Generation::open(2, ours(TIP), sources(&ports), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert_eq!(
        survey.generation().verdict(),
        Verdict::NoQuorum {
            answered: 3,
            needed: 3,
            confirming: 2
        }
    );

    // One source left of five: nothing is confirmed, whatever it says.
    let server = serve("localhost", our(TIP));
    let ports = [server.at.port(), gone(), gone(), gone(), gone()];
    let generation = Generation::open(3, ours(TIP), sources(&ports), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert_eq!(
        survey.generation().verdict(),
        Verdict::NoQuorum {
            answered: 1,
            needed: 3,
            confirming: 1
        }
    );
    // One source is not a time either.
    assert_eq!(
        confirm(survey.stamps(), survey.generation().sources(), Instant::now(), clock(), 0).err(),
        Some(Unconfirmed::TooFew)
    );
}

#[test]
fn what_the_program_cannot_place() {
    // A block of another branch at the tip's height, a block further back
    // than the program looks, a block of the program's chain with another
    // work: none is an answer.
    let other = tip(TIP, 0xee, TIP * 10);
    let far = our(TIP - 9);
    let odd = tip(TIP - 1, u8::try_from(TIP - 1).unwrap(), 5);
    let servers = [our(TIP), our(TIP), other, far, odd].map(|then| serve("localhost", then));
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let generation = Generation::open(1, ours(TIP), sources(&ports), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert!(survey.failures().is_empty());
    assert_eq!(
        survey.generation().verdict(),
        Verdict::NoQuorum {
            answered: 2,
            needed: 3,
            confirming: 2
        }
    );
    // They still wrote a time.
    assert_eq!(survey.stamps().len(), 5);
}

#[test]
fn a_claim_of_more_and_the_block_that_settles_it() {
    // Four sources confirm; the fifth is one block further.
    let next = Said {
        height: TIP + 1,
        hash: [0xab; 32],
        total_difficulty: TIP * 10 + 10,
    };
    let further = tip(next.height, 0xab, next.total_difficulty);
    let servers = [our(TIP), our(TIP), our(TIP), our(TIP), further].map(|then| serve("localhost", then));
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let list = sources(&ports);
    let generation = Generation::open(1, ours(TIP), list.clone(), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert_eq!(survey.generation().verdict(), Verdict::Ahead);
    assert_eq!(survey.generation().claims(), [(4, next)]);

    // The claim is kept and blocks whatever later generations say.
    let mut claims = Claims::default();
    for (index, said) in survey.generation().claims() {
        assert_eq!(claims.note(&list[index].host, said, None), Noted::New);
    }
    assert!(claims.blocks());

    // A generation in which the fifth source is silent confirms by its
    // own count, and the claim still stands.
    let servers = [our(TIP), our(TIP), our(TIP), our(TIP)].map(|then| serve("localhost", then));
    let mut ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    ports.push(gone());
    let generation = Generation::open(2, ours(TIP), sources(&ports), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert_eq!(survey.generation().verdict(), Verdict::Confirmed { by: (0, 1) });
    assert!(claims.blocks());

    // The program verifies the block: the claim is settled.
    assert_eq!(claims.settle(|said| *said == next), 1);
    assert!(!claims.blocks() && !claims.caveat());
}

#[test]
fn answers_after_the_deadline() {
    // Two sources answer at once, three only after the generation's
    // deadline: their answers are not counted, however right they are.
    let slow = Duration::from_millis(2500);
    let servers = [
        serve("localhost", our(TIP)),
        serve("localhost", our(TIP)),
        serve_after(slow, "localhost", our(TIP)),
        serve_after(slow, "localhost", our(TIP)),
        serve_after(slow, "localhost", tip(TIP + 1, 0xab, TIP * 10 + 10)),
    ];
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let mut pace = Pace::default();
    let started = Instant::now();
    let generation = Generation::open(1, ours(TIP), sources(&ports), started, Duration::from_millis(1200), 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    assert!(started.elapsed() >= slow);
    let no_quorum = Verdict::NoQuorum {
        answered: 2,
        needed: 3,
        confirming: 2,
    };
    assert_eq!(survey.generation().verdict(), no_quorum);
    assert!(survey.generation().late());
    // The late claim of more is not counted and not lost.
    assert_eq!(survey.generation().claims().len(), 1);
    // Only the answers that were counted give a time.
    assert_eq!(survey.stamps().len(), 2);
    // Answers came, but late: the next generation is given longer.
    pace.after(false, survey.generation().late());
    assert_eq!(pace.within(), Duration::from_secs(90));
}

#[test]
fn a_source_with_another_time() {
    // Four servers write this computer's time, one is ten minutes ahead.
    let ahead = ours(TIP);
    let odd = Then::Tip {
        height: ahead.height,
        mark: ahead.hash[0],
        work: ahead.total_difficulty,
        ahead: 600,
    };
    let servers = [our(TIP), our(TIP), our(TIP), our(TIP), odd].map(|then| serve("localhost", then));
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let generation = Generation::open(1, ours(TIP), sources(&ports), Instant::now(), WITHIN, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), GRACE);
    run(&mut survey);
    // The tip is confirmed by the count; the time is not.
    assert_eq!(survey.generation().verdict(), Verdict::Confirmed { by: (0, 1) });
    let at = Instant::now();
    assert_eq!(
        confirm(survey.stamps(), survey.generation().sources(), at, clock(), 0).err(),
        Some(Unconfirmed::Disagree)
    );
    // Without that one the rest agree - and say this computer's clock
    // is right; with a clock an hour off they still agree, and say so.
    let rest: Vec<_> = survey.stamps().iter().filter(|stamp| stamp.source != 4).copied().collect();
    assert!(confirm(&rest, survey.generation().sources(), at, clock(), 0).is_ok());
    assert_eq!(
        confirm(&rest, survey.generation().sources(), at, clock() + 3_600_000, 0).err(),
        Some(Unconfirmed::Clock)
    );
}

#[test]
fn a_survey_ends_whoever_is_silent() {
    // One source answers; four take the question and never say a word.
    let silent = || serve("localhost", Then::Silence(Duration::from_secs(30)));
    let servers = [serve("localhost", our(TIP)), silent(), silent(), silent(), silent()];
    let ports: Vec<u16> = servers.iter().map(|s| s.at.port()).collect();
    let started = Instant::now();
    let within = Duration::from_millis(600);
    let grace = Duration::from_millis(600);
    let generation = Generation::open(1, ours(TIP), sources(&ports), started, within, 3);
    let mut survey = Survey::start(&asker(), generation, recent(), grace);
    run(&mut survey);
    assert!(started.elapsed() >= within + grace);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!survey.step(Duration::from_secs(1)));
    assert_eq!(
        survey.generation().verdict(),
        Verdict::NoQuorum {
            answered: 1,
            needed: 3,
            confirming: 1
        }
    );
    // Silence is not a late answer: the next deadline stays as it was.
    assert!(!survey.generation().late());
}
