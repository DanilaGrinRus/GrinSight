//! `fly-chain` - the chain process.
//!
//! Without arguments it is started by the wallet process and speaks the
//! chain pipe on standard input and output. With `headers ...` it follows
//! the header chain by itself and reports on standard output, and with
//! `state ...` it goes on to collect the state at the nodes' archive
//! header, with `blocks ...` to apply the blocks to the tip, and with
//! `old ...` to read, as a wallet would, the outputs older than the blocks
//! - for trying the program against the network:
//!
//! ```text
//! fly-chain headers --network main|test --data <directory> [--peer host:port]... [--seconds N]
//! fly-chain state   --network main|test --data <directory> [--peer host:port]... [--seconds N]
//! fly-chain blocks  --network main|test --data <directory> [--peer host:port]... [--seconds N]
//! fly-chain select  --network main|test --data <directory> [--peer host:port]... [--seconds N]
//! fly-chain old     --network main|test --data <directory> [--peer host:port]... [--seconds N]
//! fly-chain proofs  --network main|test --data <directory> --peer host:port... [--rounds N] [--sample N]
//! fly-chain segments --network main|test --data <directory> [--peer host:port]... [--nodes N]
//! fly-chain point   --network main|test --data <directory> [--peer host:port]... --kind release|own --out <directory> [--height N]
//! fly-chain tor     --network main|test --data <directory>
//! ```
//!
//! `tor` brings Tor up the way the program does before it sends a
//! transaction, asks every public node of the list what its tip is through
//! Tor, and shakes hands through Tor with up to two of eight nodes of the
//! network found by the seed names - everything a transaction would need,
//! without one. For a node not reached through Tor it says whether the
//! node takes a connection directly: the node, or the way through Tor.
//!
//! `point` follows the headers, makes the record of a starting point at the
//! header nodes now give their state out at (or at `--height`, no higher),
//! and asks the public nodes of the list for the header at that height. A
//! release point needs two operators on different networks to name it and
//! nobody to name another; its record and its origin are written to
//! `<network>.json` and `<network>.origin.json`, to be compiled in. An own
//! point only needs nobody to name another; its record is written to
//! `own-point.json`, for the data directory of a wallet.
//!
//! `proofs` follows the headers and then asks each named node for header
//! proofs (the HEADER_PROOF_HIST extension), checks them and says how long
//! the answers took.
#![forbid(unsafe_code)]
use fly_chain::feed::{describe, Feed};
use fly_chain::node::View;
use fly_chain_headers::Net;
use fly_paycore_chain_pipe::{serve, Config};
use fly_paycore_chain_port::ChainFeed;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Started by the wallet process.
fn pipe() -> ExitCode {
    let stop = Arc::new(AtomicBool::new(false));
    let mut worker = None;
    let served = serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock(), |config: Config| {
        let net = Net::from_tag(config.network).ok_or("a network this program does not know")?;
        let (view, events, handle) = fly_chain::start(net, config.genesis, PathBuf::from(config.data_dir), config.peers, fly_chain::Sending { direct_post: config.direct_post, tor_off: config.tor_off, tor_bridges: config.tor_bridges }, stop.clone())?;
        worker = Some(handle);
        Ok(Feed::new(view, events))
    });
    stop.store(true, Ordering::Relaxed);
    if let Some(handle) = worker {
        let _ = handle.join();
    }
    if served.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

struct Trial {
    net: Net,
    data: PathBuf,
    peers: Vec<String>,
    seconds: u64,
    /// Quarter seconds for which "caught up" must hold before it is believed.
    steady: u32,
    /// How many times each request for header proofs is made.
    rounds: u32,
    /// How many heights to draw over the whole history instead; 0: none.
    sample: usize,
    /// How many nodes to try segments of other heights on.
    nodes: usize,
}

fn trial_args(args: &[String]) -> Result<Trial, String> {
    let (mut net, mut data, mut peers, mut seconds, mut steady, mut rounds, mut sample, mut nodes) = (None, None, Vec::new(), 600u64, 20u32, 5u32, 0usize, 2usize);
    let mut it = args.iter();
    while let Some(name) = it.next() {
        let value = it.next().ok_or_else(|| format!("{name} needs a value"))?;
        match name.as_str() {
            "--network" => {
                net = Some(match value.as_str() {
                    "main" => Net::Main,
                    "test" => Net::Test,
                    "automated" => Net::Automated,
                    _ => return Err("--network is main or test".to_string()),
                })
            }
            "--data" => data = Some(PathBuf::from(value)),
            "--peer" if peers.len() < 32 => peers.push(value.clone()),
            "--seconds" => seconds = value.parse().map_err(|_| "--seconds is a number".to_string())?,
            "--steady" => steady = value.parse().map_err(|_| "--steady is a number".to_string())?,
            "--rounds" => rounds = value.parse().ok().filter(|n| (1..=100).contains(n)).ok_or("--rounds is a number from 1 to 100")?,
            "--nodes" => nodes = value.parse().ok().filter(|n| (1..=8).contains(n)).ok_or("--nodes is a number from 1 to 8")?,
            "--sample" => sample = value.parse().ok().filter(|n| (1..=20_000).contains(n)).ok_or("--sample is a number from 1 to 20000")?,
            _ => return Err(format!("unknown argument {name}")),
        }
    }
    Ok(Trial {
        net: net.ok_or("--network is missing")?,
        data: data.ok_or("--data is missing")?,
        peers,
        seconds,
        steady,
        rounds,
        sample,
        nodes,
    })
}

/// How far a trial run goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Goal {
    /// The headers have caught up with the nodes.
    Headers,
    /// The state at the archive header is collected.
    State,
    /// The blocks are applied to the tip.
    Blocks,
    /// And the outputs older than the blocks have been read.
    Old,
    /// The blocks are applied to the tip and the tip is selected: public
    /// nodes named it and the time is confirmed.
    Select,
}

/// What reading the old outputs has come to.
#[derive(Default)]
struct OldRead {
    next: u64,
    pieces: u64,
    outputs: u64,
    proof_bytes: u64,
    since: Option<Instant>,
    shown: Option<Instant>,
}

/// Follow the headers and say how it goes; go on to the state and to the
/// blocks if that is the goal.
fn run_trial(args: &[String], goal: Goal) -> ExitCode {
    let state = goal != Goal::Headers;
    let trial = match trial_args(args) {
        Ok(trial) => trial,
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let genesis = trial.net.genesis_hash();
    let (view, events, handle) = match fly_chain::start(trial.net, genesis, trial.data.clone(), trial.peers.clone(), fly_chain::Sending::default(), stop.clone()) {
        Ok(started) => started,
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    let read = || -> View {
        match view.lock() {
            Ok(view) => view.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    };
    let began = Instant::now();
    let limit = Duration::from_secs(trial.seconds);
    let (mut opened, mut last, mut steady) = (false, String::new(), 0u32);
    let (mut state_at, mut synced_at, mut last_shown) = (None, None, Instant::now());
    let (mut blocks_shown, mut at_tip_for) = (false, 0u32);
    let mut feed = Feed::new(view.clone(), events);
    let mut old = OldRead::default();
    let code = loop {
        std::thread::sleep(Duration::from_millis(250));
        let now = read();
        if let Some(failed) = &now.failed {
            println!("failed: {failed}");
            break 3;
        }
        if now.ready && !opened {
            opened = true;
            println!("start: height={} ({})", now.start, now.point.note());
            if let Some(earlier) = now.replaced {
                println!("replaced: the header file of the starting point at {earlier} gave way to this one");
            }
            println!("opened: kept={} cut_bytes={}", now.kept, now.cut_bytes);
        }
        if !now.ready {
            let line = describe(&now);
            if began.elapsed() >= limit {
                println!("timeout: height={} hash={} ({line})", now.height, hex(&now.hash));
                break 1;
            }
            if line != last && (last.is_empty() || last_shown.elapsed() >= Duration::from_secs(2)) {
                println!("{:7.1}s {line}", began.elapsed().as_secs_f32());
                last = line;
                last_shown = Instant::now();
            }
            continue;
        }
        if let Some(found) = now.state.as_ref().filter(|found| state && state_at != Some(found.height)) {
            if let Some(from) = found.again_from {
                println!("state: the network moved on from height {from}; begun again");
            }
            state_at = Some(found.height);
            println!(
                "state: height={} hash={} segments={} kept={} cut_bytes={}",
                found.height,
                hex(&found.hash),
                found.segments,
                found.kept,
                found.cut_bytes
            );
        }
        let mut pieces = now.state.as_ref().filter(|_| state).map(|s| format!(" state={}/{}", s.done, s.segments)).unwrap_or_default();
        if let Some(blocks) = now.blocks.as_ref().filter(|_| goal == Goal::Blocks || goal == Goal::Old || goal == Goal::Select) {
            if !blocks_shown {
                blocks_shown = true;
                println!("blocks: base={} kept={} cut_bytes={}", blocks.base, blocks.kept, blocks.cut_bytes);
            }
            pieces = format!(" blocks={}/{}", blocks.height, now.height);
        }
        let line = format!(
            "height={} nodes_at={} peers={}{}",
            now.height,
            now.best_seen,
            now.peers,
            now.problem.as_ref().map(|p| format!(" problem=\"{p}\"")).unwrap_or_default()
        );
        // the count of pieces moves all the time: shown once a second
        let due = !pieces.is_empty() && last_shown.elapsed() >= Duration::from_secs(1);
        if line != last || due {
            println!("{:7.1}s {line}{pieces}", began.elapsed().as_secs_f32());
            last = line;
            last_shown = Instant::now();
        }
        // "caught up" must hold for a while: the first node to connect may be behind
        steady = if now.caught_up { steady.saturating_add(1) } else { 0 };
        if steady >= trial.steady.max(1) && synced_at.is_none() {
            synced_at = Some(began.elapsed());
            println!(
                "synced: height={} hash={} work={} headers={} seconds={:.1}",
                now.height,
                hex(&now.hash),
                now.work,
                now.height.saturating_sub(now.start),
                began.elapsed().as_secs_f32()
            );
            if !state {
                break 0;
            }
        }
        if let Some(done) = now.state.as_ref().filter(|found| goal == Goal::State && found.complete) {
            println!(
                "collected: height={} hash={} unspent={} segments={} file_bytes={} seconds={:.1} check_ms={} take_ms={}",
                done.height,
                hex(&done.hash),
                done.unspent,
                done.segments,
                done.file_bytes,
                began.elapsed().as_secs_f32(),
                done.work_ms.0,
                done.work_ms.1
            );
            break 0;
        }
        // "at the tip" must hold for a while, as "caught up" must
        at_tip_for = if now.blocks.as_ref().is_some_and(|blocks| blocks.at_tip) { at_tip_for.saturating_add(1) } else { 0 };
        if old.since.is_some() || (goal == Goal::Old && at_tip_for >= trial.steady.max(1)) {
            // as a wallet reads: piece after piece, the same one again
            // until it is given
            let since = *old.since.get_or_insert_with(Instant::now);
            let mut finished = None;
            let round = Instant::now();
            while round.elapsed() < Duration::from_millis(200) {
                let Ok(piece) = feed.old_outputs(old.next) else {
                    break;
                };
                old.pieces = piece.pieces;
                old.outputs = old.outputs.saturating_add(u64::try_from(piece.outputs.len()).unwrap_or(u64::MAX));
                let bytes: usize = piece.outputs.iter().map(|o| o.proof.len()).sum();
                old.proof_bytes = old.proof_bytes.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
                match piece.next {
                    Some(next) => old.next = next,
                    None => {
                        finished = Some(piece);
                        break;
                    }
                }
            }
            if let Some(last) = finished {
                println!(
                    "old: pieces={} outputs={} proof_bytes={} at={} before={} seconds={:.1}",
                    old.pieces,
                    old.outputs,
                    old.proof_bytes,
                    last.at.height,
                    last.before,
                    since.elapsed().as_secs_f32()
                );
                break 0;
            }
            if old.shown.is_none_or(|shown| shown.elapsed() >= Duration::from_secs(5)) {
                old.shown = Some(Instant::now());
                println!("{:7.1}s old: piece={}/{} outputs={} proof_bytes={}", began.elapsed().as_secs_f32(), old.next, old.pieces, old.outputs, old.proof_bytes);
            }
        }
        if let Some(done) = now.blocks.as_ref().filter(|_| goal == Goal::Blocks && at_tip_for >= trial.steady.max(1)) {
            println!(
                "applied: height={} hash={} base={} blocks={} unspent={} file_bytes={} seconds={:.1}",
                done.height,
                hex(&done.hash),
                done.base,
                done.height.saturating_sub(done.base),
                done.unspent,
                done.file_bytes,
                began.elapsed().as_secs_f32()
            );
            break 0;
        }
        let (selected, confirmed_time) = now.selection();
        if goal == Goal::Select && selected && now.blocks.as_ref().is_some_and(|blocks| blocks.at_tip) {
            println!(
                "selected: height={} hash={} confirmed_time={} seconds={:.1}",
                now.height,
                hex(&now.hash),
                confirmed_time.map_or("none".to_string(), |time| time.to_string()),
                began.elapsed().as_secs_f32()
            );
            println!("said: {}", describe(&now));
            break 0;
        }
        if began.elapsed() > limit {
            println!("timeout: height={} hash={} ({})", now.height, hex(&now.hash), describe(&now));
            break 1;
        }
    };
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    ExitCode::from(code)
}

/// One kind of request for header proofs: what it is called and the
/// heights it asks for.
struct Kind {
    name: &'static str,
    heights: Vec<u64>,
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Follow the headers, then ask each named node for header proofs.
fn run_proofs(args: &[String]) -> ExitCode {
    use fly_chain::probe::{check, helper_on_whole, sample, spread, with_predecessors, Checked, Session};
    use fly_chain_headers::chain::HeaderChain;
    use grin_core::core::hash::{Hash, Hashed};
    use std::net::ToSocketAddrs;
    let trial = match trial_args(args) {
        Ok(trial) if !trial.peers.is_empty() => trial,
        Ok(_) => {
            eprintln!("fly-chain: proofs needs --peer: the nodes to ask");
            return ExitCode::from(2);
        }
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    // the headers first: the anchor is a header this program has verified
    let synced = run_trial(args, Goal::Headers);
    if synced != ExitCode::SUCCESS {
        return synced;
    }
    let chain = fly_chain::starting_point(trial.net, &trial.data)
        .and_then(|point| HeaderChain::open(&trial.data, trial.net, &point.record).map_err(|_| "the header file cannot be opened".to_string()));
    let chain = match chain {
        Ok((chain, _)) => chain,
        Err(why) => {
            println!("failed: {why}");
            return ExitCode::from(3);
        }
    };
    let (start, tip) = (chain.start().height(), chain.tip());
    let known = |height: u64| chain.header_at(height).ok().flatten();
    // a little below the tip, so that a node a few blocks behind has it
    let Some(anchor) = known(tip.height.saturating_sub(20).max(start)) else {
        println!("failed: no anchor");
        return ExitCode::from(3);
    };
    // where headers of the fifth version begin: the full check is for those
    let (mut low, mut high) = (0u64, start);
    while low < high {
        let mid = low.saturating_add(high.saturating_sub(low) / 2);
        if grin_core::consensus::header_version(mid) >= grin_core::core::HeaderVersion(5) {
            high = mid;
        } else {
            low = mid.saturating_add(1);
        }
    }
    let hf4 = low;
    println!("anchor: height={} hash={}; this program has verified {}..={}; headers of version 5 from {hf4}", anchor.height, hex(anchor.hash().as_bytes()), start, tip.height);
    let mut kinds: Vec<Kind> = Vec::new();
    let mut add = |name: &'static str, tops: Vec<u64>| {
        if let Some(heights) = with_predecessors(&tops) {
            kinds.push(Kind { name, heights });
        }
    };
    add("one-old", spread(hf4, start, 1));
    add("many-old", spread(hf4, start, 21));
    add("one-verified", spread(start, anchor.height, 1));
    add("many-verified", spread(start, anchor.height, 21));
    add("before-hf4", spread(hf4 / 2, hf4, 1).into_iter().take(1).collect());
    let wait = Duration::from_secs(20);
    let mut failed = false;
    // The sample: heights over the whole history below the anchor, the
    // same ones for every node. Drawn evenly; this measures what proofs
    // for so many headers cost, and is not a rule for what to ask.
    let tops = if trial.sample > 0 {
        // good enough for a measurement, and no new dependency: the keys of
        // a hasher the standard library seeds from the system
        let seeded = std::collections::hash_map::RandomState::new();
        let mut draws = 0u64;
        let tops = sample(1, anchor.height, trial.sample, || {
            use std::hash::BuildHasher;
            draws = draws.wrapping_add(1);
            seeded.hash_one(draws)
        });
        println!(
            "sample: drawn={} from 1..{}, each with its two predecessors; below version 5: {}; requests of up to 21 of them",
            tops.len(),
            anchor.height,
            tops.iter().filter(|top| **top < hf4).count()
        );
        tops
    } else {
        Vec::new()
    };
    for peer in &trial.peers {
        let Some(addr) = peer.to_socket_addrs().ok().and_then(|mut found| found.next()) else {
            println!("node: {peer} - the address does not resolve");
            failed = true;
            continue;
        };
        // A node takes one connection from an address, and it lets go of
        // a closed one only when it next tidies its list of peers. The
        // connection this program followed the headers on has just been
        // closed: tried again for a minute and a half.
        let mut tried = Session::connect(addr, trial.net.genesis_hash(), tip.total_work, tip.height);
        let mut waited = 0u32;
        while tried.is_err() && waited < 18 {
            if waited == 0 {
                println!("node: {peer} - not let in yet (a node keeps the connection just closed for a while); trying for 90 s");
            }
            waited = waited.saturating_add(1);
            std::thread::sleep(Duration::from_secs(5));
            tried = Session::connect(addr, trial.net.genesis_hash(), tip.total_work, tip.height);
        }
        let mut session = match tried {
            Ok(session) => session,
            Err(why) => {
                println!("node: {peer} - {why}");
                failed = true;
                continue;
            }
        };
        println!(
            "node: {peer} agent=\"{}\" header_proofs={} connected_ms={:.0}",
            session.user_agent,
            if session.serves_proofs() { "yes" } else { "no" },
            millis(session.connected_in)
        );
        if !session.serves_proofs() {
            // an older node ignores the request: nothing to measure
            continue;
        }
        if trial.sample > 0 {
            let began = Instant::now();
            let (mut took, mut bytes, mut asked, mut answered, mut heights, mut check_ms) = (Vec::new(), 0u64, 0u32, 0u32, 0usize, 0.0f64);
            let (mut sum, mut trouble) = (Checked::default(), String::new());
            for request in tops.chunks(21) {
                let Some(with) = with_predecessors(request) else {
                    continue;
                };
                asked = asked.saturating_add(1);
                heights = heights.saturating_add(with.len());
                match session.ask(anchor.hash(), &with, wait) {
                    Ok(Some(answer)) => {
                        answered = answered.saturating_add(1);
                        bytes = bytes.saturating_add(answer.bytes);
                        took.push(millis(answer.took));
                        let checking = Instant::now();
                        match check(&anchor, &answer.proofs, &with, known) {
                            Ok(c) => {
                                sum.members = sum.members.saturating_add(c.members);
                                sum.pow = sum.pow.saturating_add(c.pow);
                                sum.full = sum.full.saturating_add(c.full);
                                sum.before_hf4 = sum.before_hf4.saturating_add(c.before_hf4);
                                sum.same = sum.same.saturating_add(c.same);
                            }
                            Err(why) => {
                                failed = true;
                                trouble = format!(" REFUSED: {why}");
                            }
                        }
                        check_ms += millis(checking.elapsed());
                    }
                    Ok(None) => {
                        failed = true;
                        trouble = " a request was not answered".to_string();
                    }
                    Err(why) => {
                        failed = true;
                        trouble = format!(" the session ended: {why}");
                        break;
                    }
                }
            }
            took.sort_by(f64::total_cmp);
            let at = |i: usize| took.get(i).copied().unwrap_or(0.0);
            println!(
                "sample: node={peer} sampled={} heights={heights} requests={asked} answered={answered}/{asked} bytes={bytes} seconds={:.1} answer_ms_median={:.1} answer_ms_max={:.1} check_ms_total={check_ms:.1} members={} pow={} full={} before_hf4={} same_as_verified={}{trouble}",
                tops.len(),
                began.elapsed().as_secs_f64(),
                at(took.len() / 2),
                at(took.len().saturating_sub(1)),
                sum.members,
                sum.pow,
                sum.full,
                sum.before_hf4,
                sum.same,
            );
            continue;
        }
        for kind in &kinds {
            let (mut took, mut verify, mut bytes, mut answered) = (Vec::new(), Vec::new(), 0u64, 0u32);
            let (mut verdict, mut whole) = (String::new(), String::new());
            for _ in 0..trial.rounds {
                match session.ask(anchor.hash(), &kind.heights, wait) {
                    Ok(Some(answer)) => {
                        answered = answered.saturating_add(1);
                        bytes = answer.bytes;
                        took.push(millis(answer.took));
                        let began = Instant::now();
                        verdict = match check(&anchor, &answer.proofs, &kind.heights, known) {
                            Ok(c) => format!("members={} pow={} full={} before_hf4={} same_as_verified={}", c.members, c.pow, c.full, c.before_hf4, c.same),
                            Err(why) => {
                                failed = true;
                                format!("REFUSED: {why}")
                            }
                        };
                        verify.push(millis(began.elapsed()));
                        whole = match helper_on_whole(&anchor, &answer.proofs) {
                            Ok(()) => "ok".to_string(),
                            Err(why) => why,
                        };
                    }
                    Ok(None) => {}
                    Err(why) => {
                        verdict = format!("the session ended: {why}");
                        failed = true;
                        break;
                    }
                }
            }
            took.sort_by(f64::total_cmp);
            verify.sort_by(f64::total_cmp);
            let at = |v: &Vec<f64>, i: usize| v.get(i).copied().unwrap_or(0.0);
            println!(
                "proofs: node={peer} kind={} heights={} answered={answered}/{} bytes={bytes} ms_min={:.1} ms_median={:.1} ms_max={:.1} check_ms={:.1} {verdict}",
                kind.name,
                kind.heights.len(),
                trial.rounds,
                at(&took, 0),
                at(&took, took.len() / 2),
                at(&took, took.len().saturating_sub(1)),
                at(&verify, verify.len() / 2),
            );
            if !whole.is_empty() {
                println!("proofs: node={peer} kind={} the node's own helper on the whole answer, nothing trusted beforehand: {whole}", kind.name);
            }
        }
        // a request the node cannot answer is ignored, and the next one is served all the same
        let nowhere = Hash::from_vec(&[0x5a; 32]);
        let ignored = match kinds.first() {
            Some(kind) => session.ask(nowhere, &kind.heights, Duration::from_secs(3)),
            None => Ok(None),
        };
        let after = match (&ignored, kinds.first()) {
            (Ok(None), Some(kind)) => match session.ask(anchor.hash(), &kind.heights, wait) {
                Ok(Some(_)) => "served",
                Ok(None) => "not answered",
                Err(_) => "the session ended",
            },
            _ => "not tried",
        };
        println!(
            "proofs: node={peer} kind=unknown-anchor {}; the request after it: {after}",
            match ignored {
                Ok(None) => "ignored (no answer in 3 s)".to_string(),
                Ok(Some(_)) => "ANSWERED".to_string(),
                Err(why) => format!("the session ended: {why}"),
            }
        );
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Collect the state as usual, then ask nodes for segments of the output
/// and rangeproof MMRs of larger heights than this program asks for, and
/// check every answer the way the usual ones are checked: against the
/// roots in the verified header, with the verified bitmap. A measurement
/// of what nodes give; nothing here is used by the wallet.
fn run_segments(args: &[String]) -> ExitCode {
    use fly_chain::probe::Session;
    use fly_chain::state::Fetch;
    use fly_chain_headers::chain::HeaderChain;
    use fly_chain_state::advance::Live;
    use fly_chain_state::archive::{output_segment_holds, rangeproof_segment_holds, segments_of_height};
    use fly_chain_state::store::Store;
    use grin_core::core::hash::Hashed;
    use grin_core::core::SegmentIdentifier;
    let trial = match trial_args(args) {
        Ok(trial) => trial,
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    // the state first: an answer is checked against its bitmap
    let collected = run_trial(args, Goal::State);
    if collected != ExitCode::SUCCESS {
        return collected;
    }
    let opened = fly_chain::starting_point(trial.net, &trial.data)
        .and_then(|point| HeaderChain::open(&trial.data, trial.net, &point.record).map_err(|_| "the header file cannot be opened".to_string()))
        .and_then(|(chain, _)| {
            let (height, _) = Store::peek(&trial.data).ok().flatten().ok_or("no state was collected")?;
            let header = chain.header_at(height).ok().flatten().ok_or("the state is at a header this program does not have")?;
            let state = Fetch::open(&trial.data, header.clone(), false).ok().and_then(|mut fetch| fetch.take_state());
            let live = state.and_then(Live::new).ok_or("the collected state cannot be opened")?;
            Ok((chain.tip(), header, live))
        });
    let (tip, header, live) = match opened {
        Ok(opened) => opened,
        Err(why) => {
            println!("failed: {why}");
            return ExitCode::from(3);
        }
    };
    let (block, bitmap, size) = (header.hash(), live.bitmap(), header.output_mmr_size);
    println!("segments: state at height={} output_mmr_size={size} unspent={}", header.height, bitmap.cardinality());
    let heights = 11u8..=16;
    let needed: Vec<String> = heights.clone().map(|height| format!("{height}:{}", segments_of_height(size, height))).collect();
    println!("segments: how many of each height the whole tree takes (height:segments) {}", needed.join(" "));

    // A node takes one connection from an address and lets go of a closed
    // one only after a while; the nodes the state was just collected from
    // refuse at first. Every address in turn, again after a pause.
    let addrs = fly_chain::node::addresses(trial.net, &trial.peers);
    let (began, mut done, mut probed, mut failed) = (Instant::now(), Vec::new(), 0usize, false);
    for round in 0..4u64 {
        if probed >= trial.nodes || addrs.iter().all(|addr| done.contains(addr)) {
            break;
        }
        if round > 0 {
            println!("segments: nodes tried so far did not let in or do not give state; again in a while ({probed} of {} done)", trial.nodes);
            std::thread::sleep(Duration::from_secs(30u64.saturating_mul(round)).saturating_sub(began.elapsed()));
        }
        for addr in &addrs {
            if probed >= trial.nodes || done.contains(addr) {
                continue;
            }
            let Ok(mut session) = Session::connect(*addr, trial.net.genesis_hash(), tip.total_work, tip.height) else {
                continue;
            };
            done.push(*addr);
            if !session.serves_state() {
                println!("node: {addr} agent=\"{}\" does not say it gives its state out", session.user_agent);
                continue;
            }
            probed = probed.saturating_add(1);
            println!("node: {addr} agent=\"{}\" connected_ms={:.0}", session.user_agent, millis(session.connected_in));
            // the first request makes a node build its state at this header
            let mut wait = Duration::from_secs(45);
            let mut gone = false;
            for kind in ["rangeproofs", "outputs"] {
                let (mut silent, mut good) = (0u32, Vec::new());
                for height in heights.clone() {
                    if gone || silent >= 2 {
                        break;
                    }
                    let count = segments_of_height(size, height);
                    let mut idxs = vec![0, count / 2, count.saturating_sub(1)];
                    idxs.dedup();
                    let (mut asked, mut answered, mut valid, mut leaves, mut bytes, mut most, mut took) = (0u32, 0u32, 0u32, 0usize, 0u64, 0u64, Vec::new());
                    let mut note = String::new();
                    for idx in idxs {
                        let id = SegmentIdentifier { height, idx };
                        asked = asked.saturating_add(1);
                        // (does it hold, how many leaves, bytes, time)
                        let got = if kind == "rangeproofs" {
                            session.ask_rangeproofs(block, id, wait).map(|piece| {
                                piece.map(|piece| {
                                    let holds = piece.block == block && piece.segment.id() == id && rangeproof_segment_holds(&piece.segment, &header, bitmap);
                                    (holds, piece.segment.parts().3.len(), piece.bytes, piece.took)
                                })
                            })
                        } else {
                            session.ask_outputs(block, id, wait).map(|piece| {
                                piece.map(|piece| {
                                    let holds = piece.block == block
                                        && piece.segment.id() == id
                                        && piece.bitmap_root.is_some_and(|root| output_segment_holds(&piece.segment, &header, bitmap, root));
                                    (holds, piece.segment.parts().3.len(), piece.bytes, piece.took)
                                })
                            })
                        };
                        match got {
                            Ok(Some((holds, count, size, time))) => {
                                answered = answered.saturating_add(1);
                                valid = valid.saturating_add(u32::from(holds));
                                leaves = leaves.saturating_add(count);
                                bytes = bytes.saturating_add(size);
                                most = most.max(size);
                                took.push(millis(time));
                                wait = Duration::from_secs(20);
                            }
                            Ok(None) => {
                                note = " (no answer; the rest of this height was not asked)".to_string();
                                break;
                            }
                            Err(why) => {
                                note = format!(" (the session ended: {why})");
                                gone = true;
                                break;
                            }
                        }
                    }
                    took.sort_by(f64::total_cmp);
                    println!(
                        "segments: node={addr} kind={kind} height={height} whole_tree={count} asked={asked} answered={answered} valid={valid} leaves={leaves} bytes={bytes} largest={most} ms_median={:.0} ms_max={:.0}{note}",
                        took.get(took.len() / 2).copied().unwrap_or(0.0),
                        took.last().copied().unwrap_or(0.0),
                    );
                    if answered > valid {
                        failed = true;
                    }
                    if answered == 0 {
                        silent = silent.saturating_add(1);
                    } else {
                        silent = 0;
                        if answered == valid {
                            good.push(height.to_string());
                        }
                    }
                }
                println!("segments: node={addr} kind={kind} given and valid at heights: {}", if good.is_empty() { "none".to_string() } else { good.join(",") });
            }
        }
    }
    if probed == 0 {
        println!("failed: no node that gives its state out let this program in");
        return ExitCode::from(1);
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// What `point` writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PointGoal {
    Release,
    Own,
}

/// Make the record of a starting point from the verified headers.
fn run_point(args: &[String]) -> ExitCode {
    use fly_chain_headers::chain::HeaderChain;
    use fly_chain_headers::origin::{Confirmed, Kind, Origin};
    use fly_chain_tips::point::{ask_all, judge, Asked, Verdict, Voice};
    let (mut goal, mut out, mut height, mut rest) = (None, None, None, Vec::new());
    let mut it = args.iter();
    while let Some(name) = it.next() {
        let value = it.next();
        match (name.as_str(), value) {
            ("--kind", Some(v)) if v == "release" => goal = Some(PointGoal::Release),
            ("--kind", Some(v)) if v == "own" => goal = Some(PointGoal::Own),
            ("--kind", _) => {
                eprintln!("fly-chain: --kind is release or own");
                return ExitCode::from(2);
            }
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            ("--height", Some(v)) => match v.parse::<u64>() {
                Ok(h) => height = Some(h),
                Err(_) => {
                    eprintln!("fly-chain: --height is a number");
                    return ExitCode::from(2);
                }
            },
            (_, Some(v)) => {
                rest.push(name.clone());
                rest.push(v.clone());
            }
            (_, None) => {
                eprintln!("fly-chain: {name} needs a value");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(goal), Some(out)) = (goal, out) else {
        eprintln!("fly-chain: point needs --kind release|own and --out <directory>");
        return ExitCode::from(2);
    };
    let trial = match trial_args(&rest) {
        Ok(trial) => trial,
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    // the headers first: the point is a header this program has verified
    let synced = run_trial(&rest, Goal::Headers);
    if synced != ExitCode::SUCCESS {
        return synced;
    }
    let chain = fly_chain::starting_point(trial.net, &trial.data)
        .and_then(|point| HeaderChain::open(&trial.data, trial.net, &point.record).map_err(|_| "the header file cannot be opened".to_string()));
    let chain = match chain {
        Ok((chain, _)) => chain,
        Err(why) => {
            println!("failed: {why}");
            return ExitCode::from(3);
        }
    };
    let tip = chain.tip();
    // no higher than where nodes give their state out now: a wallet that
    // starts from the point can collect the state at once, and the header
    // is too deep to be taken back
    let highest = fly_chain::node::archive_height(tip.height);
    let at = height.unwrap_or(highest);
    if at > highest {
        println!("failed: height {at} is above {highest}, where nodes give their state out now (the tip is {})", tip.height);
        return ExitCode::from(1);
    }
    let made = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (record, header) = match (chain.record_at(at, made), chain.header_at(at)) {
        (Ok(Some(record)), Ok(Some(header))) => (record, header),
        _ => {
            println!(
                "failed: no point can be made at height {at}: it has to be at least three above this program's starting point ({})",
                chain.start().height()
            );
            return ExitCode::from(1);
        }
    };
    let asked = Asked {
        height: at,
        hash: fly_chain_headers::hash_bytes(&header),
        work: header.total_difficulty().to_num(),
    };
    println!("point: height={at} hash={} work={} tip={}", hex(&asked.hash), asked.work, tip.height);
    let setup = fly_chain::accept::Setup::of(trial.net, &trial.data);
    let Some(asker) = setup.asker else {
        println!("failed: the secure channel to public nodes cannot be set up");
        return ExitCode::from(3);
    };
    let voices = ask_all(&asker, &setup.sources, asked, Duration::from_secs(20));
    for (source, voice) in setup.sources.iter().zip(&voices) {
        let said = match voice {
            Voice::Same => "the same header".to_string(),
            Voice::Other(other) => format!("ANOTHER header: hash={} work={}", hex(&other.hash), other.total_difficulty),
            Voice::Silent(why) => format!("no answer: {why}"),
        };
        println!("said: {} ({}): {said}", source.host, source.group);
    }
    let by = match judge(&setup.sources, &voices) {
        Verdict::Differs { who } => {
            let names: Vec<&str> = who.iter().filter_map(|i| setup.sources.get(*i)).map(|s| s.host.as_str()).collect();
            println!("failed: public nodes name another header at height {at}: {}; no point is written", names.join(", "));
            return ExitCode::from(1);
        }
        Verdict::TooFew { same } if goal == PointGoal::Release => {
            println!("failed: a release point needs public nodes of two operators on different networks to name it; {same} named it");
            return ExitCode::from(1);
        }
        Verdict::TooFew { .. } => Vec::new(),
        Verdict::Confirmed { by } => by,
    };
    let confirmed: Vec<Confirmed> = by
        .iter()
        .filter_map(|i| setup.sources.get(*i))
        .filter_map(|source| {
            Some(Confirmed {
                group: source.group.clone(),
                host: source.host.clone(),
                asn: source.asn?,
            })
        })
        .collect();
    if std::fs::create_dir_all(&out).is_err() {
        println!("failed: the directory {} cannot be made", out.display());
        return ExitCode::from(3);
    }
    let name = match trial.net {
        Net::Main => "main",
        Net::Test => "test",
        Net::Automated => "automated",
    };
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    match goal {
        PointGoal::Own => files.push((out.join(fly_chain::OWN_POINT_FILE), record)),
        PointGoal::Release => {
            let start = match fly_chain_headers::checkpoint::check(&record, trial.net) {
                Ok(start) => start,
                Err(_) => {
                    println!("failed: the record made does not pass its own check");
                    return ExitCode::from(3);
                }
            };
            let from = if trial.peers.is_empty() {
                "headers from nodes found through the network's seed names".to_string()
            } else {
                let named: String = trial.peers.join(", ").chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(200).collect();
                format!("headers from the nodes named: {named}")
            };
            let origin = Origin::of(Kind::Release, &start, made, &from, confirmed.clone());
            let Some(origin_bytes) = origin.write().filter(|_| origin.vouches_for(&start)) else {
                println!("failed: the origin made does not vouch for the point");
                return ExitCode::from(3);
            };
            files.push((out.join(format!("{name}.json")), record));
            files.push((out.join(format!("{name}.origin.json")), origin_bytes));
        }
    }
    for (path, bytes) in &files {
        if std::fs::write(path, bytes).is_err() {
            println!("failed: {} cannot be written", path.display());
            return ExitCode::from(3);
        }
        println!("written: {}", path.display());
    }
    let operators: Vec<&str> = confirmed.iter().map(|c| c.group.as_str()).collect();
    println!(
        "made: height={at} hash={} kind={} confirmed_by={}",
        hex(&asked.hash),
        if goal == PointGoal::Release { "release" } else { "own" },
        if operators.is_empty() { "nobody".to_string() } else { operators.join(",") }
    );
    ExitCode::SUCCESS
}

fn tor_peer_line(to: &std::net::SocketAddr, height: u64, agent: &str, elapsed: Duration) -> String {
    let agent = fly_chain::probe::display_agent(agent);
    format!("network: {to} height={height} agent={agent} seconds={:.1}", elapsed.as_secs_f32())
}

/// Bring Tor up and reach through it every way a transaction would go.
fn run_tor(args: &[String]) -> ExitCode {
    use fly_chain::adapter::{Adapter, OurTip, Watch};
    use grin_core::pow::Difficulty;
    use grin_p2p::handshake::Handshake;
    use grin_p2p::{Capabilities, P2PConfig, Peer, PeerAddr};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    let trial = match trial_args(args) {
        Ok(trial) if trial.net != Net::Automated => trial,
        Ok(_) => {
            eprintln!("fly-chain: tor is for the main and the test network");
            return ExitCode::from(2);
        }
        Err(why) => {
            eprintln!("fly-chain: {why}");
            return ExitCode::from(2);
        }
    };
    if std::fs::create_dir_all(&trial.data).is_err() {
        eprintln!("fly-chain: the data directory cannot be made");
        return ExitCode::from(2);
    }
    grin_core::global::init_global_chain_type(trial.net.chain_type());
    let began = Instant::now();
    let tor = match fly_chain_tor::Tor::start(&trial.data, fly_chain::send::START_WITHIN) {
        Ok(tor) => tor,
        Err(why) => {
            println!("failed: {why} ({:.1} s)", began.elapsed().as_secs_f32());
            return ExitCode::from(1);
        }
    };
    println!("tor: up seconds={:.1}", began.elapsed().as_secs_f32());
    let setup = fly_chain::accept::Setup::of(trial.net, &trial.data);
    let Some(asker) = setup.asker else {
        println!("failed: the secure channel to public nodes cannot be set up");
        return ExitCode::from(3);
    };
    let mut api = 0usize;
    for source in &setup.sources {
        let started = Instant::now();
        let said = tor
            .bridge(&source.host, source.port, fly_chain::send::REACH_WITHIN)
            .map_err(|e| e.to_string())
            .and_then(|bridge| asker.ask_at(source, &[bridge.at], fly_chain::send::CALL_WITHIN).map_err(|e| e.to_string()));
        match said {
            Ok(answer) => {
                api = api.saturating_add(1);
                println!("api: {} ({}) height={} seconds={:.1}", source.host, source.group, answer.said.height, started.elapsed().as_secs_f32());
            }
            Err(why) => println!("api: {} ({}) failed: {why} seconds={:.1}", source.host, source.group, started.elapsed().as_secs_f32()),
        }
    }
    // nodes of the network: their names are looked up here, as the
    // program looks them up to follow the chain; only the connection goes
    // through Tor
    let (seeds, port) = match trial.net {
        Net::Main => (fly_chain::node::MAIN_SEEDS, grin_p2p::types::MAINNET_PEER_PORT),
        _ => (fly_chain::node::TEST_SEEDS, grin_p2p::types::TESTNET_PEER_PORT),
    };
    let mut nodes: Vec<SocketAddr> = Vec::new();
    for seed in seeds {
        if let Ok(found) = (*seed, port).to_socket_addrs() {
            nodes.extend(found.filter(|a| a.is_ipv4() && fly_chain_tor::public(a.ip())));
        }
    }
    let (events, _inbox) = std::sync::mpsc::sync_channel(64);
    let adapter: Arc<dyn grin_p2p::types::NetAdapter> = Arc::new(Adapter::new(
        events,
        Arc::new(OurTip::default()),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Watch::default())),
    ));
    let handshake = Handshake::new(grin_core::core::hash::Hash::from_vec(&trial.net.genesis_hash()), P2PConfig::default());
    let mut network = 0usize;
    let mut tried = 0usize;
    for to in nodes.iter().take(8) {
        if network >= 2 {
            break;
        }
        tried = tried.saturating_add(1);
        let started = Instant::now();
        let shook = tor
            .bridge(&to.ip().to_string(), to.port(), fly_chain::send::REACH_WITHIN)
            .map_err(|e| e.to_string())
            .and_then(|bridge| TcpStream::connect_timeout(&bridge.at, fly_chain::send::REACH_WITHIN).map_err(|_| "no connection".to_string()))
            .and_then(|conn| {
                let nowhere = PeerAddr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
                Peer::connect(conn, Capabilities::UNKNOWN, Difficulty::from_num(1), nowhere, &handshake, adapter.clone())
                    .map_err(|_| "the node did not take the connection".to_string())
            });
        match shook {
            Ok(peer) => {
                network = network.saturating_add(1);
                println!("{}", tor_peer_line(to, peer.info.height(), &peer.info.user_agent, started.elapsed()));
                peer.stop("checked");
            }
            Err(why) => {
                // is it the node, or the way through Tor? The program
                // connects to nodes directly to follow the chain anyway
                let direct = if TcpStream::connect_timeout(to, Duration::from_secs(5)).is_ok() { "takes" } else { "does not take" };
                println!("network: {to} failed: {why} seconds={:.1}; directly the node {direct} a connection", started.elapsed().as_secs_f32());
            }
        }
    }
    println!(
        "summary: tor=up api={api}/{} network={network}/{tried} seconds={:.1}",
        setup.sources.len(),
        began.elapsed().as_secs_f32()
    );
    // the public nodes are the way a transaction goes; the nodes of the
    // network only when none of them takes it
    if api > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => pipe(),
        Some(command @ ("import-checkpoint" | "import-checkpoint-file" | "pack-checkpoint" | "pack-profile-checkpoint")) => {
            let net = match args.get(1).map(String::as_str) {
                Some("main") => Net::Main,
                Some("test") => Net::Test,
                _ => { eprintln!("expected main or test"); return ExitCode::from(2); }
            };
            let result = match (command, args.get(2..).unwrap_or_default()) {
                ("import-checkpoint", [dir, point, proof]) =>
                    fly_chain::import_checkpoint(net, dir.as_ref(), point.as_ref(), proof.as_ref()).map(Some),
                ("import-checkpoint-file", [dir, file]) =>
                    fly_chain::import_checkpoint_file(net, dir.as_ref(), file.as_ref()).map(Some),
                ("pack-checkpoint", [point, proof, dest]) =>
                    fly_chain::pack_checkpoint(net, point.as_ref(), proof.as_ref(), dest.as_ref()).map(Some),
                ("pack-profile-checkpoint", [dir, dest]) =>
                    fly_chain::pack_profile_checkpoint(net, dir.as_ref(), dest.as_ref()),
                _ => { eprintln!("incorrect arguments to {command}"); return ExitCode::from(2); }
            };
            match result {
                Ok(Some(pass)) => {
                    println!("{}", serde_json::json!({"height":pass.height,"hash":hex(&pass.hash),"samples":pass.points}));
                    ExitCode::SUCCESS
                }
                Ok(None) => { eprintln!("no transferable active checkpoint"); ExitCode::from(3) }
                Err(e) => { eprintln!("{command} failed: {e}"); ExitCode::FAILURE }
            }
        }
        Some("verify-checkpoint") => {
            let [_, network, directory] = args.as_slice() else {
                eprintln!("usage: verify-checkpoint main|test DIRECTORY_OR_FILE");
                return ExitCode::from(2);
            };
            let net = match network.as_str() {
                "main" => Net::Main,
                "test" => Net::Test,
                _ => { eprintln!("expected main or test"); return ExitCode::from(2); }
            };
            match fly_chain::check_exported_pair(net, std::path::Path::new(directory)) {
                Ok(pass) => {
                    println!("GSHP1 sample verified: height={} hash={} samples={}; tip freshness unknown",
                        pass.height, hex(&pass.hash), pass.points);
                    ExitCode::SUCCESS
                }
                Err(e) => { eprintln!("checkpoint verification failed: {e}"); ExitCode::FAILURE }
            }
        }
        Some("headers") => run_trial(args.get(1..).unwrap_or(&[]), Goal::Headers),
        Some("state") => run_trial(args.get(1..).unwrap_or(&[]), Goal::State),
        Some("blocks") => run_trial(args.get(1..).unwrap_or(&[]), Goal::Blocks),
        Some("old") => run_trial(args.get(1..).unwrap_or(&[]), Goal::Old),
        Some("select") => run_trial(args.get(1..).unwrap_or(&[]), Goal::Select),
        Some("segments") => run_segments(args.get(1..).unwrap_or(&[])),
        Some("proofs") => run_proofs(args.get(1..).unwrap_or(&[])),
        Some("point") => run_point(args.get(1..).unwrap_or(&[])),
        Some("tor") => run_tor(args.get(1..).unwrap_or(&[])),
        Some(_) => {
            eprintln!("fly-chain: started without arguments by the wallet process, or as: fly-chain headers|state|blocks|old|select|proofs|point|tor --network main|test --data <directory> [--peer host:port]... [--seconds N]");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn tor_peer_summary_is_one_bounded_line() {
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], 3414));
        let summary = |agent: &str| tor_peer_line(&local, 42, agent, Duration::from_secs(1));
        assert_eq!(summary("Grin 5.5"), "network: 127.0.0.1:3414 height=42 agent=Grin 5.5 seconds=1.0");
        assert_eq!(summary("Grin\t 5.5\n"), summary("Grin 5.5"));
        assert_eq!(summary(&"a".repeat(65)), summary(&"a".repeat(60)));
    }
}
