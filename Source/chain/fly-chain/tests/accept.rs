//! When the tip is called selected: the rules of `accept`, without a
//! network. The chain, the clock, the connected nodes and the news of the
//! asking are made up here; the file of what is kept between runs is real.
use fly_chain::accept::{own_nodes, Accept, Ask, Block, Facts, History, Setup, Surveyed, ASK_GAP, ASK_GAP_MAX, MAX_OWN_NODES, MEMORY_FILE, OWN_NODES_FILE};
use fly_chain_tips::generation::Verdict;
use fly_chain_tips::memory::Memory;
use fly_chain_tips::time::Stamp;
use fly_chain_tips::{Asker, Said, Source};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!("fly-chain-accept-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Seconds since 1970 at the start of every test's world.
const T0: u64 = 1_795_392_000;
const START: u64 = 1000;

fn five() -> Vec<Source> {
    ["a", "b", "c", "d", "e"]
        .iter()
        .zip([1u32, 2, 3, 4, 4])
        .map(|(name, network)| Source::listed(&name.to_uppercase(), Some(network), &format!("{name}.example")))
        .collect()
}

fn setup() -> Setup {
    Setup {
        sources: five(),
        asker: Asker::new().ok(),
        least_groups: 3,
        own: 0,
        own_refused: 0,
    }
}

/// The user's own nodes: read from a file in the data directory, one
/// address a line, comments and empty lines passed over; what is not an
/// address of a node, a node named twice and one too many are counted as
/// refused. Each is asked like the listed ones and is never a voice of its
/// own: no operator, no network. They come after the listed ones, and
/// without the file there are none.
#[test]
fn the_users_own_nodes() {
    let dir = Dir::new();
    assert_eq!(own_nodes(&dir.0), (Vec::new(), 0));
    std::fs::write(
        dir.0.join(OWN_NODES_FILE),
        "# my nodes\n\nhttps://node.example\n  https://other.example:3443/v2/foreign  \nhttp://plain.example\nhttps://user@node.example\nhttps://node.example\nhttps://third.example\nhttps://fourth.example\nhttps://fifth.example\n",
    )
    .unwrap();
    let (nodes, refused) = own_nodes(&dir.0);
    let names: Vec<(&str, u16)> = nodes.iter().map(|n| (n.host.as_str(), n.port)).collect();
    assert_eq!(names, vec![("node.example", 443), ("other.example", 3443), ("third.example", 443), ("fourth.example", 443)]);
    assert_eq!(nodes.len(), MAX_OWN_NODES);
    assert_eq!(refused, 4, "plain http, a user name, a node named twice, one too many");
    assert!(nodes.iter().all(|n| n.asn.is_none() && n.group.is_empty()));
    assert!(!nodes[0].independent_of(&five()[0]) && !five()[0].independent_of(&nodes[0]));
    // the setup of a real network: the list, then the user's
    let main = Setup::of(fly_chain_headers::Net::Main, &dir.0);
    let listed = fly_chain_tips::source::mainnet().len();
    assert_eq!((main.sources.len(), main.own, main.own_refused), (listed + 4, 4, 4));
    assert_eq!(main.sources[listed].host, "node.example");
    // a file far too long is read only so far
    std::fs::write(dir.0.join(OWN_NODES_FILE), format!("https://node.example\n{}\nhttps://late.example\n", "#".repeat(5000))).unwrap();
    assert_eq!(own_nodes(&dir.0).0.len(), 1);
}

fn nodes(count: u8) -> Vec<IpAddr> {
    (0..count).map(|i| format!("51.{}.0.1", 80 + i).parse().unwrap()).collect()
}

/// A made-up world: a chain of blocks a minute apart, a moment and a
/// clock that move together, and connected nodes.
struct World {
    blocks: Vec<Block>,
    history: History,
    base: Instant,
    /// Seconds since the world's start.
    at: u64,
    /// How far this computer's clock is off, in seconds.
    clock_off: i64,
    peers: Vec<IpAddr>,
    caught_up: bool,
}

impl World {
    /// A chain of `count` blocks whose tip was mined just now.
    fn new(count: u64) -> World {
        let mut world = World {
            blocks: Vec::new(),
            history: History::default(),
            base: Instant::now(),
            at: 0,
            clock_off: 0,
            peers: nodes(3),
            caught_up: true,
        };
        for i in 0..count {
            world.blocks.push(block(START + i, 0, T0 - (count - 1 - i) * 60));
        }
        world.look();
        world
    }
    fn look(&mut self) {
        let blocks = &self.blocks;
        let at = |height: u64| blocks.iter().find(|b| b.said.height == height).copied();
        self.history.refresh(START, blocks.last().unwrap().said.height, |h| at(h).map(|b| b.said.hash), at);
    }
    fn tip(&self) -> Said {
        self.blocks.last().unwrap().said
    }
    /// A minute passes and a block comes.
    fn mine(&mut self) -> Said {
        self.at += 60;
        let height = self.tip().height + 1;
        self.blocks.push(block(height, 0, T0 + self.at));
        self.look();
        self.tip()
    }
    fn pass(&mut self, seconds: u64) {
        self.at += seconds;
    }
    fn facts(&self) -> Facts<'_> {
        Facts {
            history: &self.history,
            start: (START, self.blocks[0].time),
            caught_up: self.caught_up,
            peers: &self.peers,
            now: self.base + Duration::from_secs(self.at),
            clock_ms: ((T0 + self.at) as i64 + self.clock_off) as u64 * 1000,
        }
    }
    /// The times two or more sources wrote on answers given just now.
    fn stamps(&self, sources: &[usize]) -> Vec<Stamp> {
        let now = self.base + Duration::from_secs(self.at);
        sources
            .iter()
            .map(|source| Stamp {
                source: *source,
                date: T0 + self.at - 1,
                sent: now - Duration::from_millis(900),
                got: now - Duration::from_millis(700),
            })
            .collect()
    }
    fn news(&self, ask: &Ask, verdict: Verdict, over: bool) -> Surveyed {
        Surveyed {
            id: ask.generation.id(),
            verdict,
            claims: Vec::new(),
            stamps: self.stamps(&[0, 1, 2]),
            late: false,
            over,
        }
    }
}

fn block(height: u64, branch: u8, time: u64) -> Block {
    let mut hash = [branch; 32];
    hash[..8].copy_from_slice(&height.to_le_bytes());
    Block {
        said: Said {
            height,
            hash,
            total_difficulty: height * 100 + u64::from(branch),
        },
        time,
    }
}

const CONFIRMED: Verdict = Verdict::Confirmed { by: (0, 1) };

fn no_quorum() -> Verdict {
    Verdict::NoQuorum {
        answered: 1,
        needed: 3,
        confirming: 1,
    }
}

/// Public P2P headers remain available. Exercise the two independent HTTPS
/// inputs on first open and after a process restart with an existing time floor.
#[test]
fn public_source_loss_on_new_and_previously_selected_profile() {
    for previously_selected in [false, true] {
        for (quorum, time) in [(false, true), (true, false), (false, false)] {
            let dir = Dir::new();
            let mut world = if previously_selected {
                let (world, previous) = confirmed_world(&dir);
                drop(previous);
                world
            } else {
                World::new(200)
            };
            let mut accept = Accept::open(setup(), &dir.0);
            let ask = accept.tend(&world.facts()).unwrap();
            assert_eq!(ask.generation.id(), if previously_selected { 2 } else { 1 });
            let mut news = world.news(&ask, if quorum { CONFIRMED } else { no_quorum() }, true);
            if !time {
                news.stamps.clear();
            }
            accept.took(&news, &world.facts());
            accept.tend(&world.facts());
            assert_eq!(accept.selected(), None);
            let facts = world.facts();
            assert_eq!(accept.confirmed_time(facts.now, facts.clock_ms).is_some(), time);
            let reason = accept.note().unwrap();
            assert!(if time { reason.contains("did not confirm the tip") } else { reason.contains("time is not confirmed") },
                    "quorum={quorum}, time={time}, previously_selected={previously_selected}: {reason}");
            world.pass(ASK_GAP_MAX.as_secs());
            let ask = accept.tend(&world.facts()).unwrap();
            accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
            accept.tend(&world.facts());
            assert_eq!(accept.selected(), Some(world.tip()));
        }
    }
}

/// Goes through the first asking of a fresh program: asked, confirmed.
fn confirmed_world(dir: &Dir) -> (World, Accept) {
    let world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(world.tip()));
    (world, accept)
}

#[test]
fn nothing_is_selected_before_public_nodes_are_asked() {
    let dir = Dir::new();
    let world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    assert_eq!((accept.selected(), accept.confirmed_time(world.facts().now, world.facts().clock_ms)), (None, None));
    assert_eq!(accept.note().as_deref(), Some("public nodes have not been asked yet"));

    // The first look at a caught-up chain starts an asking, for exactly
    // the tip, with a number that is on the disk already.
    let ask = accept.tend(&world.facts()).unwrap();
    assert_eq!((ask.generation.id(), *ask.generation.tip()), (1, world.tip()));
    assert_eq!(ask.generation.sources().len(), 5);
    assert_eq!(ask.recent.len(), 64);
    assert_eq!(ask.recent[0], world.blocks[198].said);
    assert_eq!(Memory::open(&dir.0.join(MEMORY_FILE)).unwrap().generation(), 1);
    assert_eq!(accept.selected(), None);
    // While it is out, nothing more is started, however long it takes.
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("asking public nodes about the tip"));
    let mut world = world;
    world.pass(ASK_GAP_MAX.as_secs());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("asking public nodes about the tip"));

    // Two answers in: a quorum, and a time. The tip is selected at once,
    // before the last source is heard.
    accept.took(&world.news(&ask, CONFIRMED, false), &world.facts());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(world.tip()));
    assert_eq!(accept.note(), None);
    let facts = world.facts();
    assert_eq!(accept.confirmed_time(facts.now, facts.clock_ms), Some(T0 + ASK_GAP_MAX.as_secs() - 1));
    assert!(!accept.caveat());
    assert_eq!(accept.signs().map(|signs| signs.fired()), Some(false));
    assert_eq!(accept.signs_note(), None);
}

/// An asking that could not be started (no thread for it) is not waited
/// for: no news of it can come. The tip is not said to be "asked about",
/// the same tip is asked about again after the usual pause - without a new
/// block - and the next asking is given no more and no less time than the
/// first.
#[test]
fn an_asking_that_could_not_start_is_not_waited_for() {
    let dir = Dir::new();
    let mut world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let mut seen = None;
    let started = accept.tend_and_start(&world.facts(), |ask| {
        seen = Some((ask.generation.id(), *ask.generation.tip(), ask.generation.deadline()));
        Err("no thread")
    });
    assert_eq!(started, Err("no thread"));
    let (id, tip, deadline) = seen.unwrap();
    assert_eq!((id, tip), (1, world.tip()));
    assert_eq!(accept.selected(), None);

    // Before the pause is over nothing is started, and nothing is said to
    // be going on.
    world.pass(ASK_GAP.as_secs() - 1);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("the time is not confirmed yet"));

    // After it the same tip is asked about, under a new number.
    world.pass(1);
    let ask = accept.tend(&world.facts()).expect("the same tip is asked about again");
    assert_eq!((ask.generation.id(), *ask.generation.tip()), (2, tip));
    assert_eq!(ask.generation.deadline() - world.facts().now, deadline - world.base, "the sources are not blamed");

    // An asking that did start is waited for as before.
    let mut started = false;
    world.pass(ASK_GAP_MAX.as_secs());
    assert_eq!(accept.tend_and_start(&world.facts(), |_| -> Result<(), ()> { started = true; Ok(()) }), Ok(()));
    assert!(!started, "the second asking is still out");
    assert_eq!(accept.note().as_deref(), Some("asking public nodes about the tip"));
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(world.tip()));
}

#[test]
fn a_tip_built_on_a_confirmed_one_needs_no_asking_while_no_sign_is_up() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    for _ in 0..30 {
        let tip = world.mine();
        assert!(accept.tend(&world.facts()).is_none());
        assert_eq!(accept.selected(), Some(tip));
    }
    assert_eq!(Memory::open(&dir.0.join(MEMORY_FILE)).unwrap().generation(), 1);
}

#[test]
fn while_a_sign_is_up_every_tip_needs_its_own_quorum() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    // The nodes are now all of one network.
    world.peers = nodes(1);
    // The tip a quorum named stays selected.
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(world.tip()));
    assert_eq!(accept.signs_note().as_deref(), Some("connected to nodes of fewer than three networks"));
    // A new tip is not, until public nodes named it.
    let tip = world.mine();
    let ask = accept.tend(&world.facts()).unwrap();
    assert_eq!((accept.selected(), *ask.generation.tip()), (None, tip));
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(tip));

    // The other signs: a tip half an hour old, and an hour that thinned.
    world.peers = nodes(3);
    world.pass(29 * 60);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.signs_note(), None);
    world.pass(2 * 60);
    let ask = accept.tend(&world.facts());
    assert!(ask.is_none(), "the tip a quorum named needs no second one");
    assert_eq!(accept.signs_note().as_deref(), Some("the tip is old, few blocks in the last hour"));
    assert_eq!(accept.selected(), Some(tip));
}

#[test]
fn a_tip_that_left_the_confirmed_chain() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    let named = world.tip();
    // The chain turns: the last three blocks are replaced by others.
    world.pass(60);
    let keep = world.blocks.len() - 3;
    world.blocks.truncate(keep);
    for _ in 0..4 {
        let height = world.tip().height + 1;
        world.blocks.push(block(height, 7, T0 + world.at));
    }
    world.look();
    assert!(!world.history.holds(&named));
    let ask = accept.tend(&world.facts()).unwrap();
    assert_eq!((accept.selected(), *ask.generation.tip()), (None, world.tip()));
    assert_eq!(ask.generation.id(), 2);
}

#[test]
fn a_claim_of_more_stands_until_its_block_is_verified() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    world.peers = nodes(1);
    let tip = world.mine();
    let ask = accept.tend(&world.facts()).unwrap();
    // Three sources name the tip; a fourth names a block further.
    let further = block(tip.height + 1, 0, T0 + world.at + 60).said;
    let mut news = world.news(&ask, Verdict::Ahead, true);
    news.claims = vec![("d.example".to_string(), further)];
    accept.took(&news, &world.facts());
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("public node d.example names more work than is verified here"));
    // It is on the disk: a restart does not make it go away.
    assert!(Memory::open(&dir.0.join(MEMORY_FILE)).unwrap().claims().blocks());

    // Another asking confirms the tip by its own count: still blocked.
    world.pass(ASK_GAP_MAX.as_secs());
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);

    // The block arrives and is verified: the claim is settled.
    world.peers = nodes(3);
    let got = world.mine();
    assert_eq!(got, further);
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(got));
    assert!(!Memory::open(&dir.0.join(MEMORY_FILE)).unwrap().claims().blocks());

    // A claim of a block the program already holds is no claim.
    let mut news = world.news(&ask, CONFIRMED, true);
    news.id = 999;
    news.claims = vec![("e.example".to_string(), got)];
    accept.took(&news, &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(got));
}

#[test]
fn a_claim_nobody_settles_expires_into_a_caveat() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    let nowhere = block(world.tip().height + 5, 9, T0).said;
    // News of an asking long over still carries its claim.
    let stray = Surveyed {
        id: 77,
        verdict: Verdict::Ahead,
        claims: vec![("c.example".to_string(), nowhere)],
        stamps: Vec::new(),
        late: true,
        over: true,
    };
    accept.took(&stray, &world.facts());
    accept.tend(&world.facts());
    assert_eq!((accept.selected(), accept.caveat()), (None, false));
    // Twenty-nine minutes on it still blocks; after half an hour it is a
    // caveat on a tip that is selected again.
    for _ in 0..29 {
        world.mine();
        accept.tend(&world.facts());
        assert_eq!(accept.selected(), None);
    }
    world.mine();
    world.mine();
    accept.tend(&world.facts());
    assert_eq!((accept.selected(), accept.caveat()), (Some(world.tip()), true));
    // And half an hour later the caveat is gone.
    for _ in 0..31 {
        world.mine();
        accept.tend(&world.facts());
    }
    assert_eq!((accept.selected(), accept.caveat()), (Some(world.tip()), false));
}

#[test]
fn restarting_keeps_both_claim_windows_paused_until_time_returns() -> Result<(), &'static str> {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    let said = block(9001, 9, T0).said;
    accept.took(&Surveyed { id: 77, verdict: Verdict::Ahead,
        claims: vec![("c.example".into(), said)], stamps: vec![], late: true, over: true },
        &world.facts());
    for expired in [false, true] {
        drop(accept);
        world.pass(7200);
        accept = Accept::open(setup(), &dir.0);
        let ask = accept.tend(&world.facts()).ok_or("expected survey")?;
        accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
        accept.tend(&world.facts());
        let memory = Memory::open(&dir.0.join(MEMORY_FILE)).map_err(|_| "read failed")?;
        assert_eq!((memory.claims().blocks(), memory.claims().caveat()), (!expired, expired));
        world.pass(1860);
        accept.tend(&world.facts());
    }
    let memory = Memory::open(&dir.0.join(MEMORY_FILE)).map_err(|_| "read failed")?;
    assert!(!memory.claims().blocks() && !memory.claims().caveat());
    Ok(())
}

#[test]
fn choosing_a_listed_node_as_preferred_keeps_one_survey_seat() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Dir::new();
    let net = fly_chain_headers::Net::Main;
    let source = fly_chain_tips::source::mainnet().into_iter().next().ok_or("empty registry")?;
    std::fs::write(dir.0.join(OWN_NODES_FILE), format!("https://{}\n", source.host))?;
    let setup = Setup::of(net, &dir.0);
    assert_eq!(setup.sources.iter().filter(|s| s.host == source.host && s.port == source.port).count(), 1);
    assert!(setup.sources.iter().any(|s| s == &source));
    Ok(())
}

#[test]
fn a_quorum_counts_only_for_the_tip_it_was_asked_about() {
    let dir = Dir::new();
    let mut world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let ask = accept.tend(&world.facts()).unwrap();
    // A block comes before the answers do.
    let tip = world.mine();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    // The quorum named a block that is no longer the tip: not counted.
    // A new asking is started for the new tip.
    let again = accept.tend(&world.facts()).unwrap();
    assert_eq!((accept.selected(), *again.generation.tip()), (None, tip));
    assert_eq!(again.generation.id(), 2);
    // News of the first asking changes nothing now.
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    accept.took(&world.news(&again, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(tip));

    // The same when the program notices the new block before any news of
    // the asking: the asking of the old tip is dropped and the new tip is
    // asked about at once.
    world.peers = nodes(1);
    world.mine();
    world.pass(ASK_GAP.as_secs());
    let first = accept.tend(&world.facts()).unwrap();
    // The next block comes a second later.
    world.pass(1);
    let height = world.tip().height + 1;
    world.blocks.push(block(height, 0, T0 + world.at));
    world.look();
    let tip = world.tip();
    let second = accept.tend(&world.facts()).unwrap();
    assert_eq!((*second.generation.tip(), second.generation.id()), (tip, first.generation.id() + 1));
}

#[test]
fn a_later_answer_takes_the_confirmation_away() {
    let dir = Dir::new();
    let world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, false), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));
    let mut world = world;
    let further = block(world.tip().height + 1, 0, T0).said;
    let mut news = world.news(&ask, Verdict::Ahead, true);
    news.claims = vec![("e.example".to_string(), further)];
    accept.took(&news, &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    // The block comes and settles the claim. The quorum that was taken
    // away does not come back with it: public nodes are asked again.
    assert_eq!(world.mine(), further);
    let again = accept.tend(&world.facts()).unwrap();
    assert_eq!((accept.selected(), *again.generation.tip()), (None, further));
}

#[test]
fn own_node_address_is_accepted_only_as_a_complete_line() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Dir::new();
    let prefix = "https://first.example\n#";
    let visible = "https://node.example";
    let pad = 4096usize.checked_sub(prefix.len()).and_then(|v| v.checked_sub(1))
        .and_then(|v| v.checked_sub(visible.len())).ok_or("fixture length")?;
    let text = format!("{prefix}{}\n{visible}", "x".repeat(pad));
    assert_eq!(text.len(), 4096);
    std::fs::write(dir.0.join(OWN_NODES_FILE), &text)?;
    assert_eq!(own_nodes(&dir.0).0.len(), 2);
    std::fs::write(dir.0.join(OWN_NODES_FILE), format!("{text}.internal.example\n"))?;
    let (nodes, refused) = own_nodes(&dir.0);
    assert_eq!(nodes.iter().map(|node| node.host.as_str()).collect::<Vec<_>>(), vec!["first.example"]);
    assert_eq!(refused, 1);
    Ok(())
}

#[test]
fn no_time_no_tip() {
    let dir = Dir::new();
    let mut world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    // A quorum, but only one source wrote a time.
    let ask = accept.tend(&world.facts()).unwrap();
    let mut news = world.news(&ask, CONFIRMED, true);
    news.stamps = world.stamps(&[0]);
    accept.took(&news, &world.facts());
    assert!(accept.tend(&world.facts()).is_none(), "not asked again before the pause is over");
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("the time is not confirmed: too few public nodes answered"));

    // The next asking brings both fresh time and a quorum.
    world.pass(ASK_GAP.as_secs());
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));

    // This computer's clock is set an hour ahead: the time is no longer
    // relied on, and public nodes are asked again.
    world.pass(ASK_GAP.as_secs());
    world.clock_off = 3600;
    let ask = accept.tend(&world.facts()).unwrap();
    assert_eq!(accept.selected(), None);
    // Not while the asking is out either: a quorum without a time is
    // not enough.
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), None);
    // Their time is where it was; the clock is far from it.
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    assert_eq!(
        accept.note().as_deref(),
        Some("this computer's clock is far from the time of public nodes: check the clock")
    );
    // The clock is set right again.
    world.clock_off = 0;
    world.pass(ASK_GAP_MAX.as_secs());
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));

    // Sources that disagree about the time take it away.
    world.peers = nodes(1);
    let tip = world.mine();
    world.pass(ASK_GAP_MAX.as_secs());
    let ask = accept.tend(&world.facts()).unwrap();
    let mut news = world.news(&ask, CONFIRMED, true);
    news.stamps[2].date += 600;
    accept.took(&news, &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("the time is not confirmed: public nodes disagree about it"));
    let _ = tip;
}

#[test]
fn renewing_time_without_quorum_cannot_restore_a_previous_selection() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    world.pass(fly_chain_tips::time::KEPT_FOR.as_secs() + 1);
    let ask = accept.tend(&world.facts()).unwrap();
    assert_eq!(accept.selected(), None);
    for over in [false, true] {
        let news = world.news(&ask, Verdict::NoQuorum { answered: 2, needed: 3, confirming: 0 }, over);
        accept.took(&news, &world.facts());
        accept.tend(&world.facts());
        let facts = world.facts();
        assert!(accept.confirmed_time(facts.now, facts.clock_ms).is_some());
        assert_eq!(accept.selected(), None);
    }
    world.pass(ASK_GAP_MAX.as_secs());
    let new = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&new, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));
}

#[test]
fn the_time_runs_out_after_six_hours() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    for _ in 0..359 {
        world.mine();
    }
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), Some(world.tip()));
    world.mine();
    world.mine();
    // Nothing is wrong with the chain; the time has to be confirmed anew.
    let ask = accept.tend(&world.facts());
    assert!(ask.is_some());
    assert_eq!(accept.selected(), None);
    let facts = world.facts();
    assert_eq!(accept.confirmed_time(facts.now, facts.clock_ms), None);
}

#[test]
fn rounds_without_a_quorum_come_further_and_further_apart() {
    let dir = Dir::new();
    let mut world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let mut gap = ASK_GAP;
    for round in 0..6 {
        let ask = accept.tend(&world.facts()).unwrap_or_else(|| panic!("round {round}"));
        accept.took(&world.news(&ask, no_quorum(), true), &world.facts());
        assert!(accept.tend(&world.facts()).is_none());
        assert_eq!(
            accept.note().as_deref(),
            Some("public nodes did not confirm the tip (1 answered, 3 needed, 1 named it)")
        );
        gap = (gap * 2).min(ASK_GAP_MAX);
        // One second short of the pause nothing is asked.
        world.pass(gap.as_secs() - 1);
        assert!(accept.tend(&world.facts()).is_none(), "round {round}");
        world.pass(1);
    }
    assert_eq!(gap, ASK_GAP_MAX);
    // A quorum brings the pause back to the shortest.
    let ask = accept.tend(&world.facts()).unwrap();
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    world.peers = nodes(1);
    world.mine();
    world.pass(ASK_GAP.as_secs());
    assert!(accept.tend(&world.facts()).is_some());
}

#[test]
fn what_keeps_the_program_from_asking_at_all() {
    // Not at the tip of what the connected nodes have.
    let dir = Dir::new();
    let mut world = World::new(200);
    world.caught_up = false;
    let mut accept = Accept::open(setup(), &dir.0);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("not at the tip yet"));
    // A tip selected before is not selected while a node claims more.
    let (mut world, mut accept) = confirmed_world(&Dir::new());
    world.caught_up = false;
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);

    // Nobody to ask.
    let mut nobody = setup();
    nobody.sources.clear();
    let world = World::new(200);
    let mut accept = Accept::open(nobody, &Dir::new().0);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("no public nodes are listed for this network: no tip is confirmed"));
    // No way to reach them.
    let mut unreachable = setup();
    unreachable.asker = None;
    let mut accept = Accept::open(unreachable, &Dir::new().0);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("no secure channel to public nodes: no tip is confirmed"));

    // The file of what is kept between runs is damaged.
    let dir = Dir::new();
    std::fs::write(dir.0.join(MEMORY_FILE), b"not this program's").unwrap();
    let mut accept = Accept::open(setup(), &dir.0);
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("tips.state cannot be read back: no tip is confirmed"));
    assert_eq!(std::fs::read(dir.0.join(MEMORY_FILE)).unwrap(), b"not this program's");

    // The number of an asking cannot be written: nothing is asked.
    let dir = Dir::new();
    let mut accept = Accept::open(setup(), &dir.0.join("no-such-directory"));
    assert!(accept.tend(&world.facts()).is_none());
    assert_eq!(accept.note().as_deref(), Some("tips.state cannot be written: no tip is confirmed"));
}

#[test]
fn time_floor_storage_error_is_visible_to_the_caller() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Dir::new();
    let mut world = World::new(200);
    let mut accept = Accept::open(setup(), &dir.0);
    let ask = accept.tend(&world.facts()).ok_or("expected initial survey")?;
    accept.took(&world.news(&ask, CONFIRMED, false), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));
    world.pass(1);
    // Local temporary directory models a failed write without changing user permissions.
    let temporary = dir.0.join(format!("{MEMORY_FILE}.new"));
    std::fs::create_dir(&temporary)?;
    accept.took(&world.news(&ask, CONFIRMED, true), &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.note().as_deref(), Some("tips.state cannot be written: no tip is confirmed"));
    assert!(accept.selected().is_none());
    assert!(accept.confirmed_time(world.facts().now, world.facts().clock_ms).is_none());
    std::fs::remove_dir(temporary)?;
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), Some(world.tip()));
    assert!(accept.confirmed_time(world.facts().now, world.facts().clock_ms).is_some());
    Ok(())
}

#[test]
fn the_history_follows_the_chain() {
    let mut world = World::new(5000);
    assert_eq!(world.history.tip().map(|b| b.said), Some(world.tip()));
    // Only as far back as the signs look.
    assert!(world.history.holds(&world.blocks[5000 - 2881].said));
    assert!(!world.history.holds(&world.blocks[5000 - 2882].said));
    assert_eq!(world.history.recent().len(), 64);
    assert_eq!(world.history.recent()[63], world.blocks[5000 - 65].said);
    // A turn of the chain: the blocks that were replaced are gone from it.
    let old = world.blocks[4990].said;
    world.blocks.truncate(4990);
    world.blocks.push(block(START + 4990, 5, T0));
    world.look();
    assert!(!world.history.holds(&old) && world.history.holds(&world.tip()));
    assert!(world.history.holds(&world.blocks[4989].said));
    // A short chain is held whole.
    let short = World::new(3);
    assert!(short.history.holds(&short.blocks[0].said));
    assert_eq!(short.history.recent().len(), 2);
}

#[test]
fn a_time_before_one_confirmed_earlier() {
    let dir = Dir::new();
    let (mut world, mut accept) = confirmed_world(&dir);
    assert!(Memory::open(&dir.0.join(MEMORY_FILE)).unwrap().floor_ms() > (T0 - 5) * 1000);
    // This computer's clock and the public nodes both go a day back.
    world.pass(ASK_GAP.as_secs());
    world.clock_off = -86_400;
    let ask = accept.tend(&world.facts()).unwrap();
    let mut news = world.news(&ask, CONFIRMED, true);
    for stamp in &mut news.stamps {
        stamp.date -= 86_400;
    }
    accept.took(&news, &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("public nodes name a time before one confirmed earlier"));
    // After a restart too: the earlier time is on the disk.
    let mut accept = Accept::open(setup(), &dir.0);
    world.pass(ASK_GAP_MAX.as_secs());
    let ask = accept.tend(&world.facts()).unwrap();
    let mut news = world.news(&ask, CONFIRMED, true);
    for stamp in &mut news.stamps {
        stamp.date -= 86_400;
    }
    accept.took(&news, &world.facts());
    accept.tend(&world.facts());
    assert_eq!(accept.selected(), None);
    assert_eq!(accept.note().as_deref(), Some("public nodes name a time before one confirmed earlier"));
}
