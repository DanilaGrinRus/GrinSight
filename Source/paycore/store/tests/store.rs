//! Stage E1 acceptance tests: crash at every operation, corruption of every
//! byte, truncation at every length, the tail-guard table, locking.
use fly_paycore_store::sim::{DataLoss, Fault, Reboot, Sim, SimDir, SimGuard};
use fly_paycore_store::{
    CommitError, GuardCheck, Identity, OpenError, Opened, RootKey, Store, KIND_RECOVERY,
    MAX_BODY_LEN,
};

type S = Store<SimDir, SimGuard>;

fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [7u8; 32],
        instance: [9u8; 16],
    }
}

fn key() -> RootKey {
    RootKey::new([0x42; 32])
}

fn create(sim: &Sim) -> Result<S, OpenError> {
    Store::create(sim.dir(), sim.guard(), &key(), id())
}

fn open(sim: &Sim) -> Result<Opened<SimDir, SimGuard>, OpenError> {
    Store::open(sim.dir(), sim.guard(), &key(), id())
}

/// Logical content of a journal: last snapshot and the frames after it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct View {
    snapshot: Option<Vec<u8>>,
    frames: Vec<(u8, Vec<u8>)>,
}

fn view(o: &Opened<SimDir, SimGuard>) -> View {
    View {
        snapshot: o.snapshot.as_ref().map(|s| s.to_vec()),
        frames: o.frames.iter().map(|f| (f.kind, f.body.to_vec())).collect(),
    }
}

#[derive(Clone, Copy)]
enum Step {
    Create,
    Commit(u8, &'static [u8]),
    Sealed(u8, &'static [u8]),
    Checkpoint(&'static [u8]),
}

const SCENARIO: &[Step] = &[
    Step::Create,
    Step::Commit(1, b"alpha"),
    Step::Sealed(2, b"bravo: armed"),
    Step::Commit(1, b""),
    Step::Checkpoint(b"state after three frames"),
    Step::Sealed(2, b"delta"),
    Step::Commit(
        3,
        b"echo echo echo echo echo echo echo echo echo echo echo echo echo echo",
    ),
    Step::Checkpoint(b"state after five frames"),
    Step::Checkpoint(b"state after five frames, again"),
    Step::Sealed(2, b"foxtrot"),
    Step::Commit(1, b"golf"),
];

/// View after the first `n` steps.
fn expected(n: usize) -> Option<View> {
    let mut v = None;
    for step in &SCENARIO[..n] {
        match *step {
            Step::Create => v = Some(View::default()),
            Step::Commit(k, b) | Step::Sealed(k, b) => {
                v.as_mut().unwrap().frames.push((k, b.to_vec()))
            }
            Step::Checkpoint(s) => {
                v = Some(View {
                    snapshot: Some(s.to_vec()),
                    frames: vec![],
                })
            }
        }
    }
    v
}

struct Run {
    /// Steps that returned `Ok`.
    acked: usize,
    /// Journal position covered by the last sealed acknowledgement.
    sealed_next_seq: Option<u64>,
    store: Option<S>,
}

fn run(sim: &Sim) -> Run {
    let mut r = Run {
        acked: 0,
        sealed_next_seq: None,
        store: None,
    };
    for step in SCENARIO {
        let ok = match *step {
            Step::Create => match create(sim) {
                Ok(s) => {
                    r.store = Some(s);
                    true
                }
                Err(_) => false,
            },
            Step::Commit(k, b) => r.store.as_mut().unwrap().commit(k, b).is_ok(),
            Step::Sealed(k, b) => match r.store.as_mut().unwrap().commit_sealed(k, b) {
                Ok(s) => {
                    r.sealed_next_seq = Some(s.seq() + 1);
                    true
                }
                Err(_) => false,
            },
            Step::Checkpoint(st) => match r.store.as_mut().unwrap().checkpoint(st) {
                Ok(s) => {
                    r.sealed_next_seq = Some(s.seq() + 1);
                    true
                }
                Err(_) => false,
            },
        };
        if !ok {
            break;
        }
        r.acked += 1;
    }
    r
}

#[test]
fn scenario_without_faults() {
    let sim = Sim::new();
    let r = run(&sim);
    assert_eq!(r.acked, SCENARIO.len());
    drop(r);
    let o = open(&sim).unwrap();
    assert_eq!(view(&o), expected(SCENARIO.len()).unwrap());
    // the last step was an unsealed commit, so the guard was one frame behind
    assert_eq!(o.guard, GuardCheck::CaughtUp);
    assert_eq!(o.store.generation(), 3);
    drop(o);
    let o = open(&sim).unwrap();
    assert_eq!(o.guard, GuardCheck::Match);
    // two generations are kept, older files are gone
    let mut names = sim.file_names();
    names.sort();
    assert_eq!(
        names,
        vec![
            "journal-0000000000000002.fly",
            "journal-0000000000000003.fly",
            "snapshot-0000000000000002.fly",
            "snapshot-0000000000000003.fly"
        ]
    );
}

/// I-crash / K6: whatever operation the machine dies at, and whatever the
/// crash does to un-synced data, the journal reopens to the state after the
/// acknowledged steps or after the one in flight, never anything else; the
/// guard never raises a false alarm and never lags an acknowledged sealed
/// frame; and the journal keeps working.
#[test]
fn crash_at_every_operation() {
    let total_ops = {
        let sim = Sim::new();
        run(&sim);
        sim.ops()
    };
    assert!(total_ops > 40, "scenario too small: {total_ops}");
    let losses = [
        DataLoss::LoseAll,
        DataLoss::KeepAll,
        DataLoss::Zeros,
        DataLoss::Garbage,
        DataLoss::Torn(1),
        DataLoss::Torn(3),
        DataLoss::Torn(4),
        DataLoss::Torn(5),
        DataLoss::Torn(44),
        DataLoss::Torn(69),
        DataLoss::Torn(80),
        DataLoss::Torn(81),
        DataLoss::Torn(84),
        DataLoss::Torn(120),
        DataLoss::Torn(175),
        DataLoss::Torn(176),
    ];
    let mut runs = 0u32;
    for op in 0..total_ops {
        for fault in [Fault::CrashBefore(op), Fault::CrashAfter(op)] {
            for data in losses {
                for keep_dir_changes in [false, true] {
                    let ctx = format!("{fault:?} {data:?} keep_dir={keep_dir_changes}");
                    let sim = Sim::new();
                    sim.set_fault(Some(fault));
                    let r = run(&sim);
                    assert!(sim.crashed(), "{ctx}: fault did not fire");
                    let acked = r.acked;
                    let sealed = r.sealed_next_seq;
                    drop(r);
                    // K16: an acknowledged sealed frame is covered by the guard
                    if let Some(n) = sealed {
                        assert!(
                            sim.guard_value().unwrap().next_seq >= n,
                            "{ctx}: guard behind a sealed frame"
                        );
                    }
                    sim.reboot(Reboot {
                        data,
                        keep_dir_changes,
                    });
                    runs += 1;

                    let opened = match open(&sim) {
                        Ok(o) => o,
                        Err(e) => {
                            // only a crash inside the very first step may leave no usable journal
                            assert_eq!(
                                acked, 0,
                                "{ctx}: open failed after acknowledged steps: {e:?}"
                            );
                            assert!(
                                matches!(e, OpenError::NotFound | OpenError::BadHeader),
                                "{ctx}: {e:?}"
                            );
                            create(&sim).unwrap_or_else(|e| {
                                panic!("{ctx}: cannot create after failed first create: {e:?}")
                            });
                            continue;
                        }
                    };
                    let got = view(&opened);
                    let fits = [acked, acked + 1]
                        .iter()
                        .any(|n| *n <= SCENARIO.len() && expected(*n).as_ref() == Some(&got));
                    assert!(fits, "{ctx}: acked {acked} steps, reopened as {got:?}");
                    assert!(
                        matches!(opened.guard, GuardCheck::Match | GuardCheck::CaughtUp),
                        "{ctx}: false alarm {:?}",
                        opened.guard
                    );
                    let mut store = opened.store;
                    assert_eq!(
                        sim.guard_value().unwrap(),
                        store.tail(),
                        "{ctx}: guard not at the tail after open"
                    );

                    // the journal keeps working and stays consistent
                    store
                        .commit_sealed(9, b"after the crash")
                        .unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
                    drop(store);
                    let again = open(&sim).unwrap_or_else(|e| panic!("{ctx}: second open: {e:?}"));
                    let mut want = got.clone();
                    want.frames.push((9, b"after the crash".to_vec()));
                    assert_eq!(view(&again), want, "{ctx}");
                    assert_eq!(again.guard, GuardCheck::Match, "{ctx}");
                }
            }
        }
    }
    println!("crash matrix: {runs} runs over {total_ops} operations");
}

/// A failed (not crashed) write poisons the store; reopening resolves it.
#[test]
fn failed_operation_poisons_until_reopen() {
    let base_ops = {
        let sim = Sim::new();
        let mut s = create(&sim).unwrap();
        s.commit(1, b"one").unwrap();
        sim.ops()
    };
    // the next commit_sealed performs: append, sync, guard store
    // a failed append or sync leaves the outcome open; a failed guard update
    // comes after the frame is durable
    for (k, on_disk) in [(0u64, false), (1, false), (2, true)] {
        let sim = Sim::new();
        let mut s = create(&sim).unwrap();
        s.commit(1, b"one").unwrap();
        sim.set_fault(Some(Fault::Fail(base_ops + k)));
        assert_eq!(
            s.commit_sealed(2, b"two").unwrap_err(),
            CommitError::Unknown
        );
        sim.set_fault(None);
        assert_eq!(s.commit(1, b"three").unwrap_err(), CommitError::Poisoned);
        assert_eq!(
            s.commit_sealed(1, b"three").unwrap_err(),
            CommitError::Poisoned
        );
        assert_eq!(s.checkpoint(b"x").unwrap_err(), CommitError::Poisoned);
        drop(s);
        // the process restarts; un-synced data may or may not have reached the disk
        for data in [DataLoss::LoseAll, DataLoss::KeepAll] {
            let sim2 = Sim::new();
            sim2.restore_disk(&sim.disk_image());
            sim2.set_guard_value(sim.guard_value());
            sim2.reboot(Reboot {
                data,
                keep_dir_changes: true,
            });
            let o = open(&sim2).unwrap();
            let n = o.frames.len();
            if on_disk {
                assert_eq!(n, 2, "fault {k} {data:?}");
            } else {
                assert!(
                    n == 1 || (n == 2 && data == DataLoss::KeepAll),
                    "fault {k} {data:?}: {n}"
                );
            }
            assert!(matches!(o.guard, GuardCheck::Match | GuardCheck::CaughtUp));
        }
    }
}

fn small_journal() -> (Sim, Vec<u8>, View) {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    s.commit(1, b"alpha").unwrap();
    s.commit_sealed(2, b"bravo").unwrap();
    s.commit(1, b"charlie").unwrap();
    drop(s);
    let bytes = sim.file("journal-0000000000000000.fly").unwrap();
    // Not opened here: opening would advance the guard over the unsealed last frame.
    let v = View {
        snapshot: None,
        frames: vec![
            (1, b"alpha".to_vec()),
            (2, b"bravo".to_vec()),
            (1, b"charlie".to_vec()),
        ],
    };
    (sim, bytes, v)
}

/// Every single-bit-pattern change anywhere in the file is either rejected or
/// costs exactly the damaged tail, and then the guard notices if that tail
/// held a sealed frame. Altered content is never returned.
#[test]
fn corruption_of_every_byte() {
    let (sim, bytes, full) = small_journal();
    let guard = sim.guard_value();
    let name = "journal-0000000000000000.fly";
    let (mut rejected, mut tail_dropped) = (0, 0);
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80, 0xFF] {
            let mut b = bytes.clone();
            b[i] ^= mask;
            sim.set_file(name, &b);
            sim.set_guard_value(guard);
            match open(&sim) {
                Err(e) => {
                    assert!(
                        matches!(
                            e,
                            OpenError::BadHeader | OpenError::Corrupt | OpenError::WrongIdentity
                        ),
                        "byte {i}: {e:?}"
                    );
                    rejected += 1;
                }
                Ok(o) => {
                    let got = view(&o);
                    assert!(
                        got.frames.len() < full.frames.len(),
                        "byte {i} mask {mask:#x}: change went unnoticed"
                    );
                    assert_eq!(
                        got.frames[..],
                        full.frames[..got.frames.len()],
                        "byte {i}: altered content returned"
                    );
                    // only the last frame can be mistaken for a torn write
                    assert_eq!(got.frames.len(), 2, "byte {i} mask {mask:#x}");
                    // the guard sits after the sealed second frame, where the journal now ends
                    assert_eq!(o.guard, GuardCheck::Match, "byte {i}");
                    tail_dropped += 1;
                }
            }
        }
    }
    assert!(rejected > 0 && tail_dropped > 0);
    println!("corruption: {rejected} rejected, {tail_dropped} reduced to the valid prefix");
}

/// Same when the damaged last frame is itself sealed: the guard reports it.
#[test]
fn corrupted_sealed_tail_is_reported_by_the_guard() {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    s.commit(1, b"alpha").unwrap();
    s.commit_sealed(2, b"bravo").unwrap();
    drop(s);
    let name = "journal-0000000000000000.fly";
    let mut b = sim.file(name).unwrap();
    let last = b.len() - 1;
    b[last] ^= 1;
    sim.set_file(name, &b);
    let mut o = open(&sim).unwrap();
    assert_eq!(o.frames.len(), 1);
    assert_eq!(o.guard, GuardCheck::RolledBack);
    assert_eq!(
        o.store.commit(1, b"x").unwrap_err(),
        CommitError::RecoveryRequired
    );
}

/// Cutting the file at every length gives an error or a valid prefix, and
/// the guard reports every cut that removes the sealed frame.
#[test]
fn truncation_at_every_length() {
    let (sim, bytes, full) = small_journal();
    let guard = sim.guard_value();
    let name = "journal-0000000000000000.fly";
    let mut seen = [0usize; 4];
    for len in 0..bytes.len() {
        sim.set_file(name, &bytes[..len]);
        sim.set_guard_value(guard);
        match open(&sim) {
            Err(e) => {
                assert!(len < 176, "length {len}: {e:?}");
                assert!(matches!(e, OpenError::BadHeader), "length {len}: {e:?}");
            }
            Ok(o) => {
                let got = view(&o);
                let n = got.frames.len();
                assert!(n < 3);
                assert_eq!(got.frames[..], full.frames[..n]);
                seen[n] += 1;
                let want = if n < 2 {
                    GuardCheck::RolledBack
                } else {
                    GuardCheck::Match
                };
                assert_eq!(o.guard, want, "length {len}");
            }
        }
    }
    assert!(seen[0] > 0 && seen[1] > 0 && seen[2] > 0);
}

#[test]
fn wrong_key_and_wrong_identity_are_refused() {
    let (sim, _, _) = small_journal();
    let other_key = RootKey::new([0x43; 32]);
    assert!(matches!(
        Store::open(sim.dir(), sim.guard(), &other_key, id()),
        Err(OpenError::BadHeader)
    ));
    for other in [
        Identity { network: 1, ..id() },
        Identity {
            genesis: [8; 32],
            ..id()
        },
        Identity {
            instance: [1; 16],
            ..id()
        },
    ] {
        assert!(matches!(
            Store::open(sim.dir(), sim.guard(), &key(), other),
            Err(OpenError::WrongIdentity)
        ));
    }
    assert!(matches!(create(&sim), Err(OpenError::AlreadyExists)));
    assert!(matches!(open(&Sim::new()), Err(OpenError::NotFound)));
}

/// Section 5.7, the four rows of the table.
#[test]
fn tail_guard_table() {
    // rollback to an older copy of the journal
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    s.commit_sealed(2, b"prepared").unwrap();
    let backup = sim.disk_image();
    s.commit_sealed(2, b"armed").unwrap();
    drop(s);
    sim.restore_disk(&backup);
    let mut o = open(&sim).unwrap();
    assert_eq!(o.guard, GuardCheck::RolledBack);
    assert!(o.store.recovery_required());
    assert_eq!(
        o.store.commit(1, b"x").unwrap_err(),
        CommitError::RecoveryRequired
    );
    assert_eq!(
        o.store.commit_sealed(2, b"armed again").unwrap_err(),
        CommitError::RecoveryRequired
    );
    assert_eq!(
        o.store.checkpoint(b"s").unwrap_err(),
        CommitError::RecoveryRequired
    );
    let sealed = o
        .store
        .commit_recovery(b"new branch 7, operations locked")
        .unwrap();
    assert_eq!(sealed.seq(), 1);
    assert!(!o.store.recovery_required());
    o.store.commit(1, b"y").unwrap();
    drop(o);
    let o = open(&sim).unwrap();
    assert_eq!(o.guard, GuardCheck::CaughtUp);
    assert_eq!(
        o.frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
        vec![2, KIND_RECOVERY, 1]
    );

    // same length, different history
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    let empty = sim.disk_image();
    s.commit_sealed(2, b"one history").unwrap();
    drop(s);
    let guard = sim.guard_value();
    sim.restore_disk(&empty);
    sim.set_guard_value(Some(fly_paycore_store::GuardValue {
        next_seq: 0,
        tail: open_tail(&sim),
    }));
    let mut s = open(&sim).unwrap().store;
    s.commit(2, b"another history").unwrap();
    drop(s);
    sim.set_guard_value(guard);
    assert_eq!(open(&sim).unwrap().guard, GuardCheck::RolledBack);

    // no guard on this device
    let (sim, _, _) = small_journal();
    sim.set_guard_value(None);
    let mut o = open(&sim).unwrap();
    assert_eq!(o.guard, GuardCheck::Missing);
    assert_eq!(
        o.store.commit(1, b"x").unwrap_err(),
        CommitError::RecoveryRequired
    );
    o.store.commit_recovery(b"moved").unwrap();

    // a guard left by an earlier installation, a fresh journal
    let (old, _, _) = small_journal();
    let sim = Sim::new();
    sim.set_guard_value(old.guard_value());
    let s = create(&sim).unwrap();
    assert_eq!(sim.guard_value().unwrap(), s.tail());
    assert_eq!(s.tail().next_seq, 0);

    // recovery frames are refused when nothing is pending
    let (sim, _, _) = small_journal();
    let mut o = open(&sim).unwrap();
    assert!(matches!(
        o.store.commit_recovery(b"x"),
        Err(CommitError::NotWritten(_))
    ));
}

fn open_tail(sim: &Sim) -> [u8; 32] {
    let saved = sim.guard_value();
    sim.set_guard_value(None);
    let t = open(sim).unwrap().store.tail().tail;
    sim.set_guard_value(saved);
    t
}

/// Trace A5 of the model: a frame survives a crash without its guard write,
/// something is disclosed after restart, then the journal is rolled back to
/// a copy taken before that frame. Catching the guard up at open is what
/// makes the rollback visible.
#[test]
fn model_trace_a5_guard_catch_up() {
    let sim = Sim::new();
    let s = create(&sim).unwrap();
    drop(s);
    let backup = sim.disk_image();
    let ops = sim.ops();
    let mut s = open(&sim).unwrap().store;
    // commit_sealed = append, sync, guard store: die after the sync
    sim.set_fault(Some(Fault::CrashAfter(ops + 1)));
    assert_eq!(
        s.commit_sealed(2, b"draft #0").unwrap_err(),
        CommitError::Unknown
    );
    drop(s);
    assert_eq!(
        sim.guard_value().unwrap().next_seq,
        0,
        "guard was not written before the crash"
    );
    sim.reboot(Reboot {
        data: DataLoss::LoseAll,
        keep_dir_changes: false,
    });
    let o = open(&sim).unwrap();
    assert_eq!(o.frames.len(), 1, "the frame was durable");
    assert_eq!(o.guard, GuardCheck::CaughtUp);
    assert_eq!(sim.guard_value().unwrap().next_seq, 1);
    drop(o);
    sim.restore_disk(&backup);
    assert_eq!(open(&sim).unwrap().guard, GuardCheck::RolledBack);
}

/// Rolling back across a checkpoint, and to a state between the rotate frame
/// and the guard update.
#[test]
fn guard_across_generations() {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    s.commit_sealed(2, b"a").unwrap();
    let before = sim.disk_image();
    s.checkpoint(b"state").unwrap();
    s.commit(1, b"b").unwrap();
    drop(s);
    let o = open(&sim).unwrap();
    assert_eq!(
        o.guard,
        GuardCheck::CaughtUp,
        "unsealed frame after the checkpoint"
    );
    assert_eq!(
        o.snapshot.as_deref().map(|s| s.as_slice()),
        Some(&b"state"[..])
    );
    drop(o);
    sim.restore_disk(&before);
    assert_eq!(open(&sim).unwrap().guard, GuardCheck::RolledBack);

    // die at each operation of a checkpoint: the guard never raises a false
    // alarm, and the journal is either before or after the checkpoint
    let mut completed = false;
    for probe in 0..40 {
        let sim = Sim::new();
        let mut s = create(&sim).unwrap();
        s.commit_sealed(2, b"a").unwrap();
        sim.set_fault(Some(Fault::CrashBefore(sim.ops() + probe)));
        let done = s.checkpoint(b"state").is_ok();
        drop(s);
        if done {
            completed = true;
            break;
        }
        sim.reboot(Reboot {
            data: DataLoss::LoseAll,
            keep_dir_changes: false,
        });
        let o = open(&sim).unwrap();
        assert!(
            matches!(o.guard, GuardCheck::Match | GuardCheck::CaughtUp),
            "probe {probe}: {:?}",
            o.guard
        );
        match o.snapshot.as_deref() {
            None => assert_eq!(o.frames.len(), 1, "probe {probe}"),
            Some(st) => {
                assert_eq!(st.as_slice(), b"state", "probe {probe}");
                assert!(o.frames.is_empty(), "probe {probe}");
            }
        }
    }
    assert!(completed);
}

#[test]
fn limits_and_reserved_kinds() {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    let big = vec![0u8; MAX_BODY_LEN + 1];
    assert!(matches!(s.commit(1, &big), Err(CommitError::NotWritten(_))));
    for kind in [0xF0u8, KIND_RECOVERY, 0xFF] {
        assert!(matches!(
            s.commit(kind, b"x"),
            Err(CommitError::NotWritten(_))
        ));
        assert!(matches!(
            s.commit_sealed(kind, b"x"),
            Err(CommitError::NotWritten(_))
        ));
    }
    // refusals leave the journal usable and unchanged
    assert_eq!(s.tail().next_seq, 0);
    s.commit(0xEF, b"highest user kind").unwrap();
    let body = vec![0xABu8; 300_000];
    s.commit(1, &body).unwrap();
    drop(s);
    let o = open(&sim).unwrap();
    assert_eq!(o.frames.len(), 2);
    assert_eq!(o.frames[1].body.as_slice(), &body[..]);
}

#[test]
fn single_writer() {
    let sim = Sim::new();
    let s = create(&sim).unwrap();
    assert!(matches!(open(&sim), Err(OpenError::Locked)));
    assert!(matches!(create(&sim), Err(OpenError::Locked)));
    drop(s);
    let o = open(&sim).unwrap();
    assert!(matches!(open(&sim), Err(OpenError::Locked)));
    drop(o);
    open(&sim).unwrap();
}

/// Frames never repeat a nonce and the same body never encrypts the same way.
#[test]
fn frames_are_randomised() {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    for _ in 0..50 {
        s.commit(1, b"same body").unwrap();
    }
    drop(s);
    let bytes = sim.file("journal-0000000000000000.fly").unwrap();
    let frames: Vec<&[u8]> = bytes[176..].chunks(4 + 65 + 9 + 16).collect();
    assert_eq!(frames.len(), 50);
    let mut nonces = std::collections::BTreeSet::new();
    let mut cts = std::collections::BTreeSet::new();
    for f in frames {
        assert!(nonces.insert(f[45..69].to_vec()));
        assert!(cts.insert(f[69..].to_vec()));
    }
    assert!(
        !bytes.windows(9).any(|w| w == b"same body"),
        "plaintext on disk"
    );
}

/// Random damage (overwrite, insert, delete, append) never makes `open`
/// panic and never yields anything but a prefix of what was written.
#[test]
fn random_damage_never_panics_or_forges() {
    let sim = Sim::new();
    let mut s = create(&sim).unwrap();
    let bodies: Vec<Vec<u8>> = (0u8..12).map(|i| vec![i; usize::from(i) * 7]).collect();
    for b in &bodies {
        s.commit(1, b).unwrap();
    }
    drop(s);
    let name = "journal-0000000000000000.fly";
    let original = sim.file(name).unwrap();
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % (n as u64)) as usize
    };
    let (mut ok, mut err) = (0, 0);
    for _ in 0..20_000 {
        let mut b = original.clone();
        for _ in 0..1 + rnd(3) {
            let at = rnd(b.len());
            match rnd(5) {
                0 => b[at] = rnd(256) as u8,
                1 => {
                    let n = 1 + rnd(40);
                    for (i, v) in b.iter_mut().enumerate().skip(at).take(n) {
                        *v = (i as u8).wrapping_mul(31) ^ (rnd(256) as u8);
                    }
                }
                2 => {
                    b.insert(at, rnd(256) as u8);
                }
                3 => {
                    b.drain(at..(at + 1 + rnd(60)).min(b.len()));
                }
                _ => {
                    let n = rnd(300);
                    b.extend((0..n).map(|i| (i as u8) ^ 0x5A));
                }
            }
        }
        sim.set_file(name, &b);
        sim.set_guard_value(None);
        match open(&sim) {
            Err(_) => err += 1,
            Ok(o) => {
                ok += 1;
                assert!(o.frames.len() <= bodies.len());
                for (f, want) in o.frames.iter().zip(&bodies) {
                    assert_eq!(f.body.as_slice(), &want[..]);
                }
            }
        }
    }
    assert!(ok > 100 && err > 100, "ok {ok} err {err}");
}
