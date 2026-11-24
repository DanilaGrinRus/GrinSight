//! Stage E2 acceptance tests.
use fly_paycore_keys::ledger::{BranchState, LedgerError, PathLedger, MAX_TAG_LEN};
use fly_paycore_keys::path::{classify, KeyPath, STATELESS_MARKER};
use fly_paycore_keys::scan::{origin, rewind, Origin};
use fly_paycore_store::sim::{DataLoss, Fault, Reboot, Sim, SimDir, SimGuard};
use fly_paycore_store::{GuardCheck, Identity, RootKey};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

type L = PathLedger<SimDir, SimGuard>;

fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [7; 32],
        instance: [9; 16],
    }
}
fn key() -> RootKey {
    RootKey::new([0x42; 32])
}
fn create(sim: &Sim) -> Result<L, LedgerError> {
    PathLedger::create(sim.dir(), sim.guard(), &key(), id())
}
fn open(sim: &Sim) -> Result<(L, fly_paycore_keys::ledger::OpenReport), LedgerError> {
    PathLedger::open(sim.dir(), sim.guard(), &key(), id())
}

const EDGE: [u32; 6] = [0, 1, 0x3fff_ffff, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];

fn all_edge_paths() -> Vec<KeyPath> {
    let mut v = vec![];
    for account in [0u32, 1, 7, 0x7fff_ffff] {
        for a in EDGE {
            v.push(KeyPath::Legacy { account, index: a });
            for b in EDGE {
                v.push(KeyPath::Branch {
                    account,
                    branch: a,
                    index: b,
                });
            }
        }
        for r0 in [0u32, 1, (1 << 27) - 1] {
            for r1 in [0u32, 5, 0x7fff_ffff] {
                for r2 in [0u32, 9, 0x7fff_ffff] {
                    v.push(KeyPath::stateless(account, r0, r1, r2).unwrap());
                }
            }
        }
    }
    v
}

#[test]
fn path_classes_roundtrip_and_do_not_overlap() {
    let paths = all_edge_paths();
    let mut ids = BTreeSet::new();
    for p in &paths {
        let id = p.to_identifier();
        assert_eq!(classify(&id), Some(*p), "{p:?}");
        assert!(
            ids.insert(id.to_bytes()),
            "two paths share an identifier: {p:?}"
        );
    }
    assert!(paths.len() > 250);

    // out-of-range stateless components are refused
    assert!(KeyPath::stateless(0, 1 << 27, 0, 0).is_none());
    assert!(KeyPath::stateless(0, 0, 0x8000_0000, 0).is_none());
    assert!(KeyPath::stateless(0, 0, 0, 0x8000_0000).is_none());

    // identifiers of no known class
    let unknown = [
        ExtKeychain::derive_key_id(0, 0, 0, 0, 0),
        ExtKeychain::derive_key_id(1, 3, 0, 0, 0),
        ExtKeychain::derive_key_id(2, 3, 0, 0, 0), // an account path, not an output
        ExtKeychain::derive_key_id(3, 3, 1, 5, 0), // depth 3, second component not 0
        ExtKeychain::derive_key_id(4, 3, 5, 6, 7), // depth 4, no marker
        ExtKeychain::derive_key_id(4, 3, 0x4800_0000, 6, 7), // bit above r0
        ExtKeychain::derive_key_id(4, 3, 0xc000_0001, 6, 7), // hardened second component
        ExtKeychain::derive_key_id(4, 3, STATELESS_MARKER, 0x8000_0000, 7), // hardened r1
        ExtKeychain::derive_key_id(4, 3, STATELESS_MARKER, 6, 0x8000_0000), // hardened r2
    ];
    for u in &unknown {
        assert_eq!(classify(u), None, "{u:?}");
    }
    // non-canonical encodings: depth 3 with a non-zero fourth component, bad depth byte
    let mut raw = ExtKeychain::derive_key_id(4, 0, 0, 5, 6).to_bytes();
    raw[0] = 3;
    assert_eq!(classify(&Identifier::from_bytes(&raw)), None);
    raw[0] = 5;
    assert_eq!(classify(&Identifier::from_bytes(&raw)), None);
    raw[0] = 0xff;
    assert_eq!(classify(&Identifier::from_bytes(&raw)), None);
}

/// The stateless class is byte-for-byte the range of the upstream patch for
/// grin-wallet issue 844: `m/a/(0x40000000 | r0)/r1/r2`.
#[test]
fn stateless_paths_match_the_upstream_range() {
    let p = KeyPath::stateless(2, 0x0123_4567 & ((1 << 27) - 1), 0x1234_5678, 0x7654_3210).unwrap();
    assert_eq!(
        p.to_identifier(),
        ExtKeychain::derive_key_id(
            4,
            2,
            0x4000_0000 | (0x0123_4567 & 0x07ff_ffff),
            0x1234_5678,
            0x7654_3210
        )
    );
    assert_eq!(
        p.account_identifier(),
        ExtKeychain::derive_key_id(2, 2, 0, 0, 0)
    );
    let mut seen = BTreeSet::new();
    for _ in 0..2000 {
        let p = KeyPath::stateless_random(5).unwrap();
        assert_eq!(classify(&p.to_identifier()), Some(p));
        assert!(matches!(p, KeyPath::Stateless { account: 5, .. }));
        assert!(seen.insert(p), "89 random bits repeated");
    }
}

/// Random identifiers: classification never panics, and whatever it accepts
/// encodes back to the same identifier.
#[test]
fn classify_random_identifiers() {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut known = 0;
    for i in 0..200_000u32 {
        let mut raw = [0u8; 17];
        for b in raw.iter_mut() {
            *b = next() as u8;
        }
        // bias towards plausible depths and zero components
        if i % 2 == 0 {
            raw[0] = (next() % 6) as u8;
        }
        if i % 3 == 0 {
            raw[5..9].fill(0);
        }
        if i % 5 == 0 {
            raw[13..17].fill(0);
        }
        let id = Identifier::from_bytes(&raw);
        if let Some(p) = classify(&id) {
            known += 1;
            assert_eq!(p.to_identifier(), id);
        }
    }
    assert!(known > 1000, "{known}");
}

/// Real bulletproofs: an output built on a path of each class rewinds under
/// the owner's seed to exactly that path and amount, and under no other seed.
#[test]
fn real_range_proofs_rewind_to_their_path() {
    let owner = ExtKeychain::from_seed(&[0x11; 32], true).unwrap();
    let stranger = ExtKeychain::from_seed(&[0x22; 32], true).unwrap();
    let builder = ProofBuilder::new(&owner);
    let mut paths = vec![
        KeyPath::Legacy {
            account: 0,
            index: 0,
        },
        KeyPath::Legacy {
            account: 3,
            index: 0xffff_ffff,
        },
        KeyPath::Branch {
            account: 0,
            branch: 0,
            index: 0,
        },
        KeyPath::Branch {
            account: 0,
            branch: 0xffff_ffff,
            index: 0xffff_ffff,
        },
        KeyPath::Branch {
            account: 1,
            branch: 0x8000_0000,
            index: 7,
        },
        KeyPath::Branch {
            account: 0x7fff_ffff,
            branch: 0x1234_5678,
            index: 0x7fff_ffff,
        },
        KeyPath::stateless(0, 0, 0, 0).unwrap(),
        KeyPath::stateless(0, (1 << 27) - 1, 0x7fff_ffff, 0x7fff_ffff).unwrap(),
        KeyPath::stateless(9, 12345, 678, 9).unwrap(),
    ];
    for _ in 0..3 {
        paths.push(KeyPath::stateless_random(0).unwrap());
    }
    let mut state = BranchState::default();
    let _ = &mut state;
    for (n, path) in paths.iter().enumerate() {
        let amount = 1_000_000_007u64 + n as u64;
        let key_id = path.to_identifier();
        let commit = owner
            .commit(amount, &key_id, SwitchCommitmentType::Regular)
            .unwrap();
        let rp = proof::create(
            &owner,
            &builder,
            amount,
            &key_id,
            SwitchCommitmentType::Regular,
            commit,
            None,
        )
        .unwrap();
        proof::verify(owner.secp(), commit, rp, None).unwrap();

        let found = rewind(&owner, commit, rp)
            .unwrap()
            .unwrap_or_else(|| panic!("{path:?} not found"));
        assert_eq!(found.amount, amount, "{path:?}");
        assert_eq!(found.key_id, key_id, "{path:?}");
        assert_eq!(found.path, Some(*path), "{path:?}");

        assert_eq!(
            rewind(&stranger, commit, rp).unwrap(),
            None,
            "{path:?} found by another seed"
        );

        // the proof of one output does not claim another commitment
        let other = owner
            .commit(amount + 1, &key_id, SwitchCommitmentType::Regular)
            .unwrap();
        assert_eq!(rewind(&owner, other, rp).unwrap(), None, "{path:?}");
    }

    // an output on a path of no known class is still ours, with no class
    let odd = ExtKeychain::derive_key_id(4, 0, 5, 6, 7);
    let commit = owner
        .commit(5, &odd, SwitchCommitmentType::Regular)
        .unwrap();
    let rp = proof::create(
        &owner,
        &builder,
        5,
        &odd,
        SwitchCommitmentType::Regular,
        commit,
        None,
    )
    .unwrap();
    let found = rewind(&owner, commit, rp).unwrap().unwrap();
    assert_eq!((found.amount, found.path), (5, None));
}

#[test]
fn origin_follows_the_branch_history() {
    let sim = Sim::new();
    let mut l = create(&sim).unwrap();
    let first = l.issue(0, b"").unwrap().path;
    let backup = sim.disk_image();
    l.issue(0, b"").unwrap();
    drop(l);
    sim.restore_disk(&backup);
    let (mut l, report) = open(&sim).unwrap();
    assert_eq!(report.guard, GuardCheck::RolledBack);
    assert!(report.new_branch);
    let second = l.issue(0, b"").unwrap().path;
    let st = l.state();
    assert_eq!(origin(&second, st), Origin::CurrentBranch);
    assert_eq!(origin(&first, st), Origin::EarlierBranch);
    let KeyPath::Branch { branch, .. } = second else {
        panic!()
    };
    let foreign = KeyPath::Branch {
        account: 0,
        branch: branch.wrapping_add(1) ^ 0x5555,
        index: 0,
    };
    if !st.branches().contains(&(branch.wrapping_add(1) ^ 0x5555)) {
        assert_eq!(origin(&foreign, st), Origin::ForeignBranch);
    }
    assert_eq!(
        origin(&KeyPath::stateless(0, 1, 2, 3).unwrap(), st),
        Origin::Stateless
    );
    assert_eq!(
        origin(
            &KeyPath::Legacy {
                account: 0,
                index: 4
            },
            st
        ),
        Origin::Legacy
    );
}

fn branch_index(p: &KeyPath) -> (u32, u32) {
    match *p {
        KeyPath::Branch { branch, index, .. } => (branch, index),
        _ => panic!("not a branch path"),
    }
}

#[test]
fn issue_is_sequential_and_survives_reopen_and_checkpoint() {
    let sim = Sim::new();
    let mut l = create(&sim).unwrap();
    let branch = l.state().current().unwrap();
    for i in 0..5u32 {
        let p = l.issue(i % 2, b"op").unwrap().path;
        assert_eq!(
            p,
            KeyPath::Branch {
                account: i % 2,
                branch,
                index: i
            }
        );
    }
    l.checkpoint().unwrap();
    assert_eq!(branch_index(&l.issue(0, b"").unwrap().path), (branch, 5));
    drop(l);
    let (mut l, report) = open(&sim).unwrap();
    assert_eq!(report.guard, GuardCheck::Match);
    assert!(!report.new_branch);
    assert_eq!(l.state().branches(), &[branch]);
    assert_eq!(branch_index(&l.issue(0, b"").unwrap().path), (branch, 6));
    assert!(matches!(
        l.issue(0, &[0u8; MAX_TAG_LEN + 1]),
        Err(LedgerError::TagTooLong)
    ));
    assert_eq!(l.state().next_index(), 7);
    assert!(!l.branch_budget_exceeded());
}

/// K7 under crashes: a path that was handed out (the caller received the
/// sealed receipt) is never handed out again, whatever operation the machine
/// dies at and whatever happens to un-synced data.
#[test]
fn no_path_is_issued_twice_across_crashes() {
    fn scenario(sim: &Sim, out: &mut Vec<KeyPath>) -> Result<(), LedgerError> {
        let mut l = create(sim)?;
        for _ in 0..3 {
            out.push(l.issue(0, b"t")?.path);
        }
        l.checkpoint()?;
        for _ in 0..2 {
            out.push(l.issue(1, b"t")?.path);
        }
        Ok(())
    }
    let total = {
        let sim = Sim::new();
        let mut v = vec![];
        scenario(&sim, &mut v).unwrap();
        assert_eq!(v.len(), 5);
        sim.ops()
    };
    let mut runs = 0;
    for op in 0..total {
        for fault in [Fault::CrashBefore(op), Fault::CrashAfter(op)] {
            for data in [
                DataLoss::LoseAll,
                DataLoss::KeepAll,
                DataLoss::Torn(7),
                DataLoss::Torn(70),
                DataLoss::Zeros,
                DataLoss::Garbage,
            ] {
                for keep_dir_changes in [false, true] {
                    let ctx = format!("{fault:?} {data:?} {keep_dir_changes}");
                    let sim = Sim::new();
                    sim.set_fault(Some(fault));
                    let mut issued = vec![];
                    let _ = scenario(&sim, &mut issued);
                    sim.reboot(Reboot {
                        data,
                        keep_dir_changes,
                    });
                    runs += 1;
                    let mut l = match open(&sim) {
                        Ok((l, report)) => {
                            assert!(!report.guard.recovery_required(), "{ctx}: false alarm");
                            l
                        }
                        Err(e) => {
                            assert!(issued.is_empty(), "{ctx}: {e:?} after paths were issued");
                            create(&sim).unwrap_or_else(|e| panic!("{ctx}: {e:?}"))
                        }
                    };
                    for _ in 0..3 {
                        issued.push(
                            l.issue(0, b"after")
                                .unwrap_or_else(|e| panic!("{ctx}: {e:?}"))
                                .path,
                        );
                    }
                    let unique: BTreeSet<(u32, u32)> = issued.iter().map(branch_index).collect();
                    assert_eq!(
                        unique.len(),
                        issued.len(),
                        "{ctx}: a path was issued twice: {issued:?}"
                    );
                }
            }
        }
    }
    println!("path crash matrix: {runs} runs over {total} operations");
}

/// K7/K15 under rollback and move: after the journal is replaced by an older
/// copy, or opened on a device without its guard, paths come from a new
/// branch and never repeat an issued one (model variants A2, A5).
#[test]
fn rollback_or_move_opens_a_new_branch() {
    let mut all: Vec<KeyPath> = vec![];
    let sim = Sim::new();
    let mut l = create(&sim).unwrap();
    all.push(l.issue(0, b"").unwrap().path);
    let mut branches = BTreeSet::new();
    branches.insert(l.state().current().unwrap());
    for round in 0..60 {
        let backup = sim.disk_image();
        for _ in 0..2 {
            all.push(l.issue(0, b"").unwrap().path);
        }
        drop(l);
        if round % 3 == 2 {
            sim.set_guard_value(None); // moved to another device
        } else {
            sim.restore_disk(&backup); // rolled back
        }
        let (reopened, report) = open(&sim).unwrap();
        l = reopened;
        assert!(
            report.guard.recovery_required(),
            "round {round}: {:?}",
            report.guard
        );
        assert!(report.new_branch);
        assert!(
            branches.insert(l.state().current().unwrap()),
            "round {round}: branch id reused"
        );
        assert_eq!(l.state().next_index(), 0);
        all.push(l.issue(0, b"").unwrap().path);
    }
    let unique: BTreeSet<(u32, u32)> = all.iter().map(branch_index).collect();
    assert_eq!(unique.len(), all.len());
    assert_eq!(l.state().branches().len(), 61);
    drop(l);
    // a clean reopen changes nothing
    let (l, report) = open(&sim).unwrap();
    assert!(!report.new_branch);
    assert!(matches!(report.guard, GuardCheck::Match));
    let _ = l;
}

/// Two threads cannot obtain the same index.
#[test]
fn concurrent_issue_never_collides() {
    let sim = Sim::new();
    let ledger = Arc::new(Mutex::new(create(&sim).unwrap()));
    let mut handles = vec![];
    for t in 0..4u32 {
        let ledger = Arc::clone(&ledger);
        handles.push(std::thread::spawn(move || {
            let mut mine = vec![];
            for _ in 0..50 {
                mine.push(ledger.lock().unwrap().issue(t, b"thread").unwrap().path);
            }
            mine
        }));
    }
    let mut all = vec![];
    for h in handles {
        all.extend(h.join().unwrap());
    }
    let idx: BTreeSet<u32> = all.iter().map(|p| branch_index(p).1).collect();
    assert_eq!(idx.len(), 200);
    assert_eq!(idx.iter().next_back(), Some(&199));
    // a second handle on the same journal is refused outright
    assert!(matches!(
        open(&sim),
        Err(LedgerError::Open(fly_paycore_store::OpenError::Locked))
    ));
}

/// Journal content that breaks the ledger's rules is refused, not repaired.
#[test]
fn inconsistent_journal_content_is_refused() {
    use fly_paycore_keys::ledger::{KIND_BRANCH_OPEN, KIND_PATH_ISSUED};
    use fly_paycore_store::Store;
    type Frames = Vec<(u8, Vec<u8>)>;
    let cases: Vec<(&str, Frames)> = vec![
        (
            "index gap",
            vec![
                (KIND_BRANCH_OPEN, vec![1, 0, 0, 0]),
                (
                    KIND_PATH_ISSUED,
                    [&[1u8, 0, 0, 0][..], &[1, 0, 0, 0], &[0; 4]].concat(),
                ),
            ],
        ),
        (
            "wrong branch",
            vec![
                (KIND_BRANCH_OPEN, vec![1, 0, 0, 0]),
                (
                    KIND_PATH_ISSUED,
                    [&[2u8, 0, 0, 0][..], &[0; 4], &[0; 4]].concat(),
                ),
            ],
        ),
        (
            "issued before any branch",
            vec![(KIND_PATH_ISSUED, vec![0; 12])],
        ),
        (
            "branch opened twice",
            vec![
                (KIND_BRANCH_OPEN, vec![1, 0, 0, 0]),
                (KIND_BRANCH_OPEN, vec![1, 0, 0, 0]),
            ],
        ),
        ("short body", vec![(KIND_BRANCH_OPEN, vec![1, 0, 0])]),
        (
            "trailing bytes",
            vec![(KIND_BRANCH_OPEN, vec![1, 0, 0, 0, 0])],
        ),
        (
            "oversized tag",
            vec![
                (KIND_BRANCH_OPEN, vec![1, 0, 0, 0]),
                (KIND_PATH_ISSUED, vec![0; 12 + MAX_TAG_LEN + 1]),
            ],
        ),
        (
            "foreign frame kind",
            vec![(KIND_BRANCH_OPEN, vec![1, 0, 0, 0]), (0x77, vec![])],
        ),
    ];
    for (name, frames) in cases {
        let sim = Sim::new();
        let mut s = Store::create(sim.dir(), sim.guard(), &key(), id()).unwrap();
        for (kind, body) in &frames {
            s.commit_sealed(*kind, body).unwrap();
        }
        drop(s);
        assert!(matches!(open(&sim), Err(LedgerError::Corrupt)), "{name}");
    }
    for bad in [
        &[][..],
        &[1, 0, 0, 0][..],
        &[2, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0][..],
        &[0xff; 8][..],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0][..],
    ] {
        assert!(BranchState::decode(bad).is_err(), "{bad:?}");
    }
    let ok = BranchState::decode(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(BranchState::decode(&ok.encode()).unwrap(), ok);
}
