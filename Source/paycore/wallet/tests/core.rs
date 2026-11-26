//! Stages E3-E5 and E7: send, receive with a draft, stateless receive,
//! statuses. The counterparty in the interoperability tests is the real
//! `grin_wallet_libwallet` 5.5.1 with its own LMDB backend.
use fly_paycore_keys::path::{classify, KeyPath};
use fly_paycore_store::sim::{DataLoss, Fault, Reboot, Sim, SimDir, SimGuard};
use fly_paycore_store::{GuardCheck, Identity, RootKey};
use fly_paycore_wallet::{
    Advance, ChainState, Core, CoreError, DeliveryNote, DeliveryStatus, Envelope, OpId, Row,
    SendStatus, MAX_ENVELOPE_LEN, MAX_OPEN_DRAFTS, R_UNDO,
};
use grin_core::core::transaction::{Transaction, Weighting};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_core::ser;
use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::Commitment;
use grin_wallet_libwallet::api_impl::{foreign, owner};
use grin_wallet_libwallet::{
    Error as LwError, InitTxArgs, NodeClient, NodeVersionInfo, OutputData, OutputStatus, Slate,
    SlateVersion, SlatepackAddress, VersionedSlate, WalletBackend,
};
use std::collections::HashMap;

type C = Core<SimDir, SimGuard, ExtKeychain>;
const MATURITY: u64 = 3;
const GRIN: u64 = 1_000_000_000;

fn net() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
}
fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [7; 32],
        instance: [9; 16],
    }
}
fn root() -> RootKey {
    RootKey::new([0x42; 32])
}
fn kc(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], true).unwrap()
}
fn create(sim: &Sim, seed: u8) -> C {
    Core::create(sim.dir(), sim.guard(), &root(), id(), kc(seed), 0, MATURITY).unwrap()
}
fn open(sim: &Sim, seed: u8) -> (C, fly_paycore_wallet::OpenReport) {
    Core::open(sim.dir(), sim.guard(), &root(), id(), kc(seed), MATURITY).unwrap()
}

/// A toy chain: only what the wallets need to be told.
struct Chain {
    height: u64,
    pos: u64,
    legacy: u32,
}
impl Chain {
    fn new() -> Chain {
        Chain {
            height: 0,
            pos: 0,
            legacy: 0,
        }
    }
    fn block(&mut self, a: &mut Advance) {
        self.height += 1;
        a.height = self.height;
        a.hash = [self.height as u8; 32];
        a.hash[1] = (self.height >> 8) as u8;
    }
    /// Give `seed` plain outputs of the given values on old-style paths.
    fn fund(&mut self, wallets: &mut [&mut C], seed: u8, values: &[u64]) -> Vec<Commitment> {
        let k = kc(seed);
        let b = ProofBuilder::new(&k);
        let mut a = Advance::default();
        let mut commits = vec![];
        for v in values {
            let key = KeyPath::Legacy {
                account: 0,
                index: self.legacy,
            }
            .to_identifier();
            self.legacy += 1;
            let commit = k.commit(*v, &key, SwitchCommitmentType::Regular).unwrap();
            let rp = proof::create(
                &k,
                &b,
                *v,
                &key,
                SwitchCommitmentType::Regular,
                commit,
                None,
            )
            .unwrap();
            self.pos += 1;
            a.outputs.push((commit, rp, self.pos, false));
            commits.push(commit);
        }
        self.block(&mut a);
        for w in wallets.iter_mut() {
            w.chain_advance(&a).unwrap();
        }
        commits
    }
    fn advance_of(&mut self, tx: &[u8]) -> Advance {
        let tx: Transaction = ser::deserialize(
            &mut &tx[..],
            ser::ProtocolVersion::local(),
            ser::DeserializationMode::default(),
        )
        .unwrap();
        tx.validate(Weighting::AsTransaction).unwrap();
        let mut a = Advance::default();
        for o in tx.outputs() {
            self.pos += 1;
            a.outputs.push((o.commitment(), o.proof, self.pos, false));
        }
        let ins: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
        a.inputs = ins.iter().map(|c| c.commitment()).collect();
        a.kernels = tx.kernels().iter().map(|k| k.excess).collect();
        self.block(&mut a);
        a
    }
    fn mine(&mut self, wallets: &mut [&mut C], tx: &[u8]) {
        let a = self.advance_of(tx);
        for w in wallets.iter_mut() {
            w.chain_advance(&a).unwrap();
        }
    }
    fn empty(&mut self, wallets: &mut [&mut C], n: u64) {
        for _ in 0..n {
            let mut a = Advance::default();
            self.block(&mut a);
            for w in wallets.iter_mut() {
                w.chain_advance(&a).unwrap();
            }
        }
    }
}

// ----- the real grin-wallet library as counterparty -----------------------

#[derive(Clone)]
struct Node(u64);
fn na() -> LwError {
    LwError::GenericError("test node".into())
}
impl NodeClient for Node {
    fn node_url(&self) -> &str {
        ""
    }
    fn set_node_url(&mut self, _: &str) {}
    fn node_api_secret(&self) -> Option<String> {
        None
    }
    fn set_node_api_secret(&mut self, _: Option<String>) {}
    fn post_tx(&self, _: &Transaction, _: bool) -> Result<(), LwError> {
        Err(na())
    }
    fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
        None
    }
    fn get_chain_tip(&self) -> Result<(u64, String), LwError> {
        Ok((self.0, String::new()))
    }
    fn get_kernel(
        &mut self,
        _: &Commitment,
        _: Option<u64>,
        _: Option<u64>,
    ) -> Result<Option<(grin_core::core::TxKernel, u64, u64)>, LwError> {
        Err(na())
    }
    fn get_outputs_from_node(
        &self,
        _: Vec<Commitment>,
    ) -> Result<HashMap<Commitment, (String, u64, u64)>, LwError> {
        Err(na())
    }
    fn get_outputs_by_pmmr_index(
        &self,
        _: u64,
        _: Option<u64>,
        _: u64,
    ) -> Result<
        (
            u64,
            u64,
            Vec<(
                Commitment,
                grin_util::secp::pedersen::RangeProof,
                bool,
                u64,
                u64,
            )>,
        ),
        LwError,
    > {
        Err(na())
    }
    fn height_range_to_pmmr_indices(&self, _: u64, _: Option<u64>) -> Result<(u64, u64), LwError> {
        Err(na())
    }
}

struct Lw {
    w: WalletBackend<Node, ExtKeychain>,
    dir: std::path::PathBuf,
}
impl Drop for Lw {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn lw(seed: u8, tip: u64) -> Lw {
    let mut r = [0u8; 8];
    getrandom(&mut r);
    let dir = std::env::temp_dir().join(format!("fly-paycore-lw-{}", u64::from_le_bytes(r)));
    std::fs::create_dir_all(&dir).unwrap();
    let mut w = WalletBackend::new(dir.to_str().unwrap(), Node(tip)).unwrap();
    w.set_keychain(kc(seed), false, false).unwrap();
    Lw { w, dir }
}
fn getrandom(b: &mut [u8]) {
    getrandom::getrandom(b).unwrap();
}
fn to_json(s: &Slate) -> Vec<u8> {
    serde_json::to_vec(&VersionedSlate::into_version(s.clone(), SlateVersion::V4).unwrap()).unwrap()
}
fn from_json(b: &[u8]) -> Slate {
    Slate::deserialize_upgrade(std::str::from_utf8(b).unwrap()).unwrap()
}
/// Give the library wallet a spendable output it believes is confirmed.
fn lw_fund(l: &mut Lw, value: u64, n: u32) -> Commitment {
    let parent = WalletBackend::<Node, ExtKeychain>::default_path();
    let key = ExtKeychain::derive_key_id(3, 0, 0, n, 0);
    let k = l.w.keychain(None).unwrap();
    let commit = k
        .commit(value, &key, SwitchCommitmentType::Regular)
        .unwrap();
    let mut batch = l.w.batch(None).unwrap();
    batch
        .save(OutputData {
            root_key_id: parent,
            key_id: key,
            n_child: n,
            commit: Some(grin_util::ToHex::to_hex(&commit.0.to_vec())),
            mmr_index: None,
            value,
            status: OutputStatus::Unspent,
            height: 1,
            lock_height: 0,
            is_coinbase: false,
            tx_log_entry: None,
        })
        .unwrap();
    batch.commit().unwrap();
    commit
}
fn tx_bytes(s: &Slate) -> Vec<u8> {
    ser::ser_vec(s.tx_or_err().unwrap(), ser::ProtocolVersion::local()).unwrap()
}

// ----- sending ------------------------------------------------------------

struct Setup {
    sim: Sim,
    chain: Chain,
    core: C,
}
fn funded(seed: u8, values: &[u64]) -> Setup {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, seed);
    let mut chain = Chain::new();
    chain.fund(&mut [&mut core], seed, values);
    chain.empty(&mut [&mut core], 1);
    Setup { sim, chain, core }
}

/// Our send, received by grin-wallet the ordinary way and the stateless way;
/// the transaction validates, confirms, and the change is bound to its record.
#[test]
fn send_to_grin_wallet_both_receive_modes() {
    for stateless in [false, true] {
        let Setup {
            sim: _sim,
            mut chain,
            mut core,
        } = funded(1, &[5 * GRIN, 3 * GRIN]);
        assert_eq!(core.balance().spendable, 8 * GRIN);
        let p = core.send_prepare(2 * GRIN, 0, None, false).unwrap();
        assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
        let bal = core.balance();
        assert!(bal.reserved > 0 && bal.spendable + bal.reserved == 8 * GRIN);

        let mut other = lw(2, chain.height);
        let s1 = from_json(&p.s1);
        let s2 = if stateless {
            foreign::receive_tx_stateless(&mut other.w, None, &s1, None, None, false).unwrap()
        } else {
            foreign::receive_tx(&mut other.w, None, &s1, None, false).unwrap()
        };
        let fin = core.send_finalize(&p.op, &to_json(&s2)).unwrap();
        assert_eq!(core.signatures_made(), 1);
        assert_eq!(core.send_status(&p.op), Some(SendStatus::Finalized));

        chain.mine(&mut [&mut core], &fin.tx);
        assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));
        let bal = core.balance();
        assert_eq!(bal.reserved, 0);
        let fee = 8 * GRIN - 2 * GRIN - bal.spendable;
        assert!(fee > 0 && fee < GRIN / 10, "fee {fee}");
        // the change sits on a path of the instance branch
        let k = kc(1);
        let change = core
            .unspent()
            .into_iter()
            .find(|(_, v)| *v != 5 * GRIN && *v != 3 * GRIN)
            .unwrap();
        let branch = core.branches().current().unwrap();
        let expect = KeyPath::Branch {
            account: 0,
            branch,
            index: 0,
        };
        assert_eq!(
            k.commit(
                change.1,
                &expect.to_identifier(),
                SwitchCommitmentType::Regular
            )
            .unwrap()
            .0,
            change.0
        );
        // a record bound by joint inclusion has no "unrecorded" row
        assert_eq!(
            core.unrecorded_output_row(&change.0, ChainState::AtTip),
            None
        );
    }
}

/// K1: the same S2 again returns the stored result without signing; another
/// S2 is refused; cancelling after signing is refused.
#[test]
fn second_s2_is_refused_and_replay_does_not_sign() {
    let Setup {
        sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let mut other = lw(2, chain.height);
    let s1 = from_json(&p.s1);
    let a = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &s1, None, None, false).unwrap(),
    );
    let b = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &s1, None, None, false).unwrap(),
    );
    assert_ne!(a, b);
    let fin = core.send_finalize(&p.op, &a).unwrap();
    assert_eq!(core.send_finalize(&p.op, &a).unwrap(), fin);
    assert_eq!(
        core.send_finalize(&p.op, &b).unwrap_err(),
        CoreError::Conflict
    );
    assert_eq!(core.signatures_made(), 1);
    assert!(matches!(
        core.send_cancel(&p.op),
        Err(CoreError::Refused(_))
    ));
    // and after a restart
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.send_finalize(&p.op, &a).unwrap(), fin);
    assert_eq!(
        core.send_finalize(&p.op, &b).unwrap_err(),
        CoreError::Conflict
    );
    assert_eq!(core.signatures_made(), 0);
}

#[test]
fn cancel_releases_inputs_and_blocks_signing() {
    let Setup {
        sim: _s,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    assert_eq!(core.balance().spendable, 0);
    assert!(matches!(
        core.send_prepare(GRIN, 0, None, false),
        Err(CoreError::InsufficientFunds)
    ));
    core.send_cancel(&p.op).unwrap();
    assert_eq!(core.balance().spendable, 5 * GRIN);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Cancelled));
    let mut other = lw(2, chain.height);
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false)
            .unwrap(),
    );
    assert!(matches!(
        core.send_finalize(&p.op, &s2),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(core.signatures_made(), 0);
    // the released input can be used again, on the next change path
    let q = core.send_prepare(GRIN, 0, None, false).unwrap();
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&q.s1), None, None, false)
            .unwrap(),
    );
    core.send_finalize(&q.op, &s2).unwrap();
}

#[test]
fn malformed_and_mismatched_s2_are_rejected_before_arming() {
    let Setup {
        sim: _s,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let q = {
        // a second operation to borrow a foreign S2 from
        let Setup {
            sim: _s2,
            chain: c2,
            core: mut other_core,
        } = funded(3, &[5 * GRIN]);
        let q = other_core.send_prepare(GRIN, 0, None, false).unwrap();
        let mut other = lw(2, c2.height);
        to_json(
            &foreign::receive_tx_stateless(
                &mut other.w,
                None,
                &from_json(&q.s1),
                None,
                None,
                false,
            )
            .unwrap(),
        )
    };
    let mut other = lw(2, chain.height);
    let good =
        foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false)
            .unwrap();
    let mut tampered = good.clone();
    tampered.participant_data[0].part_sig = good.participant_data[0].part_sig.map(|_| {
        let mut other2 = lw(4, chain.height);
        foreign::receive_tx_stateless(&mut other2.w, None, &from_json(&p.s1), None, None, false)
            .unwrap()
            .participant_data[0]
            .part_sig
            .unwrap()
    });
    for (name, bytes) in [
        ("garbage", b"not a slate".to_vec()),
        ("empty", vec![]),
        ("S1 instead of S2", p.s1.clone()),
        ("S2 of another deal", q),
        ("signature of another recipient", to_json(&tampered)),
        ("oversized", vec![b' '; 70_000]),
    ] {
        assert!(
            matches!(
                core.send_finalize(&p.op, &bytes),
                Err(CoreError::BadSlate(_))
            ),
            "{name}"
        );
    }
    assert_eq!(
        core.send_status(&p.op),
        Some(SendStatus::Prepared),
        "a rejected S2 must not arm the operation"
    );
    assert_eq!(core.signatures_made(), 0);
    core.send_finalize(&p.op, &to_json(&good)).unwrap();
    assert_eq!(
        core.send_finalize(&[0u8; 16], &to_json(&good)).unwrap_err(),
        CoreError::NotFound
    );
}

/// K1, K2, K6 under crashes: die at every storage operation of the
/// finalization. Across the crash the operation is signed at most once, a
/// stored result is valid and is returned without signing, and an armed
/// operation without a result is never signed again.
#[test]
fn crash_at_every_operation_of_finalize() {
    net();
    let mut outcomes = std::collections::BTreeMap::new();
    for probe in 0..12u64 {
        for after in [false, true] {
            for data in [
                DataLoss::LoseAll,
                DataLoss::KeepAll,
                DataLoss::Torn(40),
                DataLoss::Garbage,
            ] {
                let Setup {
                    sim,
                    chain,
                    mut core,
                } = funded(1, &[5 * GRIN]);
                let p = core.send_prepare(GRIN, 0, None, false).unwrap();
                let mut other = lw(2, chain.height);
                let s2 = to_json(
                    &foreign::receive_tx_stateless(
                        &mut other.w,
                        None,
                        &from_json(&p.s1),
                        None,
                        None,
                        false,
                    )
                    .unwrap(),
                );
                let n = sim.ops() + probe;
                sim.set_fault(Some(if after {
                    Fault::CrashAfter(n)
                } else {
                    Fault::CrashBefore(n)
                }));
                let first = core.send_finalize(&p.op, &s2);
                let signs_before = core.signatures_made();
                let crashed = sim.crashed();
                drop(core);
                if !crashed {
                    assert!(first.is_ok());
                    continue;
                }
                assert!(
                    first.is_err(),
                    "a result was returned although the machine died"
                );
                sim.reboot(Reboot {
                    data,
                    keep_dir_changes: true,
                });
                let (mut core, report) = open(&sim, 1);
                assert!(
                    !report.recovered,
                    "probe {probe}: false alarm {:?}",
                    report.guard
                );
                let status = core.send_status(&p.op).unwrap();
                let second = core.send_finalize(&p.op, &s2);
                let total = signs_before + core.signatures_made();
                assert!(
                    total <= 1,
                    "probe {probe} after={after} {data:?}: signed {total} times"
                );
                match status {
                    SendStatus::Prepared => {
                        // the choice of S2 never became durable, so nothing was signed
                        assert_eq!(signs_before, 0);
                        second.unwrap();
                    }
                    SendStatus::Unknown => {
                        assert_eq!(second.unwrap_err(), CoreError::UnknownOutcome);
                        assert_eq!(core.signatures_made(), 0);
                        assert!(core.balance().reserved > 0, "reserve must stay");
                        assert!(matches!(
                            core.send_cancel(&p.op),
                            Err(CoreError::Refused(_))
                        ));
                    }
                    SendStatus::Finalized => {
                        let fin = second.unwrap();
                        assert_eq!(core.signatures_made(), 0);
                        let tx: Transaction = ser::deserialize(
                            &mut &fin.tx[..],
                            ser::ProtocolVersion::local(),
                            ser::DeserializationMode::default(),
                        )
                        .unwrap();
                        tx.validate(Weighting::AsTransaction).unwrap();
                    }
                    other => panic!("unexpected status {other:?}"),
                }
                *outcomes.entry(format!("{status:?}")).or_insert(0u32) += 1;
            }
        }
    }
    println!("finalize crash matrix: {outcomes:?}");
    assert_eq!(
        outcomes.len(),
        3,
        "all three outcomes must occur: {outcomes:?}"
    );
}

/// K15/K16: the journal is rolled back to a copy taken before signing. The
/// operation is locked, the next path comes from a new branch.
#[test]
fn rollback_locks_prepared_operations() {
    let Setup {
        sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN, 4 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    // a payment cancelled before the copy was taken: cancelled it stays
    let gone = core.send_prepare(GRIN, 0, None, false).unwrap();
    core.send_cancel(&gone.op).unwrap();
    let old_branch = core.branches().current().unwrap();
    let backup = sim.disk_image();
    let mut other = lw(2, chain.height);
    let s1 = from_json(&p.s1);
    let a = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &s1, None, None, false).unwrap(),
    );
    let b = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &s1, None, None, false).unwrap(),
    );
    core.send_finalize(&p.op, &a).unwrap();
    drop(core);

    sim.restore_disk(&backup);
    let (mut core, report) = open(&sim, 1);
    assert_eq!(report.guard, GuardCheck::RolledBack);
    assert!(report.recovered);
    // the context is still in the journal, but must never sign again
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    for s2 in [&a, &b] {
        assert!(matches!(
            core.send_finalize(&p.op, s2),
            Err(CoreError::Refused(_))
        ));
    }
    assert_eq!(core.signatures_made(), 0);
    assert!(
        core.balance().reserved > 0,
        "the reserve of a locked operation stays"
    );
    assert_ne!(core.branches().current().unwrap(), old_branch);
    // a new operation works and uses the new branch
    let q = core.send_prepare(GRIN, 0, None, false).unwrap();
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&q.s1), None, None, false)
            .unwrap(),
    );
    core.send_finalize(&q.op, &s2).unwrap();

    // The locked payment was in fact signed in the part of the journal that
    // was lost. It is not "cancelled": an ordinary cancel is refused and the
    // reserve stays.
    assert!(core.send_locked(&p.op) && !core.send_locked(&q.op) && !core.send_locked(&gone.op));
    let before = (core.journal_tail(), core.balance());
    assert_eq!(
        core.send_cancel(&p.op),
        Err(CoreError::Refused("operation is locked after a detected rollback"))
    );
    assert_eq!((core.journal_tail(), core.balance()), before);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    // A public chain status changes on a fork, but it cannot grant
    // authority to cancel a payment locked at profile recovery.
    let height_before_conflict = chain.height;
    let mut projected = Advance {
        inputs: core.unspent().into_iter().map(|(bytes, _)| Commitment(bytes)).collect(),
        ..Advance::default()
    };
    let mut branch = Chain::new();
    branch.height = height_before_conflict;
    branch.block(&mut projected);
    assert!(core.chain_advance(&projected).is_ok());
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    let contested = core.journal_tail();
    assert!(core.send_cancel(&p.op).is_err());
    assert_eq!(core.journal_tail(), contested);
    assert!(core.chain_rollback(height_before_conflict).is_ok());
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    assert_eq!(core.balance(), before.1);
    // only a locked payment is given up this way
    for other_op in [&q.op, &gone.op] {
        assert_eq!(
            core.send_release_locked(other_op),
            Err(CoreError::Refused("operation is not locked"))
        );
    }
    assert_eq!(core.send_release_locked(&[9u8; 16]), Err(CoreError::NotFound));
    // The user gives it up: the reserve goes, and the payment is called
    // what it is - released, possibly signed - never cancelled.
    let reserved = core.balance().reserved;
    core.send_release_locked(&p.op).unwrap();
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Released));
    assert!(core.balance().reserved < reserved);
    assert!(!core.send_locked(&p.op));
    assert_eq!(core.signatures_made(), 1, "only the new payment was signed here");
    for s2 in [&a, &b] {
        assert!(matches!(core.send_finalize(&p.op, s2), Err(CoreError::Refused(_))));
    }
    assert!(matches!(core.send_release_locked(&p.op), Err(CoreError::Refused(_))));
    assert!(matches!(core.send_cancel(&p.op), Err(CoreError::Refused(_))));
    assert!(matches!(core.prepared_s1(&p.op), Err(CoreError::Refused(_))));
    // what was cancelled before the rollback is cancelled, not released
    assert_eq!(core.send_status(&gone.op), Some(SendStatus::Cancelled));
    drop(core);
    let (core, _) = open(&sim, 1);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Released));
    assert_eq!(core.send_status(&gone.op), Some(SendStatus::Cancelled));
}

/// K3, K17: another transaction spends one input of a signed payment.
/// K196: the standing word to take small outputs along is for a new,
/// ordinary payment: a payment locked late reserves nothing and its fee
/// is reckoned as before, and the replacement of a contested payment
/// spends what it has to and no more.
#[test]
fn small_outputs_go_only_with_an_ordinary_payment() {
    let small = |core: &C| core.outputs().into_iter().find(|o| o.value == GRIN / 10).map(|o| o.reserved);
    let fee_of = |core: &C, op: &OpId| core.sends().into_iter().find(|s| s.0 == *op).map(|s| s.3);

    let Setup { mut core, .. } = funded(1, &[5 * GRIN, GRIN / 10]);
    let plain = core.send_prepare_late(GRIN, 0, None).unwrap();
    let plain_fee = fee_of(&core, &plain.op);
    core.send_cancel(&plain.op).unwrap();
    core.set_gather(8);
    let late = core.send_prepare_late(GRIN, 0, None).unwrap();
    assert_eq!(fee_of(&core, &late.op), plain_fee);
    assert_eq!(small(&core), Some(false));
    core.send_cancel(&late.op).unwrap();
    let ordinary = core.send_prepare(GRIN, 0, None, false).unwrap();
    assert_eq!(small(&core), Some(true), "an ordinary payment does take it");
    core.send_cancel(&ordinary.op).unwrap();

    let Setup { mut chain, mut core, .. } = funded(1, &[2 * GRIN, 2 * GRIN, 5 * GRIN, GRIN / 10]);
    let p = core.send_prepare(6 * GRIN, 0, None, false).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = to_json(&foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false).unwrap());
    let fin = core.send_finalize(&p.op, &s2).unwrap();
    let tx: Transaction = ser::deserialize(&mut &fin.tx[..], ser::ProtocolVersion::local(), ser::DeserializationMode::default()).unwrap();
    let ins: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
    let mut a = Advance { inputs: vec![ins[0].commitment()], ..Advance::default() };
    chain.block(&mut a);
    core.chain_advance(&a).unwrap();
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    assert_eq!(small(&core), Some(false));
    core.set_gather(8);
    core.send_prepare(GRIN / 2, 0, Some(p.op), false).unwrap();
    assert_eq!(small(&core), Some(false));
}

#[test]
fn contested_operation_replacement_and_death() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[2 * GRIN, 2 * GRIN, 5 * GRIN]);
    let funds = core.unspent();
    // the two 2-grin outputs are needed together for 3 grin... the largest is
    // picked first, so drain it into a pending operation's sibling instead
    let p = core.send_prepare(6 * GRIN, 0, None, false).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false)
            .unwrap(),
    );
    let fin = core.send_finalize(&p.op, &s2).unwrap();
    let tx: Transaction = ser::deserialize(
        &mut &fin.tx[..],
        ser::ProtocolVersion::local(),
        ser::DeserializationMode::default(),
    )
    .unwrap();
    let ins: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
    assert!(ins.len() >= 2);
    let reserved_before = core.balance().reserved;

    // a clone of the wallet spends one of the inputs in some other transaction
    let stolen = ins[0].commitment();
    let mut a = Advance {
        inputs: vec![stolen],
        ..Advance::default()
    };
    chain.block(&mut a);
    core.chain_advance(&a).unwrap();
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    assert!(
        core.balance().reserved > 0 && core.balance().reserved < reserved_before,
        "the other inputs stay reserved"
    );

    // paying again is refused unless it is a replacement or explicitly not a repeat
    assert!(matches!(
        core.send_prepare(GRIN / 2, 0, None, false),
        Err(CoreError::Refused(_))
    ));
    let spare = core.balance().spendable;
    if spare > GRIN {
        let unrelated = core.send_prepare(GRIN / 2, 0, None, true).unwrap();
        core.send_cancel(&unrelated.op).unwrap();
    }
    let r = core.send_prepare(GRIN / 2, 0, Some(p.op), false).unwrap();
    let s2r = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&r.s1), None, None, false)
            .unwrap(),
    );
    let finr = core.send_finalize(&r.op, &s2r).unwrap();
    let txr: Transaction = ser::deserialize(
        &mut &finr.tx[..],
        ser::ProtocolVersion::local(),
        ser::DeserializationMode::default(),
    )
    .unwrap();
    let insr: Vec<grin_core::core::transaction::CommitWrapper> = txr.inputs().into();
    let shared = insr
        .iter()
        .filter(|c| ins.iter().any(|d| d.commitment() == c.commitment()))
        .count();
    assert!(
        shared >= 1,
        "the replacement must spend an input of the contested payment"
    );
    assert!(
        matches!(
            core.send_prepare(GRIN / 2, 0, Some(r.op), false),
            Err(CoreError::Refused(_))
        ),
        "only a contested operation can be replaced"
    );

    // a reorg removes the foreign spend: the reserve is back in the same event
    core.chain_rollback(chain.height - 1).unwrap();
    chain.height -= 1;
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Finalized));
    assert_eq!(core.unspent().len(), funds.len());
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Finalized));

    // the foreign spend comes back and gets R_UNDO deep: the payment is dead
    let mut a = Advance {
        inputs: vec![stolen],
        ..Advance::default()
    };
    chain.block(&mut a);
    core.chain_advance(&a).unwrap();
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    chain.empty(&mut [&mut core], R_UNDO - 2);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    chain.empty(&mut [&mut core], 1);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Dead));
}

// ----- receiving ----------------------------------------------------------

/// grin-wallet sends to us with a payment proof (its default for Slatepack
/// addresses) and without; it verifies our signature while finalizing.
#[test]
fn receive_draft_from_grin_wallet_with_and_without_payment_proof() {
    for with_proof in [true, false] {
        net();
        let sim = Sim::new();
        let mut core = create(&sim, 5);
        let mut chain = Chain::new();
        chain.empty(&mut [&mut core], 3);
        let mut sender = lw(6, chain.height);
        lw_fund(&mut sender, 10 * GRIN, 0);
        let address = ed25519_public(&core.receive_address().unwrap());
        let args = InitTxArgs {
            amount: 3 * GRIN,
            minimum_confirmations: 1,
            max_outputs: 500,
            num_change_outputs: 1,
            selection_strategy_is_use_all: false,
            refresh_outputs_from_node: false,
            payment_proof_recipient_address: if with_proof { Some(address) } else { None },
            ..Default::default()
        };
        let s1 = owner::init_send_tx(&mut sender.w, None, args, false).unwrap();
        assert_eq!(s1.payment_proof.is_some(), with_proof);
        let s1_bytes = to_json(&s1);
        let tail = core.journal_tail();
        let s2 = core.receive_draft(&s1_bytes, Some(1_000)).unwrap();
        assert_eq!(
            core.journal_tail().next_seq,
            tail.next_seq + 1,
            "exactly one frame"
        );

        // K12: the same request again gives the same bytes and writes nothing
        assert_eq!(core.receive_draft(&s1_bytes, Some(2_000)).unwrap(), s2);
        assert_eq!(core.journal_tail().next_seq, tail.next_seq + 1);
        let mut other_s1 = s1.clone();
        other_s1.amount += 1;
        assert_eq!(
            core.receive_draft(&to_json(&other_s1), None).unwrap_err(),
            CoreError::Conflict
        );

        let slate_id = *s1.id.as_bytes();
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::Unknown, 3),
            Some(Row::S1)
        );
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::Behind, 3),
            Some(Row::S2)
        );
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::AtTip, 3),
            Some(Row::S4)
        );

        // grin-wallet locks, verifies the proof and finalizes
        owner::tx_lock_outputs(&mut sender.w, None, &s1).unwrap();
        let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(&s2)).unwrap();
        let tx = tx_bytes(&s3);
        chain.mine(&mut [&mut core], &tx);
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::AtTip, 3),
            Some(Row::S6)
        );
        chain.empty(&mut [&mut core], 2);
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::AtTip, 3),
            Some(Row::S8)
        );
        assert_eq!(core.balance().spendable, 3 * GRIN);
        // a reorg takes it back to "kernel not seen" and the money away
        core.chain_rollback(chain.height - 3).unwrap();
        assert_eq!(
            core.incoming_row(&slate_id, ChainState::AtTip, 3),
            Some(Row::S4)
        );
        assert_eq!(core.balance().spendable, 0);
    }
}

fn ed25519_public(bytes: &[u8; 32]) -> SlatepackAddress {
    let pk = ed25519_dalek_key(bytes);
    SlatepackAddress::new(&pk)
}

#[test]
fn receive_status_keeps_the_spend_of_the_bound_instance() -> Result<(), String> {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 10 * GRIN, 0);
    let s1 = s1_from_lw(&mut sender, GRIN);
    let slate_id = *s1.id.as_bytes();
    let s2 = core.receive_draft(&to_json(&s1), Some(1000)).map_err(|e| format!("{e:?}"))?;
    owner::tx_lock_outputs(&mut sender.w, None, &s1).map_err(|e| e.to_string())?;
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(&s2)).map_err(|e| e.to_string())?;
    let block = chain.advance_of(&tx_bytes(&s3));
    core.chain_advance(&block).map_err(|e| format!("{e:?}"))?;
    let (commit, _) = core.unspent().into_iter().next().ok_or("wallet output")?;
    let mut output = block.outputs.iter().find(|o| o.0.0 == commit).copied().ok_or("output data")?;
    let mut spend = Advance { inputs: vec![output.0], ..Default::default() };
    chain.block(&mut spend);
    core.chain_advance(&spend).map_err(|e| format!("{e:?}"))?;
    output.2 = chain.pos.checked_add(1).ok_or("position")?;
    let mut later = Advance { outputs: vec![output], ..Default::default() };
    chain.block(&mut later);
    core.chain_advance(&later).map_err(|e| format!("{e:?}"))?;
    let status = |core: &C| core.observe_incoming(&slate_id, ChainState::AtTip, 1)
        .map(|value| value.to_json()).ok_or("missing status");
    assert_eq!(status(&core)?.get("spent"), Some(&serde_json::Value::Bool(true)));
    core.chain_rollback(spend.height).map_err(|e| format!("{e:?}"))?;
    assert_eq!(status(&core)?.get("spent"), Some(&serde_json::Value::Bool(true)));
    core.chain_rollback(block.height).map_err(|e| format!("{e:?}"))?;
    assert_eq!(status(&core)?.get("spent"), Some(&serde_json::Value::Bool(false)));
    Ok(())
}
fn ed25519_dalek_key(bytes: &[u8; 32]) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::VerifyingKey::from_bytes(bytes).unwrap()
}

fn s1_from_lw(sender: &mut Lw, amount: u64) -> Slate {
    let args = InitTxArgs {
        amount,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy_is_use_all: false,
        refresh_outputs_from_node: false,
        ..Default::default()
    };
    owner::init_send_tx(&mut sender.w, None, args, false).unwrap()
}

/// A payment proof addressed to someone else is not signed.
#[test]
fn payment_proof_for_another_address_is_refused() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 10 * GRIN, 0);
    let stranger = create(&Sim::new(), 8).receive_address().unwrap();
    let args = InitTxArgs {
        amount: GRIN,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        refresh_outputs_from_node: false,
        payment_proof_recipient_address: Some(ed25519_public(&stranger)),
        ..Default::default()
    };
    let s1 = to_json(&owner::init_send_tx(&mut sender.w, None, args, false).unwrap());
    assert!(matches!(
        core.receive_draft(&s1, None),
        Err(CoreError::BadSlate(_))
    ));
    core.set_auto_receive(true, true).unwrap();
    assert!(matches!(
        core.receive_stateless(&s1, 0),
        Err(CoreError::BadSlate(_))
    ));
}

#[test]
fn draft_limit_expiry_and_late_arrival() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    for n in 0..(MAX_OPEN_DRAFTS as u32 + 2) {
        lw_fund(&mut sender, 2 * GRIN, n);
    }
    let mut slates = vec![];
    for i in 0..MAX_OPEN_DRAFTS {
        let s1 = s1_from_lw(&mut sender, GRIN);
        owner::tx_lock_outputs(&mut sender.w, None, &s1).unwrap();
        // the first half has a confirmed creation time, the rest none
        let t = if i < 8 { Some(1_000) } else { None };
        let s2 = core.receive_draft(&to_json(&s1), t).unwrap();
        slates.push((s1, s2));
    }
    let extra = s1_from_lw(&mut sender, GRIN);
    assert!(matches!(
        core.receive_draft(&to_json(&extra), None),
        Err(CoreError::Refused(_))
    ));

    // without a confirmed clock nothing expires; one second short of 7 days neither
    assert_eq!(core.drafts_expire(None).unwrap(), 0);
    assert_eq!(
        core.drafts_expire(Some(1_000 + 7 * 24 * 3600 - 1)).unwrap(),
        0
    );
    assert_eq!(core.drafts_expire(Some(1_000 + 7 * 24 * 3600)).unwrap(), 8);
    core.receive_draft(&to_json(&extra), None).unwrap();

    // a payment for an expired draft still arrives: found, but not bound
    let (s1, s2) = &slates[0];
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(s2)).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&s3));
    chain.empty(&mut [&mut core], 5);
    assert_eq!(
        core.incoming_row(s1.id.as_bytes(), ChainState::AtTip, 3),
        Some(Row::S7a)
    );
    assert_eq!(core.balance().spendable, GRIN);
    // and a live draft is bound
    let (s1, s2) = &slates[9];
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(s2)).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&s3));
    chain.empty(&mut [&mut core], 5);
    assert_eq!(
        core.incoming_row(s1.id.as_bytes(), ChainState::AtTip, 3),
        Some(Row::S8)
    );
    // state survives a checkpoint and a restart
    core.checkpoint(None).unwrap();
    drop(core);
    let (core, _) = open(&sim, 5);
    assert_eq!(
        core.incoming_row(s1.id.as_bytes(), ChainState::AtTip, 3),
        Some(Row::S8)
    );
    assert_eq!(core.balance().spendable, 2 * GRIN);
}

/// A record made before a gap in the verified state is not bound
/// automatically (Level 5: continuity from R).
#[test]
fn reanchor_between_draft_and_inclusion_prevents_binding() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 5 * GRIN, 0);
    let s1 = s1_from_lw(&mut sender, GRIN);
    owner::tx_lock_outputs(&mut sender.w, None, &s1).unwrap();
    let s2 = core.receive_draft(&to_json(&s1), None).unwrap();
    chain.height += 50;
    core.chain_reanchor(chain.height, [0xAA; 32]).unwrap();
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(&s2)).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&s3));
    chain.empty(&mut [&mut core], 5);
    assert_eq!(
        core.incoming_row(s1.id.as_bytes(), ChainState::AtTip, 3),
        Some(Row::S7a)
    );
    assert_eq!(core.balance().spendable, GRIN);
}

/// K195: the owner's mark "not to be spent" is kept in the wallet's file:
/// it is there after the wallet is opened again, it outlives a gap in the
/// blocks that takes away what the wallet knew of its outputs, and the
/// wallet's own choice of inputs passes the marked output by in every way
/// of paying. An output that is not there cannot be marked.
#[test]
fn the_mark_not_to_be_spent_is_durable() {
    let Setup { sim, chain, mut core } = funded(7, &[5 * GRIN, 3 * GRIN]);
    let outs = core.outputs();
    assert_eq!(outs.iter().map(|o| (o.value, o.kept, o.reserved, o.immature)).collect::<Vec<_>>(), [(5 * GRIN, false, false, false), (3 * GRIN, false, false, false)]);
    let five: [u8; 33] = outs[0].commit.clone().try_into().unwrap();
    core.output_keep(&five, true).unwrap();
    assert_eq!((core.balance().spendable, core.balance().kept), (3 * GRIN, 5 * GRIN));
    let ops = sim.ops();
    assert!(matches!(core.output_keep(&[9; 33], true), Err(CoreError::NotFound)));
    assert_eq!(sim.ops(), ops, "a refused mark writes nothing");
    assert!(core.output_keep(&[9; 33], false).is_ok(), "taking a mark off what has none is nothing");
    // the wallet's own choice, the ordinary way and the late lock
    assert!(matches!(core.send_prepare(4 * GRIN, 0, None, false), Err(CoreError::InsufficientFunds)));
    drop(core);
    // opened again
    let (mut core, _) = open(&sim, 7);
    assert_eq!((core.balance().spendable, core.balance().kept), (3 * GRIN, 5 * GRIN));
    assert!(core.outputs()[0].kept);
    // a gap: what the wallet knew of its outputs goes, the mark stays for
    // when the output is found again
    core.chain_reanchor(chain.height + 50, [0xAA; 32]).unwrap();
    assert_eq!((core.balance().spendable, core.balance().kept), (0, 0));
    drop(core);
    let (mut core, _) = open(&sim, 7);
    core.output_keep(&five, false).unwrap();
    assert_eq!(core.balance().kept, 0);
}

/// K198: the owner's agreement to the direct way for one payment is
/// written with that payment: it is there after the wallet is opened
/// again, it is for that payment alone, and only a signed payment that is
/// in no block takes it.
#[test]
fn the_agreement_to_the_direct_way_is_durable() {
    let Setup { sim, chain, mut core } = funded(7, &[5 * GRIN, 3 * GRIN]);
    let mut other = lw(2, chain.height);
    let mut pay = |core: &mut C| {
        let p = core.send_prepare(GRIN, 0, None, false).unwrap();
        let s2 = to_json(&foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false).unwrap());
        core.send_finalize(&p.op, &s2).unwrap();
        p.op
    };
    let unsigned = core.send_prepare(GRIN, 0, None, false).unwrap();
    let ops = sim.ops();
    assert!(matches!(core.send_agree_direct(&unsigned.op), Err(CoreError::Refused("only a signed payment that is in no block takes the direct way"))));
    assert!(matches!(core.send_agree_direct(&[9; 16]), Err(CoreError::NotFound)));
    assert_eq!(sim.ops(), ops, "a refusal writes nothing");
    core.send_cancel(&unsigned.op).unwrap();
    let first = pay(&mut core);
    assert!(!core.send_direct(&first));
    core.send_agree_direct(&first).unwrap();
    let ops = sim.ops();
    core.send_agree_direct(&first).unwrap();
    assert_eq!(sim.ops(), ops, "agreed already: nothing is written");
    let second = pay(&mut core);
    assert_eq!((core.send_direct(&first), core.send_direct(&second), core.send_direct(&[9; 16])), (true, false, false));
    drop(core);
    let (core, _) = open(&sim, 7);
    assert_eq!((core.send_direct(&first), core.send_direct(&second)), (true, false));
}

/// K8: stateless receive writes nothing; the output is found by the scan and
/// its payment never rises above S3.
#[test]
fn stateless_receive_writes_nothing_and_is_found_by_scan() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 10 * GRIN, 0);
    let address = ed25519_public(&core.receive_address().unwrap());
    let args = InitTxArgs {
        amount: 2 * GRIN,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        refresh_outputs_from_node: false,
        payment_proof_recipient_address: Some(address),
        ..Default::default()
    };
    let s1 = owner::init_send_tx(&mut sender.w, None, args, false).unwrap();
    let s1_bytes = to_json(&s1);

    assert!(
        matches!(
            core.receive_stateless(&s1_bytes, 0),
            Err(CoreError::Refused(_))
        ),
        "off by default"
    );
    assert!(
        matches!(
            core.set_auto_receive(true, false),
            Err(CoreError::Refused(_))
        ),
        "needs authenticated range proofs"
    );
    core.set_auto_receive(true, true).unwrap();
    assert_eq!(core.auto_receive_since(), Some(chain.height));

    let tail = core.journal_tail();
    let files = sim
        .file_names()
        .into_iter()
        .map(|n| (n.clone(), sim.file(&n).unwrap()))
        .collect::<Vec<_>>();
    assert!(matches!(
        core.receive_stateless(&s1_bytes, 2 * GRIN + 1),
        Err(CoreError::Refused(_))
    ));
    let a = core.receive_stateless(&s1_bytes, 2 * GRIN).unwrap();
    let b = core.receive_stateless(&s1_bytes, 0).unwrap();
    assert_ne!(a, b, "no replay record: every answer uses a fresh output");
    assert_eq!(core.journal_tail(), tail);
    for (n, bytes) in &files {
        assert_eq!(&sim.file(n).unwrap(), bytes, "{n} changed");
    }

    owner::tx_lock_outputs(&mut sender.w, None, &s1).unwrap();
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(&b)).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&s3));
    chain.empty(&mut [&mut core], 10);
    assert_eq!(core.balance().spendable, 2 * GRIN);
    let (commit, _) = core.unspent()[0];
    assert_eq!(
        core.unrecorded_output_row(&commit, ChainState::AtTip),
        Some(Row::S3)
    );
    assert_eq!(
        core.unrecorded_output_row(&commit, ChainState::Behind),
        Some(Row::S2)
    );
    assert_eq!(
        core.incoming_row(s1.id.as_bytes(), ChainState::AtTip, 3),
        None,
        "no deal record exists"
    );
    // the key is in the stateless range
    let found = fly_paycore_keys::scan::rewind(
        &kc(5),
        Commitment(commit),
        s3.tx_or_err()
            .unwrap()
            .outputs()
            .iter()
            .find(|o| o.commitment().0 == commit)
            .unwrap()
            .proof,
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        classify(&Identifier::from_bytes(&found.key_id.to_bytes())),
        Some(KeyPath::Stateless { account: 0, .. })
    ));
    // and can be spent
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let mut other = lw(2, chain.height);
    let s2 =
        to_json(&foreign::receive_tx(&mut other.w, None, &from_json(&p.s1), None, false).unwrap());
    let fin = core.send_finalize(&p.op, &s2).unwrap();
    chain.mine(&mut [&mut core], &fin.tx);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));
}

/// Two cores pay each other; state is the same after replay from the journal
/// and after a checkpoint.
#[test]
fn core_to_core_and_replay_equivalence() {
    net();
    let (sa, sb) = (Sim::new(), Sim::new());
    let mut a = create(&sa, 1);
    let mut b = create(&sb, 2);
    let mut chain = Chain::new();
    chain.fund(&mut [&mut a], 1, &[6 * GRIN]);
    chain.empty(&mut [&mut a, &mut b], 0);
    // b has not seen the funding block; bring it level
    let mut skip = Advance::default();
    skip.height = 1;
    skip.hash = [1; 32];
    b.chain_advance(&skip).unwrap();
    chain.empty(&mut [&mut a, &mut b], 1);

    let p = a.send_prepare(2 * GRIN, 0, None, false).unwrap();
    let s2 = b.receive_draft(&p.s1, None).unwrap();
    let fin = a.send_finalize(&p.op, &s2).unwrap();
    chain.mine(&mut [&mut a, &mut b], &fin.tx);
    chain.empty(&mut [&mut a, &mut b], 4);
    let slate_id = *from_json(&p.s1).id.as_bytes();
    assert_eq!(a.send_status(&p.op), Some(SendStatus::Confirmed));
    assert_eq!(
        b.incoming_row(&slate_id, ChainState::AtTip, 3),
        Some(Row::S8)
    );
    assert_eq!(b.balance().spendable, 2 * GRIN);

    let snapshot = |c: &C, op: Option<&OpId>| {
        (
            c.balance(),
            c.unspent(),
            c.tip_height(),
            op.and_then(|o| c.send_status(o)),
            c.incoming_row(&slate_id, ChainState::AtTip, 3),
        )
    };
    let before_a = snapshot(&a, Some(&p.op));
    let before_b = snapshot(&b, None);
    drop(a);
    drop(b);
    let (mut a, _) = open(&sa, 1);
    let (mut b, _) = open(&sb, 2);
    assert_eq!(snapshot(&a, Some(&p.op)), before_a);
    assert_eq!(snapshot(&b, None), before_b);
    a.checkpoint(None).unwrap();
    b.checkpoint(None).unwrap();
    drop(a);
    drop(b);
    let (a, _) = open(&sa, 1);
    let (b, _) = open(&sb, 2);
    assert_eq!(snapshot(&a, Some(&p.op)), before_a);
    assert_eq!(snapshot(&b, None), before_b);
}

#[test]
fn blocks_must_extend_the_tip_and_ttl_is_enforced() {
    let Setup {
        sim: _s,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let mut a = Advance::default();
    a.height = chain.height + 2;
    assert!(matches!(core.chain_advance(&a), Err(CoreError::Refused(_))));
    assert!(matches!(
        core.chain_rollback(chain.height),
        Err(CoreError::Refused(_))
    ));
    assert!(
        matches!(
            core.send_prepare(GRIN, chain.height, None, false),
            Err(CoreError::Refused(_))
        ),
        "ttl already reached"
    );
    assert!(matches!(
        core.send_prepare(0, 0, None, false),
        Err(CoreError::Refused(_))
    ));
    assert!(matches!(
        core.send_prepare(50 * GRIN, 0, None, false),
        Err(CoreError::InsufficientFunds)
    ));
    let p = core
        .send_prepare(GRIN, chain.height + 2, None, false)
        .unwrap();
    let mut other = lw(2, chain.height);
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false)
            .unwrap(),
    );
    chain.empty(&mut [&mut core], 2);
    assert!(
        matches!(core.send_finalize(&p.op, &s2), Err(CoreError::Refused(_))),
        "ttl passed before signing"
    );
    assert_eq!(core.signatures_made(), 0);
}

/// The opaque state V travels in the same frames as the wallet facts: its
/// per-block changes survive a restart, are dropped by a rollback together
/// with the blocks, and are replaced by a snapshot at a checkpoint.
#[test]
fn v_changes_share_the_frames_of_the_blocks() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 1);
    for h in 1..=5u64 {
        let a = Advance {
            height: h,
            hash: [h as u8; 32],
            v_delta: vec![h as u8; 3],
            ..Advance::default()
        };
        core.chain_advance(&a).unwrap();
    }
    let deltas = |c: &C| {
        c.v_state()
            .1
            .iter()
            .map(|(h, d)| (*h, d.to_vec()))
            .collect::<Vec<_>>()
    };
    assert_eq!(deltas(&core).len(), 5);
    core.chain_rollback(3).unwrap();
    assert_eq!(
        deltas(&core),
        vec![(1, vec![1; 3]), (2, vec![2; 3]), (3, vec![3; 3])]
    );
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(deltas(&core).len(), 3);
    assert!(core.v_state().0.is_none());
    core.checkpoint(Some(b"V at 3".to_vec())).unwrap();
    let a = Advance {
        height: 4,
        hash: [44; 32],
        v_delta: vec![9],
        ..Advance::default()
    };
    core.chain_advance(&a).unwrap();
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.v_state().0, Some((3, &b"V at 3"[..])));
    assert_eq!(deltas(&core), vec![(4, vec![9])]);
    // a rollback below the snapshot of V needs the previous snapshot: refused here
    assert!(matches!(core.chain_rollback(2), Err(CoreError::Refused(_))));
    core.chain_rollback(3).unwrap();
    assert!(deltas(&core).is_empty());
}

// ----- payment proof on send, broadcast bookkeeping, invoices -------------

fn lw_address(seed: u8) -> [u8; 32] {
    let parent = WalletBackend::<Node, ExtKeychain>::default_path();
    let sec = grin_wallet_libwallet::address::address_from_derivation_path(&kc(seed), &parent, 0)
        .unwrap();
    ed25519_dalek::SigningKey::from_bytes(&sec.0)
        .verifying_key()
        .to_bytes()
}

/// We ask grin-wallet for a payment proof; its signature is verified before
/// we sign, stored with the result, and a missing or forged proof is refused.
#[test]
fn send_with_payment_proof_from_grin_wallet() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core
        .send_prepare_with_proof(GRIN, 0, lw_address(2))
        .unwrap();
    let s1 = from_json(&p.s1);
    assert!(s1.payment_proof.is_some());
    let mut other = lw(2, chain.height);
    let good = foreign::receive_tx(&mut other.w, None, &s1, None, false).unwrap();
    assert!(good
        .payment_proof
        .as_ref()
        .unwrap()
        .receiver_signature
        .is_some());

    // proof stripped, proof signed by someone else
    let mut stripped = good.clone();
    stripped.payment_proof = None;
    assert!(matches!(
        core.send_finalize(&p.op, &to_json(&stripped)),
        Err(CoreError::BadSlate(_))
    ));
    let mut forged = good.clone();
    let mut stranger = lw(9, chain.height);
    let theirs =
        foreign::receive_tx_stateless(&mut stranger.w, None, &s1, None, None, false).unwrap();
    forged.payment_proof.as_mut().unwrap().receiver_signature =
        theirs.payment_proof.unwrap().receiver_signature;
    assert!(matches!(
        core.send_finalize(&p.op, &to_json(&forged)),
        Err(CoreError::BadSlate(_))
    ));
    // addresses rewritten in the reply, signature left as it was
    let mut readdressed = good.clone();
    let pp = readdressed.payment_proof.as_mut().unwrap();
    pp.receiver_address = pp.sender_address;
    assert!(matches!(
        core.send_finalize(&p.op, &to_json(&readdressed)),
        Err(CoreError::BadSlate(_))
    ));
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    assert_eq!(core.signatures_made(), 0);

    let fin = core.send_finalize(&p.op, &to_json(&good)).unwrap();
    let proof = fin.payment_proof.clone().expect("proof");
    assert!(proof.verify());
    assert_eq!(proof.amount, GRIN);
    assert_eq!(proof.excess, fin.excess.to_vec());
    assert_eq!(proof.receiver_address, lw_address(2).to_vec());
    assert_eq!(
        proof.sender_address,
        core.receive_address().unwrap().to_vec()
    );
    let mut wrong = proof.clone();
    wrong.amount += 1;
    assert!(!wrong.verify());
    // the proof is kept with the result
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(
        core.send_finalize(&p.op, &to_json(&good))
            .unwrap()
            .payment_proof,
        Some(proof)
    );
    chain.mine(&mut [&mut core], &fin.tx);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));
}

#[test]
fn broadcast_outcomes_are_recorded_and_never_resign() {
    use fly_paycore_wallet::Broadcast;
    let Setup {
        sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    assert!(matches!(
        core.send_broadcast_result(&p.op, Broadcast::Unknown),
        Err(CoreError::Refused(_))
    ));
    let mut other = lw(2, chain.height);
    let s2 = to_json(
        &foreign::receive_tx_stateless(&mut other.w, None, &from_json(&p.s1), None, None, false)
            .unwrap(),
    );
    let fin = core.send_finalize(&p.op, &s2).unwrap();
    for o in [
        Broadcast::Unknown,
        Broadcast::Unknown,
        Broadcast::Rejected,
        Broadcast::Accepted,
    ] {
        core.send_broadcast_result(&p.op, o).unwrap();
        // a lost answer never frees the inputs and the bytes to resend are the same
        assert!(core.balance().reserved > 0);
        assert_eq!(core.send_finalize(&p.op, &s2).unwrap(), fin);
    }
    assert_eq!(core.broadcast_attempts(&p.op), Some((1, 1, 2)));
    assert_eq!(core.signatures_made(), 1);
    drop(core);
    let (core, _) = open(&sim, 1);
    assert_eq!(core.broadcast_attempts(&p.op), Some((1, 1, 2)));
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Finalized));
}

/// We issue an invoice, grin-wallet pays it, we complete it.
#[test]
fn invoice_issued_by_us_paid_by_grin_wallet() {
    net();
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let (slate_id, i1) = core.invoice_issue(2 * GRIN, None).unwrap();
    let mut payer = lw(6, chain.height);
    lw_fund(&mut payer, 10 * GRIN, 0);
    let args = InitTxArgs {
        amount: 2 * GRIN,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy_is_use_all: false,
        refresh_outputs_from_node: false,
        ..Default::default()
    };
    let i2 = to_json(
        &owner::process_invoice_tx(&mut payer.w, None, &from_json(&i1), args.clone(), false)
            .unwrap(),
    );
    assert!(
        matches!(
            core.invoice_finalize(&slate_id, &i1),
            Err(CoreError::BadSlate(_))
        ),
        "I1 is not an I2"
    );
    let fin = core.invoice_finalize(&slate_id, &i2).unwrap();
    assert_eq!(core.signatures_made(), 1);
    assert_eq!(core.invoice_finalize(&slate_id, &i2).unwrap(), fin);
    assert_eq!(core.signatures_made(), 1);
    // a second, different payment of the same invoice is refused
    let mut payer2 = lw(7, chain.height);
    lw_fund(&mut payer2, 10 * GRIN, 0);
    let other = to_json(
        &owner::process_invoice_tx(&mut payer2.w, None, &from_json(&i1), args, false).unwrap(),
    );
    assert_eq!(
        core.invoice_finalize(&slate_id, &other).unwrap_err(),
        CoreError::Conflict
    );
    assert!(matches!(
        core.draft_abandon(&slate_id),
        Err(CoreError::Refused(_))
    ));

    chain.mine(&mut [&mut core], &fin.tx);
    chain.empty(&mut [&mut core], 3);
    assert_eq!(
        core.incoming_row(&slate_id, ChainState::AtTip, 3),
        Some(Row::S8)
    );
    assert_eq!(core.balance().spendable, 2 * GRIN);
    drop(core);
    let (mut core, _) = open(&sim, 5);
    assert_eq!(core.invoice_finalize(&slate_id, &i2).unwrap(), fin);
    assert_eq!(core.signatures_made(), 0);
}

#[test]
fn expiration_keeps_a_signed_invoice_and_closes_the_unanswered_one() -> Result<(), &'static str> {
    let mut payee = funded(1, &[3 * GRIN]).core;
    let mut payer = funded(2, &[5 * GRIN]).core;
    let created = Some(1000);
    let cutoff = Some(605800);
    let (signed_id, i1) = payee.invoice_issue(GRIN, created).map_err(|_| "issue")?;
    let (_, i2) = payer.invoice_pay(&i1, GRIN).map_err(|_| "pay")?;
    let signed = payee.invoice_finalize(&signed_id, &i2).map_err(|_| "finalize")?;
    let (unanswered_id, _) = payee.invoice_issue(GRIN, created).map_err(|_| "second invoice")?;
    assert_eq!(payee.drafts_expire(None), Ok(0));
    assert_eq!(payee.drafts_expire(cutoff), Ok(1));
    assert_eq!(payee.drafts_expire(cutoff), Ok(0));
    assert_eq!(payee.invoice_finalize(&signed_id, &i2), Ok(signed));
    assert_eq!(payee.signatures_made(), 1);
    assert!(payee.incomings().contains(&(signed_id, GRIN, false)));
    assert!(payee.incomings().contains(&(unanswered_id, GRIN, true)));
    Ok(())
}

/// grin-wallet issues an invoice, we pay it, grin-wallet completes it.
#[test]
fn invoice_from_grin_wallet_paid_by_us() {
    use grin_wallet_libwallet::IssueInvoiceTxArgs;
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let mut payee = lw(2, chain.height);
    let i1 = owner::issue_invoice_tx(
        &mut payee.w,
        None,
        IssueInvoiceTxArgs {
            amount: 2 * GRIN,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let i1_bytes = to_json(&i1);
    assert!(
        matches!(
            core.invoice_pay(&i1_bytes, 2 * GRIN - 1),
            Err(CoreError::Refused(_))
        ),
        "more than agreed"
    );
    assert_eq!(core.signatures_made(), 0);
    let tail = core.journal_tail();
    let (op, i2) = core.invoice_pay(&i1_bytes, 2 * GRIN).unwrap();
    assert_eq!(core.journal_tail().next_seq, tail.next_seq + 1);
    assert_eq!(core.send_status(&op), Some(SendStatus::Finalized));
    assert!(core.balance().reserved > 0);
    assert!(
        matches!(core.send_cancel(&op), Err(CoreError::Refused(_))),
        "a signed payment cannot be cancelled"
    );
    // the same invoice again: the same answer, no second payment
    assert_eq!(
        core.invoice_pay(&i1_bytes, 2 * GRIN).unwrap(),
        (op, i2.clone())
    );
    assert_eq!(core.signatures_made(), 1);
    let mut changed = i1.clone();
    changed.amount -= 1;
    assert_eq!(
        core.invoice_pay(&to_json(&changed), 2 * GRIN).unwrap_err(),
        CoreError::Conflict
    );

    let i3 = foreign::finalize_tx(&mut payee.w, None, &from_json(&i2), false).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&i3));
    assert_eq!(core.send_status(&op), Some(SendStatus::Confirmed));
    let bal = core.balance();
    assert_eq!(bal.reserved, 0);
    assert!(bal.spendable < 3 * GRIN && bal.spendable > 3 * GRIN - GRIN / 10);
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.invoice_pay(&i1_bytes, 2 * GRIN).unwrap(), (op, i2));
    assert_eq!(core.signatures_made(), 0);
}

/// Paying an invoice signs before the record is durable; a crash must never
/// leave a signed I2 outside and no record inside, nor allow a second payment.
#[test]
fn crash_while_paying_or_completing_an_invoice() {
    use grin_wallet_libwallet::IssueInvoiceTxArgs;
    net();
    for probe in 0..4u64 {
        for after in [false, true] {
            for data in [DataLoss::LoseAll, DataLoss::KeepAll] {
                let Setup {
                    sim,
                    chain,
                    mut core,
                } = funded(1, &[5 * GRIN]);
                let mut payee = lw(2, chain.height);
                let i1 = to_json(
                    &owner::issue_invoice_tx(
                        &mut payee.w,
                        None,
                        IssueInvoiceTxArgs {
                            amount: GRIN,
                            ..Default::default()
                        },
                        false,
                    )
                    .unwrap(),
                );
                let n = sim.ops() + probe;
                sim.set_fault(Some(if after {
                    Fault::CrashAfter(n)
                } else {
                    Fault::CrashBefore(n)
                }));
                let first = core.invoice_pay(&i1, GRIN);
                let crashed = sim.crashed();
                drop(core);
                if !crashed {
                    assert!(first.is_ok());
                    continue;
                }
                assert!(
                    first.is_err(),
                    "I2 was handed out although the machine died"
                );
                sim.reboot(Reboot {
                    data,
                    keep_dir_changes: true,
                });
                let (mut core, report) = open(&sim, 1);
                assert!(!report.recovered);
                // whatever survived, paying "again" yields exactly one payment record
                let (op, i2) = core.invoice_pay(&i1, GRIN).unwrap();
                assert_eq!(core.invoice_pay(&i1, GRIN).unwrap(), (op, i2));
                assert!(core.signatures_made() <= 1);
                assert_eq!(core.balance().spendable + core.balance().reserved, 5 * GRIN);
            }
        }
    }
    // an issued invoice cannot be completed after a detected rollback
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let backup = sim.disk_image();
    let (slate_id, i1) = core.invoice_issue(GRIN, None).unwrap();
    let after_issue = sim.disk_image();
    let mut payer = lw(6, chain.height);
    lw_fund(&mut payer, 10 * GRIN, 0);
    let args = InitTxArgs {
        amount: GRIN,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy_is_use_all: false,
        refresh_outputs_from_node: false,
        ..Default::default()
    };
    let i2 = to_json(
        &owner::process_invoice_tx(&mut payer.w, None, &from_json(&i1), args, false).unwrap(),
    );
    core.invoice_finalize(&slate_id, &i2).unwrap();
    drop(core);
    let _ = backup;
    sim.restore_disk(&after_issue);
    let (mut core, report) = open(&sim, 5);
    assert!(report.recovered);
    assert!(matches!(
        core.invoice_finalize(&slate_id, &i2),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(core.signatures_made(), 0);
}

/// Section 12: migration from the v0.1 database is refused while anything is
/// in flight there, and otherwise yields the amount the new scan must find.
#[test]
fn migration_from_v01_is_refused_while_operations_are_open() {
    use fly_paycore_wallet::migrate::{inspect, Blocker};
    net();
    let mut old = lw(6, 10);
    let plan = inspect(&old.w).unwrap();
    assert_eq!(
        (
            plan.expected_unspent,
            plan.unspent_outputs,
            plan.history.len()
        ),
        (0, 0, 0)
    );
    lw_fund(&mut old, 4 * GRIN, 0);
    lw_fund(&mut old, 3 * GRIN, 1);
    let plan = inspect(&old.w).unwrap();
    assert_eq!((plan.expected_unspent, plan.unspent_outputs), (7 * GRIN, 2));

    // an unfinished send: locked output, unconfirmed change, open log entry
    let s1 = s1_from_lw(&mut old, GRIN);
    owner::tx_lock_outputs(&mut old.w, None, &s1).unwrap();
    let blockers = inspect(&old.w).unwrap_err();
    assert!(
        blockers
            .iter()
            .any(|b| matches!(b, Blocker::SendInFlight { .. })),
        "{blockers:?}"
    );
    assert!(
        blockers
            .iter()
            .any(|b| matches!(b, Blocker::LockedOutput { .. })),
        "{blockers:?}"
    );

    // an unfinished receive in another wallet
    let mut other = lw(7, 10);
    foreign::receive_tx(&mut other.w, None, &s1, None, false).unwrap();
    let blockers = inspect(&other.w).unwrap_err();
    assert!(
        blockers
            .iter()
            .any(|b| matches!(b, Blocker::ReceiveInFlight { .. })),
        "{blockers:?}"
    );
    assert!(
        blockers
            .iter()
            .any(|b| matches!(b, Blocker::UnconfirmedOutput { value } if *value == GRIN)),
        "{blockers:?}"
    );

    // the new wallet finds by scan what the plan promised
    let seed = 8;
    let mut clean = lw(seed, 10);
    lw_fund(&mut clean, 4 * GRIN, 0);
    let plan = inspect(&clean.w).unwrap();
    let sim = Sim::new();
    let mut core = create(&sim, seed);
    let mut chain = Chain::new();
    chain.fund(&mut [&mut core], seed, &[4 * GRIN]);
    assert_eq!(core.balance().spendable, plan.expected_unspent);
    for line in &plan.history {
        assert!(!line.contains("key") && !line.contains("commit"));
    }
}

fn lw_s2(other: &mut Lw, s1: &[u8]) -> Vec<u8> {
    to_json(&foreign::receive_tx(&mut other.w, None, &from_json(s1), None, false).unwrap())
}

/// Late lock: S1 reserves nothing; inputs, change and the change path are
/// chosen at finalize and are durable before the signature.
#[test]
fn late_lock_reserves_only_when_arming() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN]);
    let late = core.send_prepare_late(2 * GRIN, 0, None).unwrap();
    let bal = core.balance();
    assert_eq!((bal.spendable, bal.reserved), (8 * GRIN, 0));
    assert_eq!(
        core.branches().peek().map(|p| p.1),
        Some(0),
        "no path issued yet"
    );
    let s1 = from_json(&late.s1);
    assert!(s1.tx.as_ref().map(|t| t.inputs().len()).unwrap_or(0) == 0);
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &late.s1);

    // an ordinary send in between takes the larger output and path 0
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let mut third = lw(3, chain.height);
    let fin1 = core
        .send_finalize(&p.op, &lw_s2(&mut third, &p.s1))
        .unwrap();

    let fin2 = core.send_finalize(&late.op, &s2).unwrap();
    assert_eq!(core.signatures_made(), 2);
    assert_eq!(core.send_status(&late.op), Some(SendStatus::Finalized));
    // the same reply again: stored result, no new signature, also after reopening
    assert_eq!(core.send_finalize(&late.op, &s2).unwrap().tx, fin2.tx);
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.send_finalize(&late.op, &s2).unwrap().tx, fin2.tx);
    assert_eq!(core.signatures_made(), 0);

    chain.mine(&mut [&mut core], &fin1.tx);
    chain.mine(&mut [&mut core], &fin2.tx);
    assert_eq!(core.send_status(&late.op), Some(SendStatus::Confirmed));
    let bal = core.balance();
    assert_eq!(bal.reserved, 0);
    let fees = 8 * GRIN - 3 * GRIN - bal.spendable;
    assert!(fees > 0 && fees < GRIN / 5, "fees {fees}");
    // the late change sits on the path issued in the arming frame
    let branch = core.branches().current().unwrap();
    let id = KeyPath::Branch {
        account: 0,
        branch,
        index: 1,
    }
    .to_identifier();
    let unspent = core.unspent();
    assert!(unspent.iter().any(|(c, v)| kc(1)
        .commit(*v, &id, SwitchCommitmentType::Regular)
        .unwrap()
        .0
        == *c));
    for (c, _) in &unspent {
        assert_eq!(core.unrecorded_output_row(c, ChainState::AtTip), None);
    }
}

/// Late lock when the money is gone or the fee fixed in S1 no longer pays:
/// refused before anything is armed or signed, and the operation can be
/// cancelled.
#[test]
fn late_lock_refuses_without_signing() {
    // the funds were spent meanwhile
    let Setup {
        sim: _sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let late = core.send_prepare_late(2 * GRIN, 0, None).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &late.s1);
    let p = core.send_prepare(4 * GRIN, 0, None, false).unwrap();
    assert_eq!(
        core.send_finalize(&late.op, &s2).unwrap_err(),
        CoreError::InsufficientFunds
    );
    assert_eq!(core.send_status(&late.op), Some(SendStatus::Prepared));
    assert_eq!(core.signatures_made(), 0);
    // a second, different reply is still acceptable later: nothing was chosen
    core.send_cancel(&p.op).unwrap();
    core.send_finalize(&late.op, &s2).unwrap();
    assert_eq!(core.signatures_made(), 1);

    // the fee was fixed for one input; later only many small outputs remain
    let Setup {
        sim: _sim2,
        mut chain,
        mut core,
    } = funded(4, &[5 * GRIN]);
    let late = core.send_prepare_late(2 * GRIN, 0, None).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &late.s1);
    chain.fund(&mut [&mut core], 4, &[GRIN, GRIN, GRIN, GRIN]);
    let p = core.send_prepare(4 * GRIN, 0, None, false).unwrap();
    let mut third = lw(3, chain.height);
    core.send_finalize(&p.op, &lw_s2(&mut third, &p.s1))
        .unwrap();
    let signs = core.signatures_made();
    assert!(matches!(
        core.send_finalize(&late.op, &s2),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(core.signatures_made(), signs);
    assert_eq!(core.send_status(&late.op), Some(SendStatus::Prepared));
    assert_eq!(core.balance().reserved, 5 * GRIN);
    core.send_cancel(&late.op).unwrap();
    assert!(matches!(
        core.send_finalize(&late.op, &s2),
        Err(CoreError::Refused(_))
    ));
}

/// Late lock under power loss: either nothing was chosen (no reserve, the
/// reply can be finalized again) or the arming frame survived (reserve and
/// path are there, the outcome is unknown or stored). Never two signatures.
#[test]
fn crash_at_every_operation_of_late_finalize() {
    net();
    let mut outcomes = std::collections::BTreeMap::new();
    for probe in 0..12u64 {
        for after in [false, true] {
            for data in [DataLoss::LoseAll, DataLoss::KeepAll, DataLoss::Torn(40)] {
                let Setup {
                    sim,
                    chain,
                    mut core,
                } = funded(1, &[5 * GRIN]);
                let p = core.send_prepare_late(GRIN, 0, None).unwrap();
                let mut other = lw(2, chain.height);
                let s2 = lw_s2(&mut other, &p.s1);
                let n = sim.ops() + probe;
                sim.set_fault(Some(if after {
                    Fault::CrashAfter(n)
                } else {
                    Fault::CrashBefore(n)
                }));
                let first = core.send_finalize(&p.op, &s2);
                let signs_before = core.signatures_made();
                let crashed = sim.crashed();
                drop(core);
                if !crashed {
                    assert!(first.is_ok());
                    continue;
                }
                assert!(first.is_err());
                sim.reboot(Reboot {
                    data,
                    keep_dir_changes: true,
                });
                let (mut core, report) = open(&sim, 1);
                assert!(!report.recovered, "probe {probe}: {:?}", report.guard);
                let status = core.send_status(&p.op).unwrap();
                let bal = core.balance();
                let second = core.send_finalize(&p.op, &s2);
                assert!(signs_before + core.signatures_made() <= 1);
                match status {
                    SendStatus::Prepared => {
                        assert_eq!(signs_before, 0);
                        assert_eq!(bal.reserved, 0, "no reserve without the arming frame");
                        second.unwrap();
                    }
                    SendStatus::Unknown => {
                        assert_eq!(second.unwrap_err(), CoreError::UnknownOutcome);
                        assert_eq!(core.signatures_made(), 0);
                        assert_eq!(bal.reserved, 5 * GRIN, "reserve must stay");
                        // the change path was issued with the arming frame
                        assert_eq!(core.branches().peek().map(|p| p.1), Some(1));
                    }
                    SendStatus::Finalized => {
                        second.unwrap();
                        assert_eq!(core.signatures_made(), 0);
                        assert_eq!(bal.reserved, 5 * GRIN);
                    }
                    other => panic!("unexpected status {other:?}"),
                }
                *outcomes.entry(format!("{status:?}")).or_insert(0u32) += 1;
            }
        }
    }
    println!("late finalize crash matrix: {outcomes:?}");
    assert_eq!(outcomes.len(), 3, "{outcomes:?}");
}

fn save_trace(t: &fly_paycore_wallet::trace::Trace) -> String {
    let text = serde_json::to_string_pretty(&t.to_json()).unwrap();
    // nothing that looks like a key, commitment or slate may be in a trace
    let longest_hex = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(|w| w.len())
        .max()
        .unwrap_or(0);
    assert!(longest_hex < 16, "a trace must not carry binary material");
    if let Ok(dir) = std::env::var("PAYCORE_TRACE_DIR") {
        let name = t.to_json()["scenario"].as_str().unwrap().to_string();
        std::fs::write(format!("{dir}/{name}.json"), &text).unwrap();
    }
    text
}

/// Э8: scenarios exported in the `grinsight.wallet.trace.v1` envelope with
/// the fields the payment core owns.
#[test]
fn traces_are_exported_for_the_wallet_model() {
    use fly_paycore_wallet::trace::{Trace, OWNED_FIELDS, SCHEMA};
    use serde_json::json;
    // outgoing: reorg, crash, restart (the model's scenario "a")
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[2 * GRIN, 2 * GRIN, 5 * GRIN]);
    let p = core.send_prepare(6 * GRIN, 0, None, false).unwrap();
    let mut t = Trace::new(
        "paycore_send_reorg_crash_restart",
        &core.observe_send(&p.op).unwrap(),
    );
    let mut other = lw(2, chain.height);
    let fin = core
        .send_finalize(&p.op, &lw_s2(&mut other, &p.s1))
        .unwrap();
    t.step("finalize", json!({}), &core.observe_send(&p.op).unwrap());
    let tx: Transaction = ser::deserialize(
        &mut &fin.tx[..],
        ser::ProtocolVersion::local(),
        ser::DeserializationMode::default(),
    )
    .unwrap();
    let ins: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
    let mut a = Advance {
        inputs: vec![ins[0].commitment()],
        ..Advance::default()
    };
    chain.block(&mut a);
    core.chain_advance(&a).unwrap();
    let contested = core.observe_send(&p.op).unwrap();
    assert!(contested.conflict && contested.reserve);
    t.step("block", json!({"foreign_spend_of_input": true}), &contested);
    core.chain_rollback(chain.height - 1).unwrap();
    chain.height -= 1;
    let restored = core.observe_send(&p.op).unwrap();
    assert!(!restored.conflict && restored.reserve);
    t.step("reorg", json!({"depth": 1}), &restored);
    drop(core);
    sim.reboot(Reboot {
        data: DataLoss::LoseAll,
        keep_dir_changes: true,
    });
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.observe_send(&p.op).unwrap(), restored);
    t.step(
        "crash_restart",
        json!({}),
        &core.observe_send(&p.op).unwrap(),
    );
    chain.mine(&mut [&mut core], &fin.tx);
    let done = core.observe_send(&p.op).unwrap();
    assert!(done.spent && !done.reserve && done.status == "confirmed");
    t.step("block", json!({"includes_kernel": true}), &done);
    let text = save_trace(&t);
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["schema"], SCHEMA);
    assert_eq!(doc["tick_seconds"], 15);
    assert_eq!(doc["steps"].as_array().unwrap().len(), 5);
    assert_eq!(doc["result"], doc["steps"][4]["expected"]);

    // incoming with a draft: S4 -> S6 -> S8 -> reorg -> S4
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 10 * GRIN, 0);
    let s1 = s1_from_lw(&mut sender, 3 * GRIN);
    let id = *s1.id.as_bytes();
    let s2 = core.receive_draft(&to_json(&s1), Some(1_000)).unwrap();
    let obs = |c: &C| c.observe_incoming(&id, ChainState::AtTip, 3).unwrap();
    let mut t = Trace::new("paycore_incoming_confirm_reorg", &obs(&core));
    owner::tx_lock_outputs(&mut sender.w, None, &s1).unwrap();
    let s3 = owner::finalize_tx(&mut sender.w, None, &from_json(&s2)).unwrap();
    chain.mine(&mut [&mut core], &tx_bytes(&s3));
    t.step("block", json!({"includes_kernel": true}), &obs(&core));
    chain.empty(&mut [&mut core], 2);
    t.step("block", json!({"count": 2}), &obs(&core));
    core.chain_rollback(chain.height - 3).unwrap();
    t.step("reorg", json!({"depth": 3}), &obs(&core));
    let text = save_trace(&t);
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rules: Vec<&str> = std::iter::once(&doc["initial"])
        .chain(
            doc["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| &s["expected"]),
        )
        .map(|e| e["status_rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, ["S4", "S6", "S8", "S4"]);

    // comparison with a model step looks only at the fields the core owns
    let ours = obs(&core);
    let model = json!({"status": "not_confirmed", "status_rule": "S4", "known": true,
        "spent": false, "reserve": false, "mode": "lite", "claim": "none", "snapshot": 7});
    assert!(ours.mismatches(&model).is_empty());
    let model = json!({"status": "confirmed", "status_rule": "S8", "known": true, "mode": "full"});
    assert_eq!(ours.mismatches(&model), ["status", "status_rule"]);
    assert_eq!(OWNED_FIELDS.len(), 6);
}

struct Xs(u64);
impl Xs {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    /// One random edit: flip, overwrite, delete, duplicate, truncate, or
    /// splice in JSON punctuation and digits.
    fn mutate(&mut self, src: &[u8]) -> Vec<u8> {
        let mut v = src.to_vec();
        for _ in 0..1 + self.below(3) {
            if v.is_empty() {
                break;
            }
            let i = self.below(v.len());
            match self.below(7) {
                0 => v[i] ^= 1 << self.below(8),
                1 => v[i] = b"{}[]\":,0123456789abcdef-e.\\ntu"[self.below(30)],
                2 => {
                    v.remove(i);
                }
                3 => {
                    let j = (i + 1 + self.below(40)).min(v.len());
                    let piece = v[i..j].to_vec();
                    v.splice(i..i, piece);
                }
                4 => v.truncate(i),
                5 => {
                    let j = (i + 1 + self.below(40)).min(v.len());
                    v.drain(i..j);
                }
                _ => v[i] = self.next() as u8,
            }
        }
        v
    }
}

/// Section 15: hostile input. Thousands of damaged slates go through every
/// entry point that parses one. Nothing panics; whatever is refused leaves
/// no frame, no reserve and no signature behind; whatever is accepted is a
/// transaction Grin's own validation accepts.
#[test]
fn damaged_slates_never_panic_or_leave_traces() {
    use grin_wallet_libwallet::IssueInvoiceTxArgs;
    let Setup {
        sim: _sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN]);
    let mut rng = Xs(0x9E37_79B9_7F4A_7C15);
    let mut sender = lw(6, chain.height);
    lw_fund(&mut sender, 10 * GRIN, 0);
    let s1_in = to_json(&s1_from_lw(&mut sender, GRIN));
    let mut payee = lw(7, chain.height);
    let i1_in = to_json(
        &owner::issue_invoice_tx(
            &mut payee.w,
            None,
            IssueInvoiceTxArgs {
                amount: GRIN,
                ..Default::default()
            },
            false,
        )
        .unwrap(),
    );
    core.set_auto_receive(true, true).unwrap();
    let mut refused = 0u32;
    let mut accepted = 0u32;

    // receiving and paying: every refusal must leave the journal untouched
    for round in 0..1500 {
        for (kind, src) in [(0, &s1_in), (1, &s1_in), (2, &i1_in)] {
            let bad = rng.mutate(src);
            let tail = core.journal_tail();
            let bal = core.balance();
            let signs = core.signatures_made();
            let r = match kind {
                0 => core.receive_stateless(&bad, 0).map(|_| ()),
                1 => core.receive_draft(&bad, Some(1_000)).map(|_| ()),
                _ => core.invoice_pay(&bad, GRIN).map(|_| ()),
            };
            match r {
                Err(_) => {
                    refused += 1;
                    assert!(
                        core.journal_tail() == tail
                            && core.balance() == bal
                            && core.signatures_made() == signs,
                        "round {round} kind {kind}: a refused slate left a trace"
                    );
                }
                Ok(()) => accepted += 1,
            }
        }
    }

    // finalizing: a damaged S2 either is refused before arming or yields a
    // valid transaction; the operation is never left half-way
    // (accepted invoices with an edited id are distinct invoices and hold a
    // reserve each, so this part runs on a wallet of its own)
    let Setup {
        sim: _sim2,
        chain,
        mut core,
    } = funded(3, &[GRIN; 90]);
    let mut other = lw(2, chain.height);
    let mut stuck = 0u32;
    for round in 0..200 {
        let p = match core.send_prepare(GRIN / 100, 0, None, false) {
            Ok(p) => p,
            Err(CoreError::InsufficientFunds) if round > 50 => break,
            Err(e) => panic!("round {round}: {e:?} {:?}", core.balance()),
        };
        let good = lw_s2(&mut other, &p.s1);
        for _ in 0..6 {
            let bad = rng.mutate(&good);
            if bad == good {
                continue;
            }
            let signs = core.signatures_made();
            match core.send_finalize(&p.op, &bad) {
                Err(e) => {
                    refused += 1;
                    if core.signatures_made() != signs {
                        let g: serde_json::Value = serde_json::from_slice(&good).unwrap();
                        let b: serde_json::Value = serde_json::from_slice(&bad).unwrap();
                        panic!("round {round}: {e:?}\nGOOD {g}\nBAD  {b}");
                    }
                    assert_eq!(core.signatures_made(), signs, "round {round}");
                    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
                }
                Ok(fin) => {
                    accepted += 1;
                    let tx: Transaction = ser::deserialize(
                        &mut &fin.tx[..],
                        ser::ProtocolVersion::local(),
                        ser::DeserializationMode::default(),
                    )
                    .unwrap();
                    tx.validate(Weighting::AsTransaction).unwrap();
                    break;
                }
            }
        }
        match core.send_status(&p.op) {
            Some(SendStatus::Prepared) => core.send_cancel(&p.op).unwrap(),
            Some(SendStatus::Finalized) => {}
            _ => stuck += 1,
        }
    }
    assert_eq!(stuck, 0, "an operation was armed and left without a result");

    // completing an invoice: one invoice, hundreds of damaged I2; each one is
    // refused before the payee's nonce is touched or yields a valid transaction
    let sim = Sim::new();
    let mut core = create(&sim, 5);
    let mut chain = Chain::new();
    chain.empty(&mut [&mut core], 3);
    let mut payer = lw(8, chain.height);
    lw_fund(&mut payer, 10 * GRIN, 0);
    let mut done = false;
    'invoices: for _ in 0..12 {
        let (slate_id, i1) = core.invoice_issue(GRIN, None).unwrap();
        let args = InitTxArgs {
            amount: GRIN,
            minimum_confirmations: 1,
            max_outputs: 500,
            num_change_outputs: 1,
            selection_strategy_is_use_all: false,
            refresh_outputs_from_node: false,
            ..Default::default()
        };
        let good = to_json(
            &owner::process_invoice_tx(&mut payer.w, None, &from_json(&i1), args, false).unwrap(),
        );
        for _ in 0..60 {
            let bad = rng.mutate(&good);
            if bad == good {
                continue;
            }
            let signs = core.signatures_made();
            match core.invoice_finalize(&slate_id, &bad) {
                Err(e) => {
                    refused += 1;
                    assert_ne!(e, CoreError::UnknownOutcome);
                    assert_eq!(
                        core.signatures_made(),
                        signs,
                        "payee signed for a refused I2"
                    );
                }
                Ok(fin) => {
                    accepted += 1;
                    let tx: Transaction = ser::deserialize(
                        &mut &fin.tx[..],
                        ser::ProtocolVersion::local(),
                        ser::DeserializationMode::default(),
                    )
                    .unwrap();
                    tx.validate(Weighting::AsTransaction).unwrap();
                    core.draft_abandon(&slate_id).ok();
                    continue 'invoices;
                }
            }
        }
        // after all the refusals the genuine I2 still completes the invoice
        core.invoice_finalize(&slate_id, &good).unwrap();
        done = true;
        break;
    }
    assert!(
        done,
        "no invoice survived to be completed with the genuine I2"
    );
    println!("damaged slates: {refused} refused, {accepted} accepted");
    assert!(refused > 5000, "{refused}");
}

/// The same slate with a second `off` key holding text that is not hex.
fn repeat_key(good: &[u8], bad_first: bool) -> Vec<u8> {
    let text = std::str::from_utf8(good).unwrap();
    let out = if bad_first {
        format!("{{\"off\":\"e70-a822cc93364c\",{}", &text[1..])
    } else {
        format!("{},\"off\":\"e70-a822cc93364c\"}}", &text[..text.len() - 1])
    };
    assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    out.into_bytes()
}

/// Found by the damaged-slate test: a reply whose signature verifies but
/// whose output proof or offset is wrong used to be armed and then failed to
/// build, leaving the operation "unknown" with its inputs held for good. Now
/// the counterparty's half is checked before arming. A kernel offset that is
/// not hex made Grin's own parser panic.
#[test]
fn counterparty_half_is_checked_before_arming() {
    let Setup {
        sim: _sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let mut other = lw(2, chain.height);
    let good = lw_s2(&mut other, &p.s1);
    let edit = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
        f(&mut v);
        serde_json::to_vec(&v).unwrap()
    };
    let flip = |h: &str, at: usize| {
        let mut b = h.as_bytes().to_vec();
        b[at] = if b[at] == b'0' { b'1' } else { b'0' };
        String::from_utf8(b).unwrap()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "damaged range proof",
            edit(&|v| {
                let p = v["coms"][0]["p"].as_str().unwrap().to_string();
                v["coms"][0]["p"] = flip(&p, 200).into();
            }),
        ),
        (
            "another offset",
            edit(&|v| {
                let o = v["off"].as_str().unwrap().to_string();
                v["off"] = flip(&o, 10).into();
            }),
        ),
        ("offset is not hex", edit(&|v| v["off"] = "zz".into())),
        ("offset too short", edit(&|v| v["off"] = "00ff".into())),
        ("offset is a number", edit(&|v| v["off"] = 7.into())),
        // found on Windows: with a repeated key Grin's parser reads the first
        // occurrence, an ordinary JSON reader the last
        ("repeated offset, bad first", repeat_key(&good, true)),
        ("repeated offset, bad last", repeat_key(&good, false)),
    ];
    for (what, bad) in &cases {
        assert!(
            matches!(core.send_finalize(&p.op, bad), Err(CoreError::BadSlate(_))),
            "{what}"
        );
        assert_eq!(
            core.send_status(&p.op),
            Some(SendStatus::Prepared),
            "{what}"
        );
        assert_eq!(core.signatures_made(), 0, "{what}");
        // the same damage in an incoming S1 is refused without a trace
        let tail = core.journal_tail();
        assert!(core.receive_draft(bad, None).is_err(), "{what}");
        assert!(core.journal_tail() == tail);
    }
    core.send_finalize(&p.op, &good).unwrap();
}

// ----- automatic delivery -------------------------------------------------

/// A real transport key: the x coordinate of the curve's generator.
const CONTACT: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];
/// Give the wallet a transport identity and the contact, once.
fn ready(core: &mut C) {
    if core.identity().is_none() {
        core.identity_create(false).unwrap();
    }
    if core.contacts().is_empty() {
        core.contact_set(CONTACT, "Bob", None).unwrap();
    }
}
/// The transport key that belongs to a small secret number.
fn xonly(n: u32) -> [u8; 32] {
    use grin_util::secp::key::{PublicKey, SecretKey};
    let secp = grin_util::static_secp_instance();
    let secp = secp.lock();
    let mut sk = [0u8; 32];
    sk[28..].copy_from_slice(&n.to_be_bytes());
    let pk = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secp, &sk).unwrap()).unwrap();
    pk.serialize_vec(&secp, true)[1..33].try_into().unwrap()
}

/// A stand-in for the transport: "seals" S1 and counts how often it was asked.
struct Sealing {
    calls: u32,
    id: u8,
}
impl Sealing {
    fn new(id: u8) -> Sealing {
        Sealing { calls: 0, id }
    }
    fn seal(&mut self, s1: &[u8]) -> Result<Envelope, String> {
        self.calls += 1;
        let mut bytes = b"sealed:".to_vec();
        bytes.extend_from_slice(s1);
        Ok(Envelope {
            event_id: [self.id; 32],
            bytes,
            expires_at: 1_800_000_000,
        })
    }
}
fn prepare_delivery(
    core: &mut C,
    seal: &mut Sealing,
    amount: u64,
    late: bool,
) -> Result<fly_paycore_wallet::Prepared, CoreError> {
    ready(core);
    core.send_prepare_delivery(amount, 0, None, late, CONTACT, &mut |s1| seal.seal(s1))
}

/// The envelope becomes durable in the same frame as the operation and its
/// reserve: after a crash at any point there is either all of it or none, and
/// an envelope the transport could have read survives losing unsynced data.
#[test]
fn envelope_operation_and_reserve_share_one_frame() {
    net();
    let mut seen = std::collections::BTreeMap::new();
    for probe in 0..10u64 {
        for after in [false, true] {
            for data in [
                DataLoss::LoseAll,
                DataLoss::KeepAll,
                DataLoss::Torn(40),
                DataLoss::Garbage,
            ] {
                let Setup {
                    sim,
                    chain: _chain,
                    mut core,
                } = funded(1, &[5 * GRIN]);
                ready(&mut core);
                let mut seal = Sealing::new(1);
                let n = sim.ops() + probe;
                sim.set_fault(Some(if after {
                    Fault::CrashAfter(n)
                } else {
                    Fault::CrashBefore(n)
                }));
                let first = prepare_delivery(&mut core, &mut seal, GRIN, false);
                // what the transport could have read before the machine died
                let published = first
                    .as_ref()
                    .ok()
                    .and_then(|p| core.delivery_envelope(&p.op).map(|e| (p.op, e)));
                let crashed = sim.crashed();
                drop(core);
                if crashed {
                    assert!(first.is_err(), "a result was returned by a dead machine");
                    assert!(published.is_none());
                }
                sim.reboot(Reboot {
                    data,
                    keep_dir_changes: true,
                });
                let (core, report) = open(&sim, 1);
                assert!(!report.recovered, "probe {probe}: {:?}", report.guard);
                let sends = core.sends();
                let reserved = core.balance().reserved;
                match sends.as_slice() {
                    [] => {
                        assert_eq!(reserved, 0, "a reserve without an operation");
                        assert!(published.is_none(), "a published envelope was lost");
                        assert!(core.delivery_pending().is_empty());
                        *seen.entry("nothing").or_insert(0u32) += 1;
                    }
                    [(op, status, _, _)] => {
                        assert_eq!(*status, SendStatus::Prepared);
                        assert!(reserved > 0, "an operation without its reserve");
                        let env = core
                            .delivery_envelope(op)
                            .expect("an operation without its envelope");
                        assert_eq!(env.event_id, [1; 32]);
                        assert!(env.bytes.starts_with(b"sealed:"));
                        if let Some((pop, penv)) = &published {
                            assert_eq!(pop, op);
                            assert_eq!(penv, &env, "a retry would differ from the first send");
                        }
                        assert_eq!(core.delivery_status(op), Some(DeliveryStatus::Queued));
                        assert_eq!(core.delivery_pending(), vec![*op]);
                        *seen.entry("all").or_insert(0u32) += 1;
                    }
                    more => panic!("unexpected operations {more:?}"),
                }
                assert!(seal.calls <= 1);
            }
        }
    }
    println!("delivery prepare crash matrix: {seen:?}");
    assert_eq!(seen.len(), 2, "both outcomes must occur: {seen:?}");
}

/// A sealer that fails, or returns an unusable envelope, leaves no trace; two
/// operations may not share an envelope identifier.
#[test]
fn unusable_envelopes_leave_no_trace() {
    let Setup {
        sim,
        chain: _chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN]);
    ready(&mut core);
    let ops = sim.ops();
    let bad: Vec<Box<dyn FnMut(&[u8]) -> Result<Envelope, String>>> = vec![
        Box::new(|_| Err("no key for the contact".into())),
        Box::new(|_| {
            Ok(Envelope {
                event_id: [1; 32],
                bytes: vec![],
                expires_at: 0,
            })
        }),
        Box::new(|_| {
            Ok(Envelope {
                event_id: [1; 32],
                bytes: vec![0; MAX_ENVELOPE_LEN + 1],
                expires_at: 0,
            })
        }),
    ];
    for mut f in bad {
        let r = core.send_prepare_delivery(GRIN, 0, None, false, CONTACT, &mut *f);
        assert!(matches!(r, Err(CoreError::Refused(_))), "{r:?}");
        assert_eq!(sim.ops(), ops, "a refused prepare wrote something");
        assert_eq!(core.balance().reserved, 0);
        assert!(core.sends().is_empty());
    }
    let mut seal = Sealing::new(1);
    let first = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    let reserved = core.balance().reserved;
    let ops = sim.ops();
    let again = prepare_delivery(&mut core, &mut seal, GRIN, false);
    assert_eq!(again.unwrap_err(), CoreError::Conflict);
    assert_eq!(sim.ops(), ops);
    assert_eq!(core.balance().reserved, reserved);
    assert_eq!(core.sends().len(), 1);
    assert!(core.delivery_envelope(&first.op).is_some());
}

/// What a relay says changes neither money nor the right to sign; an envelope
/// is handed out only while its operation can still be answered.
#[test]
fn delivery_notes_touch_neither_money_nor_signing() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN, 2 * GRIN]);
    let mut seal = Sealing::new(1);
    let p = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    let before = core.balance();
    let env = core.delivery_envelope(&p.op).unwrap();

    core.delivery_note(&p.op, DeliveryNote::QueueBusy).unwrap();
    assert_eq!(core.delivery_status(&p.op), Some(DeliveryStatus::QueueBusy));
    let ops = sim.ops();
    core.delivery_note(&p.op, DeliveryNote::QueueBusy).unwrap();
    assert_eq!(sim.ops(), ops, "a note that changes nothing was written");
    core.delivery_note(&p.op, DeliveryNote::QueueFull).unwrap();
    assert_eq!(core.delivery_status(&p.op), Some(DeliveryStatus::QueueFull));
    core.delivery_note(&p.op, DeliveryNote::RelayUnknown).unwrap();
    let ops = sim.ops();
    core.delivery_note(&p.op, DeliveryNote::RelayUnknown).unwrap();
    assert_eq!(sim.ops(), ops, "a silent relay must not grow the journal");
    assert_eq!(
        core.delivery_status(&p.op),
        Some(DeliveryStatus::WaitingRelay)
    );
    // every retry is the same message
    assert_eq!(core.delivery_envelope(&p.op).unwrap(), env);
    assert_eq!(core.delivery_pending(), vec![p.op]);
    core.delivery_note(&p.op, DeliveryNote::RelayAccepted).unwrap();
    assert_eq!(
        core.delivery_status(&p.op),
        Some(DeliveryStatus::RelayAccepted)
    );
    assert!(core.delivery_pending().is_empty(), "accepted: nothing to retry");
    // an acknowledgement is not a payment
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    assert_eq!(core.balance(), before);
    assert_eq!(core.signatures_made(), 0);

    // the notes survive a restart
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(
        core.delivery_status(&p.op),
        Some(DeliveryStatus::RelayAccepted)
    );
    assert_eq!(core.delivery_envelope(&p.op).unwrap(), env);

    // a closed delivery window stops publishing, not the operation
    core.delivery_note(&p.op, DeliveryNote::Expired).unwrap();
    assert_eq!(core.delivery_status(&p.op), Some(DeliveryStatus::Expired));
    assert!(core.delivery_envelope(&p.op).is_none());
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
    assert_eq!(core.balance(), before);
    let mut other = lw(2, chain.height);
    let fin = core.send_finalize(&p.op, &lw_s2(&mut other, &p.s1)).unwrap();
    chain.mine(&mut [&mut core], &fin.tx);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));

    // cancelled: nothing more is published
    let mut seal2 = Sealing::new(2);
    let c = prepare_delivery(&mut core, &mut seal2, GRIN, false).unwrap();
    assert!(core.delivery_envelope(&c.op).is_some());
    core.send_cancel(&c.op).unwrap();
    assert!(core.delivery_envelope(&c.op).is_none());
    assert!(core.delivery_pending().is_empty());

    // answered: nothing more is published
    let mut seal3 = Sealing::new(3);
    let a = prepare_delivery(&mut core, &mut seal3, GRIN, false).unwrap();
    let mut other = lw(3, chain.height);
    core.send_finalize(&a.op, &lw_s2(&mut other, &a.s1)).unwrap();
    assert!(core.delivery_envelope(&a.op).is_none());
    assert!(core.delivery_pending().is_empty());

    // from the cut-off height on, nothing more is published
    let mut seal4 = Sealing::new(4);
    let ttl = chain.height + 2;
    let t = core
        .send_prepare_delivery(GRIN / 2, ttl, None, false, CONTACT, &mut |s| seal4.seal(s))
        .unwrap();
    chain.empty(&mut [&mut core], 1);
    assert!(core.delivery_envelope(&t.op).is_some());
    chain.empty(&mut [&mut core], 1);
    assert!(core.delivery_envelope(&t.op).is_none());

    // an operation prepared by hand has no delivery to note
    core.send_cancel(&t.op).unwrap();
    let m = core.send_prepare(GRIN / 2, 0, None, false).unwrap();
    assert_eq!(core.delivery_status(&m.op), None);
    assert!(matches!(
        core.delivery_note(&m.op, DeliveryNote::RelayAccepted),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(
        core.delivery_note(&[0xEE; 16], DeliveryNote::RelayAccepted),
        Err(CoreError::NotFound)
    );
}

/// An incoming S2 is matched to its operation by slate id and by the contact
/// the S1 was sent to, without writing anything.
#[test]
fn reply_is_matched_by_slate_and_contact() {
    let Setup {
        sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN, 2 * GRIN]);
    let mut seal = Sealing::new(1);
    let p = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &p.s1);
    let ops = sim.ops();

    assert_eq!(core.send_find_for_reply(&s2, &CONTACT), Ok(p.op));
    // someone else answers with a valid reply to a slate they got hold of
    assert!(matches!(
        core.send_find_for_reply(&s2, &[0x11; 32]),
        Err(CoreError::Refused(_))
    ));
    // a reply to something we never sent
    let mut stranger = lw(4, chain.height);
    let mut other_sender = lw(5, chain.height);
    lw_fund(&mut other_sender, 4 * GRIN, 0);
    let foreign_s1 = to_json(&s1_from_lw(&mut other_sender, GRIN));
    let foreign_s2 = lw_s2(&mut stranger, &foreign_s1);
    assert_eq!(
        core.send_find_for_reply(&foreign_s2, &CONTACT),
        Err(CoreError::NotFound)
    );
    assert!(matches!(
        core.send_find_for_reply(b"{\"not\":\"a slate\"}", &CONTACT),
        Err(CoreError::BadSlate(_))
    ));
    assert_eq!(sim.ops(), ops, "looking up a reply wrote something");
    assert_eq!(core.signatures_made(), 0);

    // after signing: the same reply finds the operation, another one conflicts
    let mut second = lw(3, chain.height);
    let s2b = lw_s2(&mut second, &p.s1);
    core.send_finalize(&p.op, &s2).unwrap();
    assert_eq!(core.send_find_for_reply(&s2, &CONTACT), Ok(p.op));
    assert_eq!(
        core.send_find_for_reply(&s2b, &CONTACT),
        Err(CoreError::Conflict)
    );

    // a cancelled operation accepts no reply
    let mut seal2 = Sealing::new(2);
    let c = prepare_delivery(&mut core, &mut seal2, GRIN, false).unwrap();
    let mut third = lw(6, chain.height);
    let s2c = lw_s2(&mut third, &c.s1);
    core.send_cancel(&c.op).unwrap();
    assert!(matches!(
        core.send_find_for_reply(&s2c, &CONTACT),
        Err(CoreError::Refused(_))
    ));

    // an operation prepared by hand is found whoever hands the reply over
    let m = core.send_prepare(GRIN / 2, 0, None, false).unwrap();
    let mut fourth = lw(7, chain.height);
    let s2m = lw_s2(&mut fourth, &m.s1);
    assert_eq!(core.send_find_for_reply(&s2m, &[0x55; 32]), Ok(m.op));
}

/// Unattended signing is bound to the selected chain: the reply is chosen
/// only while the wallet stands on exactly the tip the chain layer verified,
/// and that tip is written into the arming frame.
#[test]
fn signing_is_bound_to_the_selected_tip() {
    for late in [false, true] {
        let Setup {
            sim,
            mut chain,
            mut core,
        } = funded(1, &[5 * GRIN, 3 * GRIN]);
        let mut seal = Sealing::new(1);
        let p = prepare_delivery(&mut core, &mut seal, GRIN, late).unwrap();
        let mut other = lw(2, chain.height);
        let s2 = lw_s2(&mut other, &p.s1);
        let tip = |c: &Chain| {
            let mut h = [c.height as u8; 32];
            h[1] = (c.height >> 8) as u8;
            (c.height, h)
        };
        let good = tip(&chain);
        let ops = sim.ops();
        let reserved = core.balance().reserved;
        // a tip the wallet has not reached, one it has left, and a fork at its height
        let mut fork = good;
        fork.1[7] ^= 1;
        for sel in [(good.0 + 1, good.1), (good.0 - 1, good.1), fork] {
            assert!(matches!(
                core.send_finalize_at(&p.op, &s2, sel),
                Err(CoreError::Refused(_))
            ));
        }
        assert_eq!(sim.ops(), ops, "a refused signing wrote something");
        assert_eq!(core.signatures_made(), 0);
        assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
        assert_eq!(core.balance().reserved, reserved);
        assert_eq!(core.armed_at(&p.op), None);

        let fin = core.send_finalize_at(&p.op, &s2, good).unwrap();
        assert_eq!(core.signatures_made(), 1);
        assert_eq!(core.armed_at(&p.op), Some((good.0, good.1.to_vec())));

        // the record survives a restart; a repeat returns the stored result
        // without signing even though the chain has moved on
        chain.empty(&mut [&mut core], 2);
        drop(core);
        let (mut core, _) = open(&sim, 1);
        assert_eq!(core.armed_at(&p.op), Some((good.0, good.1.to_vec())));
        let again = core.send_finalize_at(&p.op, &s2, good).unwrap();
        assert_eq!(again.tx, fin.tx);
        assert_eq!(core.signatures_made(), 0);
        chain.mine(&mut [&mut core], &fin.tx);
        assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));
    }
}

/// A reply is not chosen for signing once one of the inputs has been spent
/// by another transaction.
#[test]
fn spent_input_blocks_arming() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let funds = core.unspent();
    let mut seal = Sealing::new(1);
    let p = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &p.s1);
    let mut a = Advance {
        inputs: vec![Commitment(funds[0].0)],
        ..Advance::default()
    };
    chain.block(&mut a);
    core.chain_advance(&a).unwrap();
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Contested));
    assert!(core.delivery_envelope(&p.op).is_none());
    let ops = sim.ops();
    let mut h = [chain.height as u8; 32];
    h[1] = (chain.height >> 8) as u8;
    for r in [
        core.send_finalize(&p.op, &s2),
        core.send_finalize_at(&p.op, &s2, (chain.height, h)),
    ] {
        assert!(matches!(r, Err(CoreError::Refused(_))), "{r:?}");
    }
    assert_eq!(sim.ops(), ops);
    assert_eq!(core.signatures_made(), 0);
    assert_eq!(core.armed_at(&p.op), None);
}

/// A reply that arrived by itself is verified and kept; keeping it signs
/// nothing, reserves nothing, survives a restart and can still be cancelled.
#[test]
fn held_reply_waits_for_the_decision() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN, 2 * GRIN, 2 * GRIN]);
    let tip = |c: &Chain| {
        let mut h = [c.height as u8; 32];
        h[1] = (c.height >> 8) as u8;
        (c.height, h)
    };
    let mut seal = Sealing::new(1);
    let a = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    let mut seal = Sealing::new(2);
    let b = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
    assert_eq!(core.delivery_contacts(), vec![CONTACT]);
    let mut other = lw(2, chain.height);
    let s2a = lw_s2(&mut other, &a.s1);
    let s2a_other = lw_s2(&mut lw(3, chain.height), &a.s1);
    let s2b = lw_s2(&mut other, &b.s1);
    let before = core.balance();

    // a reply to another operation, and a damaged one, are not kept
    let ops = sim.ops();
    assert!(core.send_hold_reply(&a.op, &s2b).is_err());
    let mut damaged = s2a.clone();
    let at = damaged.len() / 2;
    damaged[at] ^= 1;
    assert!(core.send_hold_reply(&a.op, &damaged).is_err());
    assert_eq!(core.send_finalize_held(&a.op), Err(CoreError::Refused("no reply is held for this operation")));
    assert_eq!(sim.ops(), ops, "a refused reply wrote something");
    assert_eq!(core.send_held(&a.op), None);

    core.send_hold_reply(&a.op, &s2a).unwrap();
    assert_eq!(core.send_held(&a.op), Some(s2a.clone()));
    assert_eq!(core.send_status(&a.op), Some(SendStatus::Prepared));
    assert_eq!(core.balance(), before);
    assert_eq!(core.signatures_made(), 0);
    assert_eq!(core.armed_at(&a.op), None);
    // answered: nothing more to publish for it, the other one still waits
    assert!(core.delivery_envelope(&a.op).is_none());
    assert_eq!(core.delivery_pending(), vec![b.op]);
    // the same reply again changes nothing; a different one is refused
    let ops = sim.ops();
    core.send_hold_reply(&a.op, &s2a).unwrap();
    assert_eq!(core.send_hold_reply(&a.op, &s2a_other), Err(CoreError::Conflict));
    assert_eq!(sim.ops(), ops);

    // survives a restart
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.send_held(&a.op), Some(s2a.clone()));

    // unattended signing needs the selected tip
    let good = tip(&chain);
    assert!(matches!(
        core.send_finalize_held_at(&a.op, (good.0 + 1, good.1)),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(core.signatures_made(), 0);
    let fin = core.send_finalize_held_at(&a.op, good).unwrap();
    assert_eq!(core.signatures_made(), 1);
    assert_eq!(core.send_held(&a.op), None, "nothing is held once signed");
    assert_eq!(core.send_finalize_held(&a.op).unwrap().tx, fin.tx);
    assert_eq!(core.signatures_made(), 1, "a repeat signed again");
    core.send_hold_reply(&a.op, &s2a).unwrap();
    assert_eq!(core.send_hold_reply(&a.op, &s2a_other), Err(CoreError::Conflict));
    chain.mine(&mut [&mut core], &fin.tx);
    assert_eq!(core.send_status(&a.op), Some(SendStatus::Confirmed));

    // a held reply does not stop a cancel, and a cancelled operation signs nothing
    core.send_hold_reply(&b.op, &s2b).unwrap();
    assert!(core.delivery_contacts().is_empty());
    let reserved = core.balance().reserved;
    core.send_cancel(&b.op).unwrap();
    assert!(core.balance().reserved < reserved);
    assert_eq!(core.send_held(&b.op), None);
    assert!(matches!(
        core.send_finalize_held(&b.op),
        Err(CoreError::Refused(_))
    ));
    assert_eq!(core.signatures_made(), 1);

    // no reply is kept from the cut-off height on, or once an input is gone
    let mut seal = Sealing::new(3);
    let ttl = chain.height + 1;
    let t = core
        .send_prepare_delivery(GRIN / 2, ttl, None, false, CONTACT, &mut |s| seal.seal(s))
        .unwrap();
    let s2t = lw_s2(&mut lw(4, chain.height), &t.s1);
    chain.empty(&mut [&mut core], 1);
    assert!(matches!(
        core.send_hold_reply(&t.op, &s2t),
        Err(CoreError::Refused(_))
    ));
    core.send_cancel(&t.op).unwrap();
    let funds = core.unspent();
    let mut seal = Sealing::new(4);
    let half = core.balance().spendable / 2;
    let c = prepare_delivery(&mut core, &mut seal, half, false).unwrap();
    let s2c = lw_s2(&mut lw(5, chain.height), &c.s1);
    let mut adv = Advance {
        inputs: funds.iter().map(|f| Commitment(f.0)).collect(),
        ..Advance::default()
    };
    chain.block(&mut adv);
    core.chain_advance(&adv).unwrap();
    assert_eq!(core.send_status(&c.op), Some(SendStatus::Contested));
    assert!(matches!(
        core.send_hold_reply(&c.op, &s2c),
        Err(CoreError::Refused(_))
    ));
}

/// Keeping a reply is one frame: after a crash it is either kept or not, and
/// nothing was signed either way.
#[test]
fn crash_while_holding_a_reply() {
    net();
    let mut seen = std::collections::BTreeMap::new();
    for probe in 0..8u64 {
        for after in [false, true] {
            for data in [DataLoss::LoseAll, DataLoss::KeepAll, DataLoss::Torn(40)] {
                let Setup {
                    sim,
                    chain,
                    mut core,
                } = funded(1, &[5 * GRIN]);
                let mut seal = Sealing::new(1);
                let p = prepare_delivery(&mut core, &mut seal, GRIN, false).unwrap();
                let s2 = lw_s2(&mut lw(2, chain.height), &p.s1);
                let n = sim.ops() + probe;
                sim.set_fault(Some(if after {
                    Fault::CrashAfter(n)
                } else {
                    Fault::CrashBefore(n)
                }));
                let first = core.send_hold_reply(&p.op, &s2);
                assert_eq!(core.signatures_made(), 0);
                let crashed = sim.crashed();
                drop(core);
                if crashed {
                    assert!(first.is_err());
                }
                sim.reboot(Reboot {
                    data,
                    keep_dir_changes: true,
                });
                let (mut core, report) = open(&sim, 1);
                assert!(!report.recovered, "probe {probe}: {:?}", report.guard);
                assert_eq!(core.send_status(&p.op), Some(SendStatus::Prepared));
                assert!(core.balance().reserved > 0);
                match core.send_held(&p.op) {
                    None => {
                        assert!(first.is_err(), "a kept reply was lost");
                        assert!(core.delivery_envelope(&p.op).is_some());
                        core.send_hold_reply(&p.op, &s2).unwrap();
                        *seen.entry("not kept").or_insert(0u32) += 1;
                    }
                    Some(kept) => {
                        assert_eq!(kept, s2);
                        *seen.entry("kept").or_insert(0u32) += 1;
                    }
                }
                core.send_finalize_held(&p.op).unwrap();
                assert_eq!(core.signatures_made(), 1);
            }
        }
    }
    println!("hold crash matrix: {seen:?}");
    assert_eq!(seen.len(), 2, "both outcomes must occur: {seen:?}");
}

// ----- Slatepack text -------------------------------------------------------

/// Slatepack text made by Grin's own packer for the holder of `secret`.
fn grin_pack(slate_json: &[u8], encrypt_to: Option<[u8; 32]>) -> String {
    use grin_wallet_libwallet::{SlatepackAddress, Slatepacker, SlatepackerArgs};
    let slate = from_json(slate_json);
    let recipients = encrypt_to
        .map(|k| {
            vec![SlatepackAddress::new(
                &ed25519_dalek::VerifyingKey::from_bytes(&k).unwrap(),
            )]
        })
        .unwrap_or_default();
    let packer = Slatepacker::new(SlatepackerArgs {
        sender: None,
        recipients,
        dec_key: None,
    });
    packer
        .armor_slatepack(&packer.create_slatepack(&slate).unwrap())
        .unwrap()
}
/// Open Slatepack text with Grin's own packer and the given address secret.
fn grin_unpack(text: &str, secret: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    use grin_wallet_libwallet::{Slatepacker, SlatepackerArgs};
    let key = secret.map(ed25519_dalek::SigningKey::from_bytes);
    let packer = Slatepacker::new(SlatepackerArgs {
        sender: None,
        recipients: vec![],
        dec_key: key.as_ref(),
    });
    let pack = packer.deser_slatepack(text.as_bytes(), true).ok()?;
    packer.get_slate(&pack).ok().map(|s| to_json(&s))
}

/// A whole payment carried as Slatepack text in both directions, plain and
/// encrypted, against Grin's own packer.
#[test]
fn slatepack_text_carries_a_payment_both_ways() {
    let Setup {
        sim,
        mut chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN]);
    let ours = core.receive_address().unwrap();
    let their_secret = [0x33u8; 32];
    let theirs = ed25519_dalek::SigningKey::from_bytes(&their_secret)
        .verifying_key()
        .to_bytes();
    let ops = sim.ops();

    // plain: our S1 out, read by Grin; Grin's S2 back, read by us
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let text = fly_paycore_wallet::slatepack_encode(&p.s1).unwrap();
    assert!(text.starts_with("BEGINSLATEPACK.") && text.trim_end().ends_with("ENDSLATEPACK."));
    assert!(text.len() < 4096, "an S1 of {} characters", text.len());
    let s1_at_grin = grin_unpack(&text, None).unwrap();
    let mut other = lw(2, chain.height);
    let s2 = lw_s2(&mut other, &s1_at_grin);
    let back = core.slatepack_decode(&grin_pack(&s2, None)).unwrap();
    assert_eq!(
        fly_paycore_wallet::slate_stage(&back),
        Ok(fly_paycore_wallet::SlateStage::S2)
    );
    let fin = core.send_finalize(&p.op, &back).unwrap();
    chain.mine(&mut [&mut core], &fin.tx);
    assert_eq!(core.send_status(&p.op), Some(SendStatus::Confirmed));

    // encrypted for us: opened; encrypted for someone else: refused
    let q = core.send_prepare(GRIN, 0, None, false).unwrap();
    let s2 = lw_s2(&mut lw(3, chain.height), &q.s1);
    let for_us = grin_pack(&s2, Some(ours));
    assert!(grin_unpack(&for_us, None).is_none(), "the pack is not encrypted");
    assert!(grin_unpack(&for_us, Some(&their_secret)).is_none());
    let opened = core.slatepack_decode(&for_us).unwrap();
    assert_eq!(from_json(&opened).id, from_json(&s2).id);
    let for_them = grin_pack(&s2, Some(theirs));
    assert!(matches!(
        core.slatepack_decode(&for_them),
        Err(CoreError::BadSlate(_))
    ));
    core.send_finalize(&q.op, &opened).unwrap();

    // encrypted by us for them: only they can read it, and it names no one else
    let r = core.send_prepare(GRIN / 2, 0, None, false).unwrap();
    let sealed = core.slatepack_encode_for(&r.s1, theirs).unwrap();
    assert!(grin_unpack(&sealed, None).is_none());
    assert!(matches!(
        core.slatepack_decode(&sealed),
        Err(CoreError::BadSlate(_))
    ));
    let at_them = grin_unpack(&sealed, Some(&their_secret)).unwrap();
    assert_eq!(from_json(&at_them).id, from_json(&r.s1).id);

    // decoding and encoding write nothing
    let ops_after = sim.ops();
    for _ in 0..3 {
        core.slatepack_decode(&for_us).unwrap();
        fly_paycore_wallet::slatepack_encode(&r.s1).unwrap();
    }
    assert_eq!(sim.ops(), ops_after);
    assert!(ops_after > ops);

    // what is not Slatepack text
    let json = String::from_utf8(r.s1.clone()).unwrap();
    let huge = format!("BEGINSLATEPACK. {} ENDSLATEPACK.", "a".repeat(200 * 1024));
    for bad in [
        "",
        "BEGINSLATEPACK.",
        "BEGINSLATEPACK. ENDSLATEPACK.",
        "BEGINSLATEPACK. !!!! ENDSLATEPACK.",
        "BEGINSLATEPACK. дважды ENDSLATEPACK.",
        json.as_str(),
        huge.as_str(),
    ] {
        assert!(
            matches!(core.slatepack_decode(bad), Err(CoreError::BadSlate(_))),
            "accepted: {}",
            &bad[..bad.len().min(40)]
        );
    }
    assert!(fly_paycore_wallet::slatepack_encode(b"{}").is_err());
}

/// Damaged Slatepack text never panics and never yields a slate the core
/// would not have taken as JSON.
#[test]
fn damaged_slatepack_text_never_panics() {
    let Setup {
        sim,
        chain,
        mut core,
    } = funded(1, &[5 * GRIN]);
    let ours = core.receive_address().unwrap();
    let p = core.send_prepare(GRIN, 0, None, false).unwrap();
    let s2 = lw_s2(&mut lw(2, chain.height), &p.s1);
    let plain = grin_pack(&s2, None);
    let sealed = grin_pack(&s2, Some(ours));
    let ops = sim.ops();
    let alphabet: Vec<char> = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        .chars()
        .collect();
    let mut rng = Xs(0x51A7E9AC);
    let (mut read, mut refused) = (0u32, 0u32);
    for base in [&plain, &sealed] {
        let chars: Vec<char> = base.chars().collect();
        for round in 0..1500u32 {
            let mut c = chars.clone();
            match round % 5 {
                0 => {
                    let at = rng.below(c.len().max(1));
                    c[at] = alphabet[rng.below(alphabet.len())];
                }
                1 => c.truncate(rng.below(c.len().max(1))),
                2 => {
                    let at = rng.below(c.len().max(1));
                    c.remove(at);
                }
                3 => {
                    let at = rng.below(c.len().max(1));
                    let n = 1 + rng.below(40);
                    for _ in 0..n {
                        c.insert(at, alphabet[rng.below(alphabet.len())]);
                    }
                }
                _ => {
                    for _ in 0..(1 + rng.below(6)) {
                        let at = rng.below(c.len().max(1));
                        c[at] = alphabet[rng.below(alphabet.len())];
                    }
                }
            }
            let text: String = c.into_iter().collect();
            match core.slatepack_decode(&text) {
                Ok(json) => {
                    // whatever came out is a slate the core parses, and it
                    // is still subject to every check before signing
                    fly_paycore_wallet::slate_stage(&json).unwrap();
                    read += 1;
                }
                Err(CoreError::BadSlate(_)) => refused += 1,
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }
    }
    println!("slatepack fuzz: {read} read, {refused} refused");
    assert!(refused > 2000, "almost nothing was refused: {refused}");
    assert_eq!(sim.ops(), ops, "decoding wrote something");
    assert_eq!(core.signatures_made(), 0);
    // and the untouched text still works
    let good = core.slatepack_decode(&sealed).unwrap();
    core.send_finalize(&p.op, &good).unwrap();
}

// ----- transport identity and contacts ---------------------------------------

/// The transport identity is a key of its own, kept in the journal; contacts
/// decide whom a payment can be delivered to.
#[test]
fn transport_identity_and_contacts() {
    use fly_paycore_wallet::{npub_decode, npub_encode, nsec_decode, nsec_encode, MAX_CONTACTS};
    let Setup {
        sim,
        chain: _chain,
        mut core,
    } = funded(1, &[5 * GRIN, 3 * GRIN]);
    // nothing travels by itself before there is an identity and a contact
    let mut seal = Sealing::new(1);
    let ops = sim.ops();
    let r = core.send_prepare_delivery(GRIN, 0, None, false, CONTACT, &mut |s| seal.seal(s));
    assert_eq!(r.unwrap_err(), CoreError::Refused("the wallet has no transport identity"));
    assert_eq!((core.identity(), core.identity_secret().is_some()), (None, false));
    assert_eq!(core.transport_store_key().map(|k| *k), None);

    let first = core.identity_create(false).unwrap();
    let id = core.identity().unwrap();
    assert_eq!((id.public, id.imported, id.previous.len()), (first, false, 0));
    let secret = core.identity_secret().unwrap();
    assert_ne!(*secret, [0u8; 32]);
    let store_key = core.transport_store_key().unwrap();
    assert!(*store_key != *secret && *store_key != first);
    let r = core.send_prepare_delivery(GRIN, 0, None, false, CONTACT, &mut |s| seal.seal(s));
    assert_eq!(r.unwrap_err(), CoreError::Refused("the recipient is not a contact"));
    assert_eq!(core.balance().reserved, 0);
    assert_eq!(seal.calls, 0, "the transport was asked to seal for a stranger");
    assert!(sim.ops() > ops);

    // a second identity only on request; the old public key is remembered
    assert!(matches!(core.identity_create(false), Err(CoreError::Refused(_))));
    let second = core.identity_create(true).unwrap();
    assert_ne!(second, first);
    assert_eq!(core.identity().unwrap().previous, vec![first]);
    assert_ne!(*core.transport_store_key().unwrap(), *store_key);
    // an imported key: secret 1 is the generator, whose x is CONTACT
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(core.identity_import(&one, true).unwrap(), CONTACT);
    assert_eq!(*core.identity_secret().unwrap(), one);
    let id = core.identity().unwrap();
    assert_eq!((id.imported, id.previous), (true, vec![first, second]));
    assert_eq!(core.identity_import(&one, true), Err(CoreError::Conflict));
    assert!(matches!(core.identity_import(&[0u8; 32], true), Err(CoreError::BadSlate(_))));
    assert!(matches!(core.identity_import(&[0xFF; 32], true), Err(CoreError::BadSlate(_))));

    // the forms users pass around, against the examples of NIP-19
    let pk: [u8; 32] = hex_to("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    let sk: [u8; 32] = hex_to("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");
    let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    assert_eq!(npub_encode(&pk).unwrap(), npub);
    assert_eq!(nsec_encode(&sk).unwrap().as_str(), nsec);
    assert_eq!(npub_decode(npub).unwrap(), pk);
    assert_eq!(*nsec_decode(&format!("  {nsec}\n")).unwrap(), sk);
    for bad in ["", "npub1", nsec, "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7", "not a key"] {
        assert!(npub_decode(bad).is_err(), "{bad}");
    }
    assert!(nsec_decode(npub).is_err(), "a public key was taken as a secret");

    // contacts
    let bob = xonly(2);
    for (key, name) in [
        ([0xFF; 32], "Bob"),          // not a point on the curve
        (bob, ""),
        (bob, " Bob"),
        (bob, "Bob\nMallory"),
        (bob, "x".repeat(65).as_str()),
        (CONTACT, "Me"),              // the wallet's own key
    ] {
        assert!(matches!(core.contact_set(key, name, None), Err(CoreError::Refused(_))), "{name:?}");
    }
    assert!(core.contacts().is_empty());
    let address = core.receive_address().unwrap();
    core.contact_set(bob, "Боб", Some(address)).unwrap();
    core.contact_set(xonly(3), "Alice", None).unwrap();
    let list = core.contacts();
    assert_eq!(list.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Alice", "Боб"]);
    assert_eq!((list[1].key, list[1].address), (bob, Some(address)));
    core.contact_set(bob, "Bob", None).unwrap();
    assert_eq!(core.contacts().len(), 2);
    assert_eq!(core.contacts()[1].name, "Bob");
    // the wallet cannot take a contact's key as its own
    let mut two = [0u8; 32];
    two[31] = 2;
    assert!(matches!(core.identity_import(&two, true), Err(CoreError::Refused(_))));

    // everything survives a restart
    drop(core);
    let (mut core, _) = open(&sim, 1);
    assert_eq!(core.identity().unwrap().public, CONTACT);
    assert_eq!(*core.identity_secret().unwrap(), one);
    assert_eq!(core.contacts().len(), 2);

    // a delivered payment pins its contact and the identity until it is closed
    let p = core
        .send_prepare_delivery(GRIN, 0, None, false, bob, &mut |s| seal.seal(s))
        .unwrap();
    assert_eq!(seal.calls, 1);
    assert!(matches!(core.contact_remove(&bob), Err(CoreError::Refused(_))));
    assert!(matches!(core.identity_create(true), Err(CoreError::Refused(_))));
    core.contact_remove(&xonly(3)).unwrap();
    assert_eq!(core.contact_remove(&xonly(3)), Err(CoreError::NotFound));
    core.send_cancel(&p.op).unwrap();
    core.contact_remove(&bob).unwrap();
    let mut seal2 = Sealing::new(2);
    let r = core.send_prepare_delivery(GRIN, 0, None, false, bob, &mut |s| seal2.seal(s));
    assert_eq!(r.unwrap_err(), CoreError::Refused("the recipient is not a contact"));
    core.identity_create(true).unwrap();

    // the book is bounded; changing an entry still works when it is full
    for n in 0..MAX_CONTACTS as u32 {
        core.contact_set(xonly(100 + n), &format!("contact {n}"), None).unwrap();
    }
    assert!(matches!(core.contact_set(xonly(999), "one more", None), Err(CoreError::Refused(_))));
    core.contact_set(xonly(100), "renamed", None).unwrap();
    assert_eq!(core.contacts().len(), MAX_CONTACTS);
}

fn hex_to<const N: usize>(s: &str) -> [u8; N] {
    let v: Vec<u8> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

#[test]
fn invoice_payment_waits_for_wallet_search() {
    let mut payer = funded(1, &[9 * GRIN]).core;
    let mut issuer = funded(2, &[GRIN]).core;
    let (_, i1) = issuer.invoice_issue(GRIN, None).unwrap();
    payer.old_search_start().unwrap();
    let before = (payer.journal_tail(), payer.balance(), payer.signatures_made());
    assert!(matches!(payer.invoice_pay(&i1, GRIN), Err(CoreError::Refused(_))));
    assert_eq!((payer.journal_tail(), payer.balance(), payer.signatures_made()), before);
}

#[test]
fn a_new_sender_signature_waits_for_wallet_search() {
    for late in [false, true] {
        let mut payer = funded(1, &[9 * GRIN]).core;
        let mut payee = funded(2, &[GRIN]).core;
        let payment = if late {
            payer.send_prepare_late(GRIN, 0, None)
        } else {
            payer.send_prepare(GRIN, 0, None, false)
        }.unwrap();
        let s2 = payee.receive_draft(&payment.s1, None).unwrap();
        payer.old_search_start().unwrap();
        let before = (payer.journal_tail(), payer.balance(), payer.signatures_made());
        assert!(matches!(payer.send_finalize(&payment.op, &s2), Err(CoreError::Refused(_))));
        assert_eq!((payer.journal_tail(), payer.balance(), payer.signatures_made()), before);
    }
}

/// Before an invoice is paid the wallet says what paying it takes: the
/// amount asked and the fee of the inputs it would spend. Saying so reads
/// only. Paying takes both numbers as limits: with a fee above the one
/// agreed nothing is signed. After the payment the same invoice is
/// answered with what was paid and the operation; an invoice changed under
/// the same number is a conflict, one past its cutoff is refused.
#[test]
fn an_invoice_is_reviewed_before_it_is_paid() -> Result<(), &'static str> {
    let Setup { mut core, .. } = funded(1, &[9 * GRIN]);
    let mut issuer = funded(2, &[GRIN]).core;
    let tip = core.tip_height().ok_or("payer height")?;
    let (_, bytes) = issuer.invoice_issue(2 * GRIN, None).map_err(|_| "issue")?;
    let before = (core.journal_tail(), core.balance(), core.signatures_made());

    let review = core.invoice_review(&bytes).map_err(|_| "review")?;
    assert_eq!((review.amount, review.paid), (2 * GRIN, None));
    assert!(review.fee > 0 && review.fee < GRIN / 10);
    assert_eq!((core.journal_tail(), core.balance(), core.signatures_made()), before, "a review reads only");

    // more than the wallet has, a cutoff reached: said at the review
    let mut invoice = from_json(&bytes);
    invoice.amount = 10 * GRIN;
    assert!(core.invoice_review(&to_json(&invoice)).is_err());
    let mut invoice = from_json(&bytes);
    invoice.ttl_cutoff_height = tip;
    assert!(matches!(core.invoice_review(&to_json(&invoice)), Err(CoreError::BadSlate(_))));
    assert_eq!((core.journal_tail(), core.balance(), core.signatures_made()), before);

    // a fee above the agreed one: nothing is signed
    let low = review.fee.checked_sub(1).ok_or("fee")?;
    assert_eq!(
        core.invoice_pay_agreed(&bytes, review.amount, low).map_err(|e| matches!(e, CoreError::Refused("the fee is higher than agreed"))),
        Err(true)
    );
    assert_eq!((core.journal_tail(), core.balance(), core.signatures_made()), before);

    // exactly what was shown
    let (op, _) = core.invoice_pay_agreed(&bytes, review.amount, review.fee).map_err(|_| "pay")?;
    assert_eq!(core.signatures_made(), 1);
    let after = (core.journal_tail(), core.balance(), core.signatures_made());
    let paid = core.invoice_review(&bytes).map_err(|_| "review of a paid one")?;
    assert_eq!((paid.amount, paid.fee, paid.paid), (review.amount, review.fee, Some(op)));
    let mut changed = from_json(&bytes);
    changed.amount -= 1;
    assert_eq!(core.invoice_review(&to_json(&changed)), Err(CoreError::Conflict));
    assert_eq!((core.journal_tail(), core.balance(), core.signatures_made()), after);
    Ok(())
}

#[test]
fn invoice_cutoff_guards_new_signatures_and_preserves_signed_replies() -> Result<(), &'static str> {
    let Setup { mut core, mut chain, .. } = funded(1, &[9 * GRIN]);
    let mut issuer = funded(2, &[GRIN]).core;
    let tip = core.tip_height().ok_or("payer height")?;
    assert_eq!(issuer.tip_height(), Some(tip));
    let (id, bytes) = issuer.invoice_issue(GRIN, None).map_err(|_| "issue")?;
    let mut invoice = from_json(&bytes);
    let before = (core.journal_tail(), core.balance(), core.signatures_made());
    for height in [tip, tip.saturating_sub(1)] {
        invoice.ttl_cutoff_height = height;
        assert!(core.invoice_pay(&to_json(&invoice), GRIN).is_err());
        assert_eq!((core.journal_tail(), core.balance(), core.signatures_made()), before);
    }

    let cutoff = tip.checked_add(1).ok_or("height")?;
    invoice.ttl_cutoff_height = cutoff;
    let i1 = to_json(&invoice);
    let (op, i2) = core.invoice_pay(&i1, GRIN).map_err(|_| "pay before cutoff")?;
    let mut reply = from_json(&i2);
    assert_eq!(reply.ttl_cutoff_height, cutoff);
    reply.ttl_cutoff_height = tip;
    let before = (issuer.journal_tail(), issuer.signatures_made());
    assert!(issuer.invoice_finalize(&id, &to_json(&reply)).is_err());
    assert_eq!((issuer.journal_tail(), issuer.signatures_made()), before);
    let fin = issuer.invoice_finalize(&id, &i2).map_err(|_| "finish before cutoff")?;

    chain.empty(&mut [&mut core, &mut issuer], 1);
    let before = (core.journal_tail(), issuer.journal_tail(), core.signatures_made(), issuer.signatures_made());
    assert_eq!(core.invoice_pay(&i1, GRIN).map_err(|_| "repeat I1")?, (op, i2.clone()));
    assert_eq!(issuer.invoice_finalize(&id, &i2).map_err(|_| "repeat I2")?, fin);
    assert_eq!((core.journal_tail(), issuer.journal_tail(), core.signatures_made(), issuer.signatures_made()), before);
    Ok(())
}
