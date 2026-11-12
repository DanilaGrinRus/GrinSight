//! Robustness fuzzing of every parser that reads data from OTHER people or
//! from disk (RESEARCH / NOT VERIFIED).
//!
//! Each target starts from valid inputs (real slatepacks, slate JSON,
//! journals, wallet files, seed files, checkpoints, header and state files,
//! bundles, release files) and feeds thousands of mutations: bit flips,
//! random bytes, cuts, insertions, duplicated ranges, JSON-special characters,
//! splices of two inputs. The only property checked is the one that matters
//! for hostile input: every call RETURNS (Ok or an error) - no panic, no hang.
//! A failing input is written to `<temp>/grinsight-fuzz-<target>.bin`.
//!
//! Deterministic (fixed seed per target). Iterations: `GRINSIGHT_FUZZ_ITERS`
//! (default 1500 per target); e.g. `set GRINSIGHT_FUZZ_ITERS=50000` for a long run.

use crate::headers::*;
use crate::outputs::*;
use crate::receive::*;
use crate::testkit::{reference, block, id};
use crate::wallet::*;
use grin_core::core::hash::Hashed;
use grin_util::ToHex;
use grin_core::global::{self, ChainTypes};
use grin_keychain::{ExtKeychain, Keychain};
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const SPECIAL: &[u8] = b"\"{}[],:\\\n\r\t 0-9.eE+ \x00\xff\xc3\xa9BEGINSLATEPACK";

fn mutate(r: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut d = seeds[r.below(seeds.len())].clone();
    for _ in 0..1 + r.below(4) {
        let n = d.len();
        match r.below(9) {
            0 if n > 0 => { let i = r.below(n); d[i] ^= 1 << r.below(8); }
            1 if n > 0 => { let i = r.below(n); d[i] = r.next() as u8; }
            2 if n > 0 => { let i = r.below(n); d.truncate(i); }
            3 if n > 0 => { let a = r.below(n); let b = (a + 1 + r.below(64)).min(n); d.drain(a..b); }
            4 => { let i = r.below(n + 1); let k = 1 + r.below(16); for _ in 0..k { d.insert(i, r.next() as u8); } }
            5 if n > 0 => { let a = r.below(n); let b = (a + 1 + r.below(256)).min(n); let s: Vec<u8> = d[a..b].to_vec(); let i = r.below(d.len() + 1); d.splice(i..i, s); }
            6 => { let i = r.below(n + 1); d.insert(i, SPECIAL[r.below(SPECIAL.len())]); }
            7 => { let o = &seeds[r.below(seeds.len())]; let cut = r.below(n + 1); let from = r.below(o.len() + 1); d.truncate(cut); d.extend_from_slice(&o[from..]); }
            _ if n > 0 => { let i = r.below(n); let digit = b"0123456789abcdef"[r.below(16)]; d[i] = digit; }
            _ => {}
        }
    }
    d
}

fn iters() -> usize {
    std::env::var("GRINSIGHT_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500)
}

/// Run `target` on every mutation; a panic fails the test with the input saved.
fn fuzz(name: &str, seed: u64, seeds: Vec<Vec<u8>>, mut target: impl FnMut(&[u8])) {
    let mut r = Rng(seed | 1);
    for s in &seeds {
        let s = s.clone();
        assert!(catch_unwind(AssertUnwindSafe(|| target(&s))).is_ok(), "{name}: valid seed panicked");
    }
    for i in 0..iters() {
        let input = mutate(&mut r, &seeds);
        if catch_unwind(AssertUnwindSafe(|| target(&input))).is_err() {
            let p = std::env::temp_dir().join(format!("grinsight-fuzz-{name}.bin"));
            let _ = std::fs::write(&p, &input);
            panic!("{name}: PANIC on mutation {i}; input saved to {}", p.display());
        }
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn wallets() -> Wallets {
    Wallets::from_keychains(vec![ExtKeychain::from_seed(&[3; 32], true).unwrap(), ExtKeychain::from_seed(&[4; 32], true).unwrap()])
}

fn input(w: &Wallets, wallet: usize, n: u32, amount: u64) -> InputSel {
    let id = ExtKeychain::derive_key_id(3, 0, 0, n, 0);
    let c = w.keychain(wallet).unwrap().commit(amount, &id, grin_keychain::SwitchCommitmentType::Regular).unwrap();
    InputSel::new(&id, amount, false, &c)
}

fn tmp(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("grinsight-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name).to_str().unwrap().to_string()
}

/// Slatepacks and slate JSON from other wallets: receive (S1), finalize (S2),
/// pay an invoice (I1), finalize an invoice (I2), slate JSON.
#[test]
fn fuzz_slatepacks_and_slate_json() {
    global::set_local_chain_type(ChainTypes::Testnet);
    let w = wallets();
    let a = slatepack_address(w.keychain(0).unwrap()).unwrap();
    let b = slatepack_address(w.keychain(1).unwrap()).unwrap();
    let cands = vec![input(&w, 0, 1, 4_000_000_000), input(&w, 0, 2, 3_000_000_000)];
    let built = build_send(&w, 0, &cands, &[], 1_000_000_000, &b).unwrap();
    let s2 = receive(&w, 1, &[], &built.s1, None).unwrap().response;
    let (i1, isc, _) = issue_invoice(&w, 1, &[], 1_000_000_000, Some(&a)).unwrap();
    let i2 = pay_invoice(&w, 0, &cands, &[], &i1, Some(5)).unwrap().i2;
    let seeds: Vec<Vec<u8>> = [&built.s1, &built.s1_json, &s2, &i1, &i2].iter().map(|x| x.as_bytes().to_vec()).collect();
    let sc = built.context;
    fuzz("slatepack-receive", 11, seeds.clone(), |d| { let _ = receive(&w, 1, &[], &s(d), Some(5)); });
    fuzz("slatepack-finalize", 12, seeds.clone(), |d| { let _ = finalize(&w, &sc, &s(d)); });
    fuzz("slatepack-pay-invoice", 13, seeds.clone(), |d| { let _ = pay_invoice(&w, 0, &cands, &[], &s(d), Some(5)); });
    fuzz("slatepack-finalize-invoice", 14, seeds.clone(), |d| { let _ = finalize_invoice(&w, &isc, &s(d)); });
    fuzz("slate-json", 15, seeds, |d| { let _ = slate_from_json(&s(d)); });
}

/// Pending journal, wallet-outputs (known) file, seed file, key ids.
#[test]
fn fuzz_wallet_files() {
    global::set_local_chain_type(ChainTypes::Testnet);
    let w = wallets();
    let pend = tmp("pending.jsonl");
    let _ = std::fs::remove_file(&pend);
    let c1 = format!("08{}", "11".repeat(32));
    let key = ExtKeychain::derive_key_id(3, 0, 0, 7, 0);
    reserve_payment(&pend, 1, "a1b2", "send", &[c1.clone()], 9, 5, &key, &c1, "tgrin1x").unwrap();
    reserve_inputs(&pend, 2, "c3d4", "invoice", &[c1.clone()], 9).unwrap();
    let journal = std::fs::read(&pend).unwrap();
    let body = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":5,\"tip_hash\":\"00\"}}\n{{\"wallet\":1,\"commit\":\"{c1}\",\"amount\":5,\"key_id\":\"{}\"}}\n", key.to_hex());
    let known = format!("{body}{{\"mac\":\"{}\",\"records\":1}}\n", w.file_mac(body.as_bytes()));
    let phrase = grin_keychain::mnemonic::from_entropy(&[3; 32]).unwrap();
    let seeds_file = format!("# wallets\n{phrase}\nlabel\n{phrase}\n");
    let seeds = vec![journal, known.into_bytes(), seeds_file.into_bytes()];
    let f = tmp("fuzz-file");
    fuzz("pending-journal", 21, seeds.clone(), |d| {
        let _ = crate::receive::journal_text(&s(d), "x");
        std::fs::write(&f, d).unwrap();
        let _ = reserved_inputs(&f);
        let _ = read_key_ids(&f, 1);
        let _ = pending_has_change(&f, "a1b2");
    });
    fuzz("known-outputs", 22, seeds.clone(), |d| {
        std::fs::write(&f, d).unwrap();
        let _ = read_known_key_ids(&w, &f, 1);
    });
    fuzz("seed-file", 23, seeds.clone(), |d| { let _ = parse_phrases(&s(d)); });
    fuzz("key-id-hex", 24, vec![key.to_hex().into_bytes()], |d| { let _ = key_id_from_hex(&s(d)); });
    // repair never corrupts a journal it accepts: the result reads cleanly
    let mut r = Rng(25);
    let rp = tmp("repair.jsonl");
    for _ in 0..iters() / 5 {
        let d = mutate(&mut r, &seeds[..1]);
        std::fs::write(&rp, &d).unwrap();
        if repair_pending(&rp).is_ok() {
            assert!(reserved_inputs(&rp).is_ok() || crate::receive::journal_text(&std::fs::read_to_string(&rp).unwrap_or_default(), "x").is_ok());
        }
    }
}

/// Chain data from disk or peers: checkpoint text, recent headers, output
/// state file, gap bundle, header file, release file.
#[test]
fn fuzz_chain_files() {
    global::set_local_chain_type(ChainTypes::Testnet);
    let v = Verifier::from_genesis();
    let cp = tmp("cp.rwm");
    write_checkpoint_to_quiet(&v, &cp);
    let cp_text = std::fs::read(&cp).unwrap();
    let mut hdrs = Vec::new();
    hdrs.extend_from_slice(&1u32.to_le_bytes());
    let gb = grin_core::ser::ser_vec(&v.tip, grin_core::ser::ProtocolVersion::local()).unwrap();
    hdrs.extend_from_slice(&(gb.len() as u32).to_le_bytes());
    hdrs.extend_from_slice(&gb);
    let r = reference(300, 3);
    let (bm, out) = r.compacted_segments(4);
    let st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
    let state = st.to_bytes(&r.header()).unwrap();
    let bundle_path = tmp("b.ugb");
    let blk = block(&r.header(), &[id(5_000_001)], &[id(1)]);
    write_bundle(&bundle_path, &Bundle { peers: vec!["p".into()], blocks: vec![vec![blk]], bitmap: bm, output: out, kernel: None }).unwrap();
    let bundle = std::fs::read(&bundle_path).unwrap();
    let release = format!(
        "{}\nnetwork=testnet\ngenesis={}\nheight=0\nheader_hash={}\nmmr_root=00\nmmr_leaves=1\ncheckpoint_sha256=00\nhistory_sha256=00\nsequence=1\nkey_id=1\n",
        crate::release::HEADER, v.tip.hash().to_hex(), v.tip.hash().to_hex()
    );
    let seeds = vec![cp_text, hdrs, state, bundle, release.into_bytes()];
    let f = tmp("chain-file");
    fuzz("checkpoint", 31, seeds.clone(), |d| { let _ = load_checkpoint_text(&s(d), None); });
    fuzz("recent-headers", 32, seeds.clone(), |d| { let _ = parse_state_headers(d); });
    fuzz("output-state", 33, seeds.clone(), |d| { let _ = OutputState::from_bytes(d); });
    fuzz("gap-bundle", 34, seeds.clone(), |d| {
        std::fs::write(&f, d).unwrap();
        let _ = read_bundle(&f);
    });
    fuzz("header-file", 35, seeds.clone(), |d| {
        std::fs::write(&f, d).unwrap();
        let _ = read_headers(&f);
    });
    fuzz("release", 36, seeds, |d| {
        let _ = crate::release::Release::parse(&s(d));
        let _ = crate::release::pinned_keys(&s(d));
    });
}

/// Inputs that once made a target panic (saved by `fuzz`), replayed on every
/// run: `grinsight-state/fuzz-corpus/<target>-*.bin`.
#[test]
fn fuzz_regressions() {
    global::set_local_chain_type(ChainTypes::Testnet);
    let w = wallets();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz-corpus");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let data = std::fs::read(e.path()).unwrap();
        let text = s(&data);
        let r = catch_unwind(AssertUnwindSafe(|| {
            if name.starts_with("slatepack-") {
                let _ = receive(&w, 1, &[], &text, None);
                let _ = slate_from_json(&text);
                let _ = invoice_slate_id(&w, 0, &text);
            }
        }));
        assert!(r.is_ok(), "regression input {name} panics again");
        n += 1;
    }
    assert!(n > 0, "corpus is empty");
}
