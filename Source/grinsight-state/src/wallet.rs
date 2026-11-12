//! Wallet side of the verified light mode (RESEARCH / NOT VERIFIED, Floonet).
//!
//! * Keys: mnemonic -> entropy -> `ExtKeychain::from_seed(_, is_test)`,
//!   exactly as grin-wallet `WalletSeed::from_mnemonic` + `derive_keychain`.
//! * Discovery: rewind each rangeproof with `ProofBuilder` (grin-wallet's
//!   current scheme), then require `keychain.commit(amount, id, switch)` to
//!   equal the output commitment.
//! * Spend: single-party self-transfer built with `libtx::build`, validated
//!   locally before it is handed to peers.
//!
//! Phrases are read from a local file and kept only in memory; nothing derived
//! from them (keys, blinding factors) is printed or written. Output records
//! (commitment, amount, key path) are written only when asked.

use grin_core::core::{self, OutputIdentifier};
use grin_core::global;
use grin_util::secp::pedersen::RangeProof;
use grin_core::core::{KernelFeatures, Output, OutputFeatures, Transaction, Weighting};
use grin_core::core::FeeFields;
use grin_core::libtx::{build, proof, ProofBuilder};
use grin_keychain::{mnemonic, ExtKeychain, ExtKeychainPath, Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::Commitment;

pub struct Wallets {
    keychains: Vec<ExtKeychain>,
    /// BIP39 entropy of each phrase (only to derive the messenger seed).
    entropy: Vec<Vec<u8>>,
}

/// Lines with 12, 15, 18, 21 or 24 lowercase BIP39 words are phrases (wallet 1,
/// 2, ... in file order). Comments and labels are allowed, but a line that
/// LOOKS like a damaged phrase (12 or more words, at least 80% of them BIP39
/// words, yet not a valid phrase) is an ERROR with its line
/// number: skipping it silently would shift the numbers of every wallet after
/// it. Lines starting with `#` or `//` are always comments.
///
/// `path` = `-`: the phrases come on standard input (read once per process and
/// kept for later calls). The wallet service passes the decrypted phrase this
/// way, so it never exists as a file.
pub fn read_phrases(path: &str) -> Result<Vec<String>, String> {
    if path == "-" {
        static STDIN: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
        let text = STDIN.get_or_init(|| {
            use std::io::Read;
            let mut t = String::new();
            std::io::stdin()
                .take(64 * 1024)
                .read_to_string(&mut t)
                .map_err(|e| format!("seeds on standard input: {e}"))?;
            Ok(t)
        });
        return parse_phrases(text.as_ref().map_err(Clone::clone)?);
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("seed file: {e}"))?;
    parse_phrases(&text)
}

/// BIP39 phrase lengths (16..32 bytes of entropy); wallets are made with
/// 12, 18 or 24, restore also takes 15 and 21.
pub fn is_phrase_len(n: usize) -> bool {
    matches!(n, 12 | 15 | 18 | 21 | 24)
}

pub fn parse_phrases(text: &str) -> Result<Vec<String>, String> {
    let mut phrases = Vec::new();
    for (n, l) in text.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        let w: Vec<&str> = l.split_whitespace().collect();
        let lower = |x: &&str| !x.is_empty() && x.chars().all(|c| c.is_ascii_lowercase());
        if w.iter().all(lower) && is_phrase_len(w.len()) {
            // 24 words: accepted here, the checksum is checked when the keys
            // are derived (unchanged behaviour). 12/15/18/21 words: a short
            // phrase must be all BIP39 words AND carry a valid checksum, or a
            // twelve-word note would be taken for a wallet.
            let short_ok = w.len() == 24 || {
                let joined = w.join(" ");
                w.iter().all(|x| mnemonic::search(x).is_ok()) && mnemonic::to_entropy(&joined).is_ok()
            };
            if short_ok {
                phrases.push(w.join(" "));
                continue;
            }
        }
        // Mostly BIP39 words (case ignored): a damaged phrase, not a note.
        let bip39 = w.iter().filter(|x| mnemonic::search(&x.to_ascii_lowercase()).is_ok()).count();
        if w.len() >= 12 && bip39 * 5 >= w.len() * 4 {
            return Err(format!(
                "seed file line {}: looks like a damaged phrase ({} words{}); a phrase needs 12, 15, 18, 21 or 24 lowercase words with a valid checksum. \
                 Fix the line or start it with # if it is a comment (wallet numbers would shift otherwise)",
                n + 1,
                w.len(),
                if w.iter().all(lower) { "" } else { ", not all lowercase" }
            ));
        }
    }
    if phrases.is_empty() {
        return Err("no phrases (12, 15, 18, 21 or 24 words) in seed file".into());
    }
    Ok(phrases)
}

/// [`Wallets::file_mac`] from the seed entropies alone (no keychains): for a
/// host that keeps the phrase and must check the file before showing a balance.
pub fn file_mac_for_entropy(entropy: &[Vec<u8>], body: &[u8]) -> String {
    let mut kd = blake2::blake2b::Blake2b::with_key(32, b"grinsight/wallet-file/v1");
    for e in entropy {
        kd.update(&(e.len() as u64).to_be_bytes());
        kd.update(e);
    }
    let key = kd.finalize();
    let mac = blake2::blake2b::blake2b(32, key.as_bytes(), body);
    mac.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

impl Wallets {
    pub fn from_file(path: &str) -> Result<Self, String> {
        // Same call as grin-wallet `derive_keychain(global::is_testnet())`. The
        // flag only affects extended-key serialization prefixes; derived keys
        // are identical across networks (see keys_follow_the_active_network).
        let is_test = global::is_testnet();
        let mut keychains = Vec::new();
        let mut entropy = Vec::new();
        for (i, p) in read_phrases(path)?.iter().enumerate() {
            let entropy_bytes = mnemonic::to_entropy(p).map_err(|e| format!("phrase {}: {e:?}", i + 1))?;
            let k = ExtKeychain::from_seed(&entropy_bytes, is_test).map_err(|e| format!("phrase {}: {e:?}", i + 1))?;
            keychains.push(k);
            entropy.push(entropy_bytes);
        }
        Ok(Wallets { keychains, entropy })
    }

    pub fn keychain(&self, i: usize) -> Option<&ExtKeychain> {
        self.keychains.get(i)
    }

    pub fn entropy(&self, i: usize) -> Option<&[u8]> {
        self.entropy.get(i).map(|e| e.as_slice())
    }

    #[cfg(any(test, feature = "web"))]
    pub fn from_keychains(keychains: Vec<ExtKeychain>) -> Self {
        let entropy = (0..keychains.len()).map(|i| vec![i as u8; 32]).collect();
        Wallets { keychains, entropy }
    }

    pub fn len(&self) -> usize {
        self.keychains.len()
    }

    /// Rewind `items` against every keychain, using all CPU cores. A worker
    /// thread that panics is an ERROR for the whole call: its part of the
    /// outputs was not checked, and a partial result would be a wrong balance.
    pub fn discover(&self, items: &[(u64, OutputIdentifier, RangeProof)]) -> Result<Vec<Found>, String> {
        self.discover_with(items, check_one)
    }

    fn discover_with<F>(&self, items: &[(u64, OutputIdentifier, RangeProof)], check: F) -> Result<Vec<Found>, String>
    where
        F: Fn(usize, &ExtKeychain, &ProofBuilder<ExtKeychain>, u64, &OutputIdentifier, &RangeProof) -> Option<Found> + Sync,
    {
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(32);
        let chunk = items.len().div_ceil(threads).max(1);
        std::thread::scope(|s| {
            let handles: Vec<_> = items
                .chunks(chunk)
                .map(|part| {
                    let check = &check;
                    s.spawn(move || {
                        let builders: Vec<_> = self.keychains.iter().map(ProofBuilder::new).collect();
                        let mut out = Vec::new();
                        for (pos0, id, rp) in part {
                            for (w, (k, b)) in self.keychains.iter().zip(&builders).enumerate() {
                                if let Some(f) = check(w, k, b, *pos0, id, rp) {
                                    out.push(f);
                                }
                            }
                        }
                        out
                    })
                })
                .collect();
            let mut all = Vec::new();
            for h in handles {
                all.extend(h.join().map_err(|_| "output scan thread panicked: scan incomplete".to_string())?);
            }
            Ok(all)
        })
    }

    /// MAC of a wallet-outputs file body: keyed BLAKE2b-256, the key derived
    /// from the entropy of EVERY wallet in the seed file. Without the seeds a
    /// file cannot be shortened, extended, reordered or edited unnoticed, so a
    /// dropped record (lower balance) or a duplicated one (double count) is
    /// detected; any change in the seed set also invalidates the file.
    pub fn file_mac(&self, body: &[u8]) -> String {
        file_mac_for_entropy(&self.entropy, body)
    }

    /// Re-check an output record that came from a file (not from a rewound
    /// rangeproof): its key id and amount must reproduce its commitment with
    /// this wallet's keychain. A damaged or edited record (wrong amount, key or
    /// wallet number) is refused, so a file cannot inflate a balance.
    /// Features are not bound by the commitment: callers check them against
    /// the verified UTXO state (`OutputState::utxo`).
    pub fn verify_known(&self, f: &Found) -> Result<(), String> {
        let k = self.keychains.get(f.wallet).ok_or(format!("wallet {} not in the seed file", f.wallet + 1))?;
        if f.switch != SwitchCommitmentType::Regular {
            return Err("only regular switch commitments are supported".into());
        }
        let c = k.commit(f.amount, &f.id, SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))?;
        if c != f.commit {
            return Err(format!(
                "record for {} does not match its key and amount (wallet {}, amount {})",
                f.commit.0.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                f.wallet + 1,
                f.amount
            ));
        }
        Ok(())
    }

    /// Build and validate a self-transfer spending `f` to a fresh key of the
    /// same wallet. Returns (tx, new output commitment, kernel excess, new key id).
    pub fn self_spend(&self, f: &Found, used: &[Identifier]) -> Result<(Transaction, Commitment, Commitment, Identifier), String> {
        let k = &self.keychains[f.wallet];
        if f.switch != SwitchCommitmentType::Regular {
            return Err("only regular switch commitments are supported".into());
        }
        // Fee: minimum relay fee for 1 input, 2 outputs (change + nothing) -> 1 in, 1 out, 1 kernel, times 2.
        let weight = Transaction::weight_by_iok(1, 1, 1);
        let fee = weight * global::get_accept_fee_base() * 2;
        if f.amount <= fee * 2 {
            return Err(format!("output amount {} too small for fee {fee}", f.amount));
        }
        // Fresh key: same parent path, next child index after the highest seen.
        let base = ExtKeychainPath::from_identifier(&f.id);
        let depth = base.depth;
        let idx = |id: &Identifier| -> u32 { u32::from(ExtKeychainPath::from_identifier(id).path[(depth - 1) as usize]) };
        let next = used.iter().filter(|x| ExtKeychainPath::from_identifier(x).depth == depth).map(idx).max().unwrap_or(0) + 1;
        let mut p = base;
        p.path[(depth - 1) as usize] = next.into();
        let new_id = p.to_identifier();
        let builder = ProofBuilder::new(k);
        let input = if f.features.is_coinbase() {
            build::coinbase_input(f.amount, f.id.clone())
        } else {
            build::input(f.amount, f.id.clone())
        };
        let fee_fields = FeeFields::new(0, fee).map_err(|e| format!("fee: {e:?}"))?;
        let tx = build::transaction(
            KernelFeatures::Plain { fee: fee_fields },
            &[input, build::output(f.amount - fee, new_id.clone())],
            k,
            &builder,
        )
        .map_err(|e| format!("build tx: {e:?}"))?;
        tx.validate(Weighting::AsTransaction).map_err(|e| format!("tx does not validate: {e:?}"))?;
        if tx.inputs().len() != 1 || tx.outputs().len() != 1 || tx.kernels().len() != 1 {
            return Err("unexpected tx shape".into());
        }
        let new_commit = tx.outputs()[0].commitment();
        if k.commit(f.amount - fee, &new_id, SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))? != new_commit {
            return Err("new output commitment mismatch".into());
        }
        Ok((tx.clone(), new_commit, tx.kernels()[0].excess, new_id))
    }
}

#[derive(Clone, Debug)]
pub struct Found {
    pub wallet: usize,
    pub pos0: u64,
    pub commit: Commitment,
    pub features: OutputFeatures,
    pub amount: u64,
    pub id: Identifier,
    pub switch: SwitchCommitmentType,
}

fn check_one(w: usize, k: &ExtKeychain, b: &ProofBuilder<ExtKeychain>, pos0: u64, id: &OutputIdentifier, rp: &RangeProof) -> Option<Found> {
    let (amount, kid, switch) = proof::rewind(k.secp(), b, id.commit, None, *rp).ok().flatten()?;
    // The rewound path must reproduce the commitment, or it is not ours.
    if k.commit(amount, &kid, switch).ok()? != id.commit {
        return None;
    }
    Some(Found { wallet: w, pos0, commit: id.commit, features: id.features, amount, id: kid, switch })
}

pub fn outputs_of_block(b: &core::Block) -> Vec<(u64, OutputIdentifier, RangeProof)> {
    b.outputs().iter().map(|o: &Output| (u64::MAX, o.identifier, o.proof)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_phrase_line_is_an_error_not_a_shift() {
        let p24 = vec!["abandon"; 23].join(" ") + " art";
        let p23 = vec!["abandon"; 23].join(" ");
        // comments and labels are fine
        let ok = format!("# my wallets\nwallet one:\n{p24}\n// note\n\n{p24}\n");
        assert_eq!(parse_phrases(&ok).unwrap().len(), 2);
        // a 23-word line is not skipped (the next phrase would become wallet 1)
        let e = parse_phrases(&format!("{p23}\n{p24}\n")).unwrap_err();
        assert!(e.contains("line 1") && e.contains("23 words"), "{e}");
        // 25 words, or a capitalised word, also refused
        assert!(parse_phrases(&format!("{p24} extra\n")).is_err());
        let cap = p24.replacen("abandon", "Abandon", 1);
        assert!(parse_phrases(&format!("{cap}\n{p24}\n")).unwrap_err().contains("lowercase"));
        // an ordinary sentence of 12+ words is a note, not a phrase
        assert_eq!(parse_phrases(&format!("These are the funded testnet wallets for the experiment, keep them offline please\n{p24}\n")).unwrap().len(), 1);
        // the same text commented out is fine
        assert_eq!(parse_phrases(&format!("# {p23}\n{p24}\n")).unwrap().len(), 1);
    }

    /// 12/18-word phrases are wallets too; a bad checksum or a 12-word note is not.
    #[test]
    fn short_phrases_are_accepted_with_valid_checksum_only() {
        let p12 = mnemonic::from_entropy(&[7u8; 16]).unwrap();
        let p18 = mnemonic::from_entropy(&[8u8; 24]).unwrap();
        let p24 = mnemonic::from_entropy(&[9u8; 32]).unwrap();
        assert_eq!(p12.split(' ').count(), 12);
        assert_eq!(p18.split(' ').count(), 18);
        assert_eq!(parse_phrases(&format!("{p12}\n{p18}\n{p24}\n")).unwrap(), vec![p12.clone(), p18.clone(), p24.clone()]);
        // twelve BIP39 words with a wrong checksum: an error, not skipped
        let bad = vec!["abandon"; 12].join(" ");
        let e = parse_phrases(&format!("{bad}\n{p24}\n")).unwrap_err();
        assert!(e.contains("line 1") && e.contains("12 words"), "{e}");
        // a twelve-word note is a note
        assert_eq!(parse_phrases(&format!("these are my wallets for the test network please keep it safe\n{p12}\n")).unwrap().len(), 1);
        // keys derive from the entropy of any length (same call as grin-wallet)
        let id = ExtKeychain::derive_key_id(3, 1, 0, 0, 0);
        let mut seen = Vec::new();
        for p in [&p12, &p18, &p24] {
            let e = mnemonic::to_entropy(p).unwrap();
            let k = ExtKeychain::from_seed(&e, true).unwrap();
            seen.push(k.commit(1, &id, SwitchCommitmentType::Regular).unwrap());
        }
        assert!(seen[0] != seen[1] && seen[1] != seen[2] && seen[0] != seen[2]);
    }

    /// A panicking scan thread makes the whole discovery fail (no partial
    /// result that would show a too-small balance as a normal one).
    #[test]
    fn panic_in_a_scan_thread_is_an_error() {
        let w = Wallets::from_keychains(vec![ExtKeychain::from_seed(&[1; 32], true).unwrap()]);
        let k = w.keychain(0).unwrap();
        let id = ExtKeychain::derive_key_id(3, 0, 0, 1, 0);
        let b = ProofBuilder::new(k);
        let commit = k.commit(5, &id, SwitchCommitmentType::Regular).unwrap();
        let rp = proof::create(k, &b, 5, &id, SwitchCommitmentType::Regular, commit, None).unwrap();
        let oid = OutputIdentifier::new(grin_core::core::OutputFeatures::Plain, &commit);
        let items: Vec<_> = (0..64u64).map(|p| (p, oid, rp)).collect();
        assert_eq!(w.discover(&items).unwrap().len(), 64);
        // Only the thread that gets the last item panics; the others succeed.
        let r = w.discover_with(&items, |wi, k, b, pos, id, rp| {
            if pos == 63 {
                panic!("boom");
            }
            check_one(wi, k, b, pos, id, rp)
        });
        assert!(r.unwrap_err().contains("panicked"));
    }
    use grin_core::global::ChainTypes;
    use std::time::Instant;

    /// Rewind cost on this machine (run with --release --ignored).
    #[test]
    #[ignore]
    fn bench_rewind() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let dir = std::env::temp_dir().join(format!("wallet-bench-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("s.txt");
        let ph: Vec<String> = (1..=3u8).map(|i| mnemonic::from_entropy(&[i; 32]).unwrap()).collect();
        std::fs::write(&f, ph.join("\n")).unwrap();
        let w = Wallets::from_file(f.to_str().unwrap()).unwrap();
        let other = ExtKeychain::from_seed(&[42u8; 32], true).unwrap();
        let ob = ProofBuilder::new(&other);
        let items: Vec<_> = (0..2000u64)
            .map(|i| {
                let id = ExtKeychainPath::new(3, 0, 0, i as u32, 0).to_identifier();
                let c = other.commit(i + 1, &id, SwitchCommitmentType::Regular).unwrap();
                let rp = proof::create(&other, &ob, i + 1, &id, SwitchCommitmentType::Regular, c, None).unwrap();
                (i, OutputIdentifier { features: OutputFeatures::Plain, commit: c }, rp)
            })
            .collect();
        let t = Instant::now();
        assert!(w.discover(&items).unwrap().is_empty());
        let per = t.elapsed().as_secs_f64() / items.len() as f64;
        eprintln!(
            "BENCH_REWIND threads={} wallets=3 per_proof_us={:.1} est_floonet_2958013_s={:.0} est_mainnet_350574_s={:.0}",
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
            per * 1e6, per * 2_958_013.0, per * 350_574.0
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_follow_the_active_network() {
        let phrase = mnemonic::from_entropy(&[5u8; 32]).unwrap();
        let dir = std::env::temp_dir().join(format!("wallet-net-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("s.txt");
        std::fs::write(&f, &phrase).unwrap();
        let id = ExtKeychainPath::new(3, 0, 0, 0, 0).to_identifier();
        let commit_for = |chain| {
            global::set_local_chain_type(chain);
            let w = Wallets::from_file(f.to_str().unwrap()).unwrap();
            w.keychains[0].commit(1, &id, SwitchCommitmentType::Regular).unwrap()
        };
        let main = commit_for(ChainTypes::Mainnet);
        let test = commit_for(ChainTypes::Testnet);
        // In grin the network flag only changes extended-key serialization
        // prefixes, not derivation: one phrase gives the same commitments.
        assert_eq!(main, test);
        // Same derivation as grin-wallet: entropy -> from_seed(entropy, is_testnet()).
        let e = mnemonic::to_entropy(&phrase).unwrap();
        assert_eq!(main, ExtKeychain::from_seed(&e, false).unwrap().commit(1, &id, SwitchCommitmentType::Regular).unwrap());
        assert_eq!(test, ExtKeychain::from_seed(&e, true).unwrap().commit(1, &id, SwitchCommitmentType::Regular).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discover_and_self_spend_roundtrip() {
        global::set_local_chain_type(ChainTypes::Testnet);
        // A throwaway phrase generated for the test (not one of the user's).
        let entropy = [7u8; 32];
        let phrase = mnemonic::from_entropy(&entropy).unwrap();
        let dir = std::env::temp_dir().join(format!("wallet-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("seeds.txt");
        std::fs::write(&f, format!("label line\n\n{phrase}\nother text\n")).unwrap();
        let w = Wallets::from_file(f.to_str().unwrap()).unwrap();
        assert_eq!(w.len(), 1);
        let k = &w.keychains[0];
        let b = ProofBuilder::new(k);
        let id1 = ExtKeychainPath::new(3, 0, 0, 5, 0).to_identifier();
        let commit = k.commit(1_000_000_000, &id1, SwitchCommitmentType::Regular).unwrap();
        let rp = proof::create(k, &b, 1_000_000_000, &id1, SwitchCommitmentType::Regular, commit, None).unwrap();
        // A foreign output (other keychain) must not be claimed.
        let other = ExtKeychain::from_seed(&[9u8; 32], true).unwrap();
        let ob = ProofBuilder::new(&other);
        let oc = other.commit(5, &id1, SwitchCommitmentType::Regular).unwrap();
        let orp = proof::create(&other, &ob, 5, &id1, SwitchCommitmentType::Regular, oc, None).unwrap();
        let items = vec![
            (11, OutputIdentifier { features: OutputFeatures::Plain, commit }, rp),
            (12, OutputIdentifier { features: OutputFeatures::Plain, commit: oc }, orp),
        ];
        let found = w.discover(&items).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].pos0, found[0].amount, found[0].id.clone()), (11, 1_000_000_000, id1.clone()));
        // A proof attached to a different commitment is not claimed.
        let swapped = vec![(13, OutputIdentifier { features: OutputFeatures::Plain, commit: oc }, rp)];
        assert!(w.discover(&swapped).unwrap().is_empty());

        let (tx, new_commit, excess, _new_id) = w.self_spend(&found[0], &[id1.clone()]).unwrap();
        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs()[0].commitment(), new_commit);
        assert_eq!(tx.kernels()[0].excess, excess);
        // The new output is discoverable by the same wallet at index 6.
        let again = w.discover(&[(20, tx.outputs()[0].identifier, tx.outputs()[0].proof)]).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(ExtKeychainPath::from_identifier(&again[0].id).path[2], 6u32.into());
        assert!(again[0].amount < 1_000_000_000);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_known_refuses_edited_records() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let k1 = ExtKeychain::from_seed(&[7u8; 32], true).unwrap();
        let k2 = ExtKeychain::from_seed(&[8u8; 32], true).unwrap();
        let w = Wallets::from_keychains(vec![k1.clone(), k2]);
        let id = ExtKeychainPath::new(3, 0, 0, 5, 0).to_identifier();
        let other_id = ExtKeychainPath::new(3, 0, 0, 6, 0).to_identifier();
        let commit = k1.commit(1_000_000_000, &id, SwitchCommitmentType::Regular).unwrap();
        let good = Found { wallet: 0, pos0: 0, commit, features: OutputFeatures::Plain, amount: 1_000_000_000, id: id.clone(), switch: SwitchCommitmentType::Regular };
        assert!(w.verify_known(&good).is_ok());
        // inflated amount, other key, other wallet, missing wallet: all refused
        assert!(w.verify_known(&Found { amount: 9_000_000_000, ..good.clone() }).is_err());
        assert!(w.verify_known(&Found { id: other_id, ..good.clone() }).is_err());
        assert!(w.verify_known(&Found { wallet: 1, ..good.clone() }).is_err());
        assert!(w.verify_known(&Found { wallet: 5, ..good.clone() }).is_err());
        // File MAC: depends on every byte and on the seed set.
        let body = b"{\"meta\":1}\nline-a\nline-b\n";
        let m = w.file_mac(body);
        assert_eq!(m, w.file_mac(body));
        assert_ne!(m, w.file_mac(b"{\"meta\":1}\nline-a\n"));
        assert_ne!(m, w.file_mac(b"{\"meta\":1}\nline-a\nline-b\nline-b\n"));
        let w2 = Wallets::from_keychains(vec![ExtKeychain::from_seed(&[7u8; 32], true).unwrap()]);
        assert_ne!(m, w2.file_mac(body));
    }
}

