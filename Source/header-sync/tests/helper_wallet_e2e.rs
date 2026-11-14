//! Synthetic helper -> UTXO -> wallet discovery. This is the offline core of
//! A3: the wallet sees only the helper's per-UTXO data and must recover the
//! output amount from its rangeproof; no node/wallet RPC is involved.

use grin_core::core::hash::Hashed;
use grin_core::core::{OutputFeatures, OutputIdentifier};
use grin_core::libtx::{proof, ProofBuilder};
use grin_keychain::{mnemonic, ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use grinsight_state::outputs::OutputState;
use grinsight_state::testkit;
use grinsight_state::wallet::Wallets;

#[test]
fn helper_utxo_is_found_and_balance_is_recovered_by_wallet() {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let entropy = [7u8; 32];
    let phrase = mnemonic::from_entropy(&entropy).unwrap();
    let dir = std::env::temp_dir().join(format!("grinsight-helper-wallet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let seeds = dir.join("seeds.txt");
    std::fs::write(&seeds, &phrase).unwrap();
    let wallets = Wallets::from_file(seeds.to_str().unwrap()).unwrap();
    let keychain = ExtKeychain::from_seed(&entropy, false).unwrap();
    let path = ExtKeychainPath::new(3, 0, 0, 5, 0).to_identifier();
    let amount = 1_000_000_000u64;
    let commit = keychain.commit(amount, &path, SwitchCommitmentType::Regular).unwrap();
    let proof = proof::create(
        &keychain,
        &ProofBuilder::new(&keychain),
        amount,
        &path,
        SwitchCommitmentType::Regular,
        commit,
        None,
    )
    .unwrap();
    let oid = OutputIdentifier::new(OutputFeatures::Plain, &commit);

    let mut reference = testkit::Reference::new();
    reference.apply(&[oid], &[]);
    let header = reference.header();
    let (bitmap, output) = reference.segments(11);
    let state = OutputState::from_segments(&header, &bitmap, &output).unwrap();
    assert!(state.utxo.contains_key(&commit.0), "helper UTXO must contain the output");

    let found = wallets.discover(&[(0, oid, proof)]).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].commit, commit);
    assert_eq!(found[0].amount, amount);
}
