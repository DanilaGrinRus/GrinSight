//! Offline test input for the released wallet hosts. Supply a new test wallet's
//! mnemonic on stdin and a new directory as the only argument. The directory
//! contains public outputs and synthetic chain data for host-chain-stub.
use fly_paycore_bridge::chain_pipe::wire::encode_block;
use fly_paycore_bridge::chain_port::{BlockFacts, OutputFact};
use fly_paycore_keys::path::KeyPath;
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("missing new fixture directory")?,
    );
    global::set_local_chain_type(ChainTypes::Testnet);
    let mut phrase = Zeroizing::new(String::new());
    io::stdin().take(512).read_to_string(&mut phrase)?;
    let seed = Zeroizing::new(
        grin_keychain::mnemonic::to_entropy(phrase.trim()).map_err(|_| "invalid test mnemonic")?,
    );
    let keys = ExtKeychain::from_seed(&seed, true).map_err(|_| "cannot open test keychain")?;
    let builder = ProofBuilder::new(&keys);
    let mut outputs = Vec::new();
    for index in 0..3u32 {
        let amount = 5_000_000_000;
        let id = KeyPath::Legacy { account: 0, index }.to_identifier();
        let switch = SwitchCommitmentType::Regular;
        let commit = keys
            .commit(amount, &id, switch)
            .map_err(|_| "cannot commit test output")?;
        let rp = proof::create(&keys, &builder, amount, &id, switch, commit, None)
            .map_err(|_| "cannot prove test output")?;
        outputs.push(OutputFact {
            commit: commit.0,
            proof: rp.proof[..rp.plen].to_vec(),
            pos: u64::from(index) + 1,
            coinbase: false,
        });
    }

    fs::create_dir(&dir)?;
    fs::create_dir(dir.join("blocks"))?;
    fs::write(dir.join("old-pieces"), "1")?;
    fs::write(dir.join("time"), "1000")?;
    fs::write(dir.join("k_conf"), "3")?;
    fs::write(dir.join("selected"), "")?;
    for height in 101..=105 {
        let block = BlockFacts {
            height,
            hash: [height as u8; 32],
            outputs: std::mem::take(&mut outputs),
            ..BlockFacts::default()
        };
        let bytes = encode_block(&block).ok_or("cannot encode test block")?;
        fs::write(dir.join("blocks").join(format!("{height:020}.blk")), bytes)?;
    }
    // Publish the anchor last, once all five complete blocks can be read.
    let mut anchor = 100u64.to_le_bytes().to_vec();
    anchor.extend_from_slice(&[1; 32]);
    fs::write(dir.join("anchor.part"), anchor)?;
    fs::rename(dir.join("anchor.part"), dir.join("anchor"))?;
    println!("Testnet fixture ready: anchor 100, tip 105, three synthetic outputs");
    Ok(())
}
