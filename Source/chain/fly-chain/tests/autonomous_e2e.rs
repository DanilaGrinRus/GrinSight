//! A wallet IPC client connected to two loopback Grin peers. No checkpoint,
//! external API, proof provider, private wallet, or relay is configured.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain_headers::Net;
use fly_chain_state::testkit::Source;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level};
use kit::{wait_for, Node, Temp, FLY};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[test]
fn genesis_to_restoration_inputs_keeps_tip_freshness_separate() {
    let source = Source::thin_with_old(40);
    source.compact();
    let old = source.unspent_at(20);
    let final_outputs = source.unspent_at(40);
    let expected: BTreeSet<_> = old.into_keys().filter(|c| final_outputs.contains_key(c)).collect();
    assert_eq!(expected.len(), 5);
    let source = Arc::new(RwLock::new(source));
    let first = Node::with_state(&source);
    let second = Node::with_state(&source);
    let data = Temp::new("autonomous-restore");
    fly_paycore_chain_port::bootstrap::schedule(&data.0, Net::Automated.tag()).unwrap();
    let config = Config {
        network: Net::Automated.tag(),
        genesis: Net::Automated.genesis_hash(),
        data_dir: data.0.to_str().unwrap().to_owned(),
        peers: vec![first.addr.to_string(), second.addr.to_string()],
        start_timeout_secs: 30, direct_post: false, tor_off: true, tor_bridges: String::new(),
    };
    // A migrated user's legacy checkpoint is untrusted input; the new path
    // must neither depend on its format nor modify the legacy file.
    let legacy = data.0.join(fly_chain::OWN_POINT_FILE);
    std::fs::write(&legacy, b"legacy point discarded by autonomous selection").unwrap();
    let mut chain = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
    wait_for("headers and blocks at the tip", || {
        chain.status().is_some_and(|s| s.level == Level::AtTip)
    });
    let status = chain.status().unwrap();
    let tip = status.tip.unwrap();
    assert_eq!(tip.height, 40);
    assert!(status.selected.is_none(), "two peers on loopback do not establish tip freshness");
    let mut found = BTreeSet::new();
    let mut piece = Some(0);
    while let Some(index) = piece {
        let mut answer = None;
        wait_for("verified rangeproof segment", || {
            answer = chain.old_outputs(index).ok();
            answer.is_some()
        });
        let answer = answer.unwrap();
        assert_eq!((answer.at, answer.before), (tip, 20));
        assert!(!answer.bare);
        for output in answer.outputs {
            assert!(!output.proof.is_empty());
            assert!(found.insert(output.commit.to_vec()));
        }
        piece = answer.next;
    }
    assert_eq!(found, expected);
    assert_eq!(std::fs::read(legacy).unwrap(), b"legacy point discarded by autonomous selection");
    let exports = data.0.join("history-exports");
    let files: Vec<_> = std::fs::read_dir(&exports).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 1);
    let recipient = Temp::new("gs-proof-recipient");
    for name in ["checkpoint.json", "history.proof"] {
        std::fs::copy(files[0].join(name), recipient.0.join(name)).unwrap();
    }
    let checked = fly_chain::check_exported_pair(Net::Automated, &recipient.0).unwrap();
    assert_eq!((checked.height, checked.points), (20, fly_chain_headers::proof::POINTS));
    assert_eq!(checked.hash, fly_chain_headers::hash_bytes(&source.read().unwrap().headers()[20]));
    assert!(!data.0.join("autonomous-headers-v1.bin").exists(), "published export retained full replay");
    drop(chain);
    let fresh = Temp::new("gs-imported-restore");
    let portable_file = recipient.0.join("from-first-wallet.gshp");
    assert_eq!(fly_chain::pack_profile_checkpoint(Net::Automated, &data.0, &portable_file).unwrap(), Some(checked));
    // It is the only file supplied to the importer. The original two-file
    // export also remains available and byte-for-byte unchanged on the source.
    let imported = fly_chain::import_checkpoint_file(Net::Automated, &fresh.0, &portable_file).unwrap();
    assert_eq!(imported, checked);
    for name in ["checkpoint.json", "history.proof"] {
        assert_eq!(std::fs::read(files[0].join(name)).unwrap(),
                   std::fs::read(fresh.0.join("imported-gshp1-v1").join(name)).unwrap());
    }
    std::fs::OpenOptions::new().write(true).open(recipient.0.join("history.proof")).unwrap().set_len(40).unwrap();
    assert!(fly_chain::check_exported_pair(Net::Automated, &recipient.0).is_err());
    // Both peers can serve headers only from the imported anchor onward.
    // A receiver trying to replay from genesis cannot reach the tip here.
    let tail = source.read().unwrap().headers().split_off(20);
    first.set(&tail);
    second.set(&tail);
    let config = Config { data_dir: fresh.0.to_str().unwrap().to_owned(), ..config };
    for _ in 0..2 {
        let mut second_wallet = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
        wait_for("second wallet applies blocks from the imported anchor to the tip", || {
            second_wallet.status().is_some_and(|s| s.level == Level::AtTip && s.tip == Some(tip))
        });
        let detail = second_wallet.problem().unwrap();
        assert!(detail.contains("imported starting point: GSHP1 sample verified for this checkpoint (20)"), "{detail}");
        assert!(second_wallet.status().unwrap().selected.is_none());
        assert!(!fresh.0.join("autonomous-headers-v1.bin").exists());
    }
}
