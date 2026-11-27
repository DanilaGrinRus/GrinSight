//! Crash recovery of the real executable between two initial WAL advances.
//! The peer gates the next headers, keeping this boundary repeatable on fast
//! or slow machines. The test never writes or shortens the child's files.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain_headers::{chain::HeaderChain, checkpoint, hash_bytes, write_header, Net};
use fly_chain_state::testkit::Source;
use grin_core::core::BlockHeader;
use kit::{apply, hex, wait_for, Node, Temp, FLY};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok() == Some(None) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

// Expected prefix from the independent node. Never injected into the wallet.
fn frames(headers: &[BlockHeader]) -> Vec<u8> {
    let mut result = Vec::new();
    for header in headers {
        let bytes = write_header(header).unwrap();
        result.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        result.extend_from_slice(&bytes);
    }
    result
}

#[test]
fn forced_process_exit_during_bootstrap_resumes_to_the_nodes_pmmr_root() {
    let source = Arc::new(RwLock::new(Source::thin(40)));
    let headers = source.read().unwrap().headers();
    let peer = Node::with_state(&source);
    peer.set(&headers[..=4]);
    let data = Temp::new("genesis-process-kill");
    fly_paycore_chain_port::bootstrap::schedule(&data.0, Net::Automated.tag()).unwrap();
    let journal = data.0.join("autonomous-headers-v1.bin");
    let mut child = Running(
        Command::new(FLY)
            .args(["blocks", "--network", "automated", "--data"])
            .arg(&data.0)
            .arg("--peer")
            .arg(peer.addr.to_string())
            .args(["--seconds", "120"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let four = frames(&headers[..=4]);
    wait_for("first acknowledged header prefix", || {
        std::fs::read(&journal).is_ok_and(|v| v == four)
    });
    peer.set(&headers[..=6]);
    let six = frames(&headers[..=6]);
    wait_for(
        "journal advancement before the first usable checkpoint",
        || std::fs::read(&journal).is_ok_and(|v| v == six),
    );
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap(); // TerminateProcess on Windows; no graceful shutdown.
    assert!(!child.0.wait().unwrap().success());
    assert_eq!(std::fs::read(&journal).unwrap(), six);
    drop(child);

    peer.set(&headers);
    let reopened = apply(&data, &[peer.addr], 90);
    assert_eq!(reopened.code, 0, "{}", reopened.out);
    assert_eq!(reopened.field("applied:", "height"), "40");
    assert_eq!(
        reopened.field("applied:", "hash"),
        hex(&hash_bytes(&headers[40]))
    );
    assert!(!journal.exists());

    // Open the new process's persisted chain again and compare its PMMR after
    // height 40 with Grin's actual prev_root when the independent node mines 41.
    let archive = source.read().unwrap().archive().height;
    let manifest = std::fs::read(data.0.join("autonomous-compact-v1.bin")).unwrap();
    let anchor = &manifest[82..manifest.len()-32];
    assert_eq!(checkpoint::check(anchor, Net::Automated).unwrap().height(), archive);
    let (persisted, _) =
        HeaderChain::open(&data.0.join("autonomous-live"), Net::Automated, anchor).unwrap();
    assert_eq!(persisted.tip().hash, hash_bytes(&headers[40]));
    let tip = checkpoint::check(
        &persisted.record_at(40, 0).unwrap().unwrap(),
        Net::Automated,
    )
    .unwrap();
    source.write().unwrap().grow(1);
    assert_eq!(
        tip.peaks.root(),
        source.read().unwrap().headers()[41].prev_root
    );
}
