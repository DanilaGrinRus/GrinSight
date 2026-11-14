//! Network side of the wallet: broadcast a finished transaction to peers.
//! Keys, discovery and transactions live in `grinsight_state::wallet`.

use super::*;
pub(super) use grinsight_state::wallet::*;
use grin_core::core::{Transaction, Weighting};

/// Send `tx` to a peer as a fluff transaction and keep the connection open
/// long enough for a TX_KERNEL_HASH peer to request the full body.
pub(super) fn broadcast(peer_arg: &str, tx: &Transaction) -> Result<(), String> {
    // A node refuses a new connection from an IP it still lists as connected
    // (right after segment/block fetches): retry with a pause, as gap does.
    let mut last = String::new();
    for attempt in 0..6 {
        if attempt > 0 {
            println!("GAP_SPEND_RECONNECT={peer_arg} attempt={} after: {last}", attempt + 1);
            // The node forgets a closed connection within 20 s (peer clean-up).
            std::thread::sleep(Duration::from_secs(if attempt <= 3 { 7 } else { 20 }));
        }
        match broadcast_once(peer_arg, tx) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Read a transaction written by `--gap-tx-out`, validate it and send it.
pub(super) fn broadcast_file(path: &str, peers: &[String]) -> Result<(), String> {
    let hex = std::fs::read_to_string(path).map_err(|e| format!("tx file: {e}"))?;
    let bytes = grin_util::from_hex(hex.trim()).map_err(|_| "tx file is not hex")?;
    let tx: Transaction = ser::deserialize_default(&mut &bytes[..]).map_err(|e| format!("tx decode: {e:?}"))?;
    tx.validate(Weighting::AsTransaction).map_err(|e| format!("tx does not validate: {e:?}"))?;
    println!(
        "BROADCAST_TX_KERNEL_EXCESS={}\nBROADCAST_TX_INPUTS={}\nBROADCAST_TX_OUTPUTS={}\nBROADCAST_TX_FEE={}",
        tx.kernels()[0].excess.0.to_hex(),
        tx.inputs().len(),
        tx.outputs().len(),
        tx.fee()
    );
    // All peers at once; stop waiting as soon as BROADCAST_ENOUGH peers took it
    // (the network relays it further). A dead peer (connect timeouts and
    // retries, ~2.5 min) no longer holds the run; its thread dies with us.
    const BROADCAST_ENOUGH: usize = 2;
    let need = BROADCAST_ENOUGH.min(peers.len());
    let tx = Arc::new(tx);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    for p in peers {
        let (p, tx, done_tx) = (p.clone(), tx.clone(), done_tx.clone());
        std::thread::spawn(move || {
            let r = broadcast(&p, &tx);
            let _ = done_tx.send((p, r));
        });
    }
    drop(done_tx);
    let mut ok = 0;
    let mut answered = std::collections::HashSet::new();
    while let Ok((p, r)) = done_rx.recv() {
        answered.insert(p.clone());
        match r {
            Ok(()) => {
                ok += 1;
                println!("BROADCAST_TX={p} SENT");
            }
            Err(e) => println!("BROADCAST_TX={p} FAIL {e}"),
        }
        if ok >= need {
            break;
        }
    }
    for p in peers.iter().filter(|p| !answered.contains(*p)) {
        println!("BROADCAST_TX={p} NOT_WAITED (already sent to {ok} peers; they relay it)");
    }
    if ok == 0 {
        return Err("not sent to any peer".into());
    }
    Ok(())
}

fn broadcast_once(peer_arg: &str, tx: &Transaction) -> Result<(), String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    )
    .map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let adapter = Arc::new(SyncAdapter {
        peer_claim: Arc::new(Mutex::new((0, 0))),
        headers: Arc::new(Mutex::new(Vec::new())),
        blocks: Arc::new(Mutex::new(Vec::new())),
        wanted: Arc::new(Mutex::new(HashSet::new())),
        segments: Arc::new(Mutex::new(SegmentInbox::default())),
        outgoing_tx: Arc::new(Mutex::new(Some(tx.clone()))),
    });
    let peer = Peer::connect(conn, Capabilities::default(), Difficulty::min_dma(), PeerAddr(local), &hs, adapter)
        .map_err(|e| format!("handshake {e:?}"))?;
    let r = peer.send_transaction(tx).map(|_| ()).map_err(|e| format!("send tx: {e:?}"));
    // Leave time for GetTransaction (kernel-hash relay) to be answered.
    std::thread::sleep(Duration::from_secs(20));
    peer.stop();
    let _ = peer.wait();
    r
}

