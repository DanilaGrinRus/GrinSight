//! Opt-in end-to-end test with a second Rust workspace's wallet binary.
//! Only the host's test-network switch and password KDF cost differ here.
//! Passing --chain replaces all stand-in ports with the real chain process.
use super::{kit, Operator, TEST_ROOTS_FILE, TEST_SOURCES_FILE};
use fly_chain_state::testkit::{Source, PAID_SEED};
use grin_core::consensus::REWARD;
use grin_core::core::KernelFeatures;
use grin_core::libtx::{build, proof::ProofBuilder};
use grin_keychain::{mnemonic, ExtKeychain, Keychain};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

const FEE: u32 = 15_000_000;
const PAYMENT: u64 = 1_000_000_000;

struct Host {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Value>,
    next_id: u64,
}
impl Host {
    fn start(base: &Path, name: &str, peers: &[kit::Node]) -> Host {
        let exe = std::env::var_os("FLY_AUTOMATED_HOST")
            .expect("build fly-paycore-host-test and set FLY_AUTOMATED_HOST");
        let mut cmd = Command::new(exe);
        cmd.arg("--profile")
            .arg(base.join(name))
            .arg("--guard-dir")
            .arg(base.join(format!("{name}-guard")))
            .arg("--chain")
            .arg(kit::FLY)
            .arg("--chain-no-tor");
        for node in peers {
            cmd.arg("--chain-peer").arg(node.addr.to_string());
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stream = child.stdout.take().unwrap();
        let (to, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                if msg.get("id").is_some() && to.send(msg).is_err() {
                    break;
                }
            }
        });
        Host {
            child,
            input,
            output,
            next_id: 0,
        }
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        self.next_id += 1;
        let req = json!({"jsonrpc":"2.0","id":self.next_id,"method":name,"params":args});
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{req}").unwrap();
        input.flush().unwrap();
        let mut got = self
            .output
            .recv_timeout(Duration::from_secs(20))
            .expect("wallet reply");
        assert_eq!(got["id"], self.next_id);
        assert!(
            got.get("result").is_some(),
            "{name} returned error {}",
            got["error"]["message"]
        );
        got["result"].take()
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        drop(self.input.take());
        let end = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().ok() == Some(None) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.child.try_wait().ok() == Some(None) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// Bind only the loopback TLS fixtures and their CA to the instance before
// its first unlock. A freshly created journal directory exposes the instance
// suffix without opening the vault, reading a key, or injecting any state.
fn sources(profile: &Path, operators: &[Operator]) {
    let journal = std::fs::read_dir(profile)
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix("wallet-")
                .map(str::to_owned)
        })
        .unwrap();
    let dir = profile.join(format!("chain-{journal}"));
    std::fs::create_dir_all(&dir).unwrap();
    fly_paycore_chain_port::bootstrap::schedule(&dir, fly_chain_headers::Net::Automated.tag()).unwrap();
    let registry: String = operators
        .iter()
        .enumerate()
        .map(|(i, op)| format!("https://localhost:{} Operator-{i} {}\n", op.port, i + 1))
        .collect();
    std::fs::write(dir.join(TEST_SOURCES_FILE), registry).unwrap();
    std::fs::write(
        dir.join(TEST_ROOTS_FILE),
        include_bytes!("../../../tips/tests/certs/ca.pem"),
    )
    .unwrap();
}

fn announce(chain: &Arc<RwLock<Source>>, nodes: &[kit::Node], operators: &[Operator]) {
    let headers = chain.read().unwrap().headers();
    for op in operators {
        *op.chain.lock().unwrap() = headers.clone();
        op.say(headers.last().unwrap());
    }
    for node in nodes {
        node.set(&headers);
        node.announce();
    }
}

#[test]
#[ignore = "cross-workspace test: set FLY_AUTOMATED_HOST to the local fly-paycore-host-test executable"]
fn old_phrase_genesis_restore_and_payment() {
    // An ordinary, legacy m/0/0/7 output was created BEFORE the archive.
    // Both that block and its source coinbase are mined and validated by Grin.
    let mut production = Source::thin(14);
    production.grow_paying(1);
    production.grow(3);
    let kc = ExtKeychain::from_seed(&PAID_SEED, false).unwrap();
    let parts = [
        build::coinbase_input(REWARD, ExtKeychain::derive_key_id(2, 1, 15, 0, 0)),
        build::output(
            REWARD - u64::from(FEE),
            ExtKeychain::derive_key_id(3, 0, 0, 7, 0),
        ),
    ];
    let funding = build::transaction(
        KernelFeatures::Plain { fee: FEE.into() },
        &parts,
        &kc,
        &ProofBuilder::new(&kc),
    )
    .unwrap();
    production.mine_with(&[funding]);
    production.grow(21);
    assert_eq!(production.archive().height, 20);
    production.compact();
    let source = Arc::new(RwLock::new(production));
    let nodes = [
        kit::Node::with_state(&source),
        kit::Node::with_state(&source),
    ];
    let operators: Vec<_> = (0..5).map(|_| Operator::start()).collect();
    announce(&source, &nodes, &operators);
    let dir = kit::Temp::new("wallet-genesis-payment");
    let mut payer = Host::start(&dir.0, "payer", &nodes);
    let mut recipient = Host::start(&dir.0, "recipient", &nodes);
    payer.call("host.profile.restore", json!({"network":"automated","password":"fixture-only","mnemonic":mnemonic::from_entropy(&PAID_SEED).unwrap()}));
    recipient.call(
        "host.profile.create",
        json!({"network":"automated","password":"fixture-only"}),
    );
    sources(&dir.0.join("payer"), &operators);
    sources(&dir.0.join("recipient"), &operators);
    for wallet in [&mut payer, &mut recipient] {
        wallet.call("host.unlock", json!({"password":"fixture-only"}));
        kit::wait_for(
            "local blocks and the independently surveyed local tip",
            || wallet.call("paycore.wallet.chain_status", json!({}))["selected_height"] == 40,
        );
    }
    kit::wait_for(
        "one archived legacy output belonging to the restored wallet",
        || {
            let search = payer.call("paycore.search.status", json!({}));
            search["state"] == "done" && search["found"] == 1
        },
    );
    assert_eq!(
        payer.call("paycore.balance", json!({}))["spendable"],
        (REWARD - u64::from(FEE)).to_string()
    );
    assert!(
        nodes.iter().any(|node| node
            .served
            .answered
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0),
        "the portable chain process obtained actual archive segments"
    );
    let intent = payer.call(
        "paycore.send.prepare",
        json!({"amount":PAYMENT.to_string()}),
    );
    let reply = recipient.call("paycore.receive.draft", json!({"slate":intent["slate"]}));
    let signed = payer.call(
        "paycore.send.finalize",
        json!({"op":intent["op"],"slate":reply["slate"]}),
    );
    kit::wait_for("transaction received over local P2P", || {
        nodes.iter().any(|n| n.stems() + n.pooled() > 0)
    });
    let received = nodes
        .iter()
        .find_map(|n| {
            n.served
                .stems
                .lock()
                .unwrap()
                .first()
                .cloned()
                .or_else(|| n.served.pool.lock().unwrap().first().cloned())
        })
        .unwrap();
    let raw = grin_core::ser::ser_vec(&received, grin_core::ser::ProtocolVersion::local()).unwrap();
    assert!(
        Some(kit::hex(&raw).as_str()) == signed["tx"].as_str(),
        "node received the exact signed transaction"
    );
    source.write().unwrap().mine_with(&[received]);
    announce(&source, &nodes, &operators);
    kit::wait_for("wallet recognizes its kernel in the verified block", || {
        payer.call("paycore.send.status", json!({"op":intent["op"]}))["state"] == "confirmed"
    });
    kit::wait_for("the recipient finds its output", || {
        recipient.call("paycore.balance", json!({}))["spendable"] == PAYMENT.to_string()
    });
}
