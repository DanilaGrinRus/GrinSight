//! How a host process (the Rust service behind the Flutter app) wires the
//! payment core: open the journal, build the bridge, route `paycore.*`.
//!
//!     cargo run --example host
//!
//! This example uses a throw-away directory and a random seed. In the
//! product the seed comes from the service's vault after unlock, the journal
//! key and the guard key are derived from it or kept by the OS, and the four
//! ports are the service's real network, clock and chain layers.
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, JsonCodec, Ports};
use fly_paycore_bridge::Bridge;
use fly_paycore_store::{FileGuard, FsDir, Identity, RootKey};
use fly_paycore_wallet::{Advance, Broadcast, ChainState, Core, CoreError};
use grin_keychain::{ExtKeychain, Keychain};
use zeroize::Zeroizing;

struct NoNetwork;
impl Broadcaster for NoNetwork {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        // product: POST to the node (Foreign API push_transaction);
        // a timeout must be reported as Unknown
        Broadcast::Unknown
    }
}
struct NoClock;
impl Clock for NoClock {
    fn confirmed_time(&self) -> Option<u64> {
        None // product: time confirmed against block headers
    }
}
struct FlyChain;
impl ChainView for FlyChain {
    fn chain_state(&self) -> ChainState {
        ChainState::Unknown // product: from the Fly core's verified state
    }
    fn k_conf(&self) -> u64 {
        10
    }
    fn rangeproofs_authenticated(&self) -> bool {
        false
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, CoreError> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::getrandom(b.as_mut()).map_err(|_| CoreError::Rng)?;
    Ok(b)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1 = mainnet, 2 = testnet: the tag is part of the journal identity
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Testnet);
    let base = std::env::temp_dir().join(format!("paycore-host-example-{}", std::process::id()));
    let wallet_dir = base.join("wallet");
    let os_dir = base.join("os"); // must be outside the wallet directory
    std::fs::create_dir_all(&os_dir)?;

    let seed = random::<32>().map_err(|e| format!("{e:?}"))?;
    let journal_key = random::<32>().map_err(|e| format!("{e:?}"))?;
    let guard_key = random::<32>().map_err(|e| format!("{e:?}"))?;
    let instance = random::<16>().map_err(|e| format!("{e:?}"))?;
    let identity = Identity {
        network: 2,
        genesis: [0u8; 32], // product: hash of the network's genesis block
        instance: *instance,
    };
    let keychain = ExtKeychain::from_seed(seed.as_ref(), true)?;

    // first start: create; later starts: Core::open with the same arguments
    let core = Core::create(
        FsDir::new(&wallet_dir)?,
        FileGuard::new(&os_dir.join("guard"), *guard_key)?,
        &RootKey::new(*journal_key),
        identity,
        keychain,
        0,
        1440, // coinbase maturity of the network
    )
    .map_err(|e| format!("{e:?}"))?;

    let mut bridge = Bridge::new(
        core,
        Ports {
            broadcaster: Box::new(NoNetwork),
            clock: Box::new(NoClock),
            chain: Box::new(FlyChain),
            codec: Box::new(JsonCodec),
        mailbox: None,
        },
    );

    // the chain layer feeds verified blocks directly, not through JSON
    bridge
        .core_mut()
        .chain_advance(&Advance {
            height: 1,
            hash: [1u8; 32],
            ..Advance::default()
        })
        .map_err(|e| format!("{e:?}"))?;

    // the service's /rpc handler: every method starting with "paycore." goes here
    for request in [
        r#"{"jsonrpc":"2.0","id":1,"method":"paycore.info"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"paycore.balance"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"paycore.send.prepare","params":{"amount":"1000000000"}}"#,
    ] {
        println!("> {request}\n< {}\n", bridge.call(request));
    }
    drop(bridge);
    std::fs::remove_dir_all(&base)?;
    Ok(())
}
