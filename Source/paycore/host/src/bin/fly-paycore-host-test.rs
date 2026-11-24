//! The host with a stand-in chain, for the tests (feature "test-chain").
//! Never part of a product build.
//!
//! The chain is "at the tip, time confirmed, every broadcast accepted". A
//! new profile may be given funds: `"test": {"funds": ["5000000000", ...]}`
//! in `host.profile.create` puts those outputs into the first block.
#![forbid(unsafe_code)]
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock};
use fly_paycore_host::{ChainPorts, HostCore, Setup};
use fly_paycore_keys::path::KeyPath;
use fly_paycore_wallet::{Advance, Broadcast, ChainState};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use serde_json::Value;
use std::process::ExitCode;
use std::time::Duration;

struct Net;
impl Broadcaster for Net {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Accepted
    }
}
struct Time;
impl Clock for Time {
    fn confirmed_time(&self) -> Option<u64> {
        Some(1_000)
    }
}
struct View;
impl ChainView for View {
    fn chain_state(&self) -> ChainState {
        ChainState::AtTip
    }
    fn k_conf(&self) -> u64 {
        3
    }
    fn rangeproofs_authenticated(&self) -> bool {
        true
    }
}

fn fund(core: &mut HostCore, keychain: &ExtKeychain, extra: &Value) -> Result<(), String> {
    if extra.is_null() {
        // a profile as the product makes it: no position, no money
        return Ok(());
    }
    let mut first = Advance {
        height: 1,
        hash: [1; 32],
        ..Advance::default()
    };
    let builder = ProofBuilder::new(keychain);
    let funds = extra.get("funds").and_then(Value::as_array).cloned().unwrap_or_default();
    for (n, amount) in funds.iter().enumerate() {
        let amount: u64 = amount
            .as_str()
            .and_then(|a| a.parse().ok())
            .ok_or("funds are amounts as text")?;
        let index = u32::try_from(n).map_err(|_| "too many outputs")?;
        let key = KeyPath::Legacy { account: 0, index }.to_identifier();
        let commit = keychain
            .commit(amount, &key, SwitchCommitmentType::Regular)
            .map_err(|_| "commitment")?;
        let rp = proof::create(keychain, &builder, amount, &key, SwitchCommitmentType::Regular, commit, None)
            .map_err(|_| "range proof")?;
        first.outputs.push((commit, rp, u64::from(index).saturating_add(1), false));
    }
    core.chain_advance(&first).map_err(|e| format!("{e:?}"))?;
    core.chain_advance(&Advance {
        height: 2,
        hash: [2; 32],
        ..Advance::default()
    })
    .map_err(|e| format!("{e:?}"))
}

fn main() -> ExitCode {
    let setup = Setup {
        ports: || ChainPorts {
            broadcaster: Box::new(Net),
            clock: Box::new(Time),
            chain: Box::new(View),
        },
        after_create: Some(fund),
        allow_automated: true,
        kdf_log_n: 10,
        kdf_min_log_n: 10,
        tick: Duration::from_millis(200),
        transport_retry: Duration::from_secs(1),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(fly_paycore_host::run(setup, &args, std::io::stdin().lock(), std::io::stdout()))
}
