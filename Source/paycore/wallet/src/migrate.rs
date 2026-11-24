//! Moving from the v0.1 wallet (the `grin_wallet_libwallet` database) to the
//! payment core (specification, section 12).
//!
//! Nothing is converted: signing contexts never cross formats. The old
//! database is only read. Migration is refused while it holds anything in
//! flight; otherwise the caller creates a new journal (new instance, new
//! branch), lets the scan find the outputs, and keeps the old history as text.
use grin_keychain::Keychain;
use grin_wallet_libwallet::{NodeClient, OutputStatus, TxLogEntryType, WalletBackend};

/// Something in the old wallet that must be finished or cancelled there first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocker {
    /// A sent transaction that is neither confirmed nor cancelled.
    SendInFlight {
        /// Transaction log id in the old wallet.
        id: u32,
    },
    /// A received transaction that is not confirmed.
    ReceiveInFlight {
        /// Transaction log id in the old wallet.
        id: u32,
    },
    /// An output locked by an unfinished send.
    LockedOutput {
        /// Its value.
        value: u64,
    },
    /// An output expected from an unfinished receive.
    UnconfirmedOutput {
        /// Its value.
        value: u64,
    },
    /// The old database could not be read; nothing is assumed about it.
    Unreadable,
}

/// Result of inspecting a v0.1 wallet that is safe to leave behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Sum of the unspent outputs; the scan of the new wallet must find the
    /// same amount before the old database is put away.
    pub expected_unspent: u64,
    /// Number of unspent outputs.
    pub unspent_outputs: usize,
    /// One line per old transaction log entry, without keys or commitments.
    pub history: Vec<String>,
}

/// Inspect a v0.1 wallet. `Err` lists every reason migration is refused.
pub fn inspect<C: NodeClient, K: Keychain>(
    old: &WalletBackend<C, K>,
) -> Result<Plan, Vec<Blocker>> {
    let mut blockers = Vec::new();
    let mut plan = Plan {
        expected_unspent: 0,
        unspent_outputs: 0,
        history: Vec::new(),
    };
    match old.iter() {
        Ok(outputs) => {
            for o in outputs {
                match o.status {
                    OutputStatus::Locked => blockers.push(Blocker::LockedOutput { value: o.value }),
                    OutputStatus::Unconfirmed => {
                        blockers.push(Blocker::UnconfirmedOutput { value: o.value })
                    }
                    OutputStatus::Unspent => {
                        plan.expected_unspent = plan.expected_unspent.saturating_add(o.value);
                        plan.unspent_outputs = plan.unspent_outputs.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        Err(_) => blockers.push(Blocker::Unreadable),
    }
    match old.tx_log_iter() {
        Ok(entries) => {
            for e in entries {
                let e = match e {
                    Ok(e) => e,
                    Err(_) => {
                        blockers.push(Blocker::Unreadable);
                        continue;
                    }
                };
                match e.tx_type {
                    TxLogEntryType::TxSent if !e.confirmed => {
                        blockers.push(Blocker::SendInFlight { id: e.id })
                    }
                    TxLogEntryType::TxReceived if !e.confirmed => {
                        blockers.push(Blocker::ReceiveInFlight { id: e.id })
                    }
                    _ => {}
                }
                plan.history.push(format!(
                    "#{} {:?} confirmed={} credited={} debited={} slate={}",
                    e.id,
                    e.tx_type,
                    e.confirmed,
                    e.amount_credited,
                    e.amount_debited,
                    e.tx_slate_id
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| "-".into())
                ));
            }
        }
        Err(_) => blockers.push(Blocker::Unreadable),
    }
    if blockers.is_empty() {
        Ok(plan)
    } else {
        Err(blockers)
    }
}
