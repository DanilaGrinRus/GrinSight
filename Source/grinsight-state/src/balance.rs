//! Wallet balance for the screen: available / reserved / incoming / immature.
//!
//! Inputs are the two files the wallet already keeps:
//! * the known-outputs file (`wallet-outputs.jsonl`, written by `gap` after a
//!   proven run): own outputs with `unspent_at_tip` at that file's tip;
//! * the pending journal: input reservations of payments in flight, outputs
//!   promised to us (receive, invoice, change) that are not on chain yet.
//!
//! The split:
//! * **available**: unspent at the proven tip, not reserved, mature;
//! * **reserved**: unspent, but an unreleased payment uses it as an input
//!   (it leaves the wallet once that payment is mined);
//! * **incoming**: promised in the journal, not yet among the own outputs
//!   (a receive the sender has not finalized/mined yet, an invoice not paid
//!   yet, the change of our own payment);
//! * **immature**: coinbase younger than 1440 blocks.
//!
//! The MAC of the known file needs the seeds: [`check_known_mac`] is for the
//! host that keeps them (the wallet service checks it before showing the
//! balance as proven); the spend path checks it too (`receive::read_known_key_ids`).

use crate::receive::journal_text;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub const COINBASE_MATURITY: u64 = 1440;

/// May this balance be shown as proven next to this proof session?
/// The outputs file must carry a valid MAC (`entropy` = the wallet's seeds)
/// and describe exactly the session's verified tip: same height AND same
/// block hash (a file from another branch of the same height is refused).
/// `session_tip` = (height, hash hex) of the verified tip, None = no session.
pub fn check_binding(known_text: &str, entropy: &[Vec<u8>], session_tip: Option<(u64, &str)>) -> Result<(), String> {
    check_known_mac(known_text, entropy).map_err(|e| format!("wallet-outputs.jsonl: {e}"))?;
    let Some((h, hash)) = session_tip else { return Ok(()) };
    if known_text.trim().is_empty() {
        return Err("no proven outputs file for this proof; refresh".into());
    }
    let b = balance(known_text, "", 1)?;
    if b.tip_height != h {
        return Err(format!("the outputs file is for height {}, the proof for {h}; refresh", b.tip_height));
    }
    match b.tip_hash.as_deref() {
        Some(x) if x.eq_ignore_ascii_case(hash) => Ok(()),
        Some(_) => Err(format!("the outputs file is for another block at height {h} (reorg); refresh")),
        None => Err("the outputs file has no tip hash; refresh".into()),
    }
}

/// Check the MAC line of a known-outputs file (see `Wallets::file_mac`).
/// Empty text (no file yet) is fine. No mac line, a wrong mac or data after
/// the mac line is an error: the file was changed, shortened or written with
/// other seeds, and its balance must not be shown as proven.
pub fn check_known_mac(text: &str, entropy: &[Vec<u8>]) -> Result<(), String> {
    if text.trim().is_empty() {
        return Ok(());
    }
    let mut body = String::new();
    let mut mac: Option<String> = None;
    for raw in text.split_inclusive('\n') {
        let line = raw.trim();
        if mac.is_some() {
            if !line.is_empty() {
                return Err("data after the mac line".into());
            }
            continue;
        }
        if line.starts_with("{\"mac\":") {
            let v: Value = serde_json::from_str(line).map_err(|_| "bad mac line".to_string())?;
            mac = Some(v["mac"].as_str().ok_or("bad mac line")?.to_string());
            continue;
        }
        body.push_str(raw);
    }
    let mac = mac.ok_or("no mac line")?;
    if crate::wallet::file_mac_for_entropy(entropy, body.as_bytes()) != mac {
        return Err("mac mismatch (changed, shortened or written with other seeds)".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub wallet: usize,
    /// Tip height of the known-outputs file (the proven state it describes).
    pub tip_height: u64,
    /// Tip hash of that state (a branch of the same height is another state).
    pub tip_hash: Option<String>,
    pub available: u64,
    pub reserved: u64,
    pub incoming: u64,
    pub immature: u64,
    pub unspent_outputs: usize,
    pub reserved_outputs: usize,
    pub incoming_items: Vec<Incoming>,
    /// Slate ids of payments that still hold inputs.
    pub payments_in_flight: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub kind: String,
    pub slate_id: String,
    pub amount: u64,
    pub commit: String,
    pub since: String,
}

impl Balance {
    pub fn total(&self) -> u64 {
        self.available + self.reserved + self.immature
    }

    pub fn to_json(&self) -> String {
        json!({
            "wallet": self.wallet,
            "tip_height": self.tip_height,
            "available_nanogrin": self.available,
            "reserved_nanogrin": self.reserved,
            "incoming_nanogrin": self.incoming,
            "immature_nanogrin": self.immature,
            "total_nanogrin": self.total(),
            "unspent_outputs": self.unspent_outputs,
            "reserved_outputs": self.reserved_outputs,
            "payments_in_flight": self.payments_in_flight,
            "incoming": self.incoming_items.iter().map(|i| json!({
                "kind": i.kind, "slate_id": i.slate_id, "amount_nanogrin": i.amount,
                "commit": i.commit, "since": i.since,
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }
}

fn s<'a>(r: &'a serde_json::Map<String, Value>, k: &str) -> Option<&'a str> {
    r.get(k).and_then(Value::as_str)
}
fn n(r: &serde_json::Map<String, Value>, k: &str) -> Option<u64> {
    r.get(k).and_then(Value::as_u64)
}

/// `wallet` is 1-based like everywhere in the files. A damaged file is an
/// error (never a smaller number).
pub fn balance(known_text: &str, pending_text: &str, wallet: usize) -> Result<Balance, String> {
    let mut b = Balance { wallet, ..Default::default() };
    let mut own: HashSet<String> = HashSet::new();
    let mut unspent: Vec<(String, u64, bool, Option<u64>)> = Vec::new();
    let mut seen_mac = false;
    for (i, r) in journal_text(known_text, "wallet outputs")?.iter().enumerate() {
        if seen_mac {
            return Err(format!("wallet outputs record {}: data after the mac line", i + 1));
        }
        if r.contains_key("mac") {
            seen_mac = true;
            continue;
        }
        if s(r, "meta") == Some("grinsight-wallet") {
            b.tip_height = n(r, "tip_height").ok_or("wallet outputs: meta without tip_height")?;
            b.tip_hash = s(r, "tip_hash").map(|x| x.to_ascii_lowercase());
            continue;
        }
        let bad = || format!("wallet outputs record {}: malformed", i + 1);
        let w = n(r, "wallet").ok_or_else(bad)? as usize;
        let commit = s(r, "commit").filter(|c| c.len() == 66).ok_or_else(bad)?.to_ascii_lowercase();
        let amount = n(r, "amount").ok_or_else(bad)?;
        let live = r.get("unspent_at_tip").and_then(Value::as_bool).ok_or_else(bad)?;
        own.insert(commit.clone());
        if w == wallet && live {
            let coinbase = s(r, "features").is_some_and(|f| f.eq_ignore_ascii_case("coinbase"));
            unspent.push((commit, amount, coinbase, n(r, "created")));
        }
    }
    let recs = journal_text(pending_text, "pending")?;
    let released: HashSet<&str> = recs.iter().filter(|r| s(r, "kind") == Some("release")).filter_map(|r| s(r, "slate_id")).collect();
    let mut reserved: HashMap<String, String> = HashMap::new();
    for (i, r) in recs.iter().enumerate() {
        let kind = s(r, "kind").unwrap_or("");
        let bad = || format!("pending record {}: malformed {kind}", i + 1);
        match kind {
            "inputs" | "payment" => {
                let sid = s(r, "slate_id").filter(|x| !x.is_empty()).ok_or_else(bad)?;
                let commits = s(r, "commits").ok_or_else(bad)?;
                if released.contains(sid) {
                    continue;
                }
                let mut any_live = false;
                for c in commits.split(',') {
                    let c = c.to_ascii_lowercase();
                    if unspent.iter().any(|u| u.0 == c) {
                        any_live = true;
                    }
                    reserved.insert(c, sid.to_string());
                }
                // A payment whose inputs are all gone has been mined.
                if any_live && n(r, "wallet") == Some(wallet as u64) && !b.payments_in_flight.iter().any(|x| x == sid) {
                    b.payments_in_flight.push(sid.to_string());
                }
            }
            _ => {}
        }
    }
    for r in &recs {
        let kind = s(r, "kind").unwrap_or("");
        if !matches!(kind, "receive" | "invoice" | "change" | "payment") || n(r, "wallet") != Some(wallet as u64) {
            continue;
        }
        let sid = s(r, "slate_id").unwrap_or("");
        if released.contains(sid) && kind == "payment" {
            continue; // released payment: its change will never exist
        }
        let Some(commit) = s(r, "commit").map(str::to_ascii_lowercase) else { continue };
        let amount = n(r, "amount").unwrap_or(0);
        if amount == 0 || own.contains(&commit) || b.incoming_items.iter().any(|x| x.commit == commit) {
            continue;
        }
        // The change of our own payment exists only if that payment still holds inputs.
        if kind == "payment" && !b.payments_in_flight.iter().any(|x| x == sid) {
            continue;
        }
        b.incoming += amount;
        b.incoming_items.push(Incoming {
            kind: kind.into(),
            slate_id: sid.into(),
            amount,
            commit,
            since: s(r, "received_at").unwrap_or("").into(),
        });
    }
    for (commit, amount, coinbase, created) in unspent {
        b.unspent_outputs += 1;
        if reserved.contains_key(&commit) {
            b.reserved += amount;
            b.reserved_outputs += 1;
        } else if coinbase && created.map_or(false, |c| c + COINBASE_MATURITY > b.tip_height) {
            b.immature += amount;
        } else {
            b.available += amount;
        }
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(x: u8) -> String {
        format!("09{}", format!("{x:02x}").repeat(32))
    }

    fn known() -> String {
        let mut t = String::from("{\"meta\":\"grinsight-wallet\",\"tip_height\":5000,\"tip_hash\":\"ab\"}\n");
        let rec = |w: u32, cm: &str, amount: u64, f: &str, created: &str, live: bool| {
            format!("{{\"wallet\":{w},\"commit\":\"{cm}\",\"amount\":{amount},\"key_id\":\"03\",\"features\":\"{f}\",\"created\":{created},\"unspent_at_tip\":{live},\"spent_height\":null,\"tip_height\":5000}}\n")
        };
        t += &rec(1, &c(1), 100, "Plain", "4000", true);
        t += &rec(1, &c(2), 50, "Plain", "null", true);
        t += &rec(1, &c(3), 7, "Plain", "3000", false);
        t += &rec(1, &c(4), 60, "Coinbase", "4500", true);
        t += &rec(1, &c(5), 60, "Coinbase", "3000", true);
        t += &rec(2, &c(6), 999, "Plain", "4000", true);
        t += "{\"mac\":\"00\",\"records\":6}\n";
        t
    }

    #[test]
    fn split_of_the_balance() {
        let pending = format!(
            "{}\n{}\n{}\n{}\n",
            // our payment in flight: input c(2), change 20 at c(10)
            format!("{{\"kind\":\"payment\",\"what\":\"send\",\"wallet\":1,\"slate_id\":\"p1\",\"commits\":\"{}\",\"tip_height\":4999,\"amount\":20,\"key_id\":\"03\",\"commit\":\"{}\",\"to\":\"grin1x\",\"received_at\":\"t1\"}}", c(2), c(10)),
            // someone pays us 30 (not mined yet)
            format!("{{\"kind\":\"receive\",\"wallet\":1,\"slate_id\":\"r1\",\"amount\":30,\"fee\":1,\"key_id\":\"03\",\"commit\":\"{}\",\"sender\":\"x\",\"received_at\":\"t2\",\"tip_height\":4999}}", c(11)),
            // an older receive that is already on chain (c(1)): not incoming
            format!("{{\"kind\":\"receive\",\"wallet\":1,\"slate_id\":\"r0\",\"amount\":100,\"fee\":1,\"key_id\":\"03\",\"commit\":\"{}\",\"sender\":\"x\",\"received_at\":\"t0\",\"tip_height\":3999}}", c(1)),
            // another wallet's invoice: not ours
            format!("{{\"kind\":\"invoice\",\"wallet\":2,\"slate_id\":\"i9\",\"amount\":5,\"key_id\":\"03\",\"commit\":\"{}\",\"to\":\"\",\"received_at\":\"t\"}}", c(12)),
        );
        let b = balance(&known(), &pending, 1).unwrap();
        assert_eq!(b.tip_height, 5000);
        assert_eq!(b.available, 100 + 60, "c1 + mature coinbase c5");
        assert_eq!(b.reserved, 50, "c2 is the input of p1");
        assert_eq!(b.immature, 60, "coinbase c4 created at 4500");
        assert_eq!(b.incoming, 30 + 20, "receive r1 + change of p1");
        assert_eq!(b.total(), 270);
        assert_eq!(b.payments_in_flight, vec!["p1".to_string()]);
        assert_eq!(b.unspent_outputs, 4);
        let v: Value = serde_json::from_str(&b.to_json()).unwrap();
        assert_eq!(v["available_nanogrin"], json!(160));
        assert_eq!(v["incoming"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn released_or_mined_payment_holds_nothing() {
        let pay = format!("{{\"kind\":\"payment\",\"what\":\"send\",\"wallet\":1,\"slate_id\":\"p1\",\"commits\":\"{}\",\"tip_height\":4999,\"amount\":20,\"key_id\":\"03\",\"commit\":\"{}\",\"to\":\"x\",\"received_at\":\"t\"}}\n", c(2), c(10));
        let released = format!("{pay}{{\"kind\":\"release\",\"slate_id\":\"p1\",\"received_at\":\"t\"}}\n");
        let b = balance(&known(), &released, 1).unwrap();
        assert_eq!((b.reserved, b.incoming, b.available), (0, 0, 210));
        // Input c(3) already spent on chain: the payment was mined, its change
        // shows up as an own output after the next proven run, not as incoming.
        let mined = pay.replace(&c(2), &c(3));
        let b = balance(&known(), &mined, 1).unwrap();
        assert_eq!((b.reserved, b.incoming), (0, 0));
        assert!(b.payments_in_flight.is_empty());
    }

    #[test]
    fn damaged_files_are_errors() {
        assert!(balance(&known(), "{\"kind\":\"inp", 1).is_err(), "torn journal");
        assert!(balance(&format!("{}{{\"wallet\":1}}\n", known()), "", 1).is_err(), "data after mac");
        // MAC: right seeds pass, a changed record or other seeds fail.
        let e = vec![vec![7u8; 32]];
        let body = "{\"meta\":\"grinsight-wallet\",\"tip_height\":5}\n";
        let good = format!("{body}{{\"mac\":\"{}\",\"records\":0}}\n", crate::wallet::file_mac_for_entropy(&e, body.as_bytes()));
        assert!(check_known_mac(&good, &e).is_ok());
        assert!(check_known_mac("", &e).is_ok(), "no file yet");
        assert!(check_known_mac(&good.replace("\"tip_height\":5", "\"tip_height\":6"), &e).is_err(), "edited");
        assert!(check_known_mac(&good, &[vec![8u8; 32]]).is_err(), "other seeds");
        assert!(check_known_mac(body, &e).is_err(), "no mac line");
        // Binding to the proof: same height AND same block hash.
        let mk = |hash: &str| {
            let body = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":5,\"tip_hash\":\"{hash}\"}}\n");
            format!("{body}{{\"mac\":\"{}\",\"records\":0}}\n", crate::wallet::file_mac_for_entropy(&e, body.as_bytes()))
        };
        let branch_a = mk(&"aa".repeat(32));
        assert!(check_binding(&branch_a, &e, Some((5, &"aa".repeat(32)))).is_ok());
        let other_branch = check_binding(&branch_a, &e, Some((5, &"bb".repeat(32)))).unwrap_err();
        assert!(other_branch.contains("another block"), "{other_branch}");
        assert!(check_binding(&branch_a, &e, Some((6, &"aa".repeat(32)))).is_err(), "other height");
        assert!(check_binding("", &e, Some((5, &"aa".repeat(32)))).is_err(), "no file but a proof");
        assert!(check_binding("", &e, None).is_ok(), "new wallet, no proof yet");
        assert!(balance("{\"wallet\":1,\"commit\":\"09\"}\n", "", 1).is_err());
        assert!(balance(&known(), "{\"kind\":\"payment\",\"wallet\":1,\"slate_id\":\"p\"}\n", 1).is_err());
        assert_eq!(balance("", "", 1).unwrap(), Balance { wallet: 1, ..Default::default() });
    }
}
