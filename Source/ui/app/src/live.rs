//! The real wallet behind the screens: `fly-paycore-host` over JSON-RPC.
//!
//! Passwords and the words of a wallet are taken from the fields, written
//! into one request and wiped here; Slint keeps its own copy of what was
//! typed until the field is cleared, which this code cannot wipe. Everything
//! shown is asked of the host again every few seconds. Host calls run on
//! worker threads; what they bring back is put into the window on the
//! window's thread, where the state of the open windows (`Flow`) lives.
//!
//! The signing window follows О10: the amount and the fee come from the
//! wallet's own operation, the recipient is named only by О8, nothing the
//! other side wrote is shown but a checked name.

use crate::ui::{App, ChatLine, Contact, Op, OpLine, Waiting};
use crate::{fill, fill_common, model, name, note, tr};
use fly_host_link::{CallError, Client, Host};
use fly_safe_display::{address, address_of_key, amount, foreign_line, foreign_text, key_of_address, parse_amount, recipient, AmountError, Recipient, MESSAGE_CHARS, NAME_CHARS};
use serde_json::{json, Value};
use slint::{ComponentHandle, SharedString, Timer, TimerMode};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod apart;
mod bridges;
mod checkpoint;
#[cfg(test)]
mod freshness_tests;

const QUICK: Duration = Duration::from_secs(10);
/// Opening, creating or restoring a profile runs scrypt (128 MB, a second
/// or more on a slow machine).
const SLOW: Duration = Duration::from_secs(120);
/// Signing may wait for the chain process (up to 30 s) before it answers.
const SIGN: Duration = Duration::from_secs(60);
const REFRESH: Duration = Duration::from_secs(3);
/// Shortest password the interface accepts for a new wallet.
/// Notifications kept between two refreshes; more are dropped (the host
/// offers an unanswered incoming payment again on the next round).
const MAX_NOTES: usize = 64;

/// Keeps the host process and the refresh timer alive.
pub struct Live {
    _timer: Timer,
}

thread_local! {
    /// The wallet process of this window; replaced when it is started again
    /// with other arguments, dropped (and so locked) with the window.
    static HOST: RefCell<Option<Host>> = const { RefCell::new(None) };
}

impl Drop for Live {
    fn drop(&mut self) {
        end_session();
        HOST.with(|h| drop(h.borrow_mut().take()));
    }
}

/// The text a line of "All payments" can show again.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OpRef {
    /// A payment prepared by hand that waits for the recipient's reply.
    Send(String),
    /// An incoming payment this wallet answered: the reply is kept (K191).
    Reply(String),
    /// A payment this wallet signed: its final text is kept (K191).
    /// `waiting`: signed and not in a block yet.
    /// `back`: the owner may try to take it back (K197).
    Signed { op: String, waiting: bool, back: bool },
    None,
}

impl OpRef {
    /// Whether the line has a text to show again: only then the sign for
    /// it is drawn.
    fn shows(&self) -> bool {
        !matches!(self, OpRef::None)
    }
}

/// A contact as the wallet stores it, cleaned for showing.
#[derive(Clone)]
struct ContactRec {
    key: String,
    shown: String,
    raw_name: String,
    /// The contact's wallet address (`grin1…`), when one is stored.
    address: Option<String>,
    /// K199: the owner compared the check code with this contact.
    checked: bool,
}

/// What the send window passes for "over Tor, to a grin1 address"; a
/// contact is its number in the list, by hand is -1.
const TO_ADDRESS: i32 = -2;

/// Why a payment did not get through Tor, in the window's words. The
/// reasons are fixed words of the wallet and of its Tor process; what
/// another wallet said comes after "refused:" and is shown as it was
/// cleaned on the way here.
fn tor_reason(reason: &str) -> String {
    if reason.starts_with("Tor did not reach the wallet at this address") {
        return tr("Tor did not reach the wallet at this address: it is closed, offline, or its Tor is not up yet", "Tor не дошёл до кошелька по этому адресу: он закрыт, не в сети или его Tor ещё не поднялся").into();
    }
    if let Some(said) = reason.strip_prefix("the wallet at this address refused: ") {
        return fill(tr("The wallet at this address refused: {}", "Кошелёк по этому адресу отказал: {}"), &[said]);
    }
    match reason {
        "the wallet at this address did not answer in time" => tr("The wallet at this address did not answer in time", "Кошелёк по этому адресу не ответил вовремя").into(),
        "the wallet at this address refused the request" => tr("The wallet at this address does not take payments this way", "Кошелёк по этому адресу не принимает платежи таким способом").into(),
        "the connection to the wallet was lost" => tr("The connection to the wallet at this address was lost", "Связь с кошельком по этому адресу оборвалась").into(),
        "the answer is not a wallet's answer" | "the answer is not a reply to a payment" => tr("What answered at this address is not a Grin wallet's reply", "То, что ответило по этому адресу, — не ответ кошелька Grin").into(),
        "the reply does not match the payment" => tr("The reply does not match this payment and was not taken", "Ответ не подходит к этому платежу и не принят").into(),
        other if other.starts_with("Tor gave no outcome") => tr("Tor gave no outcome: whether the wallet at this address got the payment is not known", "Tor не сообщил исход: получил ли кошелёк по этому адресу платёж, неизвестно").into(),
        other => other.to_string(),
    }
}

/// What became of the payment the open text window sent over Tor.
#[derive(Debug, PartialEq, Eq)]
enum TorOutcome {
    /// Nothing yet.
    Wait,
    /// The window is closed or shows another payment: the outcome will be
    /// in the lists, not here.
    Gone,
    /// The reply is here: the window to sign opens.
    Sign,
    /// It did not get through, and why.
    Failed(String),
}

/// `shown`: the text window is open for this very payment. `held`: the
/// wallet holds the reply to it. `failed`: why its sending failed, if it did.
fn tor_outcome(shown: bool, held: bool, failed: Option<&str>) -> TorOutcome {
    if !shown {
        return TorOutcome::Gone;
    }
    // a reply that is here matters more than an earlier failure
    if held {
        return TorOutcome::Sign;
    }
    match failed {
        Some(why) => TorOutcome::Failed(why.to_string()),
        None => TorOutcome::Wait,
    }
}

/// Shows the outcome of a payment sent over Tor in the window it was sent
/// from, as soon as the wallet knows it.
fn tor_step(app: &App, view: &View) {
    let open = app.get_sheet() == 2;
    let step = with(|f| {
        let op = f.tor_wait.clone()?;
        let mine = f.send.as_ref().filter(|s| s.op == op).cloned();
        let held = view.sends.iter().any(|s| s.op == op && s.held);
        let failed = view.onion_sends.iter().find(|(sent, failed, _)| sent == &op && *failed).map(|(_, _, why)| why.as_str());
        let outcome = tor_outcome(open && mine.is_some(), held, failed);
        if outcome != TorOutcome::Wait {
            f.tor_wait = None;
        }
        Some((outcome, mine))
    });
    match step {
        Some((TorOutcome::Sign, Some(flow))) => {
            app.set_out_waiting(false);
            open_sign(app, SendFlow { held: true, s2: None, ..flow });
        }
        Some((TorOutcome::Failed(why), _)) => {
            app.set_out_waiting(false);
            app.set_out_title(tr("The payment did not get through Tor", "Платёж не дошёл через Tor").into());
            app.set_out_note(tr("The payment is still prepared and the money reserved. Send it over Tor again with the button below, pass this text on by hand and paste the reply, or cancel the payment under “Waiting for you”.", "Платёж по-прежнему подготовлен, деньги в резерве. Отправьте его через Tor ещё раз кнопкой ниже, передайте этот текст вручную и вставьте ответ или отмените платёж в «Ждут вас».").into());
            app.set_out_can_tor(true);
            sheet_error(app, why);
        }
        _ => {}
    }
}

/// How the window names a payment that arrived at the wallet's address
/// through Tor: this, then the number the wallet gave it.
const TOR_ASK: &str = "tor:";

/// The number of such a payment, if `id` names one.
fn tor_ask(id: &str) -> Option<u64> {
    id.strip_prefix(TOR_ASK)?.parse().ok()
}

/// An incoming payment the transport brought, waiting for a yes or a no.
#[derive(Clone)]
struct Incoming {
    id: String,
    slate: String,
    from: String,
}

/// One line of «Ждут вас».
#[derive(Clone)]
enum Wait {
    /// A reply came through the transport; signing needs the user.
    Sign(String),
    /// A payment passed on by hand waits for the recipient's text.
    Reply(String),
    /// A payment sent to a contact waits for the contact's reply.
    Sent(String),
    /// A payment prepared before the wallet was restored from an older
    /// copy: it cannot be signed, and its reserve stays until given up.
    Locked { op: String, amount: u64, session_expired: bool },
    /// An incoming payment through the transport.
    Incoming(Incoming),
    /// A signed payment the network check could not send: Tor did not
    /// come up. The owner chooses what to do (O45, K192).
    Unsent(String),
    /// O67: the starting point lies this many blocks below the checked
    /// chain: a new one is offered. Never made without the owner.
    Point(u64),
}

/// One outgoing operation, as the wallet's history gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SendRow {
    op: String,
    state: String,
    amount: u64,
    fee: u64,
    /// The recipient's reply is held by the wallet and waits for a signature.
    held: bool,
    /// The payment of an invoice.
    invoice: bool,
    /// Prepared and locked after a detected rollback.
    locked: bool,
    session_expired: bool,
    /// The contact it was sent to, when it went through the transport.
    to: Option<String>,
    /// The block its kernel was seen in.
    kernel_height: Option<u64>,
    /// The wallet signed it and keeps the final text.
    signed: bool,
    /// The block the wallet stood at when it was prepared.
    made: Option<u64>,
    /// The number of the payment's slate, as the wallet gives it.
    slate_id: String,
    /// K197: the payment this one replaces, and the payment under way
    /// that replaces this one.
    replaces: Option<String>,
    replaced_by: Option<String>,
    /// K198: the owner agreed to the direct way for this payment.
    direct: bool,
}

/// K197: what is said of a payment the owner takes back, and of the
/// payment that takes it back - instead of the state's usual words.
/// `None`: the usual words stand.
fn back_words(row: &SendRow, sends: &[SendRow]) -> Option<&'static str> {
    let ended = matches!(row.state.as_str(), "contested" | "dead");
    if row.replaces.is_some() && ended {
        // the first payment got into a block before this one
        return Some(tr("did not work: the payment reached a block first", "не вышло: платёж попал в блок раньше"));
    }
    if row.replaced_by.is_some() && row.state == "finalized" {
        return Some(tr("being taken back — one of the two will be in a block", "отзывается — в блок попадёт один из двух"));
    }
    if ended && sends.iter().any(|x| x.replaces.as_deref() == Some(row.op.as_str()) && x.state == "confirmed") {
        return Some(tr("taken back — the money is yours again", "отозван — деньги снова ваши"));
    }
    None
}

/// K196: the numbers of the payments this wallet made to itself - sent
/// and received under one number. Such a payment has one line, not two.
fn to_self(sends: &[SendRow], incoming: &[IncomingRow]) -> std::collections::BTreeSet<String> {
    sends.iter().filter(|s| !s.slate_id.is_empty() && incoming.iter().any(|i| i.slate_id == s.slate_id)).map(|s| s.slate_id.clone()).collect()
}

/// An incoming payment as the wallet lists it.
#[derive(Clone, Debug, Default)]
struct IncomingRow {
    value: u64,
    abandoned: bool,
    session_expired: bool,
    signature_unknown: bool,
    status: String,
    slate_id: String,
    /// The block its kernel was seen in.
    kernel_height: Option<u64>,
    /// The reply made to it is kept by the wallet.
    reply_kept: bool,
    /// K200: the sender's text is kept by the wallet.
    request_kept: bool,
    /// The block the wallet stood at when it was answered.
    made: Option<u64>,
}

/// Money of the wallet's own that came with no record of a payment (K194):
/// taken by unattended receive, by another copy of the wallet, or found by
/// the search for old money.
#[derive(Clone, Debug, Default)]
struct FoundRow {
    value: u64,
    /// The block it is in; found by the search, a block by which it was there.
    height: u64,
    by_search: bool,
    coinbase: bool,
}

/// One unspent output of the wallet, as the wallet lists it (K195).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OutRow {
    commit: String,
    value: u64,
    height: u64,
    /// "spendable", "reserved" or "immature".
    state: String,
    kept: bool,
}

/// What holds an output back from being spent, in words (O51); nothing
/// when it can be spent.
fn out_state(state: &str) -> &'static str {
    match state {
        "spendable" => "",
        "reserved" => tr("held by a payment under way", "занят платежом в пути"),
        "immature" => tr("a block reward that cannot be spent yet", "награда за блок, тратить ещё нельзя"),
        _ => tr("cannot be spent now", "сейчас тратить нельзя"),
    }
}

/// What is asked of the wallet when the owner chose the outputs for a
/// payment (O51, K195): exactly those, and the owner's separate word only
/// when a marked one is among them and the word was given. Refused here,
/// before the wallet is asked, when a marked one is chosen without it.
fn chosen_params(outputs: &[OutRow], picked: &std::collections::BTreeSet<String>, spend_kept: bool) -> Result<Option<(Vec<String>, bool)>, &'static str> {
    // only what the wallet still lists counts: an output spent meanwhile is not asked for
    let chosen: Vec<&OutRow> = outputs.iter().filter(|o| picked.contains(&o.commit)).collect();
    if chosen.is_empty() {
        return Ok(None);
    }
    let marked = chosen.iter().any(|o| o.kept);
    if marked && !spend_kept {
        return Err(tr("One of the chosen outputs is marked “not to be spent”: confirm below that it is spent in this payment, or take it out of the choice", "Один из выбранных выходов помечен «не тратить»: подтвердите ниже, что он тратится в этом платеже, или уберите его из выбора"));
    }
    Ok(Some((chosen.iter().map(|o| o.commit.clone()).collect(), marked)))
}

/// What is said of such money (O49): how deep it lies, as for an incoming
/// payment, and that no payment record stands for it; found by the search,
/// by which block it was in the chain.
fn found_words(row: &FoundRow, tip: Option<u64>, k_conf: u64, catching_up: bool) -> (String, i32) {
    if row.by_search {
        return (fill(tr("found by the search for old money · in the chain by block {}", "найдено поиском давних денег · в цепи к блоку {}"), &[&crate::sync::spaced(row.height)]), 1);
    }
    let kind = if row.coinbase { tr("a block reward", "награда за блок") } else { tr("no payment record", "без записи о платеже") };
    if catching_up {
        return (fill(tr("in a block · the wallet is catching up with the tip · {}", "в блоке · кошелёк догоняет вершину · {}"), &[kind]), 0);
    }
    match confirmations(Some(row.height), tip) {
        Some(have) if have >= k_conf.max(1) => (fill(tr("received · confirmations: {} · {}", "получено · подтверждений: {} · {}"), &[&crate::sync::spaced(have), kind]), 1),
        Some(have) => (fill(tr("in a block · confirmations: {} of {} · {}", "в блоке · подтверждений: {} из {} · {}"), &[&crate::sync::spaced(have), &crate::sync::spaced(k_conf.max(1)), kind]), 2),
        None => (fill(tr("in a block · {}", "в блоке · {}"), &[kind]), 2),
    }
}

/// Whether the owner hid an operation in this window (O50): one that
/// stands at or below the block the history was hidden through. What is
/// still under way stands above every block and so is never hidden; with
/// no such block nothing is.
fn hidden(time: u64, through: u64) -> bool {
    through != 0 && time <= through
}

/// Where an operation stands in time among the others (O49): the block it
/// is in; one that is in no block yet but still under way stands above
/// everything; one that ended without a block stands where it was made.
fn op_time(in_block: Option<u64>, made: Option<u64>, under_way: bool) -> u64 {
    match (in_block, under_way) {
        (Some(height), _) => height,
        (None, true) => u64::MAX,
        (None, false) => made.unwrap_or(0),
    }
}

/// How many confirmations a payment seen in block `kernel` has when the
/// wallet stands at block `tip`: the block it is in counts as the first.
fn confirmations(kernel: Option<u64>, tip: Option<u64>) -> Option<u64> {
    let (kernel, tip) = (kernel?, tip?);
    Some(tip.checked_sub(kernel)?.saturating_add(1))
}

/// The line under an incoming payment (K190): the word the wallet gives
/// it, and how many confirmations it has of how many it needs.
///
/// While the wallet is catching up with the tip it vouches for no status,
/// and a payment that is in a block is not said to be unconfirmed (O44):
/// the line says where it is and that the wallet is catching up.
fn incoming_words(row: &IncomingRow, tip: Option<u64>, k_conf: u64, catching_up: bool) -> (String, i32) {
    if row.signature_unknown && row.kernel_height.is_none() {
        return (tr("Check this invoice. Its signing result is unknown.", "Требуется проверка счёта. Исход подписи неизвестен.").into(), 2);
    }
    if row.abandoned {
        return (tr("abandoned", "брошен").into(), 0);
    }
    if row.session_expired && row.kernel_height.is_none() {
        return (tr("Invoice session ended. Check the payment before issuing a new invoice.", "Сеанс счёта завершён. Проверьте платёж, прежде чем выставить новый счёт.").into(), 2);
    }
    if catching_up && row.status != "confirmed" && row.kernel_height.is_some() {
        return (tr("in a block · the wallet is catching up with the tip", "в блоке · кошелёк догоняет вершину").into(), 0);
    }
    let have = confirmations(row.kernel_height, tip);
    match (row.status.as_str(), have) {
        ("confirmed", Some(have)) => (fill(tr("received · confirmations: {}", "получено · подтверждений: {}"), &[&crate::sync::spaced(have)]), 1),
        ("confirmed", None) => (tr("received", "получено").into(), 1),
        ("preliminary", Some(have)) if k_conf > 0 => (fill(tr("in a block · confirmations: {} of {}", "в блоке · подтверждений: {} из {}"), &[&crate::sync::spaced(have), &crate::sync::spaced(k_conf)]), 2),
        ("preliminary", _) => (tr("preliminary", "предварительно").into(), 2),
        _ => (tr("not in a block yet", "ещё не в блоке").into(), 2),
    }
}

/// What a payment waits for from the user, if anything. Every payment that
/// holds money in reserve without a signature has a line with a way out of
/// it: nothing prepared is left without one.
fn wait_of(row: &SendRow) -> Option<Wait> {
    if row.state != "prepared" {
        return None;
    }
    Some(if row.locked || row.session_expired {
        Wait::Locked { op: row.op.clone(), amount: row.amount, session_expired: row.session_expired }
    } else if row.held {
        Wait::Sign(row.op.clone())
    } else if row.to.is_some() {
        Wait::Sent(row.op.clone())
    } else {
        Wait::Reply(row.op.clone())
    })
}

/// What the wallet is asked to send a signed payment to the network again:
/// plainly, or with the owner's agreement to the direct way for this one
/// payment (K192). The agreement is said only when it was given.
fn resend_params(op: &str, direct: bool) -> Value {
    if direct {
        json!({ "op": op, "direct": true })
    } else {
        json!({ "op": op })
    }
}

/// What the wallet is asked to let a payment go: an ordinary cancel, or -
/// for a payment locked after a rollback, and only after the user was told
/// what that means - the release of its reserve.
fn cancel_params(op: &str, release_locked: bool) -> Value {
    if release_locked {
        json!({ "op": op, "release_locked": true })
    } else {
        json!({ "op": op })
    }
}

/// The payment the signing window is about.
#[derive(Clone)]
struct SendFlow {
    op: String,
    /// The reply came through the transport and is held by the wallet.
    held: bool,
    /// The recipient's text, for a manual payment.
    s2: Option<String>,
    /// The slate id of the payment, to tell its reply from another.
    slate_id: Option<String>,
}

/// The incoming payment the receiving window is about.
#[derive(Clone)]
struct ReceiveFlow {
    slate: String,
    /// The transport message, when it came through the transport.
    id: Option<String>,
}

/// The invoice the paying window is about: its text, and the numbers the
/// wallet gave and the window showed. Paying holds the wallet to them.
#[derive(Clone)]
struct InvoiceFlow {
    slate: String,
    amount: u64,
    fee: u64,
}

#[derive(Default)]
struct Flow {
    client: Option<Arc<Client>>,
    refresh: RefreshState,
    open_after_refresh: bool,
    lock_unconfirmed: bool,
    testnet: Option<bool>,
    /// The words of a wallet just made, until the user typed three back.
    phrase: Zeroizing<String>,
    ask: [usize; 3],
    contacts: Vec<ContactRec>,
    waits: Vec<Wait>,
    incoming: Vec<Incoming>,
    my_address: String,
    send: Option<SendFlow>,
    receive: Option<ReceiveFlow>,
    invoice: Option<InvoiceFlow>,
    /// Who each payment of this session went to, as the window named them.
    op_to: HashMap<String, (String, Option<String>)>,
    /// The locked payment the release window is about.
    release: Option<String>,
    /// O64: the invoice made here whose text is shown and whose answer is waited for.
    issued: Option<String>,
    /// O64: the contact being changed in the contact window.
    edit_key: Option<String>,
    spendable: u64,
    /// What each line of "All payments" can show again, in the order shown.
    op_rows: Vec<OpRef>,
    /// Replies to incoming payments made in this run of the window, by slate id.
    replies: HashMap<String, String>,
    /// The troubles seen since the wallet was opened.
    journal: crate::sync::Journal,
    /// A change of auto-receive was asked and not answered yet.
    auto_pending: bool,
    /// The wallet has a Tor process for payments to an address.
    onion: bool,
    /// The files last offered by "From a file", in the order shown.
    file_list: Vec<std::path::PathBuf>,
    /// The payment that went over Tor from the text window that is still
    /// open: its outcome is shown there, not only in the lists.
    tor_wait: Option<String>,
    /// K200: the incoming payments whose sender's text the wallet keeps.
    requests: std::collections::BTreeSet<String>,
    /// K200: the incoming payment whose reply is shown, when its sender's text can be shown too.
    request_of: Option<String>,
    /// O67: the block of the starting point made in this opening, if one was.
    point_made: Option<String>,
    /// K198: the payments the owner agreed to send directly, by the wallet's last history.
    direct_ops: std::collections::BTreeSet<String>,
    /// The wallet's outputs as last listed, and those chosen for the
    /// payment that is being prepared (O51).
    outputs: Vec<OutRow>,
    picked: std::collections::BTreeSet<String>,
    /// The block the wallet stood at when its history was last read.
    history_tip: Option<u64>,
    /// When this wallet was opened, and how many seconds later it first
    /// stood at the tip with its money found (O47).
    opened_at: Option<Instant>,
    synced_after: Option<u64>,
    /// The contact whose conversation is open (key, hex).
    chat: Option<String>,
    /// O75: per contact key, how many messages the owner has seen in this
    /// unlock: what came after that is new. Kept in memory only.
    seen: std::collections::BTreeMap<String, u64>,
    /// O75: per contact key, the payments to it, for its conversation.
    plaques: std::collections::BTreeMap<String, Vec<Plaque>>,
    /// How the wallet process is started: the program and its arguments
    /// without `--chain-direct-post`.
    program: std::path::PathBuf,
    base_args: Vec<String>,
    /// The owner switched a part on or off in an open wallet (O42): once
    /// the wallet is locked its process is started anew without that part.
    restart_after_lock: bool,
    /// The signed payment whose text is open and can be sent to the network again.
    resend: Option<String>,
    /// For that start: where the wallet process's notifications go.
    notes: Option<Arc<Mutex<VecDeque<Value>>>>,
    /// The profile folder, if the arguments name one.
    profile: Option<std::path::PathBuf>,
    /// the program for Tor bridges stands next to the wallet's programs
    tor_program: bool,
    /// O71: the wallet is trying the built-in Tor bridges, and since when
    /// the way of the moment.
    bridge_try: Option<(crate::tor::Try, Instant)>,
    /// How many times the message program has been started, as last read.
    transport_starts: u64,
}

thread_local! {
    static FLOW: RefCell<Flow> = RefCell::new(Flow::default());
}

fn with<T>(f: impl FnOnce(&mut Flow) -> T) -> T {
    FLOW.with(|flow| f(&mut flow.borrow_mut()))
}

fn client() -> Option<Arc<Client>> {
    with(|f| f.client.clone())
}

thread_local! {
    static SESSION: RefCell<Arc<()>> = RefCell::new(Arc::new(()));
}

// Both capture and dispatch run on the UI thread. A queued callback holds
// its old token alive, so a replacement session cannot reuse its identity.
fn scoped_callback<T>(show: impl FnOnce(T) + Send) -> impl FnOnce(T) + Send {
    let session = SESSION.with(|s| s.borrow().clone());
    move |result| {
        if SESSION.with(|s| Arc::ptr_eq(&session, &s.borrow())) {
            show(result);
        }
    }
}

fn enter_after_lock<T, E>(
    retry: bool,
    lock: impl FnOnce() -> Result<(), E>,
    unlock: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    if retry {
        lock()?;
    }
    unlock()
}

fn end_session() {
    SESSION.with(|s| *s.borrow_mut() = Arc::new(()));
    // the next opening is timed anew
    FLOW.with(|flow| {
        if let Ok(mut f) = flow.try_borrow_mut() {
            f.opened_at = None;
            f.synced_after = None;
            f.refresh = RefreshState::Idle;
            f.open_after_refresh = false;
        }
    });
}

/// A stretch of time in words: "45 s", "3 min 12 s", "1 h 02 min".
pub(crate) fn span_words(secs: u64) -> String {
    let (h, m, s) = (secs.checked_div(3600).unwrap_or(0), secs.checked_rem(3600).unwrap_or(0).checked_div(60).unwrap_or(0), secs.checked_rem(60).unwrap_or(0));
    if h > 0 {
        fill(tr("{} h {} min", "{} ч {} мин"), &[&h.to_string(), &format!("{m:02}")])
    } else if m > 0 {
        fill(tr("{} min {} s", "{} мин {} с"), &[&m.to_string(), &format!("{s:02}")])
    } else {
        fill(tr("{} s", "{} с"), &[&s.to_string()])
    }
}

/// What the mark under the buttons adds about time (O47): how long this
/// opening took to reach the tip, once it has; until then how long it has
/// been going. `good`: the mark says "VERIFIED" now. Gives the words and
/// what is to be remembered as the time it took.
pub(crate) fn opening_time(good: bool, since_opened: u64, synced_after: Option<u64>) -> (String, Option<u64>) {
    match (synced_after, good) {
        (Some(took), _) => (fill(tr("from opening to the tip: {}", "от входа до вершины: {}"), &[&span_words(took)]), Some(took)),
        (None, true) => (fill(tr("from opening to the tip: {}", "от входа до вершины: {}"), &[&span_words(since_opened)]), Some(since_opened)),
        (None, false) => (fill(tr("since opening: {}", "с входа прошло: {}"), &[&span_words(since_opened)]), None),
    }
}

#[derive(Default, PartialEq, Eq)]
enum RefreshState {
    #[default]
    Idle,
    Reading,
    ReadAgain,
}

impl RefreshState {
    fn begin(&mut self, after_action: bool) -> bool {
        if *self == Self::Idle {
            *self = Self::Reading;
            return true;
        }
        if after_action {
            *self = Self::ReadAgain;
        }
        false
    }

    fn finish(&mut self) -> bool {
        std::mem::take(self) == Self::Reading
    }
}

/// Runs `work` on a thread of its own and `done` on the window's thread.
fn spawn<T: Send + 'static>(app: &App, work: impl FnOnce() -> T + Send + 'static, done: impl FnOnce(&App, T) + Send + 'static) {
    let weak = app.as_weak();
    let deliver = scoped_callback(move |(app, out)| done(&app, out));
    std::thread::spawn(move || {
        let out = work();
        let _ = weak.upgrade_in_event_loop(move |app| deliver((app, out)));
    });
}

fn nano(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().unwrap_or(0),
        other => other.as_u64().unwrap_or(0),
    }
}

fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks(2)) {
        let s = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Who a payment went to, as far as the window can say: the contact it was
/// sent to by the wallet's own record, else what this window named when it
/// was prepared.
fn payee(f: &Flow, row: &SendRow) -> String {
    row.to
        .as_deref()
        .and_then(|key| contact_name(&f.contacts, key))
        .or_else(|| f.op_to.get(&row.op).map(|(who, _)| who.clone()))
        .unwrap_or_else(|| tr("Payment", "Отправка").into())
}

fn send_state(state: &str, invoice: bool, locked: bool) -> (&'static str, i32) {
    match state {
        // prepared before a rollback: the wallet no longer knows whether it
        // was signed afterwards, and says neither "waiting" nor "cancelled"
        "prepared" if locked => (tr("from before the restore — cannot be signed, the money is reserved", "до восстановления — подписать нельзя, деньги в резерве"), 2),
        "released" => (tr("reserve released manually; a prior signature is still possible", "резерв снят вручную, платёж мог быть подписан ранее"), 2),
        // the transaction of a paid invoice is with whoever issued it: this
        // wallet does not send it anywhere
        "finalized" if invoice => (tr("signed — whoever issued the invoice sends it to the network", "подписан — в сеть его отправляет тот, кто выставил счёт"), 2),
        "prepared" => (tr("prepared, waiting for the reply", "подготовлен, ждёт ответа"), 2),
        "cancelled" => (tr("cancelled", "отменён"), 0),
        "unknown" => (tr("Check this payment. Signing may have completed.", "Требуется проверка операции. Подпись могла состояться."), 2),
        "finalized" => (tr("signed, going to the network", "подписан, уходит в сеть"), 2),
        "confirmed" => (tr("in a block", "в блоке"), 0),
        "contested" => (tr("contested — check it", "спорный — проверьте"), 2),
        "dead" => (tr("failed", "не прошёл"), 2),
        _ => (tr("state unknown", "состояние неизвестно"), 2),
    }
}

fn outgoing_words(row: &SendRow) -> (&'static str, i32) {
    if row.state == "prepared" && row.session_expired {
        return (tr("Signing session ended. Check this payment before starting a new Slatepack.", "Сеанс подписи завершён. Проверьте платёж перед новым обменом Slatepack."), 2);
    }
    send_state(&row.state, row.invoice, row.locked)
}

/// What a failed call means to a person. The core's names are stable
/// (`bridge/README.md`); its English reasons are never shown.
fn say(err: &CallError) -> String {
    match err {
        CallError::Rpc { name, message, .. } => match name.as_str() {
            "wrong_password" => tr("Wrong password", "Пароль не подошёл").into(),
            "wrong_words" => tr("The words do not match this wallet's. Nothing was deleted.", "Слова не совпали со словами этого кошелька. Ничего не удалено.").into(),
            "no_profile" => tr("There is no wallet in this folder", "В этом каталоге нет кошелька").into(),
            "profile_exists" => tr("There is a wallet here already — a new one is not made over it", "Здесь уже есть кошелёк — поверх него новый не создаётся").into(),
            "already_unlocked" => tr("The wallet is already open", "Кошелёк уже открыт").into(),
            "guard" => tr("The rollback guard does not match this wallet — it must not be opened here", "Защита от отката не совпала с этим кошельком — открывать его здесь нельзя").into(),
            "bad_mnemonic" => tr("The words failed the check: check each word and their order", "Слова не прошли проверку: проверьте каждое слово и их порядок").into(),
            "profile_damaged" | "no_journal" => tr("The wallet's files are damaged", "Файлы кошелька повреждены").into(),
            "profile_io" => profile_io_words(message),
            "locked" => tr("The wallet is locked", "Кошелёк закрыт").into(),
            "busy" => tr("The wallet is busy, try again in a minute", "Кошелёк занят, попробуйте через минуту").into(),
            "insufficient_funds" => tr("Not enough money with the fee", "Не хватает средств с учётом комиссии").into(),
            "bad_slate" => tr("The text failed the check: it is another payment or it is damaged", "Текст не прошёл проверку: это не тот платёж или он повреждён").into(),
            "codec" => tr("This is not Slatepack text this wallet can read", "Это не текст Slatepack, который может прочитать этот кошелёк").into(),
            "refused" => refused(message).into(),
            "not_found" => tr("No such payment", "Такого платежа нет").into(),
            "conflict" => tr("Another reply was already chosen for this payment", "На этот платёж уже выбран другой ответ").into(),
            "unknown_outcome" => tr("The signature may have happened, there is no result. This payment is not signed again — follow it in the payments", "Подпись могла состояться, результата нет. Повторно этот платёж не подписывается — следите за ним в операциях").into(),
            "no_mailbox" => tr("Delivery over Tor is not set up — send by hand", "Доставка через Tor не настроена — отправьте вручную").into(),
            "no_chain" => tr("No connection to the chain", "Нет связи с цепью").into(),
            "no_point" => no_point(message).into(),
            _ => tr("The wallet refused", "Кошелёк отказал").into(),
        },
        CallError::Timeout => tr("The wallet did not answer in time", "Кошелёк не ответил вовремя").into(),
        CallError::Gone => tr("The wallet is not running", "Кошелёк не работает").into(),
    }
}

/// Why no starting point was made (K188, O38). The reason is the chain
/// program's own; it is matched here and never shown as it came.
fn no_point(reason: &str) -> &'static str {
    if reason.contains("only when the tip is confirmed") {
        tr(
            "A point can be made once the wallet stands at the confirmed tip. Wait until synchronisation is over. Nothing was changed.",
            "Точку можно сделать, когда кошелёк стоит у подтверждённой вершины. Дождитесь конца синхронизации. Ничего не изменено.",
        )
    } else if reason.contains("provisional") {
        tr(
            "No point can be made now: the tip is confirmed only with a caveat. Try later. Nothing was changed.",
            "Сейчас точку сделать нельзя: вершина подтверждена с оговоркой. Попробуйте позже. Ничего не изменено.",
        )
    } else if reason.contains("no new starting point can be made yet") {
        tr(
            "A new point would be too close to the one the wallet started from. Try again in about half a day. Nothing was changed.",
            "Новая точка оказалась бы слишком близко к той, с которой кошелёк начал. Попробуйте примерно через полдня. Ничего не изменено.",
        )
    } else if reason.contains("busy") || reason.contains("did not answer") || reason.contains("not running") {
        tr(
            "The network check is busy. Try again in a minute. Nothing was changed.",
            "Проверка сети занята. Попробуйте ещё раз через минуту. Ничего не изменено.",
        )
    } else {
        tr("The point could not be made. Nothing was changed.", "Точку сделать не удалось. Ничего не изменено.")
    }
}

/// Why the wallet will not do something now, where its own reason tells
/// the user what to wait for or do. The reasons are fixed words of the
/// wallet (`CoreError::Refused`); anything else gets the general line.
/// O54: why the wallet's files did not open. A journal held by another
/// process is said as that, with what to do; anything else names the step
/// the wallet process gave - its own words, never a secret.
fn profile_io_words(step: &str) -> String {
    if step.contains("WouldBlock") || step.contains("locked") {
        return tr(
            "The wallet's files are held by another GrinSight process: this wallet is open in another window, or a process of the last run has not ended. Close the other window, or end the processes fly-paycore-host and fly-chain, and open the wallet again.",
            "Файлы кошелька заняты другим процессом GrinSight: кошелёк открыт в другом окне или не завершился процесс прошлого запуска. Закройте другое окно или завершите процессы fly-paycore-host и fly-chain и откройте кошелёк снова.",
        )
        .into();
    }
    let said = tr("The wallet's files could not be read or written", "Не удалось прочитать или записать файлы кошелька");
    let step: String = step.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(120).collect();
    if step.trim().is_empty() {
        said.into()
    } else {
        format!("{said} ({})", step.trim())
    }
}

fn refused(reason: &str) -> &'static str {
    match reason {
        "signing session ended; start a new exchange" => tr("This signing session has ended. Check the original payment before starting a new Slatepack.", "Сеанс подписи завершён. Проверьте исходный платёж перед новым обменом Slatepack."),
        "the search for old outputs is not over" => tr(
            "The wallet is still searching the chain for your old money (see Connection → Search for old money). Sending opens when the search is over: until then the balance is not final.",
            "Кошелёк ещё ищет в цепи ваши давние деньги (см. «Связь» → «Поиск давних денег»). Отправка откроется, когда поиск закончится: до тех пор баланс не окончательный.",
        ),
        "chain state unknown" => tr(
            "The wallet has not taken its first block yet. Wait until the main screen says “Verified”.",
            "Кошелёк ещё не принял первый блок. Дождитесь слова «Проверено» на главном экране.",
        ),
        "a contested operation exists: replace it or confirm this is not a repeat" => tr(
            "An earlier payment is contested: decide about it under “Waiting for you” first.",
            "Один из прежних платежей оспорен: сначала решите, что с ним делать, в «Ждут вас».",
        ),
        "unattended receive is off" => tr("Auto-receive is off", "Автоприём выключен"),
        "the chosen outputs do not cover the amount and its fee" => tr("The chosen outputs do not cover the amount and its fee: choose more, or let the wallet choose", "Выбранных выходов не хватает на сумму и комиссию: выберите ещё или отдайте выбор кошельку"),
        "a chosen output is marked not to be spent" => tr("One of the chosen outputs is marked “not to be spent”", "Один из выбранных выходов помечен «не тратить»"),
        "a chosen output cannot be spent now" => tr("One of the chosen outputs cannot be spent now: it is held by another payment or is not mature yet", "Один из выбранных выходов сейчас тратить нельзя: он занят другим платежом или ещё не созрел"),
        // the reasons a message is not taken (O52): each has its own words
        "the wallet has no transport identity" => tr("This wallet has no message key yet: make it under “Message key” on the main page, then give it to your contact", "У этого кошелька ещё нет ключа для сообщений: создайте его в «Ключ для сообщений» на главной и передайте контакту"),
        "not a contact" | "the recipient is not a contact" => tr("This contact is no longer in the list: add it again", "Этого контакта уже нет в списке: добавьте его заново"),
        "message is not usable" => tr("The message is empty or too long", "Сообщение пустое или слишком длинное"),
        "too many messages are waiting for this contact" => tr("Too many messages to this contact are still waiting to be delivered: wait until they are", "Слишком много сообщений этому контакту ещё ждут доставки: подождите, пока они дойдут"),
        "the transport cannot seal now" => tr("The message could not be sealed for this contact: the message service is not running. Check “Problems”; if Nostr is switched off, switch it on and open the wallet again", "Сообщение не удалось запечатать для этого контакта: служба сообщений не работает. Загляните в «Неполадки»; если Nostr выключен, включите его и откройте кошелёк заново"),
        "only a signed payment that is in no block can be taken back" => tr("This payment can no longer be taken back: it is in a block already, or it was never signed", "Этот платёж уже не отозвать: он уже в блоке или не был подписан"),
        "this payment is being taken back already" | "this payment is being taken back" => tr("This payment is being taken back already: the wallet does not send it again", "Этот платёж уже отзывается: кошелёк его больше не отправляет"),
        "the payment of an invoice is not taken back" => tr("The payment of an invoice is not taken back", "Оплата счёта не отзывается"),
        "the payment would not pay the fee of taking it back" | "an input of the payment is spent already" => tr("This payment cannot be taken back: its money is spent already or does not cover the fee", "Этот платёж не отозвать: его деньги уже потрачены или их не хватит на комиссию"),
        "the contact has no address to check" => tr("There is nothing to check yet: save the contact's wallet address first", "Сверять пока нечего: сначала сохраните адрес кошелька контакта"),
        "there are not two outputs to collect" => tr("There is nothing to collect: fewer than two outputs can be spent now", "Собирать нечего: сейчас можно потратить меньше двух выходов"),
        "the outputs would not pay the fee of collecting them" => tr("These outputs hold less than the fee of collecting them", "В этих выходах меньше, чем комиссия за их сбор"),
        "a chosen output is not an unspent output of this wallet" => tr("One of the chosen outputs is no longer in the wallet: open the list again", "Одного из выбранных выходов в кошельке уже нет: откройте список заново"),
        _ => tr("The wallet will not do this now: for example, the chain is not verified yet or the payment is closed", "Кошелёк сейчас этого не делает: например, цепь ещё не проверена или платёж уже закрыт"),
    }
}

/// [`say`] for a payment to an address through Tor, where a refusal has a
/// reason worth telling.
fn say_tor(err: &CallError) -> String {
    match err {
        CallError::Rpc { name, message, .. } if name == "refused" => {
            if message.contains("Tor is not ready yet") {
                tr("Tor is still connecting. Try again in a minute or pass the text by hand", "Tor ещё подключается. Попробуйте через минуту или передайте текст вручную").into()
            } else if message.contains("the sender no longer waits") {
                tr("The sender's wallet no longer waits for the answer. Nothing was signed; ask them to send again", "Кошелёк отправителя уже не ждёт ответа. Ничего не подписано; попросите отправить ещё раз").into()
            } else if message.contains("names no address") {
                tr("This payment names no address: it goes by hand", "В этом платеже нет адреса: он передаётся вручную").into()
            } else if message.contains("a reply is already here") {
                tr("The reply is already here — sign the payment under “Waiting for you”", "Ответ уже пришёл — подпишите платёж в «Ждут вас»").into()
            } else {
                say(err)
            }
        }
        CallError::Rpc { name, .. } if name == "no_onion" => tr("Tor for payments to an address is not set up — pass the text by hand", "Tor для платежей на адрес не настроен — передайте текст вручную").into(),
        _ => say(err),
    }
}

/// [`say`] for an invoice, where the same names mean something narrower.
fn say_invoice(err: &CallError) -> String {
    match err {
        CallError::Rpc { name, message, .. } if name == "refused" && message == "signing session ended; start a new exchange" => say(err),
        CallError::Rpc { name, .. } => match name.as_str() {
            "bad_slate" => tr("The invoice failed the check: it is damaged, of a kind this wallet does not pay, or its time has run out", "Счёт не прошёл проверку: он повреждён, такие счета кошелёк не оплачивает или его срок истёк").into(),
            "conflict" => tr("This wallet already prepared a reply to a different invoice with this number", "Кошелёк уже подготовил ответ на другой счёт с тем же номером").into(),
            "refused" => tr("The wallet will not pay now: the chain is not verified yet, a payment is contested, or the fee has changed. Read the invoice again", "Кошелёк сейчас не платит: цепь ещё не проверена, есть спорный платёж или изменилась комиссия. Прочитайте счёт ещё раз").into(),
            "unknown_outcome" => tr("Check the operation before paying again. A signature may already exist.", "Требуется проверка операции. Подпись могла состояться. Проверьте платёж, прежде чем платить снова.").into(),
            _ => say(err),
        },
        _ => say(err),
    }
}

fn amount_error(err: AmountError) -> &'static str {
    match err {
        AmountError::Empty => tr("Type an amount", "Впишите сумму"),
        AmountError::Characters => tr("Only digits and one point or comma in an amount", "В сумме только цифры и одна точка или запятая"),
        AmountError::TooPrecise => tr("No more than nine digits after the point", "Не больше девяти знаков после точки"),
        AmountError::TooLarge => tr("Too large an amount", "Слишком большая сумма"),
        AmountError::Zero => tr("The amount must be more than zero", "Сумма должна быть больше нуля"),
    }
}

// ----- what the main screen shows

/// One message as the host gave it: from the wallet, time, words, state.
type Said = (bool, u64, String, String);

/// What the screens show, gathered off the window's thread.
#[derive(Default)]
struct View {
    /// Where the wallet process keeps the rollback guards, as it says.
    guard_dir: String,
    testnet: Option<bool>,
    balance: Option<(u64, u64, u64, bool)>,
    address: Option<String>,
    npub: Option<String>,
    /// What the synchronisation block and the list of troubles are made of.
    sync: crate::sync::Facts,
    transport_line: String,
    transport_ready: bool,
    sends: Vec<SendRow>,
    /// Amount, abandoned, status, slate id.
    incoming: Vec<IncomingRow>,
    /// Own money that came with no record of a payment.
    found: Vec<FoundRow>,
    /// The wallet's unspent outputs (K195), and what is marked "not to be spent".
    outputs: Vec<OutRow>,
    kept: u64,
    /// Confirmations after which an incoming payment is "received", as the wallet goes by.
    k_conf: u64,
    /// The wallet's block when the payments were listed.
    history_tip: Option<u64>,
    contacts: Vec<ContactRec>,
    auto_on: Option<bool>,
    /// Payments that arrived at the wallet's address through Tor and wait
    /// for a yes or a no: the name the window gives each, and its text.
    onion_asks: Vec<(String, String)>,
    /// Payments sent to an address over Tor whose outcome is not a held
    /// reply: the operation, whether it failed, and why.
    onion_sends: Vec<(String, bool, String)>,
    /// Per contact key: messages, newest time, newest from the wallet.
    summaries: Vec<(String, u64, u64, bool)>,
    /// The open conversation: (dir is out, at, text, state).
    chat: Option<(String, Vec<Said>)>,
}

fn network_value(name: Option<&str>) -> Option<bool> {
    match name {
        Some("main") => Some(false),
        Some("test") => Some(true),
        _ => None,
    }
}

fn view_address(key: Option<[u8; 32]>, testnet: Option<bool>) -> Option<String> {
    Some(address_of_key(&key?, testnet?))
}

/// `known`: the network this session already learned from the host, kept
/// when one status answer is missing (a timeout must not blank or flip the
/// addresses); a status answer that names the network always wins.
fn gather(client: &Client, chat: Option<String>, known: Option<bool>) -> View {
    gather_from(chat, known, |method, params| client.call(method, params, QUICK))
}

fn gather_from(
    chat: Option<String>,
    known: Option<bool>,
    mut call: impl FnMut(&str, Value) -> Result<Value, CallError>,
) -> View {
    let mut view = View { testnet: known, ..View::default() };
    view.sync.tor_off = crate::tor_off();
    view.sync.nostr_off = crate::nostr_off();
    if let Ok(info) = call("paycore.info", json!({})) {
        view.auto_on = match info.get("auto_receive_since") {
            Some(Value::Null) => Some(false),
            Some(value) if value.as_u64().is_some() => Some(true),
            _ => None,
        };
    }
    if let Ok(sum) = call("paycore.messages.summary", json!({})) {
        for c in sum.get("conversations").and_then(Value::as_array).into_iter().flatten() {
            view.summaries.push((
                text(c, "key").unwrap_or_default(),
                c.get("count").and_then(Value::as_u64).unwrap_or(0),
                c.get("last_at").and_then(Value::as_u64).unwrap_or(0),
                text(c, "last_dir").as_deref() == Some("out"),
            ));
        }
    }
    if let Some(key) = chat {
        if let Ok(list) = call("paycore.messages.list", json!({ "key": key })) {
            view.chat = Some((key, apart::said(&list)));
        }
    }
    if let Ok(status) = call("host.status", json!({})) {
        let part = |name: &str| {
            let p = status.get(name);
            let word = |key: &str| p.and_then(|p| p.get(key)).and_then(Value::as_str).map(|s| foreign_line(s, 160).text).unwrap_or_default();
            crate::sync::Part {
                configured: p.and_then(|p| p.get("configured")).and_then(Value::as_bool).unwrap_or(false),
                phase: word("phase"),
                error: word("error"),
                problem: word("problem"),
                starts: p.and_then(|p| p.get("starts")).and_then(Value::as_u64).unwrap_or(0),
            }
        };
        view.sync.answered = true;
        view.guard_dir = status.get("guard_dir").and_then(Value::as_str).map(str::to_string).unwrap_or_default();
        view.sync.chain = part("chain");
        // the chain process describes its whole state: room for all of it
        view.sync.chain.problem = status.get("chain").and_then(|c| c.get("problem")).and_then(Value::as_str).map(|s| foreign_line(s, 700).text).unwrap_or_default();
        view.sync.transport = part("transport");
        view.sync.onion.configured = status.get("onion").and_then(|o| o.get("configured")).and_then(Value::as_bool).unwrap_or(false);
        view.testnet = network_value(status.get("network").and_then(Value::as_str)).or(known);
        let transport = status.get("transport");
        let phase = |part: Option<&Value>| part.and_then(|p| p.get("phase")).and_then(Value::as_str).unwrap_or("none").to_string();
        let configured = transport.and_then(|t| t.get("configured")).and_then(Value::as_bool).unwrap_or(false);
        view.transport_line = if !configured {
            tr("Message delivery is not set up — payments go by hand (Slatepack)", "Доставка сообщений не настроена — платежи передаются вручную (Slatepack)").into()
        } else {
            view.transport_ready = phase(transport) == "ready";
            match phase(transport).as_str() {
                "ready" => tr("Messages go over Tor", "Сообщения идут через Tor").into(),
                "starting" => tr("Message delivery is starting", "Связь для сообщений поднимается").into(),
                _ => tr("Message delivery does not work — see the log", "Связь для сообщений не работает — посмотрите журнал").into(),
            }
        };
    }
    if view.sync.onion.configured {
        if let Ok(onion) = call("paycore.onion.status", json!({})) {
            view.sync.onion.phase = text(&onion, "phase").unwrap_or_default();
            // the words are the Tor process's and may quote another wallet
            view.sync.onion.problem = text(&onion, "problem").map(|s| foreign_line(&s, 160).text).unwrap_or_default();
            for send in onion.get("sends").and_then(Value::as_array).into_iter().flatten() {
                let failed = text(send, "state").as_deref() == Some("failed");
                let why = text(send, "reason").map(|s| tor_reason(&foreign_line(&s, 200).text)).unwrap_or_default();
                if failed {
                    view.sync.onion_failed.push(why.clone());
                }
                view.onion_sends.push((text(send, "op").unwrap_or_default(), failed, why));
            }
            for ask in onion.get("asks").and_then(Value::as_array).into_iter().flatten() {
                if let (Some(id), Some(slate)) = (ask.get("id").and_then(Value::as_u64), text(ask, "slate")) {
                    view.onion_asks.push((format!("{TOR_ASK}{id}"), slate));
                }
            }
        }
    }
    if let Ok(a) = call("paycore.address", json!({})) {
        view.address = view_address(a.get("address").and_then(Value::as_str).and_then(hex32), view.testnet);
    }
    if let Ok(id) = call("paycore.identity.get", json!({})) {
        view.npub = text(&id, "npub");
    }
    if let Ok(c) = call("paycore.wallet.chain_status", json!({})) {
        // The wallet serializes one RPC with its sync rounds. A second
        // balance request can cross a block, a rollback or a reservation.
        view.balance = c.get("balance").and_then(|b| {
            let amount = |name: &str| b.get(name)?.as_str()?.parse::<u64>().ok();
            Some((amount("spendable")?, amount("reserved")?, amount("immature")?, b.get("incomplete")?.as_bool()?))
        });
        view.kept = c.get("balance").and_then(|b| b.get("kept")?.as_str()?.parse::<u64>().ok()).unwrap_or(0);
        view.sync.state = text(&c, "state");
        view.sync.status_answered = view.sync.state.is_some();
        view.sync.confirmed_time = c.get("confirmed_time").and_then(Value::as_u64);
        view.sync.k_conf = c.get("k_conf").and_then(Value::as_u64);
        view.sync.wallet_height = c.get("tip_height").and_then(Value::as_u64);
        view.sync.selected_height = c.get("selected_height").and_then(Value::as_u64)
            .filter(|_| view.sync.confirmed_time.is_some());
        // Incomplete or older replies cannot authorize a positive badge.
        if view.sync.state.as_deref() == Some("at_tip") && (view.sync.selected_height.is_none()
            || view.sync.wallet_height != view.sync.selected_height) {
            view.sync.state = Some("behind".into());
        }
    }
    if let Ok(s) = call("paycore.search.status", json!({})) {
        let count = |key: &str| s.get(key).and_then(Value::as_u64);
        view.sync.search = text(&s, "state").map(|state| crate::sync::Search {
            state,
            next: count("next"),
            pieces: count("pieces").unwrap_or(0),
            found: count("found").unwrap_or(0),
            gone: count("gone").unwrap_or(0),
        });
    }
    // K190: the owner's number of confirmations for "received" is told to
    // the wallet whenever the wallet goes by another one
    let mut history = call("paycore.history", json!({}));
    let wanted = crate::confirmations();
    if let (Ok(h), true) = (&history, wanted != 0) {
        if h.get("k_conf").and_then(Value::as_u64) != Some(wanted) && call("paycore.settings.confirmations", json!({ "count": wanted })).is_ok() {
            history = call("paycore.history", json!({}));
        }
    }
    if let Ok(h) = history {
        view.k_conf = h.get("k_conf").and_then(Value::as_u64).unwrap_or(0);
        view.history_tip = h.get("tip_height").and_then(Value::as_u64);
        for send in h.get("sends").and_then(Value::as_array).into_iter().flatten() {
            view.sends.push(SendRow {
                op: text(send, "op").unwrap_or_default(),
                state: text(send, "state").unwrap_or_default(),
                amount: nano(field(send, "amount")),
                fee: nano(field(send, "fee")),
                held: send.get("reply_held").and_then(Value::as_bool) == Some(true),
                invoice: send.get("invoice").and_then(Value::as_bool) == Some(true),
                locked: send.get("locked").and_then(Value::as_bool) == Some(true),
                session_expired: send.get("session_expired").and_then(Value::as_bool) == Some(true),
                to: text(send, "deliver_to"),
                kernel_height: send.get("kernel_height").and_then(Value::as_u64),
                signed: send.get("signed").and_then(Value::as_bool) == Some(true),
                made: send.get("made_height").and_then(Value::as_u64),
                slate_id: text(send, "slate_id").unwrap_or_default(),
                replaces: text(send, "replaces"),
                replaced_by: text(send, "replaced_by"),
                direct: send.get("direct").and_then(Value::as_bool) == Some(true),
            });
        }
        // K196: the owner's word about small outputs is told to the wallet
        // whenever the wallet goes by another one (it keeps it in memory)
        if h.get("gather").and_then(Value::as_bool).is_some_and(|told| told != crate::gather()) {
            let _ = call("paycore.settings.gather", json!({ "on": crate::gather() }));
        }
        for inc in h.get("incoming").and_then(Value::as_array).into_iter().flatten() {
            view.incoming.push(IncomingRow {
                value: nano(field(inc, "amount")),
                abandoned: inc.get("abandoned").and_then(Value::as_bool).unwrap_or(false),
                session_expired: inc.get("session_expired").and_then(Value::as_bool) == Some(true),
                signature_unknown: inc.get("signature_unknown").and_then(Value::as_bool) == Some(true),
                status: text(inc, "status").unwrap_or_default(),
                slate_id: text(inc, "slate_id").unwrap_or_default(),
                kernel_height: inc.get("kernel_height").and_then(Value::as_u64),
                reply_kept: inc.get("reply_kept").and_then(Value::as_bool) == Some(true),
                request_kept: inc.get("request_kept").and_then(Value::as_bool) == Some(true),
                made: inc.get("made_height").and_then(Value::as_u64),
            });
        }
        if let Ok(o) = call("paycore.outputs.list", json!({})) {
            for out in o.get("outputs").and_then(Value::as_array).into_iter().flatten() {
                view.outputs.push(OutRow {
                    commit: text(out, "commit").unwrap_or_default(),
                    value: nano(field(out, "amount")),
                    height: out.get("height").and_then(Value::as_u64).unwrap_or(0),
                    state: text(out, "state").unwrap_or_default(),
                    kept: out.get("kept").and_then(Value::as_bool) == Some(true),
                });
            }
        }
        for found in h.get("found").and_then(Value::as_array).into_iter().flatten() {
            view.found.push(FoundRow {
                value: nano(field(found, "amount")),
                height: found.get("height").and_then(Value::as_u64).unwrap_or(0),
                by_search: found.get("by_search").and_then(Value::as_bool) == Some(true),
                coinbase: found.get("coinbase").and_then(Value::as_bool) == Some(true),
            });
        }
    }
    if let Ok(c) = call("paycore.contacts.list", json!({})) {
        for contact in c.get("contacts").and_then(Value::as_array).into_iter().flatten() {
            let raw_name = text(contact, "name").unwrap_or_default();
            view.contacts.push(ContactRec {
                key: text(contact, "key").unwrap_or_default(),
                shown: foreign_line(&raw_name, NAME_CHARS).text,
                raw_name,
                address: view_address(text(contact, "address").as_deref().and_then(hex32), view.testnet),
                checked: contact.get("checked").and_then(Value::as_bool) == Some(true),
            });
        }
    }
    view
}

#[cfg(test)]
pub(crate) fn auto_receive_fixture(app: &App, info: Option<Value>) {
    let view = gather_from(None, None, |method, _| match (method, &info) {
        ("paycore.info", Some(info)) => Ok(info.clone()),
        _ => Err(CallError::Timeout),
    });
    apply(app, view);
}

#[cfg(test)]
pub(crate) fn refresh_balance_fixture(app: &App, available: bool) {
    apply(app, View {
        balance: available.then_some((123_000_000_000, 0, 0, false)),
        sync: crate::sync::Facts {
            state: Some("at_tip".into()), wallet_height: Some(10), selected_height: Some(10),
            confirmed_time: Some(1_800_000_000), status_answered: true, ..Default::default()
        },
        ..View::default()
    });
}

fn contact_name(contacts: &[ContactRec], key: &str) -> Option<String> {
    contacts.iter().find(|c| c.key == key).map(|c| c.shown.clone())
}

/// The mark under the buttons: where the wallet stands with the chain,
/// in one word and one line, and whether all is well. "VERIFIED" is said
/// only when the wallet is at the tip and its money is found: while the
/// search for old outputs runs the amount can still grow and the wallet
/// does not send, and the mark says that instead.
pub(crate) fn chain_chip(chain: Option<(&str, Option<u64>, Option<u64>)>, configured: bool, searching: bool) -> (&'static str, bool, String) {
    let block = |n: Option<u64>| n.map_or("—".to_string(), |n| n.to_string());
    match chain {
        Some(("at_tip", tip, _)) if searching => (
            tr("SEARCHING", "ИДЁТ ПОИСК"),
            false,
            fill(tr("the chain is checked to block {} · your old money is still being looked for: the amount can grow, sending opens when the search ends", "цепь проверена до блока {} · ваши давние деньги ещё ищутся: сумма может вырасти, отправка откроется, когда поиск закончится"), &[&block(tip)]),
        ),
        Some(("at_tip", tip, _)) => (tr("VERIFIED", "ПРОВЕРЕНО"), true, fill(tr("Your wallet is ready to use. Public nodes verified the tip at block {}.", "Кошельком можно пользоваться. Публичные ноды подтвердили вершину на блоке {}."), &[&block(tip)])),
        // behind, and the tip to catch up with is not chosen yet
        Some(("behind", tip, None)) => (
            tr("CATCHING UP", "ДОГОНЯЕТ"),
            false,
            fill(tr("the wallet is at block {} · the tip is not chosen yet: waiting for the network check and public nodes. Sending opens at the tip", "кошелёк на блоке {} · вершина ещё не выбрана: ждём проверку сети и публичные ноды. Отправка откроется на вершине"), &[&block(tip)]),
        ),
        Some(("behind", tip, Some(selected))) => (
            tr("CATCHING UP", "ДОГОНЯЕТ"),
            false,
            fill(tr("the wallet is at block {} of {} · {} to go. Sending opens at the tip", "кошелёк на блоке {} из {} · осталось {}. Отправка откроется на вершине"), &[&block(tip), &selected.to_string(), &selected.saturating_sub(tip.unwrap_or(0)).to_string()]),
        ),
        Some(_) if !configured => (tr("NO CHAIN", "НЕТ ЦЕПИ"), false, tr("the part that checks the network is missing: nothing is known about the chain", "нет части программы, которая проверяет сеть: о цепи ничего не известно").into()),
        Some(_) => (tr("CHECKING", "ПРОВЕРЯЕТСЯ"), false, tr("the chain is still being checked", "цепь ещё проверяется").into()),
        None => (tr("NO DATA", "НЕТ ДАННЫХ"), false, tr("the wallet said nothing about the chain", "кошелёк не ответил о цепи").into()),
    }
}

/// The line under the amount for money that is held: reserved by a
/// payment under way (its change comes back when the payment is in a
/// block, all of it when the payment is cancelled) or still maturing.
/// Empty when nothing is held.
pub(crate) fn held_line(reserved: u64, immature: u64, kept: u64) -> String {
    let mut parts = Vec::new();
    // what the owner marked is theirs and is not in "Available" (O51)
    if kept > 0 {
        parts.push(fill(tr("{} GRIN marked “not to be spent”", "{} GRIN помечены «не тратить»"), &[&amount(kept)]));
    }
    if reserved > 0 {
        parts.push(fill(tr("{} GRIN held by a payment under way", "{} GRIN заняты платежом в пути"), &[&amount(reserved)]));
    }
    if immature > 0 {
        parts.push(fill(tr("{} GRIN maturing", "{} GRIN созревают"), &[&amount(immature)]));
    }
    parts.join(" · ")
}

/// O60: what the window to sign says when Tor looks unable to send:
/// why, and what the owner can do before signing.
fn sign_doubt_words(why: &str) -> String {
    fill(
        tr(
            "{}. A payment signed now may wait until Tor works again. You can sign and wait; sign and let this one payment go directly — the node then sees the address of your device; switch Tor off for all payments; or not sign yet.",
            "{}. Платёж, подписанный сейчас, может ждать, пока Tor заработает. Можно подписать и ждать; подписать и разрешить этому одному платежу уйти напрямую — тогда нода увидит адрес вашего устройства; выключить Tor для всех платежей; или пока не подписывать.",
        ),
        &[why],
    )
}

/// What is said when a starting point of the wallet's own was made.
fn point_made_words(block: &str) -> String {
    fill(tr("Your own starting point is made: block {}. The wallet starts from it at the next unlock.", "Своя стартовая точка сделана: блок {}. Кошелёк начнёт с неё со следующего входа."), &[block])
}

/// What the window wrote once in the language of the moment, written
/// again after the language was changed: how Tor is reached, and the
/// note about a starting point made in this opening.
pub(crate) fn say_again(app: &App) {
    tor_way(app);
    if let Some(block) = with(|f| f.point_made.clone()) {
        if app.get_point_good() {
            app.set_point_note(point_made_words(&block).into());
        }
    }
}

/// K198: what stands under a signed payment about the direct way: said
/// only while the payment waits, Tor is in use, and the owner agreed.
fn direct_note(waiting: bool, agreed: bool, tor_off: bool) -> &'static str {
    if waiting && agreed && !tor_off {
        tr("You agreed that this payment goes directly when Tor fails to send it. The wallet remembers this for this payment.", "Вы согласились, что этот платёж уйдёт напрямую, если Tor его не отправит. Кошелёк помнит это для этого платежа.")
    } else {
        ""
    }
}

/// O64: completes an invoice this wallet made with the payer's answer:
/// the wallet checks the answer against its invoice and signs its part.
/// `expected`: the invoice whose window is open; an answer to another one
/// is refused there. Without it the answer names its invoice itself.
fn finish_invoice(app: &App, expected: Option<String>, reply: String) {
    let Some(client) = client() else { return };
    if reply.is_empty() {
        return sheet_error(app, tr("Paste the payer's answer", "Вставьте ответ плательщика"));
    }
    app.set_sheet_busy(true);
    app.set_sheet_error(SharedString::new());
    spawn(
        app,
        move || {
            let read = client.call("paycore.slate.read", json!({ "slate": reply }), QUICK)?;
            let id = match invoice_answer(read.get("stage").and_then(Value::as_str), text(&read, "slate_id"), expected.as_deref()) {
                Ok(id) => id,
                Err(why) => return Ok(Err(why)),
            };
            client.call("paycore.invoice.finalize", json!({ "slate_id": id, "slate": reply }), SIGN).map(Ok)
        },
        |app, out: Result<Result<Value, &'static str>, CallError>| match out {
            Ok(Ok(_)) => {
                with(|f| f.issued = None);
                close_sheet(app);
                app.set_wait_note(tr("Transaction signed. Track its submission and confirmations in Payments.", "Транзакция подписана. Отправку и подтверждения можно проверить в операциях.").into());
                refresh(app);
            }
            Ok(Err(why)) => sheet_error(app, why),
            Err(CallError::Rpc { name, .. }) if name == "not_found" => sheet_error(app, tr("This wallet made no such invoice", "Такого счёта этот кошелёк не выставлял")),
            Err(e) => sheet_error(app, say_invoice(&e)),
        },
    );
}

/// O64: which invoice a pasted text answers, or why it is not taken: it
/// has to be a payer's answer, and - where an invoice's window is open -
/// the answer to that invoice.
fn invoice_answer(stage: Option<&str>, id: Option<String>, expected: Option<&str>) -> Result<String, &'static str> {
    if stage != Some("I2") {
        return Err(tr("This is not a payer's answer to an invoice", "Это не ответ плательщика на счёт"));
    }
    let id = id.ok_or(tr("The answer does not name its invoice", "В ответе не назван счёт"))?;
    if expected.is_some_and(|e| e != id) {
        return Err(tr("This answers another invoice", "Это ответ на другой счёт"));
    }
    Ok(id)
}

/// O65: the check code as the window shows it: the wallet's six words in
/// their order, a dash between them. They are the wallet's own words from
/// its own list; anything else is not shown.
fn code_line(answer: &Value) -> String {
    let words: Vec<&str> = answer.get("words").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).filter(|w| !w.is_empty() && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase())).collect();
    if words.len() == 6 {
        words.join(" – ")
    } else {
        String::new()
    }
}

/// O63: deletes contacts, each with its conversation, one after another.
fn remove_contacts(app: &App, keys: Vec<String>) {
    let Some(client) = client() else { return };
    if keys.is_empty() {
        return;
    }
    // a conversation that goes is not left on the screen
    apart::close_keys(&keys);
    if with(|f| f.chat.as_ref().is_some_and(|open| keys.contains(open))) {
        with(|f| f.chat = None);
        app.set_chat_index(-1);
        app.set_chat_lines(model(Vec::new()));
    }
    app.set_sheet_error(SharedString::new());
    spawn(
        app,
        move || {
            for key in keys {
                client.call("paycore.contacts.remove", json!({ "key": key }), QUICK)?;
            }
            Ok::<_, CallError>(())
        },
        |app, out| {
            if let Err(e) = out {
                app.set_sheet_error(say(&e).into());
            }
            refresh(app);
        },
    );
}

/// O63: what the wallet is asked for a list of contacts typed as two
/// columns - message keys one a line, addresses one a line, line to line.
/// Empty lines of keys are passed over together with their address line;
/// an address may be missing. The whole list is checked before anything
/// is asked: a wrong line is named and nothing is added. `taken`: how
/// many contacts there are, for the names "Contact N".
fn contact_list(keys: &str, addresses: &str, testnet: bool, taken: usize) -> Result<Vec<Value>, String> {
    let addresses: Vec<&str> = addresses.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (line, key) in keys.lines().map(str::trim).enumerate() {
        if key.is_empty() {
            continue;
        }
        let at = line.saturating_add(1).to_string();
        if !key.starts_with("npub1") {
            return Err(fill(tr("Line {}: a message key starts with npub1", "Строка {}: ключ для сообщений начинается с npub1"), &[&at]));
        }
        let name = fill(tr("Contact {}", "Контакт {}"), &[&taken.saturating_add(out.len()).saturating_add(1).to_string()]);
        let mut params = json!({ "npub": key, "name": name });
        let typed = addresses.get(line).copied().unwrap_or_default();
        if !typed.is_empty() {
            let key = address(typed).ok().filter(|a| a.testnet == testnet).and_then(|a| key_of_address(&a)).ok_or_else(|| fill(tr("Line {}: the address is broken or of the other network", "Строка {}: адрес с ошибкой или из другой сети"), &[&at]))?;
            if let Some(fields) = params.as_object_mut() {
                fields.insert("address".into(), json!(hex(&key)));
            }
        }
        out.push(params);
    }
    if out.is_empty() {
        return Err(tr("There is no message key in the list", "В списке нет ни одного ключа для сообщений").into());
    }
    if out.len() > 200 {
        return Err(tr("At most 200 contacts at once", "Не больше 200 контактов за раз").into());
    }
    Ok(out)
}

/// K197: what the owner is told before a signed payment is taken back.
fn back_ask_words(returns: u64, fee: u64) -> String {
    fill(
        tr(
            "Take this payment back? The wallet signs a second payment of the same money - to itself: {} GRIN return to you, the fee is {} GRIN more. Only one of the two can be in a block, and it is not sure to be this one: if the first payment has reached the network, or the recipient sends it there, it may get into a block all the same - then the payment stands and only this try is lost. Without a connection it waits like any payment. Until one of them is in a block the payment is shown as “being taken back”, and the wallet stops sending the first one.",
            "Отозвать этот платёж? Кошелёк подпишет второй платёж теми же деньгами — самому себе: к вам вернётся {} GRIN, комиссия — ещё {} GRIN. В блок попадёт только один из двух, и не обязательно этот: если первый платёж уже дошёл до сети или его отправит туда получатель, в блок может попасть он — тогда платёж состоится, а пропадёт только эта попытка. Без связи отзыв ждёт так же, как любой платёж. Пока ни один не в блоке, платёж показан как «отзывается», и первый кошелёк больше не отправляет.",
        ),
        &[&amount(returns), &amount(fee)],
    )
}

/// K196: what the owner is asked before outputs are collected into one.
fn collect_words(count: u64, into: u64, fee: u64) -> String {
    fill(
        tr(
            "Collect {} outputs into one of {} GRIN? The fee is {} GRIN. It is one transaction: whoever looks at the chain sees that these outputs had one owner, and that cannot be taken back. Marked outputs are left alone.",
            "Собрать выходы ({} шт.) в один на {} GRIN? Комиссия {} GRIN. Это одна транзакция: по ней в цепи видно, что у этих выходов был один владелец, и назад этого не вернуть. Помеченные выходы не трогаются.",
        ),
        &[&count.to_string(), &amount(into), &amount(fee)],
    )
}

/// The wallet's outputs on the screen, with the owner's marks and the
/// choice for the payment being prepared (O51).
fn show_outputs(app: &App) {
    let (lines, sum, marked) = with(|f| {
        let lines: Vec<crate::ui::OutLine> = f
            .outputs
            .iter()
            .map(|o| crate::ui::OutLine {
                amount: amount(o.value).into(),
                block: crate::sync::spaced(o.height).into(),
                state: out_state(&o.state).into(),
                free: o.state == "spendable",
                kept: o.kept,
                picked: f.picked.contains(&o.commit),
            })
            .collect();
        let chosen: Vec<&OutRow> = f.outputs.iter().filter(|o| f.picked.contains(&o.commit)).collect();
        let sum = chosen.iter().fold(0u64, |sum, o| sum.saturating_add(o.value));
        (lines, (!chosen.is_empty()).then(|| amount(sum)), chosen.iter().any(|o| o.kept))
    });
    app.set_outs(model(lines));
    app.set_picked_sum(sum.unwrap_or_default().into());
    app.set_picked_kept(marked);
    if !marked {
        // the word is for one payment and one choice: it does not linger
        app.set_spend_kept(false);
    }
}

fn clear_output_choice(app: &App) {
    with(|f| f.picked.clear());
    show_outputs(app);
}

fn show_auto(app: &App, setting: Option<bool>) {
    app.set_auto_known(setting.is_some());
    app.set_auto_on(setting == Some(true));
    app.set_auto_receive(match setting {
        Some(true) => tr("Verified Nostr contacts are accepted automatically. Direct Tor payments require your approval.", "Платежи от подтверждённых контактов Nostr принимаются автоматически. Входящие напрямую по Tor требуют вашего согласия."),
        Some(false) => tr("off: you accept each payment", "выключен: каждый платёж принимаете вы"),
        None => tr("auto-receive status unavailable", "состояние автоприёма неизвестно"),
    }.into());
}

fn apply(app: &App, view: View) {
    tor_step(app, &view);
    app.set_network(match view.testnet { Some(true) => "TESTNET", Some(false) => "MAINNET", None => tr("NETWORK UNKNOWN", "СЕТЬ НЕ ОПРЕДЕЛЕНА") }.into());
    if let Some((spendable, reserved, immature, incomplete)) = view.balance {
        app.set_balance(amount(spendable).into());
        let mut note = fill(tr("spendable · reserved {} · maturing {}", "можно тратить · в резерве {} · созревает {}"), &[&amount(reserved), &amount(immature)]);
        if incomplete {
            note.push_str(tr(" · the search for your money is still running", " · поиск ваших денег ещё идёт"));
        }
        app.set_balance_note(note.into());
        with(|f| f.spendable = spendable);
    } else {
        app.set_balance("—".into());
        app.set_balance_note(tr("Balance unavailable", "Баланс недоступен").into());
        with(|f| f.spendable = 0);
    }
    // money that is the wallet's and cannot be spent now is said in a line of its own
    let held = view.balance.map(|(_, reserved, immature, _)| held_line(reserved, immature, view.kept)).unwrap_or_default();
    let changed = with(|f| {
        let before = f.picked.len();
        // what is gone or held meanwhile is not chosen any more
        f.picked.retain(|commit| view.outputs.iter().any(|o| &o.commit == commit && o.state == "spendable"));
        let marks_changed = view.outputs.iter().any(|o| {
            f.picked.contains(&o.commit)
                && !f.outputs.iter().any(|old| old.commit == o.commit && old.kept == o.kept)
        });
        f.outputs = view.outputs.clone();
        f.picked.len() != before || marks_changed
    });
    if changed {
        app.set_spend_kept(false);
    }
    show_outputs(app);
    app.set_incoming(held.into());
    let (groups, full): (Vec<SharedString>, String) = match view.address.as_deref().map(address) {
        Some(Ok(a)) => (a.groups.iter().cloned().map(SharedString::from).collect(), a.full),
        _ => (vec![tr("address unavailable", "адрес недоступен").into()], String::new()),
    };
    app.set_address_groups(model(groups));
    app.set_address_full(full.clone().into());
    app.set_phrase_label(tr("Message key", "Ключ для сообщений").into());
    app.set_identity_made(view.npub.is_some());
    app.set_phrase(view.npub.map(|n| foreign_line(&n, 80).text).unwrap_or_else(|| tr("not made", "не создан").into()).into());
    let searching = matches!(view.balance, Some((_, _, _, true)));
    let chain = view.sync.state.as_deref().map(|state| (state, view.sync.wallet_height, view.sync.selected_height));
    let chain = chain.filter(|(state, _, _)| *state != "at_tip" || view.balance.is_some());
    let (chip, good, line) = chain_chip(chain, view.sync.chain.configured, searching);
    let time = with(|f| {
        let opened = *f.opened_at.get_or_insert_with(Instant::now);
        let (time, took) = opening_time(good, opened.elapsed().as_secs(), f.synced_after);
        f.synced_after = took;
        time
    });
    app.set_verified_chip(chip.into());
    app.set_verified_good(good);
    app.set_verified(format!("{line} · {time}").into());
    app.set_link_good(view.transport_ready);
    let journal = with(|f| {
        f.journal.note(unix_now(), &crate::sync::troubles(&view.sync));
        f.journal.clone()
    });
    crate::show_sync(app, &view.sync, &journal);
    if view.k_conf > 0 {
        app.set_confirmations(i32::try_from(view.k_conf).unwrap_or(i32::MAX));
    }
    app.set_gather(crate::gather());
    app.set_point_hint(crate::sync::point_hint(crate::sync::point_gap(&view.sync)).into());
    // O60: a doubt about Tor is said in the window to sign - unless the
    // owner already agreed that everything goes directly when Tor fails
    let doubt = if crate::direct() { None } else { crate::sync::tor_doubt(&view.sync) };
    app.set_sign_tor_doubt(doubt.map(sign_doubt_words).unwrap_or_default().into());
    // O71: one more way out of that doubt - the built-in bridges, tried by the wallet
    bridges::step(app, &view.sync);
    app.set_sign_bridges_offered(doubt.is_some() && bridges::offered());
    // where the files are (O40): the folder of the profile, and the guards;
    // both are this program's own words and are shown whole, to be copied
    app.set_files_path(own_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default().into());
    app.set_guard_path(view.guard_dir.clone().into());
    // a change that is on its way is not painted over by an older answer
    if !with(|f| f.auto_pending) {
        show_auto(app, view.auto_on);
    }
    let now = unix_now();
    if let Some((key, lines)) = &view.chat {
        let open = with(|f| f.chat.as_deref() == Some(key.as_str()));
        if open {
            let pays = with(|f| f.plaques.get(key).cloned().unwrap_or_default());
            app.set_chat_lines(model(chat_view(lines, &pays, now)));
        }
    }
    // O70: the conversations in windows of their own are read with every reading
    apart::read(app);

    with(|f| {
        f.testnet = view.testnet;
        f.my_address = full;
        f.contacts = view.contacts.clone();
        let mut ops = Vec::new();
        let mut refs: Vec<OpRef> = Vec::new();
        let mut times: Vec<u64> = Vec::new();
        // for the table (O50): the block, the direction, the contact
        let mut extras: Vec<(Option<u64>, bool, String)> = Vec::new();
        let mut waits = Vec::new();
        let unsent = !view.sync.tor_off && crate::sync::not_sent(&view.sync).is_some();
        let own = to_self(&view.sends, &view.incoming);
        for row in &view.sends {
            let (sub, tone) = outgoing_words(row);
            // in a block: how deep it lies by now (K190)
            let sub = match confirmations(row.kernel_height, view.history_tip).filter(|_| row.state == "confirmed") {
                Some(have) => fill(tr("in a block · confirmations: {}", "в блоке · подтверждений: {}"), &[&crate::sync::spaced(have)]),
                None => sub.to_string(),
            };
            // paid to itself: the money stayed, only the fee left (K196)
            let own_one = own.contains(&row.slate_id);
            let sub = back_words(row, &view.sends).map(str::to_string).unwrap_or(sub);
            let who = if own_one && row.replaces.is_some() {
                tr("To yourself: taking a payment back", "Себе: отзыв платежа").into()
            } else if own_one {
                tr("To yourself: outputs collected", "Себе: сбор выходов").into()
            } else if row.invoice {
                tr("Invoice payment", "Оплата счёта").into()
            } else {
                payee(f, row)
            };
            let left = if own_one { row.fee } else { row.amount.saturating_add(row.fee) };
            ops.push(Op { who: who.into(), sub: sub.into(), amount: format!("−{}", amount(left)).into(), tone, show: false });
            times.push(op_time(row.kernel_height, row.made, matches!(row.state.as_str(), "prepared" | "finalized" | "unknown" | "contested")));
            extras.push((row.kernel_height, false, row.to.as_deref().and_then(|key| contact_name(&f.contacts, key)).unwrap_or_default()));
            // the text of a payment that still waits for its reply can be shown again
            // O55: every payment that is not signed can be opened from its
            // line and cancelled there - one sent to a contact too
            refs.push(if row.state == "prepared" && !row.locked && !row.session_expired && !row.invoice {
                OpRef::Send(row.op.clone())
            } else if row.signed {
                // every signed payment keeps its final text (K191)
                let waiting = row.state == "finalized" && !row.invoice;
                // K197: taking back is offered for a payment to someone else that nothing replaces yet
                OpRef::Signed { op: row.op.clone(), waiting, back: waiting && !own_one && row.replaced_by.is_none() }
            } else {
                OpRef::None
            });
            waits.extend(wait_of(row));
            // signed, and the network check says it could not send: the owner is asked
            if unsent && row.state == "finalized" && !row.invoice {
                waits.push(Wait::Unsent(row.op.clone()));
            }
        }
        // O67: a starting point far below the chain - a new one is offered, once it has not been made in this opening
        if let Some(gap) = crate::sync::point_gap(&view.sync).filter(|gap| *gap > crate::sync::POINT_OLD && f.point_made.is_none()) {
            waits.push(Wait::Point(gap));
        }
        f.direct_ops = view.sends.iter().filter(|row| row.direct).map(|row| row.op.clone()).collect();
        f.requests = view.incoming.iter().filter(|row| row.request_kept && !row.abandoned).map(|row| row.slate_id.clone()).collect();
        for row in &view.incoming {
            // its line is the line of the payment (K196)
            if own.contains(&row.slate_id) {
                continue;
            }
            // the reply made to it is kept by the wallet and can be shown again
            refs.push(if !row.abandoned && row.reply_kept { OpRef::Reply(row.slate_id.clone()) } else { OpRef::None });
            let (label, tone) = incoming_words(row, view.history_tip, view.k_conf, view.sync.state.as_deref() != Some("at_tip"));
            ops.push(Op {
                who: tr("Incoming", "Входящий").into(),
                sub: label.into(),
                amount: format!("+{}", amount(row.value)).into(),
                tone,
                show: false,
            });
            times.push(op_time(row.kernel_height, row.made, !row.abandoned));
            extras.push((row.kernel_height, true, String::new()));
        }
        // money that came with no record of a payment has its line too (K194)
        for row in &view.found {
            refs.push(OpRef::None);
            let (label, tone) = found_words(row, view.history_tip, view.k_conf, view.sync.state.as_deref() != Some("at_tip"));
            ops.push(Op { who: tr("Incoming", "Входящий").into(), sub: label.into(), amount: format!("+{}", amount(row.value)).into(), tone, show: false });
            times.push(op_time(Some(row.height), None, false));
            extras.push((Some(row.height), true, String::new()));
        }
        f.history_tip = view.history_tip;
        // the newest on top, whatever kind it is (O49)
        let mut order: Vec<usize> = (0..ops.len()).collect();
        order.sort_by(|a, b| times.get(*b).cmp(&times.get(*a)).then(b.cmp(a)));
        // what the owner hid in this window is left out of both lists (O50)
        let all = order.len();
        order.retain(|at| times.get(*at).is_some_and(|time| !hidden(*time, crate::history_hidden())));
        app.set_ops_hidden(i32::try_from(all.saturating_sub(order.len())).unwrap_or(i32::MAX));
        let ops: Vec<Op> = order.iter().filter_map(|at| ops.get(*at).cloned()).collect();
        let refs: Vec<OpRef> = order.iter().filter_map(|at| refs.get(*at).cloned()).collect();
        let extras: Vec<(Option<u64>, bool, String)> = order.iter().filter_map(|at| extras.get(*at).cloned()).collect();
        let mut names: Vec<SharedString> = Vec::new();
        for (_, _, contact) in &extras {
            if !contact.is_empty() && !names.iter().any(|n| n.as_str() == contact) {
                names.push(contact.into());
            }
        }
        app.set_op_contacts(model(names));
        app.set_all_ops(model(
            ops.iter()
                .zip(refs.iter())
                .zip(extras.iter())
                .map(|((o, r), (block, incoming, contact))| OpLine {
                    who: o.who.clone(),
                    sub: o.sub.clone(),
                    amount: o.amount.clone(),
                    tone: o.tone,
                    show: r.shows(),
                    block: block.map_or_else(|| "—".to_string(), crate::sync::spaced).into(),
                    incoming: *incoming,
                    contact: contact.into(),
                })
                .collect(),
        ));
        // the latest few on the main screen, each with the same way back to its text
        let latest: Vec<Op> = ops.iter().zip(refs.iter()).take(6).map(|(o, r)| Op { show: r.shows(), ..o.clone() }).collect();
        f.op_rows = refs;
        app.set_ops(model(latest));
        // what waits at the wallet's address is what the wallet says waits
        // there now: a payment whose sender gave up is gone from the list
        f.onion = view.sync.onion.configured;
        app.set_tor_address(f.onion);
        f.incoming.retain(|i| tor_ask(&i.id).is_none() || view.onion_asks.iter().any(|(id, _)| id == &i.id));
        for (id, slate) in &view.onion_asks {
            if !f.incoming.iter().any(|i| &i.id == id) && f.incoming.len() < 16 {
                f.incoming.push(Incoming { id: id.clone(), slate: slate.clone(), from: String::new() });
            }
        }
        waits.extend(f.incoming.iter().cloned().map(Wait::Incoming));
        let rows: Vec<Waiting> = waits
            .iter()
            .map(|w| match w {
                Wait::Sign(op) => {
                    let row = view.sends.iter().find(|s| &s.op == op);
                    let who = row.map_or_else(|| tr("Recipient", "Получатель").into(), |row| payee(f, row));
                    let value = row.map_or(0, |s| s.amount);
                    Waiting { who: who.into(), what: fill(tr("replied to the payment of {} GRIN — your signature is needed", "ответил на платёж {} GRIN — нужна ваша подпись"), &[&amount(value)]).into(), action: tr("Look", "Посмотреть").into(), second: "".into() }
                }
                Wait::Reply(op) => {
                    let value = view.sends.iter().find(|s| &s.op == op).map_or(0, |s| s.amount);
                    Waiting { who: tr("Payment", "Платёж").into(), what: fill(tr("{} GRIN waits for the recipient's reply", "{} GRIN ждёт ответа получателя"), &[&amount(value)]).into(), action: tr("Paste the reply", "Вставить ответ").into(), second: tr("Cancel", "Отменить").into() }
                }
                Wait::Sent(op) => {
                    let row = view.sends.iter().find(|s| &s.op == op);
                    let who = row.map_or_else(|| tr("Payment", "Платёж").into(), |row| payee(f, row));
                    let value = row.map_or(0, |s| s.amount);
                    Waiting { who: who.into(), what: fill(tr("has not replied to the payment of {} GRIN yet — the money is reserved", "ещё не ответил на платёж {} GRIN — деньги в резерве"), &[&amount(value)]).into(), action: tr("Cancel the payment", "Отменить платёж").into(), second: "".into() }
                }
                Wait::Locked { amount: value, session_expired, .. } => {
                    let what = if *session_expired {
                        tr("The signing session for {} GRIN ended. Review the payment before starting a new exchange.", "Сеанс подписи платежа на {} GRIN завершён. Проверьте операцию перед новым обменом.")
                    } else {
                        tr("of {} GRIN was prepared before the wallet was restored from an older copy — it cannot be signed, the money is reserved", "{} GRIN подготовлен до восстановления кошелька из старой копии — подписать его нельзя, деньги в резерве")
                    };
                    Waiting { who: tr("Payment", "Платёж").into(), what: fill(what, &[&amount(*value)]).into(), action: tr("Review payment", "Проверить платёж").into(), second: "".into() }
                }
                Wait::Point(gap) => Waiting { who: tr("Starting point", "Стартовая точка").into(), what: fill(tr("is {} blocks below the checked chain — with a new one the wallet opens faster next time", "на {} блоков ниже проверенной цепи — с новой кошелёк в следующий раз откроется быстрее"), &[&crate::sync::spaced(*gap)]).into(), action: tr("Make a new point", "Сделать новую точку").into(), second: "".into() },
                Wait::Unsent(op) => {
                    let value = view.sends.iter().find(|s| &s.op == op).map_or(0, |s| s.amount);
                    Waiting { who: tr("Payment", "Платёж").into(), what: fill(tr("of {} GRIN is signed, but Tor did not come up and it has not gone to the network — choose what to do", "{} GRIN подписан, но Tor не поднялся и в сеть он не ушёл — выберите, что делать"), &[&amount(value)]).into(), action: tr("What to do", "Что делать").into(), second: "".into() }
                }
                // through Tor nobody vouches for the sender, and their wallet
                // waits for the answer in an open connection: said in the row
                Wait::Incoming(inc) if tor_ask(&inc.id).is_some() => Waiting {
                    who: tr("Over Tor, sender unverified", "Через Tor, отправитель не подтверждён").into(),
                    what: tr("a payment to your address — the sender's wallet waits about 40 seconds: look and accept?", "платёж на ваш адрес — кошелёк отправителя ждёт около 40 секунд: посмотреть и принять?").into(),
                    action: tr("Look", "Посмотреть").into(),
                    second: tr("Decline", "Отклонить").into(),
                },
                Wait::Incoming(inc) => {
                    let who = contact_name(&f.contacts, &inc.from).unwrap_or_else(|| tr("Not one of your contacts", "Не из ваших контактов").into());
                    Waiting { who: who.into(), what: tr("sent a payment — look and accept?", "прислал платёж — посмотреть и принять?").into(), action: tr("Look", "Посмотреть").into(), second: tr("Decline", "Отклонить").into() }
                }
            })
            .collect();
        f.waits = waits;
        app.set_waiting(model(rows));
        app.set_contact_names(model(f.contacts.iter().map(|c| SharedString::from(c.shown.as_str())).collect()));
        // O63: the contacts a payment to whom is in a block
        let paid: std::collections::BTreeSet<String> = view.sends.iter().filter(|row| row.state == "confirmed").filter_map(|row| row.to.clone()).collect();
        f.plaques = plaques(&view.sends, view.history_tip, now);
        let (contacts, seen_map, open_chat) = (&f.contacts, &mut f.seen, &f.chat);
        app.set_contacts(model(
            contacts
                .iter()
                .map(|c| {
                    let shown = foreign_line(&c.raw_name, NAME_CHARS);
                    let summary = view.summaries.iter().find(|s| s.0 == c.key);
                    let talk = summary.map(|s| fill(tr("{} messages", "сообщений: {}"), &[&s.1.to_string()]));
                    // O75: what is new since the owner last looked, in this unlock
                    let count = summary.map_or(0, |s| s.1);
                    let unread = unread(seen_map, &c.key, count, open_chat.as_deref() == Some(c.key.as_str()));
                    let time = summary.map(|s| when(s.2, now)).unwrap_or_default();
                    let last = if shown.changed {
                        tr("name changed: it had hidden characters", "имя изменено: в нём были скрытые знаки").to_string()
                    } else if shown.mixed_scripts {
                        tr("look-alike letters in the name", "похожие буквы в имени").to_string()
                    } else if let Some(t) = talk {
                        t
                    } else if c.address.is_none() {
                        tr("no address stored", "адрес не сохранён").to_string()
                    } else {
                        String::new()
                    };
                    Contact {
                        initial: c.shown.chars().next().map(|ch| ch.to_string()).unwrap_or_default().into(),
                        name: c.shown.clone().into(),
                        last: last.into(),
                        attention: shown.changed || shown.mixed_scripts,
                        traded: paid.contains(&c.key),
                        checked: c.checked,
                        time: time.into(),
                        unread,
                    }
                })
                .collect(),
        ));
    });
}

/// Takes what the transport brought since the last refresh.
fn take_notes(notes: &Mutex<VecDeque<Value>>) {
    let taken: Vec<Value> = match notes.lock() {
        Ok(mut q) => q.drain(..).collect(),
        Err(_) => return,
    };
    with(|f| {
        for note in taken {
            let Some(params) = note.get("params") else { continue };
            if params.get("source").and_then(Value::as_str) != Some("events") {
                continue;
            }
            let event = field(params, "event");
            if event.get("kind").and_then(Value::as_str) != Some("needs_approval") {
                continue;
            }
            let (Some(id), Some(slate)) = (text(event, "id"), text(event, "slate")) else { continue };
            if f.incoming.iter().any(|i| i.id == id) || f.incoming.len() >= 16 {
                continue;
            }
            f.incoming.push(Incoming { id, slate, from: text(event, "from").unwrap_or_default() });
        }
    });
}

/// Seconds of this computer's clock, for showing times only.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// When something happened, in words: minutes and hours while recent, the
/// date (UTC) after a day.
pub(crate) fn when(at: u64, now: u64) -> String {
    let ago = now.saturating_sub(at);
    if ago < 60 {
        tr("just now", "только что").to_string()
    } else if ago < 3600 {
        fill(tr("{} min ago", "{} мин назад"), &[&(ago / 60).to_string()])
    } else if ago < 86_400 {
        fill(tr("{} h ago", "{} ч назад"), &[&(ago / 3600).to_string()])
    } else {
        civil_date(at)
    }
}

/// The date of a moment, day.month.year (UTC).
fn civil_date(at: u64) -> String {
    {
        // days since 1970 to a civil date (Howard Hinnant's algorithm)
        let z = i64::try_from(at / 86_400).unwrap_or(0).saturating_add(719_468);
        let era = z.div_euclid(146_097);
        let doe = z.saturating_sub(era.saturating_mul(146_097));
        let yoe = (doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096)) / 365;
        let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe / 4).saturating_sub(yoe / 100));
        let mp = (doy.saturating_mul(5).saturating_add(2)) / 153;
        let d = doy.saturating_sub((mp.saturating_mul(153).saturating_add(2)) / 5).saturating_add(1);
        let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
        let y = yoe.saturating_add(era.saturating_mul(400)).saturating_add(i64::from(m <= 2));
        format!("{d:02}.{m:02}.{y}")
    }
}

fn text_notice(shown: &fly_safe_display::Shown) -> &'static str {
    match (shown.changed, shown.mixed_scripts) {
        (false, false) => "",
        (true, false) => tr("Text adjusted", "Текст изменён"),
        (false, true) => tr("Look-alike letters", "Похожие буквы"),
        (true, true) => tr("Text adjusted · look-alike letters", "Текст изменён · похожие буквы"),
    }
}

/// O75: a payment to a contact, shown in the conversation with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Plaque {
    /// When, as near as the wallet can say: the time of its block, counted
    /// back from now a minute a block; one under way is now.
    at: u64,
    text: String,
    state: String,
    warn: bool,
}

/// The payments to contacts, per contact key (O75).
fn plaques(sends: &[SendRow], tip: Option<u64>, now: u64) -> std::collections::BTreeMap<String, Vec<Plaque>> {
    let mut out: std::collections::BTreeMap<String, Vec<Plaque>> = std::collections::BTreeMap::new();
    for row in sends {
        let Some(key) = &row.to else { continue };
        if matches!(row.state.as_str(), "cancelled" | "expired") {
            continue;
        }
        let block = row.kernel_height.or(row.made);
        let at = match (block, tip) {
            (Some(h), Some(tip)) => now.saturating_sub(tip.saturating_sub(h).saturating_mul(60)),
            _ => now,
        };
        let confirmed = row.state == "confirmed";
        let state = match confirmations(row.kernel_height, tip).filter(|_| confirmed) {
            Some(have) => fill(tr("in a block · confirmations: {}", "в блоке · подтверждений: {}"), &[&crate::sync::spaced(have)]),
            None => outgoing_words(row).0.to_string(),
        };
        let text = fill(tr("You sent {} GRIN", "Вы отправили {} GRIN"), &[&amount(row.amount)]);
        out.entry(key.clone()).or_default().push(Plaque { at, text, state, warn: !confirmed });
    }
    out
}

/// O75: how many of a contact's `count` messages are new. The first count
/// seen in an unlock is taken as seen; an open conversation is seen whole.
fn unread(seen: &mut std::collections::BTreeMap<String, u64>, key: &str, count: u64, open: bool) -> i32 {
    let mark = seen.entry(key.to_string()).or_insert(count);
    if open || *mark > count {
        *mark = count;
    }
    i32::try_from(count.saturating_sub(*mark)).unwrap_or(i32::MAX)
}

/// The day of a moment, for the line over a day's messages (O75).
fn day_words(at: u64, now: u64) -> String {
    let (day, today) = (at / 86_400, now / 86_400);
    if day == today {
        tr("Today", "Сегодня").to_string()
    } else if today.checked_sub(1) == Some(day) {
        tr("Yesterday", "Вчера").to_string()
    } else {
        civil_date(at)
    }
}

/// The whole conversation for the screen (O75): the messages, the payments
/// to the contact among them by time, and a line for each day.
pub(crate) fn chat_view(lines: &[Said], pays: &[Plaque], now: u64) -> Vec<ChatLine> {
    let mut events: Vec<(u64, ChatLine)> = lines.iter().map(|(out, at, words, state)| (*at, chat_line(*out, *at, words, state, now))).collect();
    for p in pays {
        events.push((p.at, ChatLine { mine: true, text: p.text.clone().into(), when: when(p.at, now).into(), state: p.state.clone().into(), warn: p.warn, kind: 1 }));
    }
    // stable: messages of one moment keep their order
    events.sort_by_key(|(at, _)| *at);
    let mut out = Vec::with_capacity(events.len().saturating_add(4));
    let mut last_day: Option<u64> = None;
    for (at, line) in events {
        if last_day != Some(at / 86_400) {
            last_day = Some(at / 86_400);
            out.push(ChatLine { mine: false, text: day_words(at, now).into(), when: SharedString::new(), state: SharedString::new(), warn: false, kind: 2 });
        }
        out.push(line);
    }
    out
}

/// One line of a conversation for the screen (О9): the words through
/// `foreign_text` (О1–О5), the state honest (О10).
fn chat_line(out: bool, at: u64, words: &str, state: &str, now: u64) -> ChatLine {
    let (state, warn) = match (out, state) {
        (false, _) => ("", false),
        (true, "relay_accepted") => (tr("accepted for delivery", "принято к доставке"), false),
        (true, "expired") => (tr("not sent: the delivery window closed", "не отправлено: окно доставки закрылось"), true),
        (true, _) => (tr("waiting to be delivered", "ждёт доставки"), false),
    };
    let shown = foreign_text(words, MESSAGE_CHARS);
    let notice = text_notice(&shown);
    let label = match (state, notice) {
        ("", text) | (text, "") => text.into(),
        _ => format!("{state} · {notice}").into(),
    };
    ChatLine { mine: out, text: shown.text.into(), when: when(at, now).into(), state: label, warn: warn || !notice.is_empty(), kind: 0 }
}

// ----- windows

fn sheet_error(app: &App, message: impl Into<SharedString>) {
    app.set_sheet_busy(false);
    app.set_sheet_error(message.into());
}

/// Names a payment's recipient by О8: a contact only for the very address
/// stored for it.
fn who_of(f: &Flow, to_address: Option<&str>) -> (String, String, Vec<SharedString>) {
    match to_address.map(address) {
        Some(Ok(a)) => {
            let contacts: Vec<(&str, &str)> = f.contacts.iter().filter_map(|c| c.address.as_deref().map(|ad| (c.raw_name.as_str(), ad))).collect();
            let groups = a.groups.iter().cloned().map(SharedString::from).collect();
            match recipient(&a, contacts) {
                Recipient::Contact(name) => {
                    let notice = text_notice(&name);
                    (name.text, notice.into(), groups)
                }
                Recipient::Unknown => (tr("Not an address of your contacts", "Адрес не из ваших контактов").into(), tr("Check the address with the recipient another way.", "Сверьте адрес с получателем по другому каналу.").into(), groups),
            }
        }
        Some(Err(_)) => (tr("Broken address", "Адрес с ошибкой").into(), tr("It cannot be paid to.", "Платить на него нельзя.").into(), Vec::new()),
        None => (tr("A recipient without an address", "Получатель без адреса").into(), tr("The payment will have no payment proof.", "У платежа не будет доказательства оплаты.").into(), Vec::new()),
    }
}

fn review_recipient(f: &Flow, flow: &SendFlow, review: &Value, testnet: bool) -> Option<(String, String, Vec<SharedString>)> {
    if review.get("op")?.as_str()? != flow.op { return None; }
    let addr = match review.get("receiver_address")? {
        Value::Null => None,
        Value::String(key) => Some(address_of_key(&hex32(key)?, testnet)),
        _ => return None,
    };
    Some(who_of(f, addr.as_deref()))
}

/// Opens the signing window for `op` with the wallet's own numbers.
fn open_sign(app: &App, flow: SendFlow) {
    let Some(client) = client() else { return };
    let op = flow.op.clone();
    spawn(
        app,
        move || {
            let review = client.call("paycore.send.review", json!({"op": op}), QUICK)?;
            let status = client.call("host.status", json!({}), QUICK)?;
            Ok((review, status))
        },
        move |app, result| {
            let (review, status) = match result {
                Ok(values) => values,
                Err(e) => return sheet_error(app, say(&e)),
            };
            let invalid = || sheet_error(app, tr("Cannot verify signing details", "Не удалось проверить данные для подписи"));
            let testnet = match status.get("network").and_then(Value::as_str) {
                Some("test") => true,
                Some("main") => false,
                _ => return invalid(),
            };
            let number = |key| review.get(key).and_then(Value::as_str).and_then(|s| s.parse::<u64>().ok());
            let (Some(sent), Some(fee)) = (number("amount"), number("fee")) else { return invalid() };
            let Some(total) = sent.checked_add(fee) else { return invalid() };
            let details = with(|f| review_recipient(f, &flow, &review, testnet));
            let Some((who, note, groups)) = details else { return invalid() };
            with(|f| {
                app.set_sign_amount(amount(sent).into());
                app.set_sign_fee(amount(fee).into());
                app.set_sign_total(amount(total).into());
                app.set_sign_who(who.into());
                app.set_sign_who_note(note.into());
                app.set_sign_who_groups(model(groups));
                app.set_sign_can_cancel(true);
                f.send = Some(flow);
            });
            app.set_sheet_busy(false);
            app.set_sheet_error(SharedString::new());
            app.set_sheet(3);
        },
    );
}

/// O65: what is said of the address a payment names, against the address
/// saved for the contact it came from: another address is said aloud -
/// and louder when the saved one was compared by the check code.
fn address_note(saved: Option<&str>, checked: bool, declared: &str) -> &'static str {
    match saved {
        Some(saved) if saved != declared && checked => tr("Careful: the payment names another address than the one you checked with this contact", "Осторожно: в платеже другой адрес, не тот, что вы сверяли с этим контактом"),
        Some(saved) if saved != declared => tr("The payment names another address than the one saved for this contact", "В платеже другой адрес, не тот, что сохранён у этого контакта"),
        Some(_) if checked => tr("The address of the payment is the one you checked with this contact", "Адрес в платеже — тот, что вы сверяли с этим контактом"),
        _ => tr("Address declared in the payment", "Адрес, указанный в платеже"),
    }
}

// The S1 proof address is declared by the sender. Only the authenticated
// delivery envelope identifies a local contact before the receiver answers.
fn incoming_sender(f: &Flow, id: Option<&str>, sender: Option<[u8; 32]>) -> (String, String, Vec<SharedString>) {
    let known = id.and_then(|id| f.incoming.iter().find(|i| i.id == id)).and_then(|i| f.contacts.iter().find(|c| c.key == i.from));
    let contact = known.map(|c| c.shown.clone());
    let from = contact.unwrap_or_else(|| tr("Sender unverified", "Отправитель не подтверждён").into());
    match sender {
        Some(key) => {
            let Some(declared) = view_address(Some(key), f.testnet) else {
                return (from, tr("Address unavailable until network is known", "Адрес недоступен, пока сеть не определена").into(), Vec::new());
            };
            let groups = address(&declared).ok().into_iter().flat_map(|a| a.groups).map(SharedString::from).collect();
            (from, address_note(known.and_then(|c| c.address.as_deref()), known.is_some_and(|c| c.checked), &declared).into(), groups)
        }
        None => (from, tr("The sender named no address.", "Отправитель не указал адрес.").into(), Vec::new()),
    }
}

/// Reads an incoming payment and opens the window that asks about it.
fn open_incoming(app: &App, flow: ReceiveFlow) {
    let Some(client) = client() else { return };
    let slate = flow.slate.clone();
    app.set_sheet_busy(true);
    spawn(
        app,
        move || client.call("paycore.slate.read", json!({ "slate": slate }), QUICK),
        move |app, read| {
            let read = match read {
                Ok(r) => r,
                Err(e) => return sheet_error(app, say(&e)),
            };
            match read.get("stage").and_then(Value::as_str) {
                Some("S1") => {}
                // an invoice is paid by its text; one that came as a message
                // has no place to send the reply back to
                Some("I1") if flow.id.is_none() => return open_invoice(app, flow.slate),
                Some("I1") => return sheet_error(app, tr("This is an invoice. It is paid by its text: “Receive”, then paste the text.", "Это счёт на оплату. Он оплачивается по тексту: «Получить», затем вставьте текст.")),
                Some("S2") => return sheet_error(app, tr("This is a recipient's reply. It goes into the send window.", "Это ответ получателя. Его вставляют в окне отправки.")),
                // O64: the payer's answer to an invoice this wallet made
                Some("I2") => return finish_invoice(app, None, flow.slate),
                _ => return sheet_error(app, tr("This is not a payment that can be accepted", "Это не платёж, который можно принять")),
            }
            let Some(value) = read.get("amount").and_then(Value::as_str).and_then(|a| a.parse::<u64>().ok()) else {
                return sheet_error(app, tr("The payment names no amount", "В платеже не указана сумма"));
            };
            let sender = text(&read, "sender_address").as_deref().and_then(hex32);
            with(|f| {
                let (from, note, groups) = incoming_sender(f, flow.id.as_deref(), sender);
                app.set_in_amount(amount(value).into());
                app.set_in_from(from.into());
                app.set_in_from_note(note.into());
                app.set_in_from_groups(model(groups));
                f.receive = Some(flow);
            });
            app.set_sheet_busy(false);
            app.set_sheet_error(SharedString::new());
            app.set_sheet(5);
        },
    );
}

/// Asks the wallet what paying the invoice takes and opens the window that
/// shows it. The numbers are the wallet's own, not read from the text here.
fn open_invoice(app: &App, slate: String) {
    let Some(client) = client() else { return };
    app.set_sheet_busy(true);
    let asked = slate.clone();
    spawn(
        app,
        move || client.call("paycore.invoice.review", json!({ "slate": asked }), QUICK),
        move |app, review| {
            let review = match review {
                Ok(r) => r,
                Err(e) => return sheet_error(app, say_invoice(&e)),
            };
            let Some(shown) = invoice_numbers(&review) else {
                return sheet_error(app, tr("Cannot verify the invoice's details", "Не удалось проверить данные счёта"));
            };
            let flow = InvoiceFlow { slate, amount: shown.amount, fee: shown.fee };
            if shown.paid {
                // paid by this wallet already: nothing to agree to, the
                // wallet gives the stored reply and signs nothing
                return pay_invoice(app, flow, true);
            }
            app.set_inv_amount(amount(shown.amount).into());
            app.set_inv_fee(amount(shown.fee).into());
            app.set_inv_total(amount(shown.total).into());
            app.set_inv_until(match shown.cutoff {
                0 => SharedString::new(),
                height => fill(tr("The invoice can be paid before block {}.", "Счёт можно оплатить до блока {}."), &[&height.to_string()]).into(),
            });
            with(|f| {
                f.receive = None;
                f.invoice = Some(flow);
            });
            app.set_sheet_busy(false);
            app.set_sheet_error(SharedString::new());
            app.set_sheet(10);
        },
    );
}

/// What the wallet said about an invoice, or nothing if any of it is
/// missing or does not add up: the window shows all of it or none.
#[derive(Debug, PartialEq, Eq)]
struct InvoiceNumbers {
    amount: u64,
    fee: u64,
    total: u64,
    cutoff: u64,
    paid: bool,
}

fn invoice_numbers(review: &Value) -> Option<InvoiceNumbers> {
    let number = |key: &str| review.get(key).and_then(Value::as_str).and_then(|s| s.parse::<u64>().ok());
    let amount = number("amount").filter(|asked| *asked > 0)?;
    let fee = number("fee")?;
    Some(InvoiceNumbers {
        amount,
        fee,
        total: amount.checked_add(fee)?,
        cutoff: review.get("ttl_cutoff_height")?.as_u64()?,
        paid: match review.get("paid_op")? {
            Value::Null => false,
            Value::String(op) if !op.is_empty() => true,
            _ => return None,
        },
    })
}

/// What the wallet is asked when an invoice is paid: the text read, and
/// both numbers the window showed as the most the user agreed to.
fn invoice_pay_params(flow: &InvoiceFlow) -> Value {
    json!({ "slate": flow.slate, "max_amount": flow.amount.to_string(), "max_fee": flow.fee.to_string() })
}

fn invoice_reply_title(again: bool) -> &'static str {
    if again {
        tr("Saved reply — send it to the invoice issuer", "Ответ сохранён — передайте его тому, кто выставил счёт")
    } else {
        tr("Reply ready — send it to the invoice issuer", "Ответ готов — передайте его тому, кто выставил счёт")
    }
}

/// Prepares the payer's reply or returns its previously saved bytes.
fn pay_invoice(app: &App, flow: InvoiceFlow, again: bool) {
    let Some(client) = client() else { return };
    app.set_sheet_busy(true);
    app.set_sheet_error(SharedString::new());
    spawn(
        app,
        move || client.call("paycore.invoice.pay", invoice_pay_params(&flow), SIGN),
        move |app, paid| {
            let reply = match paid {
                Ok(paid) => text(&paid, "slate").filter(|reply| !reply.is_empty()),
                Err(e) => return sheet_error(app, say_invoice(&e)),
            };
            let Some(reply) = reply else {
                return sheet_error(app, tr("The wallet gave no reply to pass on. Read the invoice again", "Кошелёк не выдал ответ для передачи. Прочитайте счёт ещё раз"));
            };
            with(|f| f.invoice = None);
            let note = tr("Send this text to whoever issued the invoice. They complete the payment and send it to the network; until then the money stays reserved. If the text is lost, read the same invoice again: the wallet gives this reply again and pays nothing twice.", "Отправьте этот текст тому, кто выставил счёт. Он завершит платёж и отправит его в сеть; до тех пор деньги остаются в резерве. Если текст потерян, прочитайте тот же счёт ещё раз: кошелёк выдаст этот ответ снова и дважды не заплатит.");
            show_out(app, invoice_reply_title(again), note, &reply, false);
        },
    );
}

fn close_sheet(app: &App) {
    // what a closed window was about does not linger for the next one (O64)
    with(|f| {
        f.issued = None;
        f.edit_key = None;
    });
    app.set_contact_editing(false);
    app.set_contact_edit_name(SharedString::new());
    app.set_contact_edit_address(SharedString::new());
    app.set_contact_code(SharedString::new());
    app.set_sheet_busy(false);
    app.set_sheet_error(SharedString::new());
    app.set_sheet(0);
}

/// Shows a Slatepack text to pass on.
/// K200: next to a reply that is shown, offers the sender's text of the same payment.
fn offer_request(app: &App, slate_id: Option<String>) {
    app.set_out_can_request(slate_id.is_some());
    with(|f| f.request_of = slate_id);
}

fn show_out(app: &App, title: &str, note: &str, out: &str, wants_reply: bool) {
    // a text shown anew is not the invoice shown before (O64); the one
    // who shows an invoice says so after this
    with(|f| f.issued = None);
    app.set_out_title(title.into());
    app.set_out_note(note.into());
    app.set_out_text(out.into());
    app.set_out_wants_reply(wants_reply);
    app.set_out_needs_session(wants_reply);
    app.set_out_can_tor(false);
    app.set_out_can_resend(false);
    app.set_out_can_direct(false);
    app.set_out_can_back(false);
    app.set_out_back_plan(SharedString::new());
    app.set_out_can_request(false);
    app.set_out_resend_note(SharedString::new());
    app.set_out_waiting(false);
    with(|f| f.tor_wait = None);
    app.set_sheet_busy(false);
    app.set_sheet_error(SharedString::new());
    app.set_sheet(2);
}

/// What the window says once a payment went to an address over Tor.
#[allow(non_snake_case)]
fn TOR_SENT_NOTE() -> &'static str {
    tr("The payment went over Tor to the wallet at this address. When it answers — at once if it takes payments by itself, otherwise when its owner says yes — the payment appears under “Waiting for you”, where you sign it. If Tor does not reach it, you will see why under Problems; this same text can then be passed by hand.", "Платёж ушёл через Tor кошельку по этому адресу. Когда он ответит — сразу, если принимает платежи сам, иначе когда его владелец согласится, — платёж появится в «Ждут вас», там вы его подпишете. Если Tor не дойдёт, причина будет в «Неполадках»; этот же текст тогда можно передать вручную.")
}

fn wire_sheets(app: &App) {
    // the text sheet of a payment to an address: send it over Tor (again)
    let weak = app.as_weak();
    app.on_out_tor(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(flow) = with(|f| f.send.clone()) else { return sheet_error(&app, tr("No payment to send", "Нет платежа для отправки")) };
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        spawn(
            &app,
            move || client.call("paycore.onion.send", json!({ "op": flow.op }), QUICK).map(|_| flow.op),
            move |app, out| {
                app.set_sheet_busy(false);
                match out {
                    Ok(op) => {
                        app.set_out_title(tr("Payment sent over Tor", "Платёж отправлен через Tor").into());
                        app.set_out_note(TOR_SENT_NOTE().into());
                        app.set_out_waiting(true);
                        with(|f| f.tor_wait = Some(op));
                    }
                    Err(e) => sheet_error(app, say_tor(&e)),
                }
            },
        );
    });

    // send: how much and to whom
    let weak = app.as_weak();
    app.on_send_prepare(move |typed, to, typed_address| {
        let Some(app) = weak.upgrade() else { return };
        let value = match parse_amount(&typed) {
            Ok(v) => v,
            Err(e) => return sheet_error(&app, amount_error(e)),
        };
        let Some(client) = client() else { return };
        let (params, named) = match with(|f| {
            let testnet = f.testnet.ok_or(tr("Wallet network unavailable", "Сеть кошелька недоступна"))?;
            if let Ok(index) = usize::try_from(to) {
                let c = f.contacts.get(index).ok_or(tr("No such contact", "Нет такого контакта"))?;
                let mut params = json!({ "amount": value.to_string(), "deliver_to": c.key });
                if let Some(key) = c.address.as_deref().and_then(|a| address(a).ok()).as_ref().and_then(key_of_address) {
                    if let Some(fields) = params.as_object_mut() {
                        fields.insert("proof_to".into(), json!(hex(&key)));
                    }
                }
                return Ok((params, Some((c.shown.clone(), c.address.clone()))));
            }
            let typed_address = typed_address.trim();
            if typed_address.is_empty() {
                if to == TO_ADDRESS {
                    return Err(tr("Type the recipient's grin1… address", "Впишите адрес получателя grin1…"));
                }
                return Ok((json!({ "amount": value.to_string() }), None));
            }
            let a = address(typed_address).map_err(|_| tr("Broken address: check all of it", "Адрес с ошибкой: проверьте его целиком"))?;
            if a.testnet != testnet {
                return Err(if testnet { tr("This is a Mainnet address, the wallet is on Testnet", "Это адрес Mainnet, а кошелёк в Testnet") } else { tr("This is a Testnet address, the wallet is on Mainnet", "Это адрес Testnet, а кошелёк в Mainnet") });
            }
            let key = key_of_address(&a).ok_or(tr("This is not a Grin wallet address", "Это не адрес кошелька Grin"))?;
            let who = who_of(f, Some(&a.full)).0;
            Ok((json!({ "amount": value.to_string(), "proof_to": hex(&key) }), Some((who, Some(a.full)))))
        }) {
            Ok(x) => x,
            Err(message) => return sheet_error(&app, message),
        };
        // O51: the outputs the owner chose, and the word for a marked one
        let mut params = params;
        match with(|f| chosen_params(&f.outputs, &f.picked, app.get_spend_kept())) {
            Ok(Some((inputs, spend_kept))) => {
                if let Some(fields) = params.as_object_mut() {
                    fields.insert("inputs".into(), json!(inputs));
                    if spend_kept {
                        fields.insert("spend_kept".into(), json!(true));
                    }
                }
            }
            Ok(None) => {}
            Err(message) => return sheet_error(&app, message),
        }
        let delivered = params.get("deliver_to").is_some();
        // "Over Tor — to a grin1 address" was chosen in the send window
        let to_address = !delivered && to == TO_ADDRESS && params.get("proof_to").is_some() && with(|f| f.onion);
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        spawn(
            &app,
            move || {
                let prepared = client.call("paycore.send.prepare", params, SIGN)?;
                let slate = text(&prepared, "slate").unwrap_or_default();
                let id = client.call("paycore.slate.read", json!({ "slate": slate }), QUICK).ok().and_then(|r| text(&r, "slate_id"));
                let op = text(&prepared, "op").unwrap_or_default();
                // the payment is prepared whatever Tor says; what Tor says
                // decides only how its text travels
                let posted = to_address.then(|| client.call("paycore.onion.send", json!({ "op": op }), QUICK).map(|_| ()).map_err(|e| say_tor(&e)));
                Ok::<_, CallError>((op, slate, id, posted))
            },
            move |app, out| match out {
                Err(e) => sheet_error(app, say(&e)),
                Ok((op, slate, id, posted)) => {
                    clear_output_choice(app);
                    let who = named.as_ref().map(|(w, _)| w.clone());
                    with(|f| {
                        f.op_to.insert(op.clone(), named.unwrap_or_else(|| (tr("Payment", "Отправка").into(), None)));
                        if !delivered {
                            f.send = Some(SendFlow { op: op.clone(), held: false, s2: None, slate_id: id });
                        }
                    });
                    if delivered {
                        let who = who.unwrap_or_default();
                        show_out(app, tr("Payment prepared", "Платёж подготовлен"), &fill(tr("The payment goes to “{}” over Tor. When they reply it appears under “Waiting for you”, where you sign it. If Tor fails, this same text can be passed on by hand.", "Платёж уйдёт контакту «{}» через Tor. Когда он ответит, платёж появится в «Ждут вас» — там вы его подпишете. Если Tor не дойдёт, этот же текст можно передать вручную."), &[&who]), &slate, false);
                        app.set_out_needs_session(true);
                    } else if let Some(posted) = posted {
                        match posted {
                            Ok(()) => {
                                show_out(app, tr("Payment sent over Tor", "Платёж отправлен через Tor"), TOR_SENT_NOTE(), &slate, true);
                                app.set_out_waiting(true);
                                with(|f| f.tor_wait = Some(op.clone()));
                            }
                            Err(why) => {
                                show_out(app, tr("Payment prepared — Tor did not take it", "Платёж подготовлен — Tor его не принял"), tr("The payment is prepared and the money reserved. Send it over Tor again with the button below, or pass this text to the recipient by hand and paste their reply.", "Платёж подготовлен, деньги в резерве. Отправьте его через Tor ещё раз кнопкой ниже или передайте этот текст получателю вручную и вставьте его ответ."), &slate, true);
                                app.set_sheet_error(why.into());
                            }
                        }
                        app.set_out_can_tor(true);
                    } else {
                        show_out(app, tr("Pass on to the recipient", "Передайте получателю"), tr("Send this text to the recipient any way you like. They paste it into their wallet and send a reply — paste the reply below. The money is reserved until the payment is signed or cancelled.", "Отправьте этот текст получателю любым способом. Он вставит его в свой кошелёк и пришлёт ответ — вставьте ответ ниже. Деньги зарезервированы, пока платёж не подписан или не отменён."), &slate, true);
                    }
                }
            },
        );
    });

    // the recipient's answer to a manual payment
    let weak = app.as_weak();
    app.on_out_reply(move |reply| {
        let Some(app) = weak.upgrade() else { return };
        // O64: the answer to an invoice made here
        if let Some(id) = with(|f| f.issued.clone()) {
            return finish_invoice(&app, Some(id), reply.trim().to_string());
        }
        let Some(flow) = with(|f| f.send.clone()) else { return sheet_error(&app, tr("No payment this replies to", "Нет платежа, на который это ответ")) };
        let Some(client) = client() else { return };
        let reply = reply.trim().to_string();
        if reply.is_empty() {
            return sheet_error(&app, tr("Paste the recipient's reply", "Вставьте ответ получателя"));
        }
        app.set_sheet_busy(true);
        let text_back = reply.clone();
        spawn(
            &app,
            move || client.call("paycore.slate.read", json!({ "slate": text_back }), QUICK),
            move |app, read| {
                let read = match read {
                    Ok(r) => r,
                    Err(e) => return sheet_error(app, say(&e)),
                };
                if read.get("stage").and_then(Value::as_str) != Some("S2") {
                    return sheet_error(app, tr("This is not the recipient's reply to a payment", "Это не ответ получателя на платёж"));
                }
                if flow.slate_id.is_some() && text(&read, "slate_id") != flow.slate_id {
                    return sheet_error(app, tr("This replies to another payment", "Это ответ на другой платёж"));
                }
                open_sign(app, SendFlow { s2: Some(reply), ..flow });
            },
        );
    });

    // sign and hand to the chain
    let weak = app.as_weak();
    app.on_sign(move || {
        let Some(app) = weak.upgrade() else { return };
        sign_now(&app, false);
    });
    // O60: signed with the owner's agreement that this one payment goes
    // directly if Tor fails to send it (K192, kept with the payment - K198)
    let weak = app.as_weak();
    app.on_sign_direct(move || {
        let Some(app) = weak.upgrade() else { return };
        sign_now(&app, true);
    });
    let weak = app.as_weak();
    app.on_sign_tor_off(move || {
        let Some(app) = weak.upgrade() else { return };
        // the same switch as on the main screen; the window to sign stays
        app.invoke_switch_tor(false);
    });
    let weak = app.as_weak();
    app.on_sign_try_bridges(move || {
        let Some(app) = weak.upgrade() else { return };
        bridges::begin(&app);
    });
    let weak = app.as_weak();
    app.on_sign_stop_bridges(move || {
        let Some(app) = weak.upgrade() else { return };
        bridges::stop(&app);
    });
    install_rest(app);
}

/// Signs the payment that waits in the window and hands it to the network.
/// `direct`: with the owner's agreement to the direct way for this one.
fn sign_now(app: &App, direct: bool) {
    let Some(flow) = with(|f| f.send.clone()) else { return };
    let Some(client) = client() else { return };
    app.set_sheet_busy(true);
    app.set_sheet_error(SharedString::new());
    spawn(
        app,
        move || {
            if flow.held {
                client.call("paycore.send.finalize_held", json!({ "op": flow.op }), SIGN)?;
            } else {
                let s2 = flow.s2.clone().unwrap_or_default();
                client.call("paycore.send.finalize", json!({ "op": flow.op, "slate": s2 }), SIGN)?;
            }
            // a failed hand-over is retried by the wallet itself
            let _ = client.call("paycore.send.broadcast", resend_params(&flow.op, direct), SIGN);
            Ok::<_, CallError>(flow.op)
        },
        move |app, out| match out {
            Ok(op) => {
                with(|f| {
                    f.send = None;
                });
                let _ = op;
                close_sheet(app);
            }
            Err(e) => {
                app.set_sign_can_cancel(!matches!(&e, CallError::Rpc { name, message, .. } if name == "unknown_outcome" || (name == "refused" && message == "signing session ended; start a new exchange")));
                sheet_error(app, say(&e));
            }
        },
    );
}

/// The rest of the window's wiring for payments (split from the function
/// above only for its length).
fn install_rest(app: &App) {
    let weak = app.as_weak();
    app.on_cancel_payment(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(flow) = with(|f| f.send.clone()) else { return };
        cancel_op(&app, flow.op, false, false);
    });

    // a payment locked after a restore: the user read the warning and gives it up
    let weak = app.as_weak();
    app.on_release_payment(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(op) = with(|f| f.release.clone()) else { return };
        cancel_op(&app, op, true, false);
    });

    // receive by text
    let weak = app.as_weak();
    app.on_receive_read(move |typed| {
        let Some(app) = weak.upgrade() else { return };
        let slate = typed.trim().to_string();
        if slate.is_empty() {
            return sheet_error(&app, tr("Paste the sender's text", "Вставьте текст отправителя"));
        }
        open_incoming(&app, ReceiveFlow { slate, id: None });
    });

    // an invoice: the user agreed to the numbers on the screen
    let weak = app.as_weak();
    app.on_invoice_pay(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(flow) = with(|f| f.invoice.clone()) else { return };
        pay_invoice(&app, flow, false);
    });

    let weak = app.as_weak();
    app.on_incoming_accept(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(flow) = with(|f| f.receive.clone()) else { return };
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        let id = flow.id.clone();
        spawn(
            &app,
            move || {
                let s2 = if let Some(ask) = flow.id.as_deref().and_then(tor_ask) {
                    // the sender waits in an open connection: the wallet
                    // signs and answers in one step, or not at all
                    let answered = client.call("paycore.onion.accept", json!({ "id": ask }), SIGN)?;
                    text(&answered, "slate").unwrap_or_default()
                } else {
                    let drafted = client.call("paycore.receive.draft", json!({ "slate": flow.slate }), SIGN)?;
                    let s2 = text(&drafted, "slate").unwrap_or_default();
                    if let Some(id) = &flow.id {
                        client.call("paycore.delivery.reply", json!({ "id": id, "slate": s2 }), SIGN)?;
                    }
                    s2
                };
                // which payment this reply belongs to, to show it again from "All payments"
                let reply_of = client.call("paycore.slate.read", json!({ "slate": s2 }), QUICK).ok().and_then(|r| text(&r, "slate_id"));
                Ok::<_, CallError>((s2, reply_of))
            },
            move |app, out| match out {
                Ok((s2, reply_of)) => {
                    with(|f| {
                        if let Some(slate_id) = reply_of {
                            f.replies.insert(slate_id, s2.clone());
                        }
                        f.receive = None;
                        if let Some(id) = &id {
                            f.incoming.retain(|i| &i.id != id);
                        }
                    });
                    if id.is_some() {
                        close_sheet(app);
                    } else {
                        show_out(app, tr("Reply to the sender", "Ответ отправителю"), tr("Pass this text to the sender. The money arrives when they sign the payment and the transaction is in a block.", "Передайте этот текст отправителю. Деньги придут, когда он подпишет платёж и транзакция попадёт в блок."), &s2, false);
                    }
                }
                Err(e) => sheet_error(app, say_tor(&e)),
            },
        );
    });

    let weak = app.as_weak();
    app.on_incoming_decline(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(flow) = with(|f| f.receive.take()) else { return close_sheet(&app) };
        if let (Some(id), Some(client)) = (flow.id, client()) {
            with(|f| f.incoming.retain(|i| i.id != id));
            std::thread::spawn(move || {
                let _ = match tor_ask(&id) {
                    Some(ask) => client.call("paycore.onion.decline", json!({ "id": ask }), QUICK),
                    None => client.call("paycore.delivery.ack", json!({ "id": id }), QUICK),
                };
            });
        }
        close_sheet(&app);
    });

    // a new contact
    let weak = app.as_weak();
    app.on_contact_add(move |typed_name, npub, typed_address| {
        let Some(app) = weak.upgrade() else { return };
        let typed_name = typed_name.trim().to_string();
        if typed_name.is_empty() {
            return sheet_error(&app, tr("Type a name", "Впишите имя"));
        }
        // O64: a contact being changed is named by its key, which stays
        let mut params = match with(|f| f.edit_key.clone()) {
            Some(key) => json!({ "key": key, "name": typed_name }),
            None => {
                let npub = npub.trim().to_string();
                if !npub.starts_with("npub1") {
                    return sheet_error(&app, tr("A message key starts with npub1", "Ключ для сообщений начинается с npub1"));
                }
                json!({ "npub": npub, "name": typed_name })
            }
        };
        let typed_address = typed_address.trim().to_string();
        if !typed_address.is_empty() {
            let Some(testnet) = with(|f| f.testnet) else { return sheet_error(&app, tr("Wallet network unavailable", "Сеть кошелька недоступна")) };
            match address(&typed_address) {
                Ok(a) if a.testnet == testnet => match key_of_address(&a) {
                    Some(key) => {
                        if let Some(fields) = params.as_object_mut() {
                            fields.insert("address".into(), json!(hex(&key)));
                        }
                    }
                    None => return sheet_error(&app, tr("This is not a Grin wallet address", "Это не адрес кошелька Grin")),
                },
                Ok(_) => return sheet_error(&app, tr("An address of the other network", "Адрес из другой сети")),
                Err(_) => return sheet_error(&app, tr("Broken address: check all of it", "Адрес с ошибкой: проверьте его целиком")),
            }
        }
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        spawn(
            &app,
            move || client.call("paycore.contacts.set", params, QUICK),
            move |app, out| match out {
                Ok(_) => close_sheet(app),
                Err(CallError::Rpc { name, .. }) if name == "invalid_params" => sheet_error(app, tr("Broken message key", "Ключ для сообщений с ошибкой")),
                Err(e) => sheet_error(app, say(&e)),
            },
        );
    });

    // «Ждут вас»
    let weak = app.as_weak();
    app.on_act(move |index, yes| {
        let Some(app) = weak.upgrade() else { return };
        let Some(wait) = usize::try_from(index).ok().and_then(|i| with(|f| f.waits.get(i).cloned())) else { return };
        app.set_sheet_error(SharedString::new());
        app.set_wait_note(SharedString::new());
        match (wait, yes) {
            (Wait::Sign(op), _) => open_sign(&app, SendFlow { op, held: true, s2: None, slate_id: None }),
            // O67: the same as the button; its answer is shown next to that button
            (Wait::Point(_), _) => app.invoke_make_point(),
            (Wait::Unsent(op), _) => {
                // taking back is offered where the payment's own line offers it
                let back = with(|f| f.op_rows.iter().any(|r| matches!(r, OpRef::Signed { op: o, back: true, .. } if *o == op)));
                show_signed(&app, op, true, back)
            }
            (Wait::Reply(op), true) => reopen_by_hand(&app, op),
            (Wait::Reply(op), false) | (Wait::Sent(op), _) => cancel_op(&app, op, false, true),
            (Wait::Locked { op, amount: value, session_expired }, _) => {
                let why = if session_expired {
                    tr("The wallet closed before a signed result for {} GRIN was saved in this profile. This Slatepack can no longer be signed. Check the original payment and its reserve before starting another exchange.", "В этом профиле не сохранился подписанный результат платежа на {} GRIN до закрытия кошелька. Этот Slatepack больше нельзя подписать. Проверьте исходный платёж и его резерв перед новым обменом.")
                } else {
                    tr("A payment of {} GRIN was prepared before this wallet was restored from an older copy. The wallet no longer knows whether it was signed after that copy was taken, so it will not sign it and keeps the money in reserve.", "Платёж {} GRIN был подготовлен до того, как этот кошелёк восстановили из старой копии. Кошелёк больше не знает, подписывали ли его после снятия копии, поэтому не подписывает его и держит деньги в резерве.")
                };
                app.set_rel_note(fill(why, &[&amount(value)]).into());
                with(|f| f.release = Some(op));
                app.set_sheet_busy(false);
                app.set_sheet(11);
            }
            (Wait::Incoming(inc), true) => open_incoming(&app, ReceiveFlow { slate: inc.slate, id: Some(inc.id) }),
            (Wait::Incoming(inc), false) => {
                with(|f| f.receive = Some(ReceiveFlow { slate: inc.slate, id: Some(inc.id) }));
                app.invoke_incoming_decline();
            }
        }
    });

    let weak = app.as_weak();
    let for_edit = app.as_weak();
    app.on_sheet_closed(move |sheet| {
        if let Some(app) = weak.upgrade() {
            app.set_sheet_busy(false);
            if sheet == 1 {
                clear_output_choice(&app);
            }
            // a question about collecting is not kept for the next opening
            app.set_collect_plan(SharedString::new());
            app.set_collect_done(SharedString::new());
        }
        with(|f| {
            f.receive = None;
            f.invoice = None;
            f.release = None;
            f.issued = None;
            f.edit_key = None;
        });
        if let Some(app) = for_edit.upgrade() {
            app.set_contact_editing(false);
            app.set_contact_edit_name(SharedString::new());
            app.set_contact_edit_address(SharedString::new());
            app.set_contact_code(SharedString::new());
        }
    });
}

/// Lets a payment go: cancels it, or - `release` - gives up one locked
/// after a restore. `listed`: asked from «Ждут вас», where no window is
/// open to show a refusal in; it is written above the list instead.
fn cancel_op(app: &App, op: String, release: bool, listed: bool) {
    let Some(client) = client() else { return };
    if !listed {
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
    }
    spawn(
        app,
        move || client.call("paycore.send.cancel", cancel_params(&op, release), QUICK),
        move |app, out| match out {
            Ok(_) => {
                with(|f| {
                    f.send = None;
                    f.release = None;
                });
                if !listed {
                    close_sheet(app);
                }
            }
            Err(e) if listed => app.set_wait_note(say_cancel(&e).into()),
            Err(e) => sheet_error(app, say_cancel(&e)),
        },
    );
}

/// [`say`] for letting a payment go.
fn say_cancel(err: &CallError) -> String {
    match err {
        CallError::Rpc { name, .. } if name == "refused" => tr("The wallet will not let this payment go: it is already signed, already cancelled, or locked after a restore. Look at it in the payments", "Кошелёк не отпускает этот платёж: он уже подписан, уже отменён или заблокирован после восстановления. Посмотрите его в операциях").into(),
        _ => say(err),
    }
}

/// Opens a payment passed on by hand again: its text, as the wallet keeps
/// it, and a place for the recipient's reply. Works for a payment prepared
/// in an earlier run of the window too.
fn reopen_by_hand(app: &App, op: String) {
    let Some(client) = client() else { return };
    spawn(
        app,
        move || client.call("paycore.send.review", json!({ "op": op }), QUICK).map(|review| (op, review)),
        move |app, out| {
            let (op, review) = match out {
                Ok(found) => found,
                Err(e) => return app.set_wait_note(say_cancel(&e).into()),
            };
            let (Some(slate), Some(id)) = (text(&review, "slate").filter(|t| !t.is_empty()), text(&review, "slate_id")) else {
                return app.set_wait_note(tr("The wallet did not give the payment's text", "Кошелёк не выдал текст платежа").into());
            };
            let can_tor = with(|f| f.onion) && review.get("receiver_address").is_some_and(|a| !a.is_null());
            with(|f| f.send = Some(SendFlow { op, held: false, s2: None, slate_id: Some(id) }));
            show_out(app, tr("Pass on to the recipient", "Передайте получателю"), tr("The payment text, if the recipient lost it. Paste their reply below.", "Текст платежа, если получатель его потерял. Его ответ вставьте ниже."), &slate, true);
            app.set_out_can_tor(can_tor);
        },
    );
}

/// What to do with a payment that is signed and has not got into a block
/// (O43): said next to its text.
#[allow(non_snake_case)]
fn WAITING_NOTE() -> &'static str {
    tr(
        "Signed, not in a block yet. The wallet keeps sending it through Tor by itself. If Tor does not come up, choose below: wait for Tor and try again; send this one payment directly — the node then sees the address of your device; or switch Tor off for everything, so that you are not asked again. This text can be passed to the recipient as proof that you signed. A signed payment cannot be cancelled; while it is in no block you can try to take it back - below.",
        "Подписан, но в блок ещё не попал. Кошелёк сам отправляет его через Tor снова. Если Tor не поднимается, выберите ниже: ждать Tor и попробовать ещё раз; отправить этот один платёж напрямую — тогда нода увидит адрес вашего устройства; или выключить Tor для всех операций, чтобы не выбирать каждый раз. Этот текст можно передать получателю как подтверждение вашей подписи. Отменить подписанный платёж нельзя; пока он не в блоке, его можно попробовать отозвать — ниже.",
    )
}

/// The final text of a payment this wallet signed (K191), and - while it
/// waits for a block - what can be done about it.
fn show_signed(app: &App, op: String, waiting: bool, back: bool) {
    let Some(client) = client() else { return };
    let asked = op.clone();
    spawn(app, move || client.call("paycore.send.result", json!({ "op": asked }), QUICK), move |app, out| {
        let Some(slate) = out.ok().and_then(|v| text(&v, "slate")).filter(|t| !t.is_empty()) else {
            return app.set_wait_note(tr("The wallet did not give the payment's text", "Кошелёк не выдал текст платежа").into());
        };
        let note = if waiting { WAITING_NOTE() } else { tr("The final text of this payment, with your signature.", "Итоговый текст этого платежа, с вашей подписью.") };
        show_out(app, tr("Signed payment", "Подписанный платёж"), note, &slate, false);
        // K198: an agreement given once is kept with the payment and is not asked for again
        let agreed = with(|f| f.direct_ops.contains(&op));
        with(|f| f.resend = waiting.then_some(op));
        app.set_out_can_resend(waiting);
        // the direct way is a choice only while Tor is in use
        app.set_out_can_direct(waiting && !crate::tor_off() && !agreed);
        app.set_out_resend_note(direct_note(waiting, agreed, crate::tor_off()).into());
        app.set_out_can_back(back);
        app.set_out_back_plan(SharedString::new());
    });
}

// ----- the conversation, the key for messages, auto-receive, the password

/// Whether the wallet process of this window answers (for the scenario).
pub fn answers() -> bool {
    client().is_some_and(|c| c.call("host.status", json!({}), QUICK).is_ok())
}

/// Capture the window's selection before transferring the read to a worker.
fn chat_work<T>(read: impl FnOnce(Option<String>, Option<bool>) -> T + Send) -> impl FnOnce() -> T + Send {
    let (selected, network) = with(|f| (f.chat.clone(), f.testnet));
    move || read(selected, network)
}

/// Asks the host again now, not at the next tick.
fn refresh(app: &App) {
    read_wallet(app, true);
}

fn open_after_refresh(app: &App) {
    app.set_busy(true);
    with(|f| f.open_after_refresh = true);
    refresh(app);
}

fn read_wallet(app: &App, after_action: bool) {
    let Some(client) = client() else { return };
    if !with(|f| f.refresh.begin(after_action)) {
        return;
    }
    spawn(app, chat_work(move |chat, network| gather(&client, chat, network)), |app, view| {
        if !with(|f| f.refresh.finish()) {
            // An action completed during this read. Read its result before drawing.
            refresh(app);
            return;
        }
        apply(app, view);
        if with(|f| std::mem::take(&mut f.open_after_refresh)) {
            app.set_busy(false);
            app.set_page(1);
        }
    });
}

/// What went wrong with a Slatepack file, in the window's words.
fn file_words(e: crate::files::FileError) -> &'static str {
    use crate::files::FileError;
    match e {
        FileError::Empty => tr("There is no text to save", "Нет текста для сохранения"),
        FileError::Folder => tr("The folder for Slatepack files cannot be used", "Папку для файлов Slatepack не удалось использовать"),
        FileError::Write => tr("The file could not be written", "Файл не удалось записать"),
        FileError::Read => tr("The file could not be read", "Файл не удалось прочитать"),
        FileError::Large => tr("The file is too large to be a Slatepack text", "Файл слишком велик для текста Slatepack"),
        FileError::NotText => tr("The file is not text", "Файл не является текстом"),
    }
}

/// Pixels a module in a saved QR code: large enough to print and to scan
/// from a screen.
const QR_FILE_ZOOM: usize = 8;

/// The wallet's own folder for Slatepack files, if the profile is known.
fn slatepack_dir() -> Option<std::path::PathBuf> {
    with(|f| f.profile.as_deref().and_then(crate::files::folder))
}

/// Slatepack text to and from files of the wallet's own folder.
fn wire_files(app: &App) {
    let files = app.global::<crate::ui::Files>();
    files.on_save(|text| {
        let Some(dir) = slatepack_dir() else {
            return tr("The wallet's folder is not known", "Папка кошелька неизвестна").into();
        };
        match crate::files::save(&dir, &text, std::time::SystemTime::now()) {
            Ok(path) => fill(tr("Saved: {}", "Сохранено: {}"), &[&path.to_string_lossy()]).into(),
            Err(e) => file_words(e).into(),
        }
    });
    // O61: the QR code of a text the window shows, as a picture in the same folder
    files.on_save_qr(|text| {
        let Some(dir) = slatepack_dir() else {
            return tr("The wallet's folder is not known", "Папка кошелька неизвестна").into();
        };
        let Some(png) = crate::qr::grid(&text).and_then(|g| g.png(QR_FILE_ZOOM)) else {
            return tr("There is no QR code to save", "Нет QR-кода для сохранения").into();
        };
        match crate::files::save_qr(&dir, &png, std::time::SystemTime::now()) {
            Ok(path) => fill(tr("Saved: {}", "Сохранено: {}"), &[&path.to_string_lossy()]).into(),
            Err(e) => file_words(e).into(),
        }
    });
    let weak = app.as_weak();
    files.on_list(move || {
        let Some(dir) = slatepack_dir() else { return model(Vec::new()) };
        if let Some(app) = weak.upgrade() {
            app.global::<crate::ui::Files>().set_folder(dir.to_string_lossy().as_ref().into());
        }
        let found = crate::files::list(&dir);
        // a name is a file's own and may hold anything: shown as plain text
        let names: Vec<SharedString> = found.iter().map(|(name, _)| foreign_line(name, 80).text.into()).collect();
        with(|f| f.file_list = found.into_iter().map(|(_, path)| path).collect());
        model(names)
    });
    files.on_load(|index| {
        let path = usize::try_from(index).ok().and_then(|i| with(|f| f.file_list.get(i).cloned()));
        // what the file holds goes into the box as pasted text would: the
        // wallet reads and checks it when the user goes on
        path.and_then(|p| crate::files::load(&p).ok()).unwrap_or_default().into()
    });
}

/// The picture of a QR code for the window: one pixel a module. An empty
/// picture says "no code" (no text, or too long a text).
pub(crate) fn qr_picture(text: &str) -> slint::Image {
    let Some(grid) = crate::qr::grid(text) else { return slint::Image::default() };
    let Ok(side) = u32::try_from(grid.side()) else { return slint::Image::default() };
    let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&grid.rgba(), side, side);
    slint::Image::from_rgba8(buffer)
}

pub(crate) fn wire_qr(app: &App) {
    app.global::<crate::ui::Qr>().on_picture(|text| qr_picture(&text));
    // O75: finding a contact by a part of its name
    app.global::<crate::ui::Find>().on_matches(|name, part| name.to_lowercase().contains(part.trim().to_lowercase().as_str()));
}

/// What the window says next to a contact's name over a conversation:
/// that the name was changed for display, or that there is no key to write with.
fn name_note(c: &ContactRec, made: bool) -> &'static str {
    let shown = foreign_line(&c.raw_name, NAME_CHARS);
    if shown.changed {
        tr("name changed: it had hidden characters", "имя изменено: в нём были скрытые знаки")
    } else if shown.mixed_scripts {
        tr("look-alike letters in the name", "похожие буквы в имени")
    } else if !made {
        tr("create a message key first (My details)", "сначала создайте ключ для сообщений («Мои реквизиты»)")
    } else {
        ""
    }
}

fn wire_more(app: &App) {
    wire_files(app);
    wire_qr(app);
    let weak = app.as_weak();
    app.on_open_chat(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let Some(c) = usize::try_from(index).ok().and_then(|i| with(|f| f.contacts.get(i).cloned())) else { return };
        // O63: on a wide window the conversation stays on the main screen
        let inline = app.get_chat_inline() && app.get_page() == 1;
        let note = name_note(&c, app.get_identity_made());
        with(|f| f.chat = Some(c.key.clone()));
        app.set_chat_index(index);
        app.set_chat_name(c.shown.into());
        app.set_chat_note(note.into());
        app.set_chat_error(SharedString::new());
        app.set_chat_lines(model(Vec::new()));
        app.set_chat_can_write(app.get_identity_made());
        if !inline {
            app.set_page(4);
        }
        refresh(&app);
    });
    let weak = app.as_weak();
    app.on_chat_closed(move || {
        with(|f| f.chat = None);
        if let Some(app) = weak.upgrade() {
            app.set_chat_index(-1);
        }
    });
    // O70: a conversation in a window of its own
    let weak = app.as_weak();
    app.on_chat_apart(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let note = match apart::open(&app, index) {
            apart::Opened::New | apart::Opened::Already => "",
            apart::Opened::Full => tr(
                "Three conversations are open in windows already. Close one to open another.",
                "В отдельных окнах уже открыты три переписки. Закройте одну, чтобы открыть другую.",
            ),
            apart::Opened::No => {
                // no window can be made here: the page of the main window instead
                app.invoke_open_chat(index);
                app.set_page(4);
                ""
            }
        };
        app.set_apart_note(note.into());
    });
    let weak = app.as_weak();
    app.on_chat_send(move |words| {
        let Some(app) = weak.upgrade() else { return };
        let Some(key) = with(|f| f.chat.clone()) else { return };
        let words = words.to_string();
        if words.trim().is_empty() {
            return;
        }
        if words.len() > 2000 {
            app.set_chat_error(tr("A message is at most 2000 bytes", "Сообщение — не больше 2000 байт").into());
            return;
        }
        let Some(client) = client() else { return };
        app.set_chat_busy(true);
        app.set_chat_error(SharedString::new());
        spawn(
            &app,
            move || client.call("paycore.messages.send", json!({ "key": key, "text": words }), QUICK),
            |app, out| {
                app.set_chat_busy(false);
                match out {
                    Ok(_) => refresh(app),
                    Err(e) => app.set_chat_error(say(&e).into()),
                }
            },
        );
    });
    let weak = app.as_weak();
    app.on_op_show(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let Some(row) = usize::try_from(index).ok().and_then(|i| with(|f| f.op_rows.get(i).cloned())) else { return };
        match row {
            OpRef::Send(op) => {
                // the reply is pasted and the payment signed on the main screen
                app.set_page(1);
                reopen_by_hand(&app, op);
            }
            OpRef::Signed { op, waiting, back } => {
                app.set_page(1);
                show_signed(&app, op, waiting, back);
            }
            OpRef::Reply(slate_id) => {
                app.set_page(1);
                // K200: the sender's text is offered next to the reply where the wallet keeps it
                let other = with(|f| f.requests.contains(&slate_id)).then(|| slate_id.clone());
                let Some(reply) = with(|f| f.replies.get(&slate_id).cloned()) else {
                    // not answered in this run of the window: the wallet keeps it
                    let Some(client) = client() else { return };
                    spawn(&app, move || client.call("paycore.receive.reply", json!({ "slate_id": slate_id }), QUICK), |app, out| match out.ok().and_then(|v| text(&v, "slate")) {
                        Some(reply) => {
                            show_out(app, tr("Reply to the sender", "Ответ отправителю"), tr("The reply you made to this payment, if the sender lost it.", "Ваш ответ на этот платёж — если отправитель его потерял."), &reply, false);
                            offer_request(app, other);
                        }
                        None => app.set_wait_note(tr("The wallet did not give the payment's text", "Кошелёк не выдал текст платежа").into()),
                    });
                    return;
                };
                show_out(&app, tr("Reply to the sender", "Ответ отправителю"), tr("The reply you made to this payment, if the sender lost it.", "Ваш ответ на этот платёж, если отправитель его потерял."), &reply, false);
                offer_request(&app, other);
            }
            OpRef::None => {}
        }
    });
    let weak = app.as_weak();
    app.on_out_tor_off(move || {
        let Some(app) = weak.upgrade() else { return };
        // the same switch as on the main screen: the wallet locks, starts
        // without Tor, and the payment goes directly once it is open again
        app.set_sheet(0);
        app.invoke_switch_tor(false);
    });
    // K200: the sender's text of the payment whose reply is shown
    let weak = app.as_weak();
    app.on_out_request(move || {
        let Some(app) = weak.upgrade() else { return };
        let (Some(slate_id), Some(client)) = (with(|f| f.request_of.take()), client()) else { return };
        spawn(&app, move || client.call("paycore.receive.request", json!({ "slate_id": slate_id }), QUICK), |app, out| match out.ok().and_then(|v| text(&v, "slate")).filter(|t| !t.is_empty()) {
            Some(came) => show_out(app, tr("The payment as it came", "Платёж, как он пришёл"), tr("The sender's text of this payment, as your wallet got it. It is kept with the payment.", "Текст отправителя по этому платежу — таким его получил ваш кошелёк. Он хранится вместе с платежом."), &came, false),
            None => app.set_out_resend_note(tr("The wallet did not give the payment's text", "Кошелёк не выдал текст платежа").into()),
        });
    });
    // K197: taking a signed payment back - asked first, then done
    let weak = app.as_weak();
    app.on_out_back_ask(move || {
        let Some(app) = weak.upgrade() else { return };
        let (Some(op), Some(client)) = (with(|f| f.resend.clone()), client()) else { return };
        spawn(&app, move || client.call("paycore.send.take_back", json!({ "op": op, "plan": true }), QUICK), |app, out| match out {
            Ok(plan) => app.set_out_back_plan(back_ask_words(nano(field(&plan, "amount")), nano(field(&plan, "fee"))).into()),
            Err(err) => app.set_out_resend_note(say(&err).into()),
        });
    });
    let weak = app.as_weak();
    app.on_out_back_cancel(move || {
        let Some(app) = weak.upgrade() else { return };
        app.set_out_back_plan(SharedString::new());
    });
    let weak = app.as_weak();
    app.on_out_back_do(move || {
        let Some(app) = weak.upgrade() else { return };
        let (Some(op), Some(client)) = (with(|f| f.resend.clone()), client()) else { return };
        app.set_out_back_plan(SharedString::new());
        app.set_out_resend_note(tr("Signing…", "Подписываю…").into());
        spawn(&app, move || client.call("paycore.send.take_back", json!({ "op": op }), SIGN), |app, out| {
            match out {
                Ok(_) => {
                    // nothing more is offered for this payment from here
                    with(|f| f.resend = None);
                    app.set_out_can_resend(false);
                    app.set_out_can_direct(false);
                    app.set_out_can_back(false);
                    app.set_out_resend_note(tr("The taking back is signed and goes to the network. Follow both lines in the payments: one of the two will be in a block.", "Отзыв подписан и уходит в сеть. Следите за обеими строками в платежах: в блок попадёт один из двух.").into());
                }
                // what was made stays in the payments, to be finished or cancelled there
                Err(err) => app.set_out_resend_note(say(&err).into()),
            }
            refresh(app);
        });
    });
    let weak = app.as_weak();
    app.on_out_resend(move |direct| {
        let Some(app) = weak.upgrade() else { return };
        let (Some(op), Some(client)) = (with(|f| f.resend.clone()), client()) else { return };
        app.set_out_resend_note(tr("Sending…", "Отправляю…").into());
        // the same stored transaction; nothing is signed again. `direct`:
        // the owner's agreement to the direct way for this one payment (K192)
        spawn(&app, move || client.call("paycore.send.broadcast", resend_params(&op, direct), SIGN), move |app, out| {
            let said = match out.as_ref().ok().and_then(|v| v.get("outcome")).and_then(Value::as_str) {
                Some("accepted") => tr("The network took it. It will show as in a block once it is.", "Сеть приняла. Когда попадёт в блок, это будет видно в операциях."),
                Some("rejected") => tr("The network refused it. Look at the payment's state in the payments.", "Сеть отказала. Посмотрите состояние платежа в операциях."),
                Some(_) if direct => tr("Handed over with your agreement to send it directly. If Tor does not send it, it goes straight to the network.", "Передан с вашим согласием на прямую отправку. Если Tor его не отправит, он уйдёт в сеть напрямую."),
                Some(_) => tr("Handed over; the answer is not known yet. The wallet keeps trying.", "Передан; ответ пока неизвестен. Кошелёк продолжает попытки."),
                None => tr("Could not be sent now. The wallet keeps trying.", "Сейчас отправить не удалось. Кошелёк продолжает попытки."),
            };
            app.set_out_resend_note(said.into());
        });
    });
    let weak = app.as_weak();
    let for_hide = app.as_weak();
    let for_keep = app.as_weak();
    app.on_out_keep(move |index, on| {
        let Some(app) = for_keep.upgrade() else { return };
        let Some(commit) = with(|f| usize::try_from(index).ok().and_then(|i| f.outputs.get(i)).map(|o| o.commit.clone())) else { return };
        let Some(client) = client() else { return };
        app.set_sheet_error(SharedString::new());
        spawn(&app, move || client.call("paycore.outputs.keep", json!({ "commit": commit, "on": on }), QUICK), |app, out| match out {
            Ok(_) => refresh(app),
            Err(err) => app.set_sheet_error(say(&err).into()),
        });
    });
    let for_gather = app.as_weak();
    app.on_set_gather(move |on| {
        let Some(app) = for_gather.upgrade() else { return };
        crate::set_gather(on);
        app.set_gather(on);
        app.global::<crate::ui::Settings>().invoke_save();
        // the wallet is told at the next reading of the history
        refresh(&app);
    });
    let for_ask = app.as_weak();
    app.on_collect_ask(move || {
        let Some(app) = for_ask.upgrade() else { return };
        let Some(client) = client() else { return };
        app.set_sheet_error(SharedString::new());
        app.set_collect_done(SharedString::new());
        spawn(&app, move || client.call("paycore.outputs.collect", json!({ "plan": true }), QUICK), |app, out| match out {
            Ok(plan) => app.set_collect_plan(collect_words(plan.get("inputs").and_then(Value::as_u64).unwrap_or(0), nano(field(&plan, "amount")), nano(field(&plan, "fee"))).into()),
            Err(err) => app.set_sheet_error(say(&err).into()),
        });
    });
    let for_collect = app.as_weak();
    app.on_collect_do(move || {
        let Some(app) = for_collect.upgrade() else { return };
        let Some(client) = client() else { return };
        app.set_sheet_error(SharedString::new());
        app.set_collect_busy(true);
        spawn(&app, move || client.call("paycore.outputs.collect", json!({}), SIGN), |app, out| {
            app.set_collect_busy(false);
            app.set_collect_plan(SharedString::new());
            match out {
                Ok(_) => app.set_collect_done(tr("Signed. The outputs are held until the payment is in a block; it has its line in the payments.", "Подписано. Выходы заняты, пока платёж не попадёт в блок; у него своя строка в платежах.").into()),
                // what was made stays in the payments, to be finished or cancelled there
                Err(err) => app.set_sheet_error(say(&err).into()),
            }
            refresh(app);
        });
    });
    let for_uncollect = app.as_weak();
    app.on_collect_cancel(move || {
        let Some(app) = for_uncollect.upgrade() else { return };
        app.set_collect_plan(SharedString::new());
    });
    let for_pick = app.as_weak();
    app.on_out_pick(move |index| {
        let Some(app) = for_pick.upgrade() else { return };
        let changed = with(|f| {
            let Some(out) = usize::try_from(index).ok().and_then(|i| f.outputs.get(i)).filter(|o| o.state == "spendable") else { return false };
            if !f.picked.remove(&out.commit) {
                f.picked.insert(out.commit.clone());
            }
            true
        });
        if changed {
            app.set_spend_kept(false);
        }
        show_outputs(&app);
    });
    let for_unpick = app.as_weak();
    app.on_outs_unpick(move || {
        let Some(app) = for_unpick.upgrade() else { return };
        clear_output_choice(&app);
    });
    app.on_hide_history(move || {
        let Some(app) = for_hide.upgrade() else { return };
        // everything that has ended by the block the wallet stands at now
        let Some(tip) = with(|f| f.history_tip) else { return };
        crate::set_history_hidden(tip);
        app.global::<crate::ui::Settings>().invoke_save();
        refresh(&app);
    });
    let for_show = app.as_weak();
    app.on_show_history(move || {
        let Some(app) = for_show.upgrade() else { return };
        crate::set_history_hidden(0);
        app.global::<crate::ui::Settings>().invoke_save();
        refresh(&app);
    });
    app.on_set_confirmations(move |count| {
        let Some(app) = weak.upgrade() else { return };
        let count = u64::try_from(count).unwrap_or(1).clamp(1, 1000);
        crate::set_confirmations(count);
        app.set_confirmations(i32::try_from(count).unwrap_or(1));
        app.global::<crate::ui::Settings>().invoke_save();
        refresh(&app);
    });
    let weak = app.as_weak();
    app.on_chat_pay(move || {
        let Some(app) = weak.upgrade() else { return };
        let index = with(|f| f.chat.as_ref().and_then(|k| f.contacts.iter().position(|c| &c.key == k)));
        // with "By hand" chosen the payment is not addressed to the contact
        let by_hand = app.global::<crate::ui::Settings>().get_by_hand();
        app.set_send_to(index.filter(|_| !by_hand).and_then(|i| i32::try_from(i).ok()).unwrap_or(-1));
        app.set_sheet_error(SharedString::new());
        app.set_sheet(1);
    });
    // O64: asking for GRIN - an invoice made here; and changing a contact
    let weak = app.as_weak();
    app.on_invoice_make(move |typed| {
        let Some(app) = weak.upgrade() else { return };
        let value = match parse_amount(&typed) {
            Ok(v) => v,
            Err(e) => return sheet_error(&app, amount_error(e)),
        };
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        spawn(&app, move || client.call("paycore.invoice.issue", json!({ "amount": value.to_string() }), QUICK), |app, out| {
            app.set_sheet_busy(false);
            let made = out.as_ref().ok().and_then(|v| Some((text(v, "slate_id")?, text(v, "slate").filter(|t| !t.is_empty())?)));
            match (made, out) {
                (Some((id, slate)), _) => {
                    show_out(app, tr("Invoice to pass on", "Счёт для передачи"), tr("Pass this text to whoever pays you. Paste their answer below: the wallet checks it against this invoice and signs its part. The money is yours when the payment is in a block.", "Передайте этот текст тому, кто платит. Его ответ вставьте ниже: кошелёк сверит его с этим счётом и подпишет свою часть. Деньги ваши, когда платёж попадёт в блок."), &slate, true);
                    with(|f| {
                        f.send = None;
                        f.issued = Some(id);
                    });
                }
                (None, Err(e)) => sheet_error(app, say(&e)),
                (None, Ok(_)) => sheet_error(app, tr("The wallet did not give the invoice's text", "Кошелёк не выдал текст счёта")),
            }
        });
    });
    let weak = app.as_weak();
    app.on_contact_edit(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let Some(c) = usize::try_from(index).ok().and_then(|i| with(|f| f.contacts.get(i).cloned())) else { return };
        with(|f| f.edit_key = Some(c.key.clone()));
        app.set_contact_editing(true);
        // the name as it is shown: what was hidden in it does not come back
        app.set_contact_edit_name(c.shown.into());
        app.set_contact_edit_address(c.address.unwrap_or_default().into());
        app.set_contact_checked(c.checked);
        app.set_contact_code(SharedString::new());
        app.set_sheet_error(SharedString::new());
        app.set_sheet(6);
    });
    // O65: the check code of the contact being changed, and the owner's mark
    let weak = app.as_weak();
    app.on_contact_code_ask(move || {
        let Some(app) = weak.upgrade() else { return };
        let (Some(key), Some(client)) = (with(|f| f.edit_key.clone()), client()) else { return };
        app.set_sheet_error(SharedString::new());
        spawn(&app, move || client.call("paycore.contacts.code", json!({ "key": key }), QUICK), |app, out| match out {
            Ok(v) => app.set_contact_code(code_line(&v).into()),
            Err(e) => sheet_error(app, say(&e)),
        });
    });
    let weak = app.as_weak();
    app.on_contact_check(move |on| {
        let Some(app) = weak.upgrade() else { return };
        let (Some(key), Some(client)) = (with(|f| f.edit_key.clone()), client()) else { return };
        app.set_sheet_error(SharedString::new());
        spawn(&app, move || client.call("paycore.contacts.check", json!({ "key": key, "on": on }), QUICK), move |app, out| match out {
            Ok(_) => {
                app.set_contact_checked(on);
                refresh(app);
            }
            Err(e) => sheet_error(app, say(&e)),
        });
    });
    // O63: the signs next to a contact on the main screen, and the list of all
    let weak = app.as_weak();
    app.on_contact_pay(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let known = usize::try_from(index).ok().is_some_and(|i| with(|f| f.contacts.get(i).is_some()));
        // with "By hand" chosen the payment is not addressed to the contact
        let by_hand = app.global::<crate::ui::Settings>().get_by_hand();
        app.set_send_to(if known && !by_hand { index } else { -1 });
        app.set_sheet_error(SharedString::new());
        app.set_sheet(1);
    });
    let weak = app.as_weak();
    app.on_contact_remove(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let Some(key) = usize::try_from(index).ok().and_then(|i| with(|f| f.contacts.get(i).map(|c| c.key.clone()))) else { return };
        remove_contacts(&app, vec![key]);
    });
    let weak = app.as_weak();
    app.on_contacts_remove_all(move || {
        let Some(app) = weak.upgrade() else { return };
        remove_contacts(&app, with(|f| f.contacts.iter().map(|c| c.key.clone()).collect()));
    });
    let weak = app.as_weak();
    app.on_contacts_add_list(move |keys, addresses| {
        let Some(app) = weak.upgrade() else { return };
        let Some(testnet) = with(|f| f.testnet) else { return sheet_error(&app, tr("Wallet network unavailable", "Сеть кошелька недоступна")) };
        let taken = with(|f| f.contacts.len());
        let list = match contact_list(&keys, &addresses, testnet, taken) {
            Ok(list) => list,
            Err(why) => return sheet_error(&app, why),
        };
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        let count = list.len();
        spawn(
            &app,
            move || {
                // one after another; the first the wallet refuses stops the rest
                for (done, params) in list.into_iter().enumerate() {
                    client.call("paycore.contacts.set", params, QUICK).map_err(|e| (done, e))?;
                }
                Ok::<_, (usize, CallError)>(())
            },
            move |app, out| {
                app.set_sheet_busy(false);
                match out {
                    Ok(()) => app.set_contacts_note(fill(tr("Added: {}", "Добавлено: {}"), &[&count.to_string()]).into()),
                    Err((done, e)) => sheet_error(app, fill(tr("Contact {} of the list: {} Added before it: {}", "Контакт {} из списка: {} Добавлено до него: {}"), &[&done.saturating_add(1).to_string(), &say(&e), &done.to_string()])),
                }
                refresh(app);
            },
        );
    });
    let weak = app.as_weak();
    app.on_make_identity(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(client) = client() else { return };
        spawn(&app, move || client.call("paycore.identity.create", json!({}), QUICK), |app, _| refresh(app));
    });
    let weak = app.as_weak();
    app.on_set_auto(move |on| {
        let Some(app) = weak.upgrade() else { return };
        if !app.get_auto_known() || with(|f| f.auto_pending) { return; }
        let Some(client) = client() else { return };
        // the switch shows what was asked and keeps its place; a second press waits
        with(|f| f.auto_pending = true);
        app.set_auto_on(on);
        app.set_auto_receive(tr("saving…", "сохраняю…").into());
        spawn(&app, move || client.call("paycore.receive.set_auto", json!({ "on": on }), QUICK), |app, out| {
            with(|f| f.auto_pending = false);
            refresh(app);
            if let Err(e) = out {
                app.set_auto_receive(say(&e).into());
            }
        });
    });
    let weak = app.as_weak();
    app.on_change_password(move |old, first, second| {
        let Some(app) = weak.upgrade() else { return };
        let mut old = old.to_string();
        let mut first = first.to_string();
        let mut second = second.to_string();
        let problem = password_problem(&first, &second);
        second.zeroize();
        if let Some(problem) = problem {
            old.zeroize();
            first.zeroize();
            app.set_sheet_error(problem.into());
            return;
        }
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        app.set_security_note(SharedString::new());
        spawn(
            &app,
            move || {
                let done = client.call_secrets("host.profile.change_password", json!({}), &[("password", &old), ("new_password", &first)], SLOW);
                old.zeroize();
                first.zeroize();
                done
            },
            |app, out| {
                app.set_sheet_busy(false);
                match out {
                    Ok(_) => app.set_security_note(tr("The password is changed.", "Пароль изменён.").into()),
                    Err(e) => app.set_sheet_error(say(&e).into()),
                }
            },
        );
    });
    // Deleting the wallet: the host asks for the password and two of the
    // 24 words by number; the window only says which two and passes on
    // what was typed. The numbers change with every try.
    delete_places(app);
    let weak = app.as_weak();
    app.on_delete_wallet(move |password, first, second| {
        let Some(app) = weak.upgrade() else { return };
        let mut password = password.to_string();
        let (first, second) = (first.trim().to_lowercase(), second.trim().to_lowercase());
        let one_word = |w: &str| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase());
        if !one_word(&first) || !one_word(&second) {
            password.zeroize();
            app.set_sheet_error(tr("Type one word in each of the two fields", "Введите по одному слову в каждое из двух полей").into());
            return;
        }
        let Some(client) = client() else { return };
        let mut words = format!("{} {first} {} {second}", app.get_delete_place_a(), app.get_delete_place_b());
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        app.set_security_note(SharedString::new());
        spawn(
            &app,
            move || {
                let done = client.call_secrets("host.profile.delete", json!({}), &[("password", &password), ("words", &words)], SLOW);
                password.zeroize();
                words.zeroize();
                done
            },
            |app, out| {
                app.set_sheet_busy(false);
                delete_places(app);
                match out {
                    Ok(_) => {
                        // the wallet is gone: back to the first screen, as for a computer with no wallet
                        app.invoke_leave();
                        app.set_has_profile(false);
                    }
                    Err(e) => app.set_sheet_error(say(&e).into()),
                }
            },
        );
    });
    let weak = app.as_weak();
    app.on_show_words(move |password| {
        let Some(app) = weak.upgrade() else { return };
        let mut password = password.to_string();
        let Some(client) = client() else { return };
        app.set_sheet_busy(true);
        app.set_sheet_error(SharedString::new());
        spawn(
            &app,
            move || {
                let got = client.call_secret("host.profile.mnemonic", json!({}), "password", &password, SLOW);
                password.zeroize();
                got.map(|mut answer| match answer.get_mut("mnemonic").map(Value::take) {
                    Some(Value::String(words)) => Zeroizing::new(words),
                    _ => Zeroizing::new(String::new()),
                })
            },
            |app, out| {
                app.set_sheet_busy(false);
                match out {
                    Ok(words) if !words.is_empty() => {
                        app.set_words(model(words.split_whitespace().map(SharedString::from).collect()));
                        // O74: one line of the words, single-spaced, for "Copy the words"
                        app.set_words_line(words.split_whitespace().collect::<Vec<_>>().join(" ").into());
                        app.set_sheet(8);
                    }
                    Ok(_) => app.set_sheet_error(tr("The wallet sent no words", "Кошелёк не прислал слова").into()),
                    Err(e) => app.set_sheet_error(say(&e).into()),
                }
            },
        );
    });
    let weak = app.as_weak();
    app.on_words_closed(move || {
        if let Some(app) = weak.upgrade() {
            app.set_words(model(Vec::new()));
            app.set_words_line(SharedString::new());
        }
    });
}

// ----- the options of the login screen

/// Where the window keeps the user's own nodes and point: next to the
/// profile folder, like `ui.txt`.
fn own_dir() -> Option<std::path::PathBuf> {
    with(|f| f.profile.as_ref().and_then(|p| p.parent().map(std::path::Path::to_path_buf)))
}

const OWN_NODES: &str = "own-nodes.txt";
const OWN_POINT: &str = "own-point.json";

fn read_option(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => std::fs::read(path).map(Some),
        Ok(_) => Err(std::io::ErrorKind::InvalidData.into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn sync_own_files() -> std::io::Result<()> {
    let profile = with(|f| f.profile.clone()).ok_or(std::io::ErrorKind::NotFound)?;
    sync_own_at(&profile)
}

fn sync_own_at(profile: &Path) -> std::io::Result<()> {
    use std::{fs, io::ErrorKind};
    let dir = profile.parent().ok_or(ErrorKind::InvalidInput)?;
    let wanted = read_option(&dir.join(OWN_NODES))?;
    let entries = match fs::read_dir(profile) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()), // before creation
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_prefix("wallet-")) else { continue };
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) || !entry.file_type()?.is_dir() { continue; }
        let chain = profile.join(format!("chain-{id}"));
        match fs::symlink_metadata(&chain) {
            Ok(m) if !m.file_type().is_dir() => return Err(ErrorKind::InvalidData.into()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if wanted.is_none() { continue; }
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
                builder.recursive(false).create(&chain)?;
            }
            Err(e) => return Err(e),
        }
        {
            let path = chain.join(OWN_NODES);
            let existing = read_option(&path)?;
            if existing == wanted { continue; }
            match &wanted {
                Some(bytes) => fs::write(&path, bytes)?,
                None => fs::remove_file(&path)?,
            }
        }
    }
    Ok(())
}

/// Two different places among the 24 words, new each time: which words a
/// person has to type to delete the wallet. Not a secret, only not always
/// the same two, so they are taken from the clock.
fn delete_places(app: &App) {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let (a, b) = two_places(nanos);
    app.set_delete_place_a(a);
    app.set_delete_place_b(b);
}

/// Two different numbers from 1 to 24 out of one number.
fn two_places(from: u32) -> (i32, i32) {
    let first = from % 24;
    let second = (first.saturating_add(1).saturating_add((from / 24) % 23)) % 24;
    (i32::try_from(first.saturating_add(1)).unwrap_or(1), i32::try_from(second.saturating_add(1)).unwrap_or(2))
}

/// The notes under «Chain starting point» and «Own nodes».
fn own_notes(app: &App) {
    let Some(dir) = own_dir() else { return };
    let nodes = std::fs::read_to_string(dir.join(OWN_NODES)).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(0);
    if nodes > 0 {
        app.set_own_nodes(fill(tr("{} set · they get transactions first; from the next unlock", "заданы: {} · получат транзакции первыми; со следующего входа"), &[&nodes.to_string()]).into());
    }

}

/// The user's nodes: one `https://` address a line, at most 4.
fn check_nodes(text: &str) -> Result<String, &'static str> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if lines.len() > 4 {
        return Err(tr("At most 4 nodes", "Не больше 4 нод"));
    }
    for l in &lines {
        if !l.starts_with("https://") || l.len() > 200 || l.chars().any(char::is_whitespace) || l.len() <= "https://".len() {
            return Err(tr("Each line is one address starting with https://", "Каждая строка — один адрес, начинается с https://"));
        }
    }
    Ok(lines.iter().map(|l| format!("{l}\n")).collect())
}

/// Longest starting point taken: the longest the chain program reads.
const MAX_POINT: usize = 64 * 1024;

/// A starting point the chain program made: a JSON object; the chain
/// program checks it when it starts.
fn check_point(text: &str) -> Result<String, &'static str> {
    let t = text.trim();
    if t.len() >= MAX_POINT {
        return Err(tr("The point is too long", "Точка слишком длинная"));
    }
    match serde_json::from_str::<Value>(t) {
        Ok(v) if v.is_object() => Ok(format!("{t}\n")),
        _ => Err(tr("This is not a starting point: paste it whole, from { to }", "Это не стартовая точка: вставьте её целиком, от { до }")),
    }
}

/// Keep the starting point the wallet's chain program made (O38): next to
/// the profile, where a pasted one goes, in place of the one before. The
/// block it stands at comes back, for the note.
fn keep_point(dir: &Path, made: &str) -> Result<u64, &'static str> {
    let unfit = tr("The point made could not be read. Nothing was changed.", "Сделанную точку не удалось прочитать. Ничего не изменено.");
    let point = check_point(made).map_err(|_| unfit)?;
    let height = serde_json::from_str::<Value>(&point).ok().and_then(|v| v.get("height").and_then(Value::as_u64)).ok_or(unfit)?;
    let unwritten = tr("The point could not be saved. Nothing was changed.", "Точку не удалось сохранить. Ничего не изменено.");
    std::fs::create_dir_all(dir).map_err(|_| unwritten)?;
    // whole or not at all: the file read at the next unlock is never half a point
    let fresh = dir.join(format!("{OWN_POINT}.new"));
    std::fs::write(&fresh, &point).map_err(|_| unwritten)?;
    std::fs::rename(&fresh, dir.join(OWN_POINT)).map_err(|_| {
        let _ = std::fs::remove_file(&fresh);
        unwritten
    })?;
    Ok(height)
}

/// Android: the service starts the wallet process; it reads the choice from
/// ui.txt, which was just written.
#[cfg(target_os = "android")]
fn respawn_host(app: &App, _direct: bool, _notes: Arc<Mutex<VecDeque<Value>>>) {
    end_session();
    if let Some(client) = client() {
        spawn(app, move || client.call("service.restart", json!({}), SLOW), |app, out| {
            if let Err(e) = out {
                app.set_login_note(format!("{} {e}", tr("The wallet did not start:", "Кошелёк не запустился:")).into());
            }
        });
    }
}

/// Starts the wallet process again with or without `--chain-direct-post`.
/// Only while the wallet is locked: the login screen.
#[cfg(not(target_os = "android"))]
fn respawn_host(app: &App, direct: bool, notes: Arc<Mutex<VecDeque<Value>>>) {
    let (program, base) = with(|f| (f.program.clone(), f.base_args.clone()));
    // the flags belong to the chain process: without one the host refuses them
    let args = crate::chosen_args(&base, direct, crate::tor_off(), crate::nostr_off());
    end_session();
    with(|f| f.client = None);
    HOST.with(|h| drop(h.borrow_mut().take()));
    match spawn_host(&program, &args, notes) {
        Ok(host) => {
            let client = host.client();
            HOST.with(|h| *h.borrow_mut() = Some(host));
            with(|f| f.client = Some(client));
        }
        Err(err) => app.set_login_note(format!("{} {err}", tr("The wallet did not start:", "Кошелёк не запустился:")).into()),
    }
}

/// A part switched on or off (O42). On the login screen the wallet process
/// is started anew at once; in an open wallet the wallet is locked first,
/// and its process is started anew when the lock is through - so the part
/// is gone, or back, before the password is asked for again.
fn switch_part(app: &App, notes: &Arc<Mutex<VecDeque<Value>>>) {
    app.global::<crate::ui::Settings>().invoke_save();
    app.set_tor_on(!crate::tor_off());
    app.set_nostr_on(!crate::nostr_off());
    if app.get_busy() {
        return;
    }
    if app.get_page() == 0 {
        respawn_host(app, crate::direct(), notes.clone());
    } else {
        with(|f| f.restart_after_lock = true);
        app.invoke_leave();
    }
}

/// After a lock: the start that a switched part was waiting for, if any.
fn restart_if_switched(app: &App) -> bool {
    let Some(notes) = with(|f| if std::mem::take(&mut f.restart_after_lock) { f.notes.clone() } else { None }) else {
        return false;
    };
    respawn_host(app, crate::direct(), notes);
    with(|f| f.lock_unconfirmed = false);
    app.set_login_error(SharedString::new());
    true
}

fn finish_genesis_choice(app: &App, answer: Option<&Value>) {
    app.set_bootstrap_submitting(false);
    if answer.and_then(|v| v.get("scheduled")).and_then(Value::as_bool) == Some(true) {
        with(|f| f.restart_after_lock = true);
        app.invoke_leave();
    } else {
        app.set_bootstrap_feedback(tr("Could not confirm the startup choice. Try again after the wallet service is ready.", "Не удалось подтвердить выбор. Повторите, когда служба кошелька будет готова.").into());
    }
}

fn finish_output_rescan(app: &App, answer: Option<&Value>) {
    app.set_search_submitting(false);
    if answer.and_then(|v| v.get("state")).and_then(Value::as_str) == Some("reading") {
        app.set_search_active(true);
        app.set_search_feedback(tr("Full output scan requested.", "Полный поиск выходов запрошен.").into());
    } else {
        app.set_search_feedback(tr("The wallet service did not confirm the scan request.", "Служба кошелька не подтвердила запрос на поиск.").into());
    }
}

fn wire_options(app: &App, notes: Arc<Mutex<VecDeque<Value>>>) {
    checkpoint::wire(app);
    let weak = app.as_weak();
    app.on_rescan_outputs(move || {
        let Some(app) = weak.upgrade() else { return };
        if app.get_page() == 0 || app.get_busy() || app.get_search_active() ||
            app.get_search_submitting() || app.get_bootstrap_submitting() { return; }
        let Some(client) = client() else {
            finish_output_rescan(&app, None);
            return;
        };
        app.set_search_submitting(true);
        app.set_search_feedback(SharedString::new());
        spawn(&app, move || client.call("paycore.search.start", json!({}), QUICK), |app, out| {
            finish_output_rescan(app, out.ok().as_ref());
        });
    });
    let weak = app.as_weak();
    app.on_choose_genesis(move || {
        let Some(app) = weak.upgrade() else { return };
        if app.get_bootstrap_submitting() || app.get_busy() || app.get_page() == 0 { return; }
        let Some(client) = client() else {
            finish_genesis_choice(&app, None);
            return;
        };
        app.set_bootstrap_submitting(true);
        app.set_bootstrap_feedback(SharedString::new());
        spawn(&app, move || client.call("paycore.chain.bootstrap_genesis", json!({}), QUICK), |app, out| {
            finish_genesis_choice(app, out.ok().as_ref());
        });
    });
    // O66: the wallet's processes anew: the same road a switched part takes
    let weak = app.as_weak();
    app.on_restart_wallet(move || {
        let Some(app) = weak.upgrade() else { return };
        if app.get_busy() {
            return;
        }
        with(|f| f.restart_after_lock = true);
        app.invoke_leave();
    });
    let weak = app.as_weak();
    let for_tor = notes.clone();
    app.on_switch_tor(move |on| {
        let Some(app) = weak.upgrade() else { return };
        crate::set_tor_off(!on);
        // K193: in an open wallet Tor is switched without closing it - the
        // wallet process is told and holds back or starts what needs Tor.
        // If it cannot be told, the old way: lock and start it anew.
        let open = app.get_page() != 0;
        match (open, client()) {
            (true, Some(client)) => {
                app.global::<crate::ui::Settings>().invoke_save();
                app.set_tor_on(on);
                let notes = for_tor.clone();
                spawn(&app, move || client.call("host.tor", json!({ "off": !on }), QUICK), move |app, out| {
                    if out.is_err() {
                        switch_part(app, &notes);
                    } else {
                        refresh(app);
                    }
                });
            }
            _ => switch_part(&app, &for_tor),
        }
    });
    let weak = app.as_weak();
    let for_nostr = notes.clone();
    app.on_switch_nostr(move |on| {
        let Some(app) = weak.upgrade() else { return };
        crate::set_nostr_off(!on);
        switch_part(&app, &for_nostr);
    });
    let weak = app.as_weak();
    app.on_direct_changed(move |on| {
        let Some(app) = weak.upgrade() else { return };
        crate::set_direct(on);
        app.global::<crate::ui::Settings>().invoke_save();
        if app.get_page() == 0 && !app.get_busy() {
            respawn_host(&app, on, notes.clone());
        }
    });
    let weak = app.as_weak();
    app.on_make_point(move || {
        let Some(app) = weak.upgrade() else { return };
        if app.get_point_busy() {
            return;
        }
        let Some(client) = client() else { return };
        app.set_point_busy(true);
        app.set_point_note(SharedString::new());
        spawn(&app, move || client.call("paycore.chain.point", json!({}), QUICK), |app, out| {
            app.set_point_busy(false);
            let kept = match out {
                Ok(answer) => match (own_dir(), text(&answer, "point")) {
                    (Some(dir), Some(point)) => keep_point(&dir, &point).map_err(str::to_string),
                    _ => Err(no_point("").to_string()),
                },
                Err(err) => Err(say(&err)),
            };
            let kept = kept.and_then(|height| match sync_own_files() {
                Ok(()) => Ok(height),
                Err(_) => Err(tr("The point is saved, but could not be handed to the network check. Open the wallet again.", "Точка сохранена, но передать её проверке сети не удалось. Откройте кошелёк заново.").to_string()),
            });
            app.set_point_good(kept.is_ok());
            match kept {
                Ok(height) => {
                    own_notes(app);
                    let block = crate::sync::spaced(height);
                    app.set_point_note(point_made_words(&block).into());
                    // kept for the offer under "Waiting for you" and for another language
                    with(|f| f.point_made = Some(block));
                    refresh(app);
                }
                Err(why) => app.set_point_note(why.into()),
            }
        });
    });
    let weak = app.as_weak();
    app.on_open_own(move || {
        let Some(app) = weak.upgrade() else { return };
        let dir = own_dir();
        let read = |name: &str| dir.as_ref().and_then(|d| std::fs::read_to_string(d.join(name)).ok()).unwrap_or_default();
        app.set_own_nodes_text(read(OWN_NODES).into());
        app.set_sheet_error(SharedString::new());
        app.set_security_note(SharedString::new());
        app.set_sheet(9);
    });
    let weak = app.as_weak();
    app.on_save_own(move |nodes| {
        let Some(app) = weak.upgrade() else { return };
        let Some(dir) = own_dir() else {
            return app.set_sheet_error(tr("No profile folder", "Нет папки профиля").into());
        };
        let nodes = match check_nodes(&nodes) {
            Ok(n) => n,
            Err(e) => return app.set_sheet_error(e.into()),
        };
        let _ = std::fs::create_dir_all(&dir);
        {
            let at = dir.join(OWN_NODES);
            let body = &nodes;
            let done = if body.is_empty() {
                if at.exists() { std::fs::remove_file(&at) } else { Ok(()) }
            } else {
                std::fs::write(&at, body)
            };
            if done.is_err() {
                return app.set_sheet_error(tr("The file could not be written", "Файл не записался").into());
            }
        }
        if sync_own_files().is_err() {
            return app.set_sheet_error(tr("Chain options could not be applied", "Не удалось применить настройки цепи").into());
        }
        crate::fill_common(&app);
        own_notes(&app);
        app.set_sheet_error(SharedString::new());
        app.set_security_note(tr("Saved. It takes effect at the next unlock.", "Сохранено. Начнёт действовать при следующем входе.").into());
    });
}

// ----- creating and restoring

/// Three different word numbers (1–24) to ask back. Not a secret: it only
/// makes the user look at the paper.
fn three_of(count: usize) -> [usize; 3] {
    use std::hash::{BuildHasher, Hasher};
    let mut picked: Vec<usize> = Vec::with_capacity(3);
    let state = std::collections::hash_map::RandomState::new();
    let mut salt = 0u64;
    while picked.len() < 3 && count >= 3 {
        let mut h = state.build_hasher();
        h.write_u64(salt);
        salt = salt.wrapping_add(1);
        let n = usize::try_from(h.finish().checked_rem(u64::try_from(count).unwrap_or(24)).unwrap_or(0)).unwrap_or(0).saturating_add(1);
        if !picked.contains(&n) {
            picked.push(n);
        }
    }
    picked.sort_unstable();
    [picked.first().copied().unwrap_or(1), picked.get(1).copied().unwrap_or(2), picked.get(2).copied().unwrap_or(3)]
}

fn password_problem(first: &str, second: &str) -> Option<&'static str> {
    if first != second {
        return Some(tr("The passwords differ", "Пароли не совпали"));
    }
    // Any length is the owner's choice (the pages advise twelve characters
    // or more); only an empty one is not a password.
    if first.is_empty() {
        return Some(tr("Enter a password", "Введите пароль"));
    }
    if first.len() > 1024 {
        return Some(tr("The password is too long", "Пароль слишком длинный"));
    }
    None
}

fn wipe_words(app: &App) {
    app.set_words(model(Vec::new()));
    with(|f| {
        f.phrase.zeroize();
        f.ask = [0; 3];
    });
}

fn wire_create(app: &App) {
    let weak = app.as_weak();
    app.on_go_create(move || {
        if let Some(app) = weak.upgrade() {
            app.set_flow_error(SharedString::new());
            app.set_create_step(0);
            app.set_page(2);
        }
    });
    let weak = app.as_weak();
    app.on_go_restore(move || {
        if let Some(app) = weak.upgrade() {
            app.set_flow_error(SharedString::new());
            app.set_page(3);
        }
    });
    let weak = app.as_weak();
    app.on_back_to_login(move || {
        let Some(app) = weak.upgrade() else { return };
        if app.get_page() == 2 && app.get_create_step() == 2 {
            // «Показать слова ещё раз»
            app.set_create_step(1);
            return;
        }
        wipe_words(&app);
        app.set_page(0);
    });

    let weak = app.as_weak();
    app.on_make(move |first, second| {
        let Some(app) = weak.upgrade() else { return };
        let mut first = first.to_string();
        let mut second = second.to_string();
        let problem = password_problem(&first, &second);
        second.zeroize();
        if let Some(problem) = problem {
            first.zeroize();
            app.set_flow_error(problem.into());
            return;
        }
        let Some(client) = client() else { return };
        let network = if app.get_testnet() { "test" } else { "main" };
        app.set_busy(true);
        spawn(
            &app,
            move || {
                let made = client.call_secret("host.profile.create", json!({ "network": network }), "password", &first, SLOW);
                first.zeroize();
                made.map(|mut answer| match answer.get_mut("mnemonic").map(Value::take) {
                    Some(Value::String(words)) => Zeroizing::new(words),
                    _ => Zeroizing::new(String::new()),
                })
            },
            move |app, out| {
                app.set_busy(false);
                match out {
                    Ok(words) if !words.is_empty() => {
                        let shown: Vec<SharedString> = words.split_whitespace().map(SharedString::from).collect();
                        let ask = three_of(shown.len());
                        app.set_words(model(shown));
                        app.set_ask(model(ask.iter().map(|n| i32::try_from(*n).unwrap_or(1)).collect()));
                        with(|f| {
                            f.phrase = words;
                            f.ask = ask;
                        });
                        app.set_has_profile(true);
                        app.set_create_step(1);
                    }
                    Ok(_) => app.set_flow_error(tr("The wallet sent no words", "Кошелёк не прислал слова").into()),
                    Err(e) => app.set_flow_error(say(&e).into()),
                }
            },
        );
    });

    let weak = app.as_weak();
    app.on_check(move |a, b, c| {
        let Some(app) = weak.upgrade() else { return };
        if app.get_create_step() == 1 {
            app.set_flow_error(SharedString::new());
            app.set_create_step(2);
            return;
        }
        let typed = [a.trim().to_lowercase(), b.trim().to_lowercase(), c.trim().to_lowercase()];
        let wrong = with(|f| {
            let words: Vec<&str> = f.phrase.split_whitespace().collect();
            f.ask.iter().zip(typed.iter()).find(|(n, t)| words.get(n.saturating_sub(1)).copied() != Some(t.as_str())).map(|(n, _)| *n)
        });
        match wrong {
            Some(n) => app.set_flow_error(fill(tr("Word No. {} does not match. Check your copy or look at the words again.", "Слово № {} не совпало. Сверьтесь с записью или посмотрите слова ещё раз."), &[&n.to_string()]).into()),
            None => {
                wipe_words(&app);
                app.set_flow_error(SharedString::new());
                app.set_login_error(SharedString::new());
                note(&app, "Wallet created. Unlock it with the password.", "Кошелёк создан. Войдите паролем.");
                app.set_page(0);
            }
        }
    });

    let weak = app.as_weak();
    app.on_restore(move |words, first, second| {
        let Some(app) = weak.upgrade() else { return };
        let mut words = Zeroizing::new(words.split_whitespace().collect::<Vec<_>>().join(" "));
        let mut first = first.to_string();
        let mut second = second.to_string();
        let problem = password_problem(&first, &second);
        second.zeroize();
        let count = words.split_whitespace().count();
        let problem = problem.or(if count == 24 || count == 12 { None } else { Some(tr("24 words (or 12) separated by spaces are needed", "Нужно 24 слова (или 12) через пробел")) });
        if let Some(problem) = problem {
            first.zeroize();
            words.zeroize();
            app.set_flow_error(problem.into());
            return;
        }
        let Some(client) = client() else { return };
        let network = if app.get_testnet() { "test" } else { "main" };
        app.set_busy(true);
        spawn(
            &app,
            move || {
                let done = client.call_secrets("host.profile.restore", json!({ "network": network }), &[("password", &first), ("mnemonic", &words)], SLOW);
                first.zeroize();
                words.zeroize();
                done
            },
            move |app, out| {
                app.set_busy(false);
                match out {
                    Ok(_) => {
                        app.set_has_profile(true);
                        app.set_login_error(SharedString::new());
                        note(app, "Wallet restored. Unlock it with the password — it then finds its money in the chain.", "Кошелёк восстановлен. Войдите паролем — после входа он найдёт свои деньги в цепи.");
                        app.set_page(0);
                    }
                    Err(e) => app.set_flow_error(say(&e).into()),
                }
            },
        );
    });
}

/// The name of the local socket the Android service listens on.
#[cfg(target_os = "android")]
pub const SERVICE_SOCKET: &str = "org.grinsight.fly.core";

/// The wallet process: on Android the one the app's service keeps (the
/// window only connects; the service may still be starting it), elsewhere
/// a child of this window.
fn open_host(program: &Path, args: &[String], notes: Arc<Mutex<VecDeque<Value>>>) -> Result<Host, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (program, args);
        let mut last = String::new();
        for _ in 0..75 {
            let queue = notes.clone();
            let on_note: Box<dyn Fn(Value) + Send> = Box::new(move |note| {
                if let Ok(mut q) = queue.lock() {
                    if q.len() < MAX_NOTES {
                        q.push_back(note);
                    }
                }
            });
            match Host::connect_service(SERVICE_SOCKET, on_note) {
                Ok(host) => return Ok(host),
                Err(e) => last = e.to_string(),
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(last)
    }
    #[cfg(not(target_os = "android"))]
    spawn_host(program, args, notes)
}

/// The arguments of the wallet process with the file of Tor bridges
/// named: next to the profile folder, whether it is there yet or not.
pub(crate) fn with_tor_bridges(args: &[String]) -> Vec<String> {
    let mut all = args.to_vec();
    if all.iter().any(|a| a == "--tor-bridges") {
        return all;
    }
    let profile = all.iter().position(|a| a == "--profile").and_then(|i| all.get(i.saturating_add(1))).map(std::path::PathBuf::from);
    if let Some(file) = profile.as_deref().and_then(crate::tor::file) {
        all.push("--tor-bridges".into());
        all.push(file.to_string_lossy().into_owned());
    }
    all
}

/// Whether the program for Tor bridges stands where the processes that use
/// Tor look for it: next to their own programs.
fn tor_program_present(args: &[String]) -> bool {
    let name = if cfg!(target_os = "android") {
        "liblyrebird.so".to_string()
    } else {
        format!("lyrebird{}", std::env::consts::EXE_SUFFIX)
    };
    ["--onion", "--transport", "--chain"].iter().any(|flag| {
        let program = args.iter().position(|a| a == flag).and_then(|i| args.get(i.saturating_add(1)));
        program.and_then(|p| Path::new(p).parent().map(|dir| dir.join(&name))).is_some_and(|p| p.is_file())
    })
}

/// Whether the wallet process takes small outputs along with payments
/// now, as it says itself (K196). For the scenario.
pub(crate) fn gather_at_host() -> Option<bool> {
    client()?.call("paycore.history", json!({}), QUICK).ok()?.get("gather")?.as_bool()
}

/// How many Tor bridges the wallet process hands to the processes that
/// use Tor, as it says itself. For the scenario.
pub(crate) fn tor_lines_at_host() -> Option<u64> {
    let status = client()?.call("host.status", json!({}), QUICK).ok()?;
    status.get("tor_bridges")?.get("lines")?.as_u64()
}

fn tor_file() -> Option<std::path::PathBuf> {
    with(|f| f.profile.as_deref().and_then(crate::tor::file))
}

/// The words for how Tor is reached, on the login screen.
pub(crate) fn tor_way(app: &App) {
    use crate::tor::Mode;
    let (mode, own) = tor_file().map(|p| crate::tor::load(&p)).unwrap_or((Mode::Direct, String::new()));
    let words = match mode {
        Mode::Direct => tr("Directly · bridges are for where Tor is blocked", "Напрямую · мосты нужны там, где Tor блокируют").to_string(),
        Mode::Obfs4 => fill(tr("Through {} built-in obfs4 bridges", "Через встроенные мосты obfs4: {}"), &[&crate::tor::built_in("obfs4").len().to_string()]),
        Mode::Snowflake => tr("Through Snowflake", "Через Snowflake").to_string(),
        Mode::Own => fill(tr("Through your own bridges: {}", "Через свои мосты: {}"), &[&own.lines().count().to_string()]),
    };
    app.set_tor_way(words.into());
}

fn own_error_words(e: crate::tor::OwnError) -> String {
    use crate::tor::OwnError;
    match e {
        OwnError::Empty => tr("No bridge lines: paste at least one", "Нет строк мостов: вставьте хотя бы одну").to_string(),
        OwnError::TooMany => fill(tr("Too many bridges: {} at most", "Слишком много мостов: не больше {}"), &[&crate::tor::MAX_LINES.to_string()]),
        OwnError::TooLong(n) => fill(tr("Line {} is too long for a bridge line", "Строка {} слишком длинная для строки моста"), &[&n.to_string()]),
        OwnError::NotABridge(n) => fill(
            tr("Line {} is not a bridge line: it should read like obfs4 203.0.113.7:443 <40 hex digits> cert=…", "Строка {} — не строка моста: она выглядит как obfs4 203.0.113.7:443 <40 шестнадцатеричных знаков> cert=…"),
            &[&n.to_string()],
        ),
    }
}

fn wire_tor(app: &App) {
    tor_way(app);
    let weak = app.as_weak();
    app.on_open_tor(move || {
        let Some(app) = weak.upgrade() else { return };
        let (mode, own) = tor_file().map(|p| crate::tor::load(&p)).unwrap_or((crate::tor::Mode::Direct, String::new()));
        app.set_tor_mode(mode.index());
        app.set_tor_own_text(own.into());
        app.set_tor_program(with(|f| f.tor_program));
        app.set_sheet_error(SharedString::new());
        app.set_security_note(SharedString::new());
        app.set_sheet(12);
    });
    let weak = app.as_weak();
    app.on_save_tor(move |mode, own| {
        let Some(app) = weak.upgrade() else { return };
        app.set_security_note(SharedString::new());
        let (Some(path), Some(mode)) = (tor_file(), crate::tor::Mode::of(mode)) else {
            return app.set_sheet_error(tr("No profile folder", "Нет папки профиля").into());
        };
        match crate::tor::save(&path, mode, &own) {
            Err(_) => app.set_sheet_error(tr("The file could not be written", "Файл не записался").into()),
            Ok(Err(e)) => app.set_sheet_error(own_error_words(e).into()),
            Ok(Ok(())) => {
                bridges::manual_saved(&app);
                tor_way(&app);
                app.set_sheet_error(SharedString::new());
                app.set_security_note(tr("Saved. It is used from the next unlock.", "Сохранено. Действует со следующего входа.").into());
            }
        }
    });
}

fn spawn_host(program: &Path, args: &[String], notes: Arc<Mutex<VecDeque<Value>>>) -> Result<Host, String> {
    let args = &with_tor_bridges(args);
    Host::spawn(
        program,
        args,
        Box::new(move |note| {
            if let Ok(mut q) = notes.lock() {
                if q.len() < MAX_NOTES {
                    q.push_back(note);
                }
            }
        }),
    )
    .map_err(|e| e.to_string())
}

impl Live {
    /// Starts the host and makes the login, the main window and its windows
    /// real.
    pub fn start(app: &App, program: &Path, args: &[String]) -> Result<Live, String> {
        end_session();
        app.set_busy(false);
        fill_common(app);
        app.set_live(true);
        let notes = Arc::new(Mutex::new(VecDeque::new()));
        let host = open_host(program, args, notes.clone())?;
        let first = host.client();
        HOST.with(|h| *h.borrow_mut() = Some(host));
        with(|f| {
            f.client = Some(first.clone());
            f.program = program.to_path_buf();
            // everything switched on: what is switched off is taken out at each start
            f.base_args = crate::chosen_args(args, false, false, false);
            f.notes = Some(notes.clone());
            f.profile = args.iter().position(|a| a == "--profile").and_then(|i| args.get(i.saturating_add(1))).map(std::path::PathBuf::from);
            f.tor_program = tor_program_present(args);
        });
        let status = first.call("host.status", json!({}), QUICK).map_err(|e| e.to_string())?;
        app.set_wallet_name(name(tr("wallet", "кошелёк")));
        match status.get("profile").and_then(Value::as_str) {
            Some("none") => {
                app.set_has_profile(false);
                if cfg!(target_os = "android") {
                    note(app, "There is no wallet on this phone yet.", "На этом телефоне кошелька ещё нет.");
                } else {
                    note(app, "There is no wallet on this computer yet.", "На этом компьютере кошелька ещё нет.");
                }
            }
            // the wallet stayed open (Android's service kept it): straight in
            Some("unlocked") => {
                open_after_refresh(app);
            }
            _ => {}
        }
        wire_create(app);
        wire_sheets(app);
        wire_more(app);
        wire_options(app, notes.clone());
        own_notes(app);
        wire_tor(app);

        let weak = app.as_weak();
        app.on_enter(move |password| {
            let Some(app) = weak.upgrade() else { return };
            if app.get_busy() { return; }
            let Some(client) = client() else { return };
            let retry_lock = with(|f| f.lock_unconfirmed);
            // the user's own nodes and point go where the chain process reads them
            if sync_own_files().is_err() {
                return app.set_login_error(tr("Chain options could not be applied", "Не удалось применить настройки цепи").into());
            }
            app.set_busy(true);
            let mut password = password.to_string();
            spawn(
                &app,
                move || {
                    let opened = enter_after_lock(retry_lock,
                        || client.call("host.lock", json!({}), SLOW).map(|_| ()),
                        || client.call_secret("host.unlock", json!(null), "password", &password, SLOW));
                    password.zeroize();
                    opened
                },
                |app, opened| {
                    match opened {
                        Ok(_) => {
                            with(|f| f.lock_unconfirmed = false);
                            app.set_login_note(SharedString::new());
                            open_after_refresh(app);
                        }
                        Err(err) => {
                            app.set_busy(false);
                            app.set_login_error(say(&err).into());
                        }
                    }
                },
            );
        });

        let weak = app.as_weak();
        let timer = Timer::default();
        timer.start(TimerMode::Repeated, REFRESH, move || {
            let Some(app) = weak.upgrade() else { return };
            if !matches!(app.get_page(), 1 | 4 | 5) {
                return;
            }
            take_notes(&notes);
            read_wallet(&app, false);
        });

        let weak = app.as_weak();
        app.on_leave(move || {
            end_session();
            with(|f| {
                f.lock_unconfirmed = true;
                f.testnet = None;
                f.phrase.zeroize();
                f.send = None;
                f.picked.clear();
                f.receive = None;
                f.invoice = None;
                f.incoming.clear();
                f.waits.clear();
                f.release = None;
                f.op_to.clear();
                f.chat = None;
            });
            // O70: no conversation stays on the screen behind a locked wallet
            apart::close_all();
            // O71: a try of the bridges cut short leaves the owner's choice in the file
            bridges::leave();
            if let Some(app) = weak.upgrade() {
                app.set_bootstrap_submitting(false);
                app.set_checkpoint_file_action(0);
                app.set_bootstrap_feedback(SharedString::new());
                app.set_search_submitting(false);
                app.set_search_feedback(SharedString::new());
                // O74: words copied and still on the clipboard do not outlive the lock; O73: nor an open "?"
                app.invoke_clear_copied_words();
                app.set_words_line(SharedString::new());
                app.global::<crate::ui::Help>().set_open(false);
                app.set_spend_kept(false);
                app.set_apart_note(SharedString::new());
                app.set_sign_bridges_note(SharedString::new());
                app.set_sign_bridges_busy(false);
                tor_way(&app);
                app.set_sheet_busy(false);
                app.set_words(model(Vec::new()));
                app.set_sheet(0);
                app.set_page(0);
                app.set_login_error(SharedString::new());
                let unavailable = tr("Wallet lock was not confirmed. Retry before opening.", "Кошелёк не подтвердил блокировку. При входе она будет повторена.");
                let Some(client) = client() else {
                    app.set_busy(false);
                    if !restart_if_switched(&app) {
                        app.set_login_error(unavailable.into());
                    }
                    return;
                };
                app.set_busy(true);
                spawn(&app, move || client.call("host.lock", json!({}), SLOW), move |app, receipt| {
                    app.set_busy(false);
                    // a process started anew holds no open wallet: that is a lock too
                    if restart_if_switched(app) {
                        return;
                    }
                    if receipt.is_ok() {
                        with(|f| f.lock_unconfirmed = false);
                    } else {
                        app.set_login_error(unavailable.into());
                    }
                });
            }
        });
        Ok(Live { _timer: timer })
    }
}

/// For `--snapshot` with a host: a Testnet profile with a throwaway password
/// is made in the given folder if there is none (its words are dropped
/// unread), opened, and the screens are filled from the host's answers.
pub fn snapshot_fill(app: &App, program: &Path, args: &[String]) -> Result<Host, String> {
    const THROWAWAY: &str = "snapshot-only-not-a-wallet";
    fill_common(app);
    app.set_live(true);
    let host = spawn_host(program, args, Arc::new(Mutex::new(VecDeque::new())))?;
    let client = host.client();
    let status = client.call("host.status", json!({}), QUICK).map_err(|e| format!("host.status: {e}"))?;
    if status.get("profile").and_then(Value::as_str) == Some("none") {
        let mut made = client
            .call_secret("host.profile.create", json!({ "network": "test" }), "password", THROWAWAY, SLOW)
            .map_err(|e| format!("host.profile.create: {e}"))?;
        if let Some(Value::String(mut words)) = made.get_mut("mnemonic").map(Value::take) {
            words.zeroize();
        }
    }
    client.call_secret("host.unlock", json!(null), "password", THROWAWAY, SLOW).map_err(|e| format!("host.unlock: {}", say(&e)))?;
    with(|f| f.client = Some(client.clone()));
    app.set_wallet_name(name(tr("test", "проба")));
    apply(app, gather(&client, with(|f| f.chat.clone()), with(|f| f.testnet)));
    Ok(host)
}

#[cfg(test)]
mod password_tests {
    use super::password_problem;

    /// A password of any length is accepted — one character too; an empty
    /// one, two that differ and one beyond what the wallet process takes
    /// are not.
    #[test]
    fn a_password_of_any_length_is_accepted() {
        assert_eq!(password_problem("1", "1"), None);
        assert_eq!(password_problem("пароль", "пароль"), None);
        assert_eq!(password_problem(&"x".repeat(1024), &"x".repeat(1024)), None);
        assert_eq!(password_problem("", ""), Some("Enter a password"));
        assert_eq!(password_problem("a", "b"), Some("The passwords differ"));
        assert_eq!(password_problem(&"x".repeat(1025), &"x".repeat(1025)), Some("The password is too long"));
    }
}

#[cfg(test)]
mod option_tests {
    use super::*;
    use std::fs;
    /// O38: the point the wallet's chain program made is kept whole where
    /// a pasted one goes, in place of the one before; one that is not a
    /// point leaves the one before as it was. A real point is longer than
    /// 8 KB and is taken.
    #[test]
    fn a_point_the_wallet_made_is_kept_whole_or_not_at_all() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("fly-keep-point-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let real = format!(r#"{{"version":1,"height":4115520,"context":"{}"}}"#, "7".repeat(9300));
        assert_eq!(keep_point(&dir, &real), Ok(4_115_520));
        assert_eq!(fs::read_to_string(dir.join(OWN_POINT))?, format!("{real}\n"));
        let later = r#"{"height":4116240}"#;
        assert_eq!(keep_point(&dir, &format!("  {later}\n")), Ok(4_116_240));
        assert_eq!(fs::read_to_string(dir.join(OWN_POINT))?, format!("{later}\n"));
        let longest = format!(r#"{{"height":5,"context":"{}"}}"#, "7".repeat(MAX_POINT));
        for unfit in ["", "not a point", "[1,2]", r#"{"height":"high"}"#, r#"{"hash":"ab"}"#, r#"{"height":4116240"#, longest.as_str()] {
            assert!(keep_point(&dir, unfit).is_err(), "{}", unfit.len());
            assert_eq!(fs::read_to_string(dir.join(OWN_POINT))?, format!("{later}\n"), "{}", unfit.len());
        }
        assert_eq!(fs::read_dir(&dir)?.count(), 1, "something else was left in the folder");
        fs::remove_dir_all(&dir)
    }

    /// Each reason the chain program gives for making no point is told
    /// apart, in the window's own words, and each says nothing changed.
    #[test]
    fn why_no_point_was_made_is_said_plainly() {
        let said = [
            "a starting point is made only when the tip is confirmed by public nodes; it is not yet",
            "a starting point is not made while what is confirmed is provisional: nobody vouches",
            "no new starting point can be made yet: it would be at block 20",
            "the chain process is busy; ask again in a moment",
            "something never heard before",
        ]
        .map(no_point);
        let mut different: Vec<&str> = said.to_vec();
        different.sort_unstable();
        different.dedup();
        assert_eq!(different.len(), said.len());
        assert_eq!(no_point("the chain process did not answer"), said[3]);
        assert_eq!(no_point("the chain process is not running now"), said[3]);
        for line in said {
            assert!(line.ends_with(tr("Nothing was changed.", "Ничего не изменено.")), "{line}");
            assert!(!line.contains("provisional") && !line.contains("chain process"), "{line}");
        }
    }

    #[test]
    fn node_options_ignore_invalid_legacy_points_and_preserve_old_files() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("fly-migration-{}", std::process::id()));
        fs::create_dir(&dir)?;
        let profile = dir.join("profile");
        let id = "0123456789abcdef0123456789abcdef";
        fs::create_dir(&profile)?;
        fs::create_dir(profile.join(format!("wallet-{id}")))?;
        let source = dir.join(OWN_POINT);
        fs::create_dir(&source)?;
        fs::write(dir.join(OWN_NODES), b"configured nodes")?;
        let chain = profile.join(format!("chain-{id}"));
        sync_own_at(&profile)?;
        assert_eq!(fs::read(chain.join(OWN_NODES))?, b"configured nodes");
        assert!(!chain.join(OWN_POINT).exists());
        fs::write(chain.join(OWN_POINT), b"legacy data")?;
        fs::remove_file(dir.join(OWN_NODES))?;
        sync_own_at(&profile)?;
        assert!(!chain.join(OWN_NODES).exists());
        assert_eq!(fs::read(chain.join(OWN_POINT))?, b"legacy data");
        fs::remove_file(chain.join(OWN_POINT))?;
        fs::remove_dir(source)?;
        fs::remove_dir(chain)?;
        fs::remove_dir(profile.join(format!("wallet-{id}")))?;
        fs::remove_dir(profile)?;
        fs::remove_dir(dir)
    }
}


#[cfg(test)]
mod signing_tests {
    use super::*;

    #[test]
    fn recipient_and_chat_keep_foreign_text_notices() {
        let addr = address_of_key(&[7u8; 32], true);
        for (words, expected) in [
            ("Desk 3", ""),
            ("Desk\t3", tr("Text adjusted", "Текст изменён")),
            ("DeskЯ", tr("Look-alike letters", "Похожие буквы")),
            ("DeskЯ\t3", tr("Text adjusted · look-alike letters", "Текст изменён · похожие буквы")),
        ] {
            let mut f = Flow::default();
            f.contacts.push(ContactRec { key: String::new(), shown: foreign_text(words, 80).text,
                raw_name: words.into(), address: Some(addr.clone()), checked: false });
            let (_, note, groups) = who_of(&f, Some(&addr));
            assert_eq!(note, expected);
            assert!(!groups.is_empty());
            let line = chat_line(false, 10, words, "", 11);
            assert_eq!(line.state.as_str(), expected);
            assert_eq!(line.warn, !expected.is_empty());
        }
        assert_eq!(chat_line(true, 10, "Desk 3", "relay_accepted", 11).kind, 0);
        assert_eq!(chat_line(true, 10, "Desk 3", "relay_accepted", 11).state.as_str(),
                   tr("accepted for delivery", "принято к доставке"));
    }

    #[test]
    fn resumed_signing_displays_the_persisted_recipient() {
        let key = [7u8; 32];
        let addr = address_of_key(&key, true);
        let mut f = Flow::default();
        f.contacts.push(ContactRec { key: String::new(), shown: "Alice".into(),
            raw_name: "Alice".into(), address: Some(addr.clone()), checked: false });
        let flow = SendFlow { op: "fixture".into(), held: false, s2: None, slate_id: None };
        let review = json!({"op": "fixture", "receiver_address": hex(&key)});
        let expected = who_of(&f, Some(&addr));
        assert_eq!(review_recipient(&f, &flow, &review, true), Some(expected.clone()));
        f.op_to.insert(flow.op.clone(), ("Old label".into(), Some(addr)));
        assert_eq!(review_recipient(&f, &flow, &review, true), Some(expected));
        assert_eq!(review_recipient(&f, &flow, &json!({"op": "other", "receiver_address": null}), true), None);
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;

    #[test]
    fn wallet_action_supersedes_an_inflight_read_without_an_overlapping_read() {
        let mut refresh = RefreshState::default();
        assert!(refresh.begin(false));
        assert!(!refresh.begin(true));
        assert!(!refresh.begin(false));
        assert!(!refresh.begin(true));
        assert!(!refresh.finish(), "discard the pre-action wallet observation");
        assert!(refresh.begin(true));
        assert!(!refresh.begin(false));
        assert!(refresh.finish(), "a timer tick must not discard a current observation");
        assert!(refresh.begin(false));
    }

    #[test]
    fn periodic_read_keeps_the_chat_open_in_the_window() {
        with(|f| f.chat = Some("test-contact".into()));
        let read = chat_work(|selected, _| selected);
        with(|f| f.chat = None);
        let selected = std::thread::spawn(read).join().ok().flatten();
        assert_eq!(selected.as_deref(), Some("test-contact"));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn old_answer_cannot_update_a_reopened_window() {
        let shown = Arc::new(AtomicBool::new(false));
        let marker = shown.clone();
        let late = scoped_callback(move |()| marker.store(true, Ordering::SeqCst));
        end_session(); // Leave, even when the host lock receipt is unavailable.
        let attempted = std::cell::Cell::new(false);
        let failed = enter_after_lock(true, || Err("lock unavailable"), || { attempted.set(true); Ok(()) });
        assert_eq!(failed, Err("lock unavailable"));
        assert!(!attempted.get());
        let next = enter_after_lock(true, || Ok::<_, &str>(()), || { attempted.set(true); Ok(()) });
        assert!(next.is_ok() && attempted.get());
        end_session(); // The replacement session.
        late(());
        assert!(!shown.load(Ordering::SeqCst));
        scoped_callback(|()| shown.store(true, Ordering::SeqCst))(());
        assert!(shown.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod chip_tests {
    use super::*;

    #[test]
    fn changing_the_payment_outputs_requires_new_consent() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        wire_more(&app);
        let marked = |commit: &str| OutRow {
            commit: commit.into(), value: 1, height: 1, state: "spendable".into(), kept: true,
        };
        let first = marked("aa");
        let second = marked("bb");
        with(|f| {
            f.outputs = vec![first.clone(), second];
            f.picked.clear();
        });
        app.invoke_out_pick(0);
        app.set_spend_kept(true);
        app.invoke_out_pick(-1);
        assert!(app.get_spend_kept());
        app.invoke_out_pick(1);
        assert!(!app.get_spend_kept());
        assert!(with(|f| chosen_params(&f.outputs, &f.picked, app.get_spend_kept())).is_err());

        app.set_spend_kept(true);
        apply(&app, View { outputs: vec![first], ..View::default() });
        assert!(!app.get_spend_kept());
        assert!(with(|f| chosen_params(&f.outputs, &f.picked, app.get_spend_kept())).is_err());

        // a mark put on another chosen output meanwhile: the consent given before it does not cover it
        let plain = OutRow { kept: false, ..marked("dd") };
        with(|f| {
            f.outputs = vec![marked("cc"), plain.clone()];
            f.picked.clear();
        });
        app.invoke_out_pick(0);
        app.invoke_out_pick(1);
        app.set_spend_kept(true);
        apply(&app, View { outputs: vec![marked("cc"), plain], ..View::default() });
        assert!(app.get_spend_kept(), "nothing changed: nothing is asked again");
        apply(&app, View { outputs: vec![marked("cc"), marked("dd")], ..View::default() });
        assert!(!app.get_spend_kept());
        Ok(())
    }

    #[test]
    fn closing_a_send_sheet_forgets_its_selected_outputs() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        wire_sheets(&app);
        wire_more(&app);
        with(|f| {
            f.outputs = vec![OutRow {
                commit: "aa".into(), value: 1, height: 1, state: "spendable".into(), kept: false,
            }];
            f.picked.clear();
        });
        app.set_sheet(1);
        app.invoke_out_pick(0);
        assert_eq!(
            with(|f| chosen_params(&f.outputs, &f.picked, app.get_spend_kept())),
            Ok(Some((vec!["aa".into()], false))),
        );
        app.invoke_sheet_closed(1);
        app.set_sheet(0);
        app.set_sheet(1);
        assert_eq!(with(|f| chosen_params(&f.outputs, &f.picked, app.get_spend_kept())), Ok(None));
        Ok(())
    }

    /// Money held by a payment under way is said in a line of its own, with its amount.
    #[test]
    fn held_money_is_said_in_a_line_of_its_own() {
        assert_eq!(held_line(0, 0, 0), "");
        assert_eq!(held_line(5_994_000_000, 0, 0), "5.994 GRIN held by a payment under way");
        assert_eq!(held_line(0, 60_000_000_000, 0), "60.00 GRIN maturing");
        assert_eq!(held_line(1_000_000_000, 2_000_000_000, 0), "1.00 GRIN held by a payment under way · 2.00 GRIN maturing");
        // O51: what the owner marked is said first
        assert_eq!(held_line(1_000_000_000, 0, 5_000_000_000), "5.00 GRIN marked “not to be spent” · 1.00 GRIN held by a payment under way");
        // O51, K195: the choice for a payment, as the wallet is asked
        let out = |commit: &str, state: &str, kept: bool| OutRow { commit: commit.into(), value: 1, height: 1, state: state.into(), kept };
        let outs = [out("aa", "spendable", false), out("bb", "spendable", true), out("cc", "reserved", false)];
        let pick = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<std::collections::BTreeSet<String>>();
        assert_eq!(chosen_params(&outs, &pick(&[]), true), Ok(None), "nothing chosen: the wallet chooses");
        assert_eq!(chosen_params(&outs, &pick(&["aa"]), false), Ok(Some((vec!["aa".into()], false))));
        assert_eq!(chosen_params(&outs, &pick(&["aa"]), true), Ok(Some((vec!["aa".into()], false))), "the word is said only for a marked one");
        assert!(chosen_params(&outs, &pick(&["aa", "bb"]), false).is_err(), "a marked one needs the owner's word");
        assert_eq!(chosen_params(&outs, &pick(&["aa", "bb"]), true), Ok(Some((vec!["aa".into(), "bb".into()], true))));
        assert_eq!(chosen_params(&outs, &pick(&["zz"]), false), Ok(None), "what the wallet no longer lists is not asked for");
        assert_eq!((out_state("spendable"), out_state("reserved")), ("", "held by a payment under way"));
    }

    /// The sign "show the text again" stands only at a line that has a text to show.
    #[test]
    fn the_sign_to_show_a_text_stands_only_where_there_is_one() {
        assert!(OpRef::Send("op".into()).shows());
        assert!(OpRef::Reply("slate".into()).shows());
        assert!(!OpRef::None.shows());
        let app = include_str!("../ui/app.slint");
        // the sign is drawn by the line's own word, and a line without it has nothing to press
        assert_eq!(app.matches("if op.show:").count(), 1);
    }

    /// Bridges are chosen from the main screen too: the button of the
    /// "Link" card opens the same window as the one on the entry screen,
    /// in both layouts. The held money is written larger than other marks.
    #[test]
    fn bridges_are_reached_from_the_main_screen_and_held_money_is_written_larger() {
        let app = include_str!("../ui/app.slint");
        assert_eq!(app.matches("bridges => { root.tor-options(); }").count(), 2);
        assert_eq!(app.matches("LinkCard {").count(), 2);
        assert_eq!(app.matches("tor-options => { root.open-tor(); }").count(), 2);
        // the button of the connection card, and the one in Settings (O73)
        assert_eq!(app.matches("clicked => { root.bridges(); }").count(), 2);
        assert!(app.contains("Chip { text: root.incoming; text-size: 15px; }"));
        assert!(include_str!("../ui/parts.slint").contains("in property <length> text-size: 13px;"));
    }

    /// "VERIFIED" is not said while the wallet cannot yet send: neither
    /// behind the tip nor while its old outputs are still looked for. Each
    /// state says where the wallet is and what opens sending.
    #[test]
    fn the_mark_under_the_buttons_says_verified_only_when_the_wallet_can_send() {
        let (chip, good, line) = chain_chip(Some(("at_tip", Some(4_120_636), Some(4_120_636))), true, false);
        assert_eq!((chip, good), ("VERIFIED", true));
        assert!(line.contains("4120636") && line.contains("ready to use"));
        let (chip, good, line) = chain_chip(Some(("at_tip", Some(4_120_636), Some(4_120_636))), true, true);
        assert_eq!((chip, good), ("SEARCHING", false));
        assert!(line.contains("4120636") && line.contains("sending opens when the search ends"));
        let (chip, good, line) = chain_chip(Some(("behind", Some(4_120_636), None)), true, true);
        assert_eq!((chip, good), ("CATCHING UP", false));
        assert!(line.contains("block 4120636") && line.contains("the tip is not chosen yet") && !line.contains("—"));
        let (chip, good, line) = chain_chip(Some(("behind", Some(4_118_023), Some(4_120_705))), true, false);
        assert_eq!((chip, good), ("CATCHING UP", false));
        assert!(line.contains("4118023 of 4120705") && line.contains("2682 to go"));
        assert_eq!(chain_chip(Some(("other", None, None)), false, false).0, "NO CHAIN");
        assert_eq!(chain_chip(Some(("other", None, None)), true, false).0, "CHECKING");
        assert_eq!(chain_chip(None, true, false).0, "NO DATA");
        for case in [chain_chip(Some(("other", None, None)), true, true), chain_chip(None, true, false), chain_chip(Some(("behind", None, None)), true, false)] {
            assert!(!case.1);
        }
    }
}

#[cfg(test)]
mod qr_tests {
    use super::*;

    /// The picture given to the window is the code itself: square, one
    /// pixel a module; no text or too long a text gives an empty picture.
    #[test]
    fn the_picture_for_the_window_is_the_code_or_nothing() {
        let shown = qr_picture("grin1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7zyv4m").size();
        let side = crate::qr::grid("grin1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7zyv4m").map(|g| g.side()).and_then(|s| u32::try_from(s).ok());
        assert_eq!(Some(shown.width), side);
        assert_eq!(shown.width, shown.height);
        assert!(shown.width > 28);
        assert_eq!(qr_picture("").size().width, 0);
        assert_eq!(qr_picture(&"a".repeat(crate::qr::MAX_BYTES.saturating_add(1))).size().width, 0);
    }

    /// A code is offered where the window shows an address of the wallet's
    /// own or a Slatepack text to pass on, and nowhere else: not at the
    /// words of the wallet, not at a text the user pastes.
    #[test]
    fn a_code_is_drawn_of_the_address_and_of_the_text_to_pass_on_only() {
        let flows = include_str!("../ui/flows.slint");
        let app = include_str!("../ui/app.slint");
        let pages = include_str!("../ui/pages.slint");
        let count = |text: &str, what: &str| text.matches(what).count();
        // one place draws, two components hold it
        assert_eq!(count(flows, "Qr.picture("), 1);
        assert_eq!(count(app, "Qr.picture(").saturating_add(count(pages, "Qr.picture(")), 0);
        assert_eq!(count(flows, "QrView {"), 2);
        assert_eq!(count(app, "QrView {").saturating_add(count(pages, "QrView {")), 0);
        // the text box offers it only for a text that is read, not typed
        assert_eq!(count(flows, "if root.read-only && root.with-qr: Btn {"), 1);
        assert_eq!(count(flows, "if root.read-only && root.as-qr: QrView { text: root.text; }"), 1);
        // who asks for it: the text to pass on, the address in two windows
        assert_eq!(count(flows, "with-qr: true"), 2);
        assert_eq!(count(flows, "read-only: true; with-files: true; with-qr: true; text: root.out;"), 1);
        assert_eq!(count(flows, "AddressLine { groups: root.groups; full: root.full; with-qr: true; }"), 1);
        assert_eq!(count(app, "with-qr: true"), 1);
        assert_eq!(count(app, "full: root.address-full; copyable: root.address-full != \"\"; with-qr: true; }"), 1);
        assert_eq!(count(pages, "with-qr"), 0);
        // the box for the 24 words is typed into and asks for no code
        let words = flows.lines().find(|l| l.contains("24 words, separated by spaces")).unwrap_or_default();
        assert!(!words.is_empty() && !words.contains("with-qr") && !words.contains("read-only"));
    }
}

#[cfg(test)]
mod tor_ask_tests {
    use super::*;

    /// A payment that waits at the wallet's address is told from one the
    /// message transport brought by its name alone.
    #[test]
    fn a_payment_through_tor_is_known_by_its_name() {
        assert_eq!(tor_ask("tor:7"), Some(7));
        assert_eq!(tor_ask(&format!("{TOR_ASK}{}", u64::MAX)), Some(u64::MAX));
        for other in ["", "tor:", "tor:x", "tor:-1", "7", "ab12", "TOR:7", "tor:7 "] {
            assert_eq!(tor_ask(other), None, "{other}");
        }
    }

    /// The outcome of a payment sent over Tor is shown in the window it was
    /// sent from: the reply opens the signing, a failure says why; a closed
    /// window gets neither.
    #[test]
    fn the_outcome_of_tor_is_shown_where_the_payment_was_sent() {
        assert_eq!(tor_outcome(true, false, None), TorOutcome::Wait);
        assert_eq!(tor_outcome(true, true, None), TorOutcome::Sign);
        assert_eq!(tor_outcome(true, false, Some("no answer")), TorOutcome::Failed("no answer".into()));
        // an earlier failure does not hide a reply that came after a second try
        assert_eq!(tor_outcome(true, true, Some("no answer")), TorOutcome::Sign);
        for (held, failed) in [(false, None), (true, None), (false, Some("no answer"))] {
            assert_eq!(tor_outcome(false, held, failed), TorOutcome::Gone);
        }
    }

    /// Why a payment did not get through is said in the window's words;
    /// what another wallet said is kept after them.
    #[test]
    fn the_reason_tor_failed_is_said_in_the_windows_words() {
        assert!(tor_reason("Tor did not reach the wallet at this address (onion service not found)").starts_with("Tor did not reach the wallet at this address: it is closed"));
        assert_eq!(tor_reason("the wallet at this address refused: busy"), "The wallet at this address refused: busy");
        assert_eq!(tor_reason("the wallet at this address did not answer in time"), "The wallet at this address did not answer in time");
        assert!(tor_reason("Tor gave no outcome; whether the wallet at this address got the payment is not known").contains("is not known"));
        assert_eq!(tor_reason("something new"), "something new");
    }

    /// A refusal whose reason tells the user what to wait for says so; one
    /// the window does not know keeps the general words and shows nothing
    /// of the wallet's own text.
    #[test]
    fn a_refusal_with_a_known_reason_says_what_to_wait_for() {
        let refusal = |message: &str| say(&CallError::Rpc { code: -32011, name: "refused".into(), message: message.into() });
        assert!(refusal("the search for old outputs is not over").contains("still searching"));
        assert!(refusal("chain state unknown").contains("first block"));
        let general = refusal("refused");
        assert!(general.starts_with("The wallet will not do this now"));
        assert_eq!(refusal("anything <b>else</b>"), general);
        assert_eq!(refusal(""), general);
    }

    /// What Tor to an address refuses is said in words that tell the user
    /// what to do; the wallet's own words are not shown as they are.
    #[test]
    fn refusals_of_tor_are_said_plainly() {
        let refused = |message: &str| CallError::Rpc { code: -32011, name: "refused".into(), message: message.into() };
        assert!(say_tor(&refused("refused: Tor is not ready yet")).contains("still connecting"));
        assert!(say_tor(&refused("the sender no longer waits")).contains("Nothing was signed"));
        assert!(say_tor(&refused("the payment names no address")).contains("by hand"));
        assert_eq!(say_tor(&refused("payment is not prepared")), say(&refused("payment is not prepared")));
        // O54: files held by another process are said as that; another failure names its step
        assert!(profile_io_words("the journal did not open: Io(Kind(WouldBlock))").contains("another GrinSight process"));
        assert!(profile_io_words("the journal did not open: Io(Custom { kind: WouldBlock, error: \"journal is locked\" })").contains("another GrinSight process"));
        assert_eq!(profile_io_words("PermissionDenied"), "The wallet's files could not be read or written (PermissionDenied)");
        assert_eq!(profile_io_words(""), "The wallet's files could not be read or written");
        // O52: a message that is not taken says why, each reason in its own words
        let vague = say(&refused("something the window has no words for"));
        let reasons = ["the wallet has no transport identity", "not a contact", "message is not usable", "too many messages are waiting for this contact", "the transport cannot seal now", "there are not two outputs to collect", "the outputs would not pay the fee of collecting them"];
        let said: std::collections::BTreeSet<String> = reasons.iter().map(|r| say(&refused(r))).collect();
        assert_eq!(said.len(), reasons.len());
        assert!(!said.contains(&vague));
        assert!(say_tor(&CallError::Rpc { code: -32032, name: "no_onion".into(), message: String::new() }).contains("not set up"));
        assert_eq!(say_tor(&CallError::Timeout), say(&CallError::Timeout));
    }
}

#[cfg(test)]
mod incoming_identity_tests {
    use super::*;
    #[test]
    fn a_declared_payment_address_is_not_the_identity_of_the_messenger() {
        let mut f = Flow { testnet: Some(false), ..Flow::default() };
        let declared = [8u8; 32];
        f.contacts.push(ContactRec { key: "a".into(), shown: "Alice".into(), raw_name: "Alice".into(),
            address: Some(address_of_key(&declared, false)), checked: false });
        f.contacts.push(ContactRec { key: "b".into(), shown: "Bob".into(), raw_name: "Bob".into(), address: None, checked: false });
        f.incoming.push(Incoming { id: "delivery".into(), slate: String::new(), from: "b".into() });
        let (manual, _, address) = incoming_sender(&f, None, Some(declared));
        assert!(manual != "Alice" && !address.is_empty());
        let (delivered, _, _) = incoming_sender(&f, Some("delivery"), Some(declared));
        assert_eq!(delivered, "Bob");
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    #[test]
    fn a_session_keeps_its_network_and_loses_it_on_leave() {
        // a missing status answer keeps what this session learned; leaving forgets it
        with(|f| f.testnet = Some(true));
        let read = chat_work(|_, network| network);
        assert_eq!(std::thread::spawn(read).join().ok().flatten(), Some(true));
        with(|f| f.testnet = None);
        let read = chat_work(|_, network| network);
        assert_eq!(std::thread::spawn(read).join().ok().flatten(), None);
    }

    #[test]
    fn a_public_key_without_a_recognised_network_has_no_receiving_address() {
        let key = [9u8; 32];
        assert!(view_address(Some(key), network_value(None)).is_none());
        assert!(view_address(Some(key), network_value(Some("future"))).is_none());
        for (network, testnet) in [("main", false), ("test", true)] {
            assert_eq!(view_address(Some(key), network_value(Some(network))), Some(address_of_key(&key, testnet)));
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// "All payments" offers the Slatepack text again only where the wallet
    /// can give it: a payment prepared by hand that still waits for its
    /// reply. Not one sent to a contact, not a signed one, not an invoice.
    #[test]
    fn the_text_is_offered_again_only_where_there_is_one() -> Result<(), Box<dyn std::error::Error>> {
        use slint::Model;
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let row = |op: &str, state: &str, to: Option<&str>, invoice: bool, locked: bool| SendRow {
            op: op.into(), state: state.into(), amount: 1_000_000_000, fee: 23_000_000, held: false, invoice, locked, session_expired: false, to: to.map(str::to_string), kernel_height: None, signed: false,
            made: None,
            slate_id: String::new(),
            replaces: None,
            replaced_by: None,
            direct: false,
        };
        let same = || View {
            sends: vec![
                row("a", "prepared", None, false, false),
                row("b", "prepared", Some("key"), false, false),
                SendRow { kernel_height: Some(5), ..row("c", "confirmed", None, false, false) },
                row("d", "prepared", None, true, false),
                row("e", "prepared", None, false, true),
                SendRow { made: Some(8), ..row("g", "cancelled", None, false, false) },
            ],
            incoming: vec![IncomingRow { value: 5, status: "confirmed".into(), slate_id: "f".into(), kernel_height: Some(9), ..IncomingRow::default() }],
            found: vec![FoundRow { value: 3, height: 7, by_search: false, coinbase: false }],
            history_tip: Some(20),
            k_conf: 10,
            ..View::default()
        };
        apply(&app, same());
        // O49: by time, whatever the kind. What is still under way stands
        // on top (e, d, b, a); then the incoming payment in block 9, the
        // cancelled one made at block 8, the money without a record in
        // block 7, the payment in block 5.
        let lines: Vec<(String, bool)> = app.get_all_ops().iter().map(|o| (o.amount.to_string(), o.show)).collect();
        let shown: Vec<bool> = lines.iter().map(|l| l.1).collect();
        // O55: the one sent to a contact (b) opens from its line as well - to be cancelled there
        assert_eq!(shown, vec![false, false, true, true, false, false, false, false]);
        assert_eq!(lines.get(4).map(|l| l.0.as_str()), Some("+0.000000005"));
        assert_eq!(lines.get(6).map(|l| l.0.as_str()), Some("+0.000000003"), "money that came with no record has its line");
        assert_eq!(app.get_all_ops().iter().nth(6).map(|o| o.sub.to_string()).as_deref(), Some("in a block · the wallet is catching up with the tip · no payment record"), "this wallet is not at the tip");
        assert_eq!(with(|f| f.op_rows.get(3).cloned()), Some(OpRef::Send("a".into())));
        assert_eq!((app.get_ops_hidden(), app.get_op_contacts().iter().count()), (0, 0));
        // O50: hidden through block 7, the two that ended by then are left
        // out of the lists and counted; what is under way and what came
        // after stay, each with the same way back to its text
        crate::set_history_hidden(7);
        apply(&app, same());
        crate::set_history_hidden(0);
        let amounts: Vec<String> = app.get_all_ops().iter().map(|o| o.amount.to_string()).collect();
        assert_eq!((amounts.len(), app.get_ops_hidden()), (6, 2), "{amounts:?}");
        assert!(!amounts.contains(&"+0.000000003".to_string()));
        assert_eq!(with(|f| f.op_rows.get(3).cloned()), Some(OpRef::Send("a".into())));
        // the table: the block in digits or a dash, and the direction
        let first = app.get_all_ops().iter().next().map(|o| (o.block.to_string(), o.incoming));
        let fifth = app.get_all_ops().iter().nth(4).map(|o| (o.block.to_string(), o.incoming));
        assert_eq!((first, fifth), (Some(("—".to_string(), false)), Some(("9".to_string(), true))));
        Ok(())
    }

    /// O67: a starting point more than 30 000 blocks below the checked
    /// chain is offered anew under "Waiting for you" - and no longer once
    /// one was made in this opening; a nearer one is only spoken of next to
    /// the button. Nothing is made without the owner.
    #[test]
    fn an_old_starting_point_is_offered_anew() -> Result<(), Box<dyn std::error::Error>> {
        use slint::Model;
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let says = |words: &str| crate::sync::Facts { answered: true, chain: crate::sync::Part { configured: true, phase: "ready".into(), problem: words.into(), ..crate::sync::Part::default() }, ..crate::sync::Facts::default() };
        let offered = |app: &App| app.get_waiting().iter().filter(|w| w.who == "Starting point").map(|w| (w.what.to_string(), w.action.to_string())).collect::<Vec<_>>();
        apply(&app, View { sync: says("headers verified to 4150000 from a release starting point (4115520)"), ..View::default() });
        assert_eq!(offered(&app), [("is 34 480 blocks below the checked chain — with a new one the wallet opens faster next time".to_string(), "Make a new point".to_string())]);
        assert!(app.get_point_hint().contains("noticeably faster"));
        assert_eq!(with(|f| f.waits.iter().filter(|w| matches!(w, Wait::Point(34_480))).count()), 1);
        // nearer than that: spoken of, not offered
        apply(&app, View { sync: says("headers verified to 4140000 from a release starting point (4115520)"), ..View::default() });
        assert!(offered(&app).is_empty() && app.get_point_hint().contains("some time"));
        apply(&app, View { sync: says("headers verified to 4120000 from a release starting point (4115520)"), ..View::default() });
        assert!(offered(&app).is_empty() && app.get_point_hint().contains("almost nothing"));
        // made in this opening: not offered again, though the chain process still counts from the old one
        with(|f| f.point_made = Some("4 147 200".into()));
        apply(&app, View { sync: says("headers verified to 4150000 from a release starting point (4115520)"), ..View::default() });
        assert!(offered(&app).is_empty());
        app.set_point_good(true);
        say_again(&app);
        assert_eq!(app.get_point_note(), "Your own starting point is made: block 4 147 200. The wallet starts from it at the next unlock.");
        Ok(())
    }

    /// O65: the check code is shown only as six of the wallet's own words;
    /// and the address a payment names is said against the saved one.
    #[test]
    fn the_check_code_and_the_address_of_a_payment() {
        assert_eq!(code_line(&json!({"words": ["able", "bird", "cat", "dog", "egg", "fox"]})), "able – bird – cat – dog – egg – fox");
        for bad in [json!({"words": ["able", "bird", "cat", "dog", "egg"]}), json!({"words": ["able", "bird", "cat", "dog", "egg", "<b>"]}), json!({"words": ["able", "bird", "cat", "dog", "egg", ""]}), json!({})] {
            assert_eq!(code_line(&bad), "", "{bad}");
        }
        assert_eq!(address_note(None, false, "grin1a"), "Address declared in the payment");
        assert_eq!(address_note(Some("grin1a"), false, "grin1a"), "Address declared in the payment");
        assert_eq!(address_note(Some("grin1a"), true, "grin1a"), "The address of the payment is the one you checked with this contact");
        assert_eq!(address_note(Some("grin1a"), false, "grin1b"), "The payment names another address than the one saved for this contact");
        assert!(address_note(Some("grin1a"), true, "grin1b").starts_with("Careful: the payment names another address"));
    }

    /// O64: the text pasted for an invoice made here has to be a payer's
    /// answer, and in the window of an invoice - the answer to that one.
    #[test]
    fn the_answer_to_an_invoice_is_checked_before_the_wallet_is_asked() {
        let id = || Some("aa".to_string());
        assert_eq!(invoice_answer(Some("I2"), id(), Some("aa")), Ok("aa".to_string()));
        assert_eq!(invoice_answer(Some("I2"), id(), None), Ok("aa".to_string()));
        assert_eq!(invoice_answer(Some("I2"), id(), Some("bb")), Err("This answers another invoice"));
        assert_eq!(invoice_answer(Some("I2"), None, None), Err("The answer does not name its invoice"));
        for stage in [Some("S1"), Some("S2"), Some("I1"), Some("unknown"), None] {
            assert_eq!(invoice_answer(stage, id(), Some("aa")), Err("This is not a payer's answer to an invoice"), "{stage:?}");
        }
    }

    /// O63: a list of contacts typed as two columns: keys and addresses go
    /// line to line, empty key lines are passed over, an address may be
    /// missing; a wrong line is named and then nothing is asked at all.
    #[test]
    fn a_list_of_contacts_is_read_line_to_line() {
        let address = address_of_key(&[7; 32], false);
        let address = address.as_str();
        let list = contact_list("npub1aa\n\n  npub1bb  \nnpub1cc", &format!("\n\n{address}\n"), false, 3);
        assert!(list.is_ok(), "{list:?}");
        let list = list.unwrap_or_default();
        let seen: Vec<(String, String, bool)> = list.iter().map(|p| (text(p, "npub").unwrap_or_default(), text(p, "name").unwrap_or_default(), p.get("address").is_some())).collect();
        assert_eq!(seen, [("npub1aa".to_string(), "Contact 4".to_string(), false), ("npub1bb".to_string(), "Contact 5".to_string(), true), ("npub1cc".to_string(), "Contact 6".to_string(), false)]);
        assert_eq!(contact_list("npub1aa\nkey", "", false, 0), Err("Line 2: a message key starts with npub1".to_string()));
        assert_eq!(contact_list("npub1aa\nnpub1bb", "\ngrin1broken", false, 0), Err("Line 2: the address is broken or of the other network".to_string()));
        assert_eq!(contact_list("npub1aa", address, true, 0), Err("Line 1: the address is broken or of the other network".to_string()), "an address of the other network");
        assert_eq!(contact_list(" \n", address, false, 0), Err("There is no message key in the list".to_string()));
        let many = "npub1x\n".repeat(201);
        assert_eq!(contact_list(&many, "", false, 0), Err("At most 200 contacts at once".to_string()));
        assert_eq!(contact_list(&"npub1x\n".repeat(200), "", false, 0).map(|l| l.len()), Ok(200));
    }

    /// An explicit owner choice takes over from an automatic bridge trial.
    #[test]
    fn saving_a_bridge_choice_ends_the_automatic_trial() -> Result<(), Box<dyn std::error::Error>> {
        use crate::tor::{load, save, Mode};
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let dir = std::env::temp_dir().join(format!("fly-ui-bridge-choice-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let file = dir.join(crate::tor::FILE);
        with(|f| {
            f.profile = Some(dir.join("profile"));
            f.tor_program = true;
        });
        wire_tor(&app);
        let initial_saved = matches!(save(&file, Mode::Snowflake, ""), Ok(Ok(())));
        bridges::begin(&app);
        let trial = (load(&file).0, app.get_sign_bridges_busy());

        app.invoke_save_tor(Mode::Own.index(), "".into());
        let refused = (load(&file).0, with(|f| f.bridge_try.is_some()), app.get_sheet_error().is_empty());

        let line = "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";
        app.invoke_save_tor(Mode::Own.index(), line.into());
        let saved = (load(&file).0, with(|f| f.bridge_try.is_some()), app.get_sign_bridges_busy());
        bridges::leave();
        let final_choice = load(&file);
        std::fs::remove_dir_all(&dir)?;

        assert!(initial_saved);
        assert_eq!(trial, (Mode::Obfs4, true));
        assert_eq!(refused, (Mode::Obfs4, true, false));
        assert_eq!(saved, (Mode::Own, false, false));
        assert_eq!(final_choice, (Mode::Own, line.to_string()));
        Ok(())
    }

    /// O73: what a "?" says opens in the help window, never as small print
    /// under the thing; the details are a window too, not a card that
    /// unfolds below the fold; the state stands above the money.
    #[test]
    fn help_and_details_open_in_windows_of_their_own() {
        let files = [include_str!("../ui/app.slint"), include_str!("../ui/flows.slint"), include_str!("../ui/pages.slint"), include_str!("../ui/parts.slint")];
        for text in files {
            for (at, _) in text.match_indices("Ask {") {
                let rest = text.get(at..).unwrap_or_default();
                let one = rest.get(..rest.find('}').unwrap_or(rest.len())).unwrap_or_default();
                assert!(one.contains("title:") && one.contains("text:"), "an Ask without its words: {one}");
            }
            for unfolding in ["ask.open", "if root.asked", "if root.point-asked", "if root.parts-asked"] {
                assert!(!text.contains(unfolding), "an answer that unfolds in place: {unfolding}");
            }
            assert!(!text.contains("sync-details"), "the details unfold in the page");
        }
        let app = files[0];
        assert!(app.contains("if Help.open: Rectangle"));
        assert!(app.contains("root.sheet == 15: SyncSheet"));
        assert!(app.contains("root.sheet == 16: SettingsSheet"));
        // the state is the first thing in the balance card, above "Available"
        let card = app.get(app.find("component BalanceCard").unwrap_or(0)..).unwrap_or_default();
        let (state, money) = (card.find("root.verified-chip").unwrap_or(usize::MAX), card.find("@tr(\"Available\")").unwrap_or(0));
        assert!(state < money);
        // the top row: the settings and the lock, nothing else
        assert!(!app.contains("Btn { text: Settings.russian ? \"RU\" : \"EN\""));
    }

    #[test]
    fn genesis_choice_restarts_only_after_an_explicit_acknowledgement() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let locks = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = locks.clone();
        app.on_leave(move || observed.set(observed.get() + 1));
        for wrong in [None, Some(json!({})), Some(json!({"scheduled": false})), Some(json!({"scheduled": "true"}))] {
            app.set_bootstrap_submitting(true);
            finish_genesis_choice(&app, wrong.as_ref());
            assert!(!app.get_bootstrap_submitting());
            assert!(!app.get_bootstrap_feedback().is_empty());
            assert_eq!(locks.get(), 0);
        }
        finish_genesis_choice(&app, Some(&json!({"scheduled":true})));
        assert_eq!(locks.get(), 1);
        assert!(with(|f| std::mem::take(&mut f.restart_after_lock)));
        Ok(())
    }

    #[test]
    fn old_outputs_rescan_acknowledgement_keeps_the_wallet_open() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        app.on_leave(|| panic!("scanning outputs cannot lock the wallet"));
        app.set_page(1);
        finish_output_rescan(&app, Some(&json!({"state":"done"})));
        assert!(!app.get_search_active());
        assert!(!app.get_search_feedback().is_empty());
        app.set_search_submitting(true);
        finish_output_rescan(&app, Some(&json!({"state":"reading", "next":0})));
        assert!(app.get_search_active());
        assert!(!app.get_search_submitting());
        assert_eq!(app.get_page(), 1);
        Ok(())
    }

    /// O75: the contacts on the left on a ground of their own, the chosen
    /// one's actions as signs in its line, the rest under "⋯" in the head of
    /// the conversation; deleting is asked in a window of its own. Startup
    /// verification is chosen under "Settings", not on the main screen.
    #[test]
    fn contacts_and_their_conversation_are_laid_out_as_agreed() {
        let app = include_str!("../ui/app.slint");
        let pages = include_str!("../ui/pages.slint");
        let panel = app.get(app.find("component ContactsPanel").unwrap_or(0)..).unwrap_or_default();
        let panel = panel.get(..panel.find("\n}\n").unwrap_or(panel.len())).unwrap_or_default();
        let (list, talk) = (panel.find("@tr(\"Your contacts\")").unwrap_or(usize::MAX), panel.find("ChatBox {").unwrap_or(0));
        assert!(list < talk, "the contacts come first, on the left");
        for sign in ["Icons.send; says: @tr(\"Send GRIN to the contact\")", "Icons.edit; says: @tr(\"Change the contact's details\")", "Icons.trash; says: @tr(\"Delete the contact\")"] {
            assert!(panel.contains(sign), "{sign}");
        }
        assert!(!panel.contains("Sign {"), "the five signs of O63 are gone");
        assert!(panel.contains("menu := PopupWindow") && pages.contains("menu := PopupWindow"));
        assert!(!panel.contains("root.remove("), "a contact is never deleted without the window");
        assert!(app.contains("root.remove-asking >= 0 && root.remove-asking < root.contacts.length: Rectangle"));
        assert_eq!(app.matches("ask-remove(i) => { root.remove-asking = i; }").count(), 1, "the main screen asks in the window");
        assert!(!app.contains("ask-remove(i) => { root.contact-remove"));
        assert!(app.contains("root.menu-for >= 0 && root.menu-for < root.contacts.length: Rectangle"));
        let link = app.get(app.find("component LinkCard").unwrap_or(0)..).unwrap_or_default();
        let link = link.get(..link.find("\n}\n").unwrap_or(link.len())).unwrap_or_default();
        assert!(!link.contains("make-point"), "the own point is not on the main screen");
        let sync = app.get(app.find("component SyncSheet").unwrap_or(0)..).unwrap_or_default();
        let sync = sync.get(..sync.find("\n}\n").unwrap_or(sync.len())).unwrap_or_default();
        let settings = app.split("component SettingsSheet inherits Sheet").nth(1).unwrap().split("\n}\n").next().unwrap();
        for action in ["recheck-history", "rescan-outputs", "import-checkpoint", "save-checkpoint"] {
            assert!(settings.contains(&format!("root.{action}()")));
            assert!(!sync.contains(action));
        }
        assert_eq!(settings.matches("SettingsAction {").count(), 4);
        assert_eq!(settings.matches("explanation: @tr(").count(), 4);
    }

    /// O75: what is new in a conversation is counted from the first count
    /// seen in this unlock; the open conversation is seen whole.
    #[test]
    fn new_messages_are_counted_from_what_was_seen() {
        let mut seen = std::collections::BTreeMap::new();
        assert_eq!(unread(&mut seen, "a", 4, false), 0, "what was there at the unlock is not new");
        assert_eq!(unread(&mut seen, "a", 6, false), 2);
        assert_eq!(unread(&mut seen, "a", 6, true), 0, "opened, all is seen");
        assert_eq!(unread(&mut seen, "a", 7, false), 1);
        assert_eq!(unread(&mut seen, "a", 3, false), 0, "fewer than seen: messages went, nothing is new");
        assert_eq!(unread(&mut seen, "a", 5, false), 2);
        assert_eq!(unread(&mut seen, "b", 9, false), 0);
    }

    /// O75: a payment to the contact stands among the messages by its time,
    /// each day has its line, and only payments to that contact are shown.
    #[test]
    fn payments_and_days_stand_among_the_messages() {
        let day = 86_400u64;
        let now = 10 * day + 3_600;
        let lines: Vec<Said> = vec![(false, 9 * day + 100, "hi".into(), String::new()), (true, 10 * day + 60, "sent".into(), "relay_accepted".into()), (false, now - 60, "got it".into(), String::new())];
        let send = |to: Option<&str>, state: &str, kernel: Option<u64>| SendRow { to: to.map(str::to_string), state: state.into(), amount: 500_000_000, kernel_height: kernel, ..SendRow::default() };
        let all = plaques(&[send(Some("k"), "confirmed", Some(990)), send(Some("k"), "cancelled", None), send(None, "confirmed", Some(995)), send(Some("j"), "prepared", None)], Some(1000), now);
        let pays = all.get("k").cloned().unwrap_or_default();
        assert_eq!(pays.len(), 1, "a cancelled one and one to nobody are not shown");
        assert_eq!(pays.first().map(|p| p.at), Some(now - 10 * 60), "ten blocks back, a minute a block");
        assert!(pays.first().is_some_and(|p| p.state.contains("11") && !p.warn), "the block it is in counts");
        assert!(all.get("j").is_some_and(|p| p.first().is_some_and(|p| p.at == now && p.warn)), "under way: now, and not yet in a block");
        let view = chat_view(&lines, &pays, now);
        let kinds: Vec<i32> = view.iter().map(|l| l.kind).collect();
        assert_eq!(kinds, [2, 0, 2, 0, 1, 0], "the payment stands between the messages by its time");
        assert_eq!(view.first().map(|l| l.text.to_string()), Some(day_words(9 * day, now)));
        assert_eq!(view.get(2).map(|l| l.text.as_str() == tr("Today", "Сегодня")), Some(true));
        assert_eq!(day_words(9 * day + 5, now), tr("Yesterday", "Вчера"));
        assert_eq!(day_words(2 * day, now), "03.01.1970");
    }

    /// K197: a payment being taken back, the payment that takes it back and
    /// how each ended are said in their own words; a payment nothing
    /// replaces keeps the usual ones. Taking back is offered only for a
    /// signed payment to someone else that nothing replaces yet, and an
    /// unsigned payment - to a contact too - opens from its line (O55).
    #[test]
    fn a_payment_taken_back_says_so() -> Result<(), Box<dyn std::error::Error>> {
        use slint::Model;
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let row = |op: &str, state: &str| SendRow { op: op.into(), state: state.into(), amount: 2_000_000_000, fee: 23_000_000, signed: true, slate_id: format!("s-{op}"), ..SendRow::default() };
        let plain = SendRow { direct: true, ..row("p", "finalized") };
        let going = SendRow { replaced_by: Some("b".into()), ..row("a", "finalized") };
        let taking = SendRow { replaces: Some("a".into()), ..row("b", "finalized") };
        let all = [plain.clone(), going.clone(), taking.clone()];
        assert_eq!(back_words(&plain, &all), None);
        assert_eq!(back_words(&going, &all), Some("being taken back — one of the two will be in a block"));
        assert_eq!(back_words(&taking, &all), None);
        // the taking back is in a block
        let won = [SendRow { state: "contested".into(), replaced_by: None, ..going.clone() }, SendRow { state: "confirmed".into(), ..taking.clone() }];
        assert_eq!((back_words(&won[0], &won), back_words(&won[1], &won)), (Some("taken back — the money is yours again"), None));
        // the first payment is
        let lost = [SendRow { state: "confirmed".into(), replaced_by: None, ..going.clone() }, SendRow { state: "dead".into(), ..taking.clone() }];
        assert_eq!((back_words(&lost[0], &lost), back_words(&lost[1], &lost)), (None, Some("did not work: the payment reached a block first")));
        // a contested payment nothing replaced keeps the usual words
        assert_eq!(back_words(&row("c", "contested"), &[row("c", "contested")]), None);

        let incoming = vec![IncomingRow { value: 1, status: "waiting".into(), slate_id: "s-b".into(), ..IncomingRow::default() }];
        let to_contact = SendRow { signed: false, to: Some("key".into()), ..row("u", "prepared") };
        apply(&app, View { sends: vec![plain, going, taking, to_contact], incoming, history_tip: Some(20), k_conf: 10, ..View::default() });
        let rows = with(|f| f.op_rows.clone());
        let back_of = |op: &str| rows.iter().find_map(|r| match r { OpRef::Signed { op: o, back, .. } if o == op => Some(*back), _ => None });
        assert_eq!((back_of("p"), back_of("a"), back_of("b")), (Some(true), Some(false), Some(false)));
        assert!(rows.contains(&OpRef::Send("u".into())));
        assert_eq!(with(|f| f.direct_ops.iter().cloned().collect::<Vec<_>>()), ["p"]);
        let names: Vec<String> = app.get_all_ops().iter().map(|o| o.who.to_string()).collect();
        assert!(names.contains(&"To yourself: taking a payment back".to_string()), "{names:?}");
        assert_eq!(names.len(), 4, "its arrival has no line of its own");
        // O60: the doubt about Tor reaches the window to sign, with the ways out
        let down = crate::sync::Facts { answered: true, transport: crate::sync::Part { configured: true, phase: "down".into(), ..crate::sync::Part::default() }, ..crate::sync::Facts::default() };
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert!(app.get_sign_tor_doubt().starts_with("Tor is not working on this device now. A payment signed now may wait"), "{}", app.get_sign_tor_doubt());
        // O71: with that doubt the built-in bridges are offered - where there
        // is the program for them and a built-in way is left to try
        use crate::tor::{load, save, Mode, TRY_WAIT};
        let dir = std::env::temp_dir().join(format!("fly-ui-bridges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join(crate::tor::FILE);
        with(|f| f.profile = Some(dir.join("profile")));
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert!(!app.get_sign_bridges_offered(), "no program for bridges here");
        with(|f| f.tor_program = true);
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert!(app.get_sign_bridges_offered());
        let late = || with(|f| {
            if let Some((_, since)) = &mut f.bridge_try {
                *since = Instant::now().checked_sub(TRY_WAIT).unwrap_or(*since);
            }
        });
        // the owner's word: obfs4 first, written down as the choice
        bridges::begin(&app);
        assert_eq!(load(&file).0, Mode::Obfs4);
        assert!(app.get_sign_bridges_busy() && app.get_sign_bridges_note().starts_with("Trying to reach Tor through the built-in obfs4 bridges"), "{}", app.get_sign_bridges_note());
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert_eq!(load(&file).0, Mode::Obfs4, "there is time left");
        // the time is up and Tor is still down: Snowflake
        late();
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert_eq!(load(&file).0, Mode::Snowflake);
        assert!(app.get_sign_bridges_busy() && app.get_sign_bridges_note().starts_with("Trying to reach Tor through Snowflake"), "{}", app.get_sign_bridges_note());
        // that fails too: the owner's choice is back, and the window says so
        late();
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert_eq!(load(&file).0, Mode::Direct);
        assert!(!app.get_sign_bridges_busy() && app.get_sign_bridges_note().starts_with("Tor did not come up through the built-in bridges. Your earlier choice is back: directly."), "{}", app.get_sign_bridges_note());
        assert!(with(|f| f.bridge_try.is_none()));
        // a Tor that comes up anew through the way tried: it worked, and the way stays
        bridges::begin(&app);
        let up = crate::sync::Facts { transport: crate::sync::Part { configured: true, phase: "ready".into(), starts: 1, ..crate::sync::Part::default() }, ..down.clone() };
        apply(&app, View { sync: up, ..View::default() });
        assert_eq!(load(&file).0, Mode::Obfs4);
        assert!(!app.get_sign_bridges_busy() && app.get_sign_bridges_note().starts_with("Tor works through the built-in obfs4 bridges."), "{}", app.get_sign_bridges_note());
        // «enough» in the middle of a try, and a lock in the middle of one: the choice goes back
        assert!(matches!(save(&file, Mode::Snowflake, ""), Ok(Ok(()))));
        bridges::begin(&app);
        assert_eq!(load(&file).0, Mode::Obfs4, "the one built-in way that was not chosen");
        bridges::stop(&app);
        assert_eq!((load(&file).0, app.get_sign_bridges_busy(), app.get_sign_bridges_note().to_string()), (Mode::Snowflake, false, String::new()));
        bridges::begin(&app);
        bridges::leave();
        assert_eq!(load(&file).0, Mode::Snowflake);
        assert!(with(|f| f.bridge_try.is_none()));
        // bridges of the owner's own are not replaced: nothing is offered
        assert!(matches!(save(&file, Mode::Own, "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543"), Ok(Ok(()))));
        apply(&app, View { sync: down.clone(), ..View::default() });
        assert!(!app.get_sign_bridges_offered());
        bridges::begin(&app);
        assert!(with(|f| f.bridge_try.is_none()) && load(&file).0 == Mode::Own);
        with(|f| {
            f.tor_program = false;
            f.profile = None;
        });
        let _ = std::fs::remove_dir_all(&dir);
        app.set_sign_bridges_note("".into());
        apply(&app, View { sync: crate::sync::Facts { tor_off: true, ..down.clone() }, ..View::default() });
        assert_eq!(app.get_sign_tor_doubt(), "");
        crate::set_direct(true);
        apply(&app, View { sync: down, ..View::default() });
        crate::set_direct(false);
        assert_eq!(app.get_sign_tor_doubt(), "", "agreed for everything: nothing to ask");
        assert_eq!((resend_params("ab", true), resend_params("ab", false)), (json!({"op": "ab", "direct": true}), json!({"op": "ab"})));
        // K198: the kept agreement is said only where it matters
        assert!(direct_note(true, true, false).starts_with("You agreed"));
        assert_eq!((direct_note(true, false, false), direct_note(false, true, false), direct_note(true, true, true)), ("", "", ""));
        let asked = back_ask_words(4_987_000_000, 13_000_000);
        assert!(asked.contains("4.987 GRIN return to you") && asked.contains("0.013 GRIN more") && asked.contains("not sure"), "{asked}");
        Ok(())
    }

    /// K196: a payment the wallet made to itself - collecting outputs - is
    /// one line: what left is the fee, and its arrival has no line of its
    /// own. Another payment under another number is not touched, and what
    /// the owner is asked says how many, into what, and for what fee.
    #[test]
    fn a_payment_to_itself_is_one_line() -> Result<(), Box<dyn std::error::Error>> {
        use slint::Model;
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let send = |op: &str, slate: &str| SendRow { op: op.into(), state: "confirmed".into(), amount: 7_987_000_000, fee: 13_000_000, kernel_height: Some(50), slate_id: slate.into(), ..SendRow::default() };
        // blocks well above anything another test hides the history through (O50): that setting is one for the program
        let came = |slate: &str, value: u64| IncomingRow { value, status: "confirmed".into(), slate_id: slate.into(), kernel_height: Some(50), ..IncomingRow::default() };
        let sends = vec![send("a", "s1"), send("b", "s2"), send("c", "")];
        // K200: the sender's text is offered for the payment whose text the wallet keeps - not for one given up
        let incoming = vec![came("s1", 7_987_000_000), IncomingRow { request_kept: true, ..came("s9", 4) }, came("", 6), IncomingRow { request_kept: true, abandoned: true, ..came("s8", 2) }];
        assert_eq!(to_self(&sends, &incoming).into_iter().collect::<Vec<_>>(), ["s1"]);
        apply(&app, View { sends, incoming, history_tip: Some(70), k_conf: 10, ..View::default() });
        let mut lines: Vec<(String, String)> = app.get_all_ops().iter().map(|o| (o.who.to_string(), o.amount.to_string())).collect();
        lines.sort();
        assert_eq!(
            lines,
            [
                ("Incoming".to_string(), "+0.000000002".to_string()),
                ("Incoming".to_string(), "+0.000000004".to_string()),
                ("Incoming".to_string(), "+0.000000006".to_string()),
                ("Payment".to_string(), "−8.00".to_string()),
                ("Payment".to_string(), "−8.00".to_string()),
                ("To yourself: outputs collected".to_string(), "−0.013".to_string()),
            ]
        );
        assert_eq!(with(|f| f.requests.iter().cloned().collect::<Vec<_>>()), ["s9"]);
        let asked = collect_words(3, 7_987_000_000, 13_000_000);
        assert!(asked.starts_with("Collect 3 outputs into one of 7.987 GRIN? The fee is 0.013 GRIN."), "{asked}");
        Ok(())
    }

    /// A sum shown while the search for old outputs is still running says so:
    /// it may grow, and nobody should take it for the whole balance.
    #[test]
    fn a_balance_under_search_says_it_is_not_final() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        apply(&app, View { balance: Some((6_217_000_000, 0, 0, true)), ..View::default() });
        assert_eq!(app.get_balance(), "6.217");
        assert!(app.get_balance_note().contains("the search for your money is still running"), "{}", app.get_balance_note());
        apply(&app, View { balance: Some((6_218_000_000, 0, 0, false)), ..View::default() });
        assert_eq!(app.get_balance(), "6.218");
        assert!(!app.get_balance_note().contains("search"), "{}", app.get_balance_note());
        Ok(())
    }

    /// The paying window shows the wallet's answer about an invoice whole
    /// or not at all: an amount, a fee, their sum, the cutoff, and whether
    /// it is paid already. A missing or misshapen part, an amount of zero
    /// or a sum that does not fit leave nothing to show.
    #[test]
    fn an_invoice_is_shown_whole_or_not_at_all() {
        let whole = json!({ "slate_id": "aa", "amount": "2000000000", "fee": "23500000", "ttl_cutoff_height": 0, "paid_op": null });
        assert_eq!(invoice_numbers(&whole), Some(InvoiceNumbers { amount: 2_000_000_000, fee: 23_500_000, total: 2_023_500_000, cutoff: 0, paid: false }));
        let with_field = |key: &str, value: Value| {
            let mut changed = whole.clone();
            if let Some(fields) = changed.as_object_mut() {
                fields.insert(key.to_string(), value);
            }
            changed
        };
        let mut paid = with_field("paid_op", json!("00112233445566778899aabbccddeeff"));
        if let Some(fields) = paid.as_object_mut() {
            fields.insert("ttl_cutoff_height".to_string(), json!(1234));
        }
        assert_eq!(invoice_numbers(&paid).map(|n| (n.paid, n.cutoff)), Some((true, 1234)));
        for (key, bad) in [
            ("amount", json!(null)),
            ("amount", json!("0")),
            ("amount", json!(2_000_000_000u64)),
            ("amount", json!("2.0")),
            ("fee", json!(null)),
            ("fee", json!("-1")),
            ("fee", json!(u64::MAX.to_string())),
            ("ttl_cutoff_height", json!(null)),
            ("ttl_cutoff_height", json!("12")),
            ("paid_op", json!(true)),
            ("paid_op", json!("")),
        ] {
            assert_eq!(invoice_numbers(&with_field(key, bad.clone())), None, "{key} = {bad}");
        }
        for key in ["amount", "fee", "ttl_cutoff_height", "paid_op"] {
            let mut missing = whole.clone();
            missing.as_object_mut().map(|fields| fields.remove(key));
            assert_eq!(invoice_numbers(&missing), None, "without {key}");
        }
    }

    /// Paying holds the wallet to both numbers the window showed: the
    /// amount and the fee, as the most the user agreed to.
    #[test]
    fn paying_an_invoice_names_the_amount_and_the_fee_shown() {
        let flow = InvoiceFlow { slate: "BEGINSLATEPACK. x. ENDSLATEPACK.".into(), amount: 1_500_000_000, fee: 23_500_000 };
        assert_eq!(
            invoice_pay_params(&flow),
            json!({ "slate": "BEGINSLATEPACK. x. ENDSLATEPACK.", "max_amount": "1500000000", "max_fee": "23500000" })
        );
    }

    /// A paid invoice is not said to be "going to the network": this
    /// wallet does not send it. Every other state reads as for a payment.
    #[test]
    fn a_paid_invoice_is_not_said_to_be_on_its_way() {
        assert_eq!(invoice_reply_title(false), tr("Reply ready — send it to the invoice issuer", "Ответ готов — передайте его тому, кто выставил счёт"));
        assert_eq!(invoice_reply_title(true), tr("Saved reply — send it to the invoice issuer", "Ответ сохранён — передайте его тому, кто выставил счёт"));
        assert_ne!(send_state("finalized", true, false).0, send_state("finalized", false, false).0);
        for state in ["prepared", "cancelled", "unknown", "confirmed", "contested", "dead", "?"] {
            assert_eq!(send_state(state, true, false), send_state(state, false, false), "{state}");
        }
    }

    /// Every payment that holds money without a signature has a line in
    /// «Ждут вас» with a way out of it, whoever prepared it and whenever:
    /// a held reply is signed or cancelled; a payment sent to a contact can
    /// be cancelled before the contact answers; one passed on by hand can
    /// be continued or cancelled without this window having prepared it; a
    /// payment locked after a restore has its own line and is never
    /// offered for a signature. What is signed, cancelled or released has
    /// none.
    #[test]
    fn nothing_prepared_is_left_without_a_way_out() {
        let row = |state: &str, held: bool, locked: bool, to: Option<&str>| SendRow {
            op: "aa".into(),
            state: state.into(),
            amount: 1,
            fee: 1,
            held,
            invoice: false,
            locked,
            session_expired: false,
            to: to.map(str::to_string),
            kernel_height: None,
            signed: false,
            made: None,
            slate_id: String::new(),
            replaces: None,
            replaced_by: None,
            direct: false,
        };
        let kind = |row: &SendRow| match wait_of(row) {
            None => "none",
            Some(Wait::Sign(_)) => "sign",
            Some(Wait::Reply(_)) => "reply",
            Some(Wait::Sent(_)) => "sent",
            Some(Wait::Locked { .. }) => "locked",
            Some(Wait::Incoming(_)) => "incoming",
            Some(Wait::Unsent(_)) => "unsent",
            Some(Wait::Point(_)) => "point",
        };
        assert_eq!(kind(&row("prepared", false, false, None)), "reply");
        assert_eq!(kind(&row("prepared", false, false, Some("bb"))), "sent");
        assert_eq!(kind(&row("prepared", true, false, Some("bb"))), "sign");
        assert_eq!(kind(&row("prepared", true, false, None)), "sign");
        for (held, to) in [(false, None), (true, None), (false, Some("bb")), (true, Some("bb"))] {
            assert_eq!(kind(&row("prepared", held, true, to)), "locked", "{held} {to:?}");
        }
        for state in ["cancelled", "released", "unknown", "finalized", "confirmed", "contested", "dead", ""] {
            assert_eq!(kind(&row(state, true, true, Some("bb"))), "none", "{state}");
        }
    }

    /// A payment from before a restore is neither "waiting for a reply"
    /// nor "cancelled" on the screen, before the reserve is released or
    /// after; and letting it go says so to the wallet, which an ordinary
    /// cancel never does.
    #[test]
    fn a_payment_from_before_a_restore_is_called_what_it_is() {
        let waiting = send_state("prepared", false, false).0;
        let cancelled = send_state("cancelled", false, false).0;
        let locked = send_state("prepared", false, true).0;
        let released = send_state("released", false, false).0;
        assert!(locked != waiting && locked != cancelled && released != cancelled && released != locked);
        assert_eq!(send_state("released", false, true).0, released);
        assert_eq!(cancel_params("aa", false), json!({ "op": "aa" }));
        assert_eq!(cancel_params("aa", true), json!({ "op": "aa", "release_locked": true }));
    }

    #[test]
    fn ended_signing_sessions_are_distinct_from_uncertain_and_saved_results() {
        let history = json!({
            "sends": [
                {"op":"a","state":"prepared","locked":true,"session_expired":true,"reply_held":true},
                {"op":"b","state":"unknown"},
                {"op":"c","state":"finalized","signed":true}
            ],
            "incoming": [
                {"slate_id":"i","session_expired":true},
                {"slate_id":"j","signature_unknown":true},
                {"slate_id":"k","status":"confirmed","kernel_height":10}
            ]
        });
        let view = gather_from(None, None, |method, _| Ok(if method == "paycore.history" { history.clone() } else { Value::Null }));
        assert!(matches!(wait_of(&view.sends[0]), Some(Wait::Locked { session_expired: true, .. })));
        assert!(wait_of(&view.sends[1]).is_none());
        assert!(wait_of(&view.sends[2]).is_none());
        assert_ne!(outgoing_words(&view.sends[0]), outgoing_words(&view.sends[1]));
        assert_ne!(outgoing_words(&view.sends[1]), outgoing_words(&view.sends[2]));
        let words = |i: usize| incoming_words(&view.incoming[i], Some(12), 2, false);
        assert_ne!(words(0), words(1));
        assert_ne!(words(1), words(2));
    }

    #[test]
    fn balance_and_verified_status_belong_to_one_wallet_state() {
        // During the refresh an ordinary sync completes. Before it the
        // balance was seven and the wallet behind, afterwards zero and at tip.
        let mut synchronized = false;
        let view = gather_from(None, None, |method, _params| {
            let spendable = if synchronized { "0" } else { "7" };
            let balance = json!({"spendable":spendable,"reserved":"0","immature":"0","incomplete":false});
            let status = json!({"state":if synchronized {"at_tip"} else {"behind"},
                                "tip_height":if synchronized {11} else {10},"selected_height":11,
                                "confirmed_time":1800000000,"balance":balance});
            let reply = match method {
                "paycore.balance" => balance,
                "paycore.wallet.chain_status" => status,
                _ => return Ok(Value::Null),
            };
            synchronized = true;
            Ok(reply)
        });
        let seen = view.balance.zip(view.sync.state).map(|(b, state)| (b.0, state));
        assert!(matches!(seen, Some((7, ref s)) if s == "behind")
             || matches!(seen, Some((0, ref s)) if s == "at_tip"), "{seen:?}");
    }

    /// The two words asked for are always two different ones among the 24.
    #[test]
    fn the_two_words_asked_for_are_different_and_among_the_24() {
        let mut seen = std::collections::BTreeSet::new();
        for from in (0..5000u32).chain([u32::MAX, u32::MAX - 1, 999_999_999]) {
            let (a, b) = super::two_places(from);
            assert!((1..=24).contains(&a) && (1..=24).contains(&b) && a != b, "{from}: {a} {b}");
            seen.insert((a, b));
        }
        // not always the same two
        assert!(seen.len() > 400, "{}", seen.len());
    }
}

#[cfg(test)]
mod part_tests {
    /// O42, K189, K193: what is switched off is not started. Nostr off
    /// takes the message program out. Tor off is said with the chain
    /// program's flag and the programs that need Tor stay named - the
    /// wallet process holds them back until the switch is turned; without
    /// a chain program there is no flag, and they are taken out. The
    /// consent to the direct way is passed as it stands; nothing is said
    /// twice, and nothing about the chain without a chain program.
    #[test]
    fn what_is_switched_off_is_not_started() {
        let v = |words: &[&str]| -> Vec<String> { words.iter().map(|w| (*w).to_string()).collect() };
        let all = v(&["--profile", "p", "--chain", "c", "--onion", "o", "--transport", "m", "--relay", "wss://r"]);
        assert_eq!(crate::chosen_args(&all, false, false, false), all);
        assert_eq!(crate::chosen_args(&all, true, false, false), v(&["--profile", "p", "--chain", "c", "--onion", "o", "--transport", "m", "--relay", "wss://r", "--chain-direct-post"]));
        assert_eq!(crate::chosen_args(&all, false, false, true), v(&["--profile", "p", "--chain", "c", "--onion", "o"]));
        assert_eq!(crate::chosen_args(&all, false, true, false), v(&["--profile", "p", "--chain", "c", "--onion", "o", "--transport", "m", "--relay", "wss://r", "--chain-no-tor"]));
        assert_eq!(crate::chosen_args(&all, true, true, true), v(&["--profile", "p", "--chain", "c", "--onion", "o", "--chain-no-tor", "--chain-direct-post"]));
        // from arguments that already carry the flags: once, and only what is chosen now
        let flagged = v(&["--profile", "p", "--chain", "c", "--chain-no-tor", "--chain-direct-post", "--onion", "o"]);
        assert_eq!(crate::chosen_args(&flagged, false, false, false), v(&["--profile", "p", "--chain", "c", "--onion", "o"]));
        assert_eq!(crate::chosen_args(&flagged, true, true, false), v(&["--profile", "p", "--chain", "c", "--onion", "o", "--chain-no-tor", "--chain-direct-post"]));
        // no chain program: nothing is said about it
        let bare = v(&["--profile", "p", "--transport", "m", "--relay", "wss://r"]);
        assert_eq!(crate::chosen_args(&bare, true, true, false), v(&["--profile", "p"]));
        // a name at the very end, without its value, is dropped alone
        assert_eq!(crate::chosen_args(&v(&["--profile", "p", "--onion"]), false, true, false), v(&["--profile", "p"]));
    }
}

#[cfg(test)]
mod payment_line_tests {
    use super::*;

    /// K190: the block a payment is in counts as its first confirmation;
    /// an incoming payment says how many it has of how many make it
    /// "received", and nothing is counted without both blocks.
    #[test]
    fn confirmations_are_counted_and_said() {
        assert_eq!(confirmations(Some(100), Some(100)), Some(1));
        assert_eq!(confirmations(Some(100), Some(109)), Some(10));
        assert_eq!(confirmations(Some(101), Some(100)), None, "a block above the tip");
        assert_eq!(confirmations(None, Some(100)), None);
        assert_eq!(confirmations(Some(100), None), None);
        let row = |status: &str, kernel: Option<u64>| IncomingRow { value: 5, status: status.into(), slate_id: "a".into(), kernel_height: kernel, ..IncomingRow::default() };
        assert_eq!(incoming_words(&row("preliminary", Some(100)), Some(102), 10, false), ("in a block · confirmations: 3 of 10".into(), 2));
        assert_eq!(incoming_words(&row("confirmed", Some(100)), Some(111), 10, false), ("received · confirmations: 12".into(), 1));
        assert_eq!(incoming_words(&row("confirmed", None), Some(111), 10, false), ("received".into(), 1));
        assert_eq!(incoming_words(&row("preliminary", None), Some(111), 10, false), ("preliminary".into(), 2));
        assert_eq!(incoming_words(&row("not_confirmed", Some(100)), Some(111), 10, false), ("not in a block yet".into(), 2));
        // O44: catching up is not "unconfirmed" for a payment that is in a block
        assert_eq!(incoming_words(&row("preliminary", Some(100)), Some(102), 10, true), ("in a block · the wallet is catching up with the tip".into(), 0));
        assert_eq!(incoming_words(&row("not_confirmed", None), Some(102), 10, true), ("not in a block yet".into(), 2));
        assert_eq!(incoming_words(&row("confirmed", Some(100)), Some(111), 10, true).1, 1);
        // O50: hidden is what has ended at or below that block - never
        // what is under way, and nothing while nothing was hidden
        assert_eq!((hidden(7, 0), hidden(0, 0), hidden(7, 7), hidden(8, 7), hidden(u64::MAX, 7), hidden(0, 7)), (false, false, true, false, false, true));
        // O49: money with no payment record has its words, and every
        // operation its place in time
        let found = |height: u64, by_search: bool, coinbase: bool| FoundRow { value: 5, height, by_search, coinbase };
        assert_eq!(found_words(&found(100, false, false), Some(111), 10, false), ("received · confirmations: 12 · no payment record".into(), 1));
        assert_eq!(found_words(&found(100, false, false), Some(102), 10, false), ("in a block · confirmations: 3 of 10 · no payment record".into(), 2));
        assert_eq!(found_words(&found(100, false, true), Some(111), 10, false), ("received · confirmations: 12 · a block reward".into(), 1));
        assert_eq!(found_words(&found(100, false, false), Some(102), 10, true), ("in a block · the wallet is catching up with the tip · no payment record".into(), 0));
        assert_eq!(found_words(&found(100, true, false), Some(111), 10, false), ("found by the search for old money · in the chain by block 100".into(), 1));
        assert_eq!(found_words(&found(100, false, false), None, 10, false), ("in a block · no payment record".into(), 2));
        assert_eq!(found_words(&found(100, false, false), Some(100), 0, false).1, 1, "one confirmation is the least");
        assert_eq!((op_time(Some(7), Some(5), true), op_time(None, Some(5), true), op_time(None, Some(5), false), op_time(None, None, false)), (7, u64::MAX, 5, 0));
        // O47: the time of this opening
        assert_eq!((span_words(0), span_words(45), span_words(192), span_words(3725)), ("0 s".into(), "45 s".into(), "3 min 12 s".into(), "1 h 02 min".into()));
        assert_eq!(opening_time(false, 65, None), ("since opening: 1 min 05 s".into(), None));
        assert_eq!(opening_time(true, 192, None), ("from opening to the tip: 3 min 12 s".into(), Some(192)));
        // once reached it stays, whatever happens later
        assert_eq!(opening_time(true, 900, Some(192)), ("from opening to the tip: 3 min 12 s".into(), Some(192)));
        assert_eq!(opening_time(false, 900, Some(192)), ("from opening to the tip: 3 min 12 s".into(), Some(192)));
        // K192: the agreement to the direct way is said only when given
        assert_eq!(resend_params("ab", false), json!({ "op": "ab" }));
        assert_eq!(resend_params("ab", true), json!({ "op": "ab", "direct": true }));
        let gone = IncomingRow { abandoned: true, ..row("confirmed", Some(100)) };
        assert_eq!(incoming_words(&gone, Some(111), 10, false), ("abandoned".into(), 0));
    }
}
