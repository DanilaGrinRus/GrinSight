//! What the main screen says about following the chain, and the list of
//! troubles with two lines of help each (interface, О14 and О15).
//!
//! Everything here is worked out from what the wallet process already
//! answers (`host.status`, `paycore.wallet.chain_status`,
//! `paycore.chain.status`, `paycore.search.status`): nothing is guessed, and
//! a number the wallet did not give is shown as a dash, not as zero.

use crate::{fill, tr};

/// One of the wallet's helper processes as `host.status` describes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Part {
    pub configured: bool,
    /// `none`, `starting`, `ready`, `down`.
    pub phase: String,
    /// Why the process does not work, in its own words.
    pub error: String,
    /// What a working process says about itself, in its own words. The
    /// delivery process names what hinders it; the chain process describes
    /// its whole state, hindered or not.
    pub problem: String,
    pub starts: u64,
}

/// The search for outputs older than the wallet's blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Search {
    /// `none`, `reading`, `done`.
    pub state: String,
    pub next: Option<u64>,
    pub pieces: u64,
    pub found: u64,
    pub gone: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    /// `host.status` answered at all.
    pub answered: bool,
    pub chain: Part,
    pub transport: Part,
    /// The Tor process for payments to and from the wallet's address, as
    /// `paycore.onion.status` describes it: `phase` is `none`, `starting`,
    /// `up`, `listening` or `failed`.
    pub onion: Part,
    /// Why payments sent to an address through Tor did not get through,
    /// one line per payment that is still waiting.
    pub onion_failed: Vec<String>,
    /// `at_tip`, `behind`, `unknown`; `None` when the wallet did not say.
    pub state: Option<String>,
    pub wallet_height: Option<u64>,
    pub selected_height: Option<u64>,
    /// `paycore.chain.status` answered; only then the two below mean anything.
    pub status_answered: bool,
    pub confirmed_time: Option<u64>,
    pub k_conf: Option<u64>,
    pub search: Option<Search>,
}

/// A line of the "Synchronisation" block. `tone`: 0 plain, 1 good, 2 needs attention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub label: String,
    pub value: String,
    pub tone: i32,
}

fn row(label: &str, value: String, tone: i32) -> Row {
    Row { label: label.into(), value, tone }
}

fn number(n: Option<u64>) -> String {
    n.map_or_else(|| "—".into(), spaced)
}

/// 4118626 as "4 118 626".
pub(crate) fn spaced(n: u64) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len.saturating_mul(2));
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && len.saturating_sub(i).checked_rem(3) == Some(0) {
            out.push(' ');
        }
        out.push(d);
    }
    out
}

/// Hours and minutes of a Unix time, UTC.
fn clock(at: u64) -> String {
    let day = at.checked_rem(86_400).unwrap_or(0);
    let hours = day.checked_div(3600).unwrap_or(0);
    let minutes = day.checked_rem(3600).unwrap_or(0).checked_div(60).unwrap_or(0);
    format!("{hours:02}:{minutes:02} UTC")
}

fn phase_words(part: &Part) -> (String, i32) {
    if !part.configured {
        return (tr("not set", "не задан").into(), 2);
    }
    let (word, tone) = match part.phase.as_str() {
        "ready" => (tr("working", "работает"), 1),
        "starting" => (tr("starting", "запускается"), 0),
        "down" => (tr("stopped", "остановлен"), 2),
        _ => (tr("not started", "не запущен"), 0),
    };
    if part.starts > 1 {
        (fill(tr("{} · started {} times", "{} · запусков: {}"), &[word, &part.starts.to_string()]), tone.max(if part.phase == "ready" { 1 } else { 2 }))
    } else {
        (word.into(), tone)
    }
}

/// The whole path, top to bottom, in the order it is walked.
pub(crate) fn rows(f: &Facts) -> Vec<Row> {
    if !f.answered {
        return vec![row(tr("Wallet process", "Процесс кошелька"), tr("did not answer", "не ответил").into(), 2)];
    }
    let mut out = Vec::with_capacity(8);
    let (value, tone) = phase_words(&f.chain);
    out.push(row(tr("Chain process", "Процесс цепи"), value, tone));

    let (value, tone) = match (f.state.as_deref(), f.selected_height) {
        (_, Some(h)) => (fill(tr("block {}", "блок {}"), &[&spaced(h)]), 1),
        (Some("unknown") | None, None) if f.chain.configured => (tr("not chosen yet: headers are being checked", "ещё не выбрана: проверяются заголовки").into(), 0),
        _ => ("—".into(), 0),
    };
    out.push(row(tr("Chosen tip", "Выбранная вершина"), value, tone));

    let (value, tone) = match (f.state.as_deref(), f.wallet_height, f.selected_height) {
        (Some("at_tip"), Some(w), _) => (fill(tr("at the tip, block {}", "на вершине, блок {}"), &[&spaced(w)]), 1),
        (Some("behind"), Some(w), Some(s)) => (
            fill(tr("block {} of {} · {} left", "блок {} из {} · осталось {}"), &[&spaced(w), &spaced(s), &spaced(s.saturating_sub(w))]),
            0,
        ),
        (_, w, _) => (fill(tr("block {} · waiting for the chain", "блок {} · ждёт цепь"), &[&number(w)]), 0),
    };
    out.push(row(tr("Wallet", "Кошелёк"), value, tone));

    let (value, tone) = match &f.search {
        None => ("—".into(), 0),
        Some(s) => match s.state.as_str() {
            "reading" => (
                fill(
                    tr("piece {} of {} · found {}", "кусок {} из {} · найдено {}"),
                    &[&s.next.map_or_else(|| spaced(s.pieces), spaced), &spaced(s.pieces), &spaced(s.found)],
                ),
                0,
            ),
            "done" => (fill(tr("finished · found {} · spent {}", "закончен · найдено {} · потрачено {}"), &[&spaced(s.found), &spaced(s.gone)]), 1),
            _ => (tr("not needed", "не нужен").into(), 1),
        },
    };
    out.push(row(tr("Search for old outputs", "Поиск давних выходов"), value, tone));

    let (value, tone) = match (f.status_answered, f.confirmed_time) {
        (true, Some(at)) => (fill(tr("confirmed by public nodes, {}", "подтверждено публичными нодами, {}"), &[&clock(at)]), 1),
        (true, None) => (tr("not confirmed yet", "ещё не подтверждено").into(), 2),
        (false, _) => ("—".into(), 0),
    };
    out.push(row(tr("Time", "Время"), value, tone));

    if let Some(k) = f.k_conf {
        out.push(row(tr("Confirmation", "Подтверждение"), fill(tr("after {} blocks", "через {} блоков"), &[&k.to_string()]), 0));
    }

    let (value, tone) = phase_words(&f.transport);
    out.push(row(tr("Message delivery", "Доставка сообщений"), value, if f.transport.configured { tone } else { 0 }));
    out
}

/// The chain process's own account of itself, one statement to a line:
/// how far the headers are verified and from which point, the pieces of
/// the state, the blocks applied, whether the tip is confirmed and, if
/// not, why. Nothing when the process is not working or says nothing.
pub(crate) fn chain_words(f: &Facts) -> Vec<String> {
    if !f.answered || f.chain.phase != "ready" {
        return Vec::new();
    }
    f.chain.problem.split("; ").map(str::trim).filter(|part| !part.is_empty()).map(str::to_string).collect()
}

/// What came to the wallet's address, as the address process counts it:
/// shown while the address listens, so that a payment somebody says they
/// sent can be told from one that never arrived. Counts only.
pub(crate) fn address_words(f: &Facts) -> Option<String> {
    if !f.answered || f.onion.phase != "listening" || !f.onion.problem.starts_with("came to the address: ") {
        return None;
    }
    if tr("en", "ru") == "ru" {
        return Some(address_words_ru(&f.onion.problem));
    }
    Some(f.onion.problem.clone())
}

/// The address process's count in Russian. The process speaks English
/// (`fly-onion`, `Seen::words`); every part it is known to say is put
/// into Russian with its number, and anything else is left as it came —
/// so the first line of a foreign request, which may hold commas of its
/// own, is shown whole and unchanged.
pub(crate) fn address_words_ru(said: &str) -> String {
    const PARTS: [(&str, &str); 7] = [
        ("handed to the wallet", "передано кошельку"),
        ("left without the wallet's answer", "осталось без ответа кошелька"),
        ("not a wallet's request", "не запрос кошелька"),
        ("silent", "молча"),
        ("malformed", "с неверной формой"),
        ("too large", "слишком большие"),
        ("cut short", "оборваны"),
    ];
    let Some(rest) = said.strip_prefix("came to the address: ") else {
        return said.to_string();
    };
    let mut out: Vec<String> = Vec::new();
    for part in rest.split(", ") {
        let (number, what) = part.split_once(' ').unwrap_or((part, ""));
        let counted = !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
        let known = PARTS.iter().find(|(en, _)| counted && *en == what).map(|(_, ru)| format!("{number} {ru}"));
        let port = what.strip_prefix("to another port (last: ").and_then(|p| p.strip_suffix(')')).filter(|p| counted && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if let Some(known) = known {
            out.push(known);
        } else if let Some(port) = port {
            out.push(format!("{number} на другой порт (последний: {port})"));
        } else if let Some(line) = part.strip_prefix("the last of them began: ") {
            out.push(format!("последний из них начинался: {line}"));
        } else {
            out.push(part.to_string());
        }
    }
    format!("пришло на адрес: {}", out.join(", "))
}

/// How the chain process begins its account when a transaction could not
/// be sent (`fly-chain`, `node.rs`).
const NOT_SENT: &str = "a transaction is not sent: ";

/// The chain process's words about a transaction it could not send, if it
/// says so now.
fn not_sent(f: &Facts) -> Option<String> {
    let said = f.chain.problem.strip_prefix(NOT_SENT)?;
    let end = said.find("; headers verified").unwrap_or(said.len());
    Some(said.get(..end).unwrap_or(said).to_string())
}

/// The state of the two Tors in plain words, each with whether it is well:
/// the one that carries messages and payments to contacts (the delivery
/// process) and the one that carries transactions to the network (the
/// chain process starts it with the first payment). `direct` is the
/// owner's consent to send a transaction without Tor when Tor fails.
pub(crate) fn tor_lines(f: &Facts, direct: bool) -> ((String, bool), (String, bool)) {
    let messages = if !f.answered {
        (tr("Tor for messages: unknown — the wallet process did not answer", "Tor для сообщений: неизвестно — процесс кошелька не ответил"), false)
    } else if !f.transport.configured {
        (tr("Tor for messages: not set up — payments go by hand", "Tor для сообщений: не настроен — платежи передаются вручную"), false)
    } else {
        match f.transport.phase.as_str() {
            "ready" if f.transport.problem.is_empty() => (tr("Tor for messages: connected", "Tor для сообщений: подключён"), true),
            "ready" => (tr("Tor for messages: connected, but delivery is hindered — see Problems", "Tor для сообщений: подключён, но доставке что-то мешает — см. «Неполадки»"), false),
            "starting" => (tr("Tor for messages: connecting…", "Tor для сообщений: подключается…"), false),
            // no message key yet: there is nothing to start it for, and nothing is wrong
            "none" => (tr("Tor for messages: not started — create a message key under My details", "Tor для сообщений: не запущен — создайте ключ для сообщений в «Моих реквизитах»"), false),
            _ => (tr("Tor for messages: not working — see Problems", "Tor для сообщений: не работает — см. «Неполадки»"), false),
        }
    };
    let transactions = if !f.answered || !f.chain.configured {
        (tr("Tor for transactions: no chain process", "Tor для транзакций: нет процесса цепи"), false)
    } else if not_sent(f).is_some() {
        (tr("Tor for transactions: the last sending failed, trying again — see Problems", "Tor для транзакций: последняя отправка не прошла, идут повторы — см. «Неполадки»"), false)
    } else if direct {
        (tr("Tor for transactions: connects when you send; directly only if Tor fails — you allowed it", "Tor для транзакций: подключается при отправке; напрямую — только если Tor не сработал, вы это разрешили"), true)
    } else {
        (tr("Tor for transactions: connects when you send; never directly", "Tor для транзакций: подключается при отправке; напрямую — никогда"), true)
    };
    ((messages.0.to_string(), messages.1), (transactions.0.to_string(), transactions.1))
}

/// The third Tor, said outright: the one that carries payments to a Grin
/// address and takes them at the wallet's own.
pub(crate) fn address_line(f: &Facts) -> (String, bool) {
    let (words, good) = if !f.answered {
        (tr("Tor for your address: unknown — the wallet process did not answer", "Tor для вашего адреса: неизвестно — процесс кошелька не ответил"), false)
    } else if !f.onion.configured {
        (tr("Tor for your address: not set up — payments to an address go by hand", "Tor для вашего адреса: не настроен — платежи на адрес передаются вручную"), false)
    } else {
        match f.onion.phase.as_str() {
            "listening" => (tr("Tor for your address: on — payments can be sent to an address and arrive at yours", "Tor для вашего адреса: работает — можно отправлять на адрес и принимать на свой"), true),
            "up" if f.onion.problem.is_empty() || f.onion.problem.contains("being announced") => (tr("Tor for your address: connected, your address is being announced…", "Tor для вашего адреса: подключён, ваш адрес объявляется…"), false),
            "up" => (tr("Tor for your address: connected — sending works, your address is not reachable yet", "Tor для вашего адреса: подключён — отправка работает, ваш адрес пока недоступен"), false),
            "starting" | "none" => (tr("Tor for your address: connecting…", "Tor для вашего адреса: подключается…"), false),
            _ => (tr("Tor for your address: not working — see Problems", "Tor для вашего адреса: не работает — см. «Неполадки»"), false),
        }
    };
    (words.to_string(), good)
}

/// What can be wrong, as far as the wallet process tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    NoAnswer,
    NoChain,
    ChainDown,
    NotSent,
    DeliveryDown,
    DeliveryProblem,
    /// Tor for the wallet's address does not work.
    AddressTor,
    /// A payment sent to an address through Tor did not get through.
    TorSend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Trouble {
    pub kind: Kind,
    /// The process's own words, already cleaned for showing; may be empty.
    pub detail: String,
}

/// What is wrong right now.
pub(crate) fn troubles(f: &Facts) -> Vec<Trouble> {
    let one = |kind, detail: &str| Trouble { kind, detail: detail.into() };
    if !f.answered {
        return vec![one(Kind::NoAnswer, "")];
    }
    let mut out = Vec::new();
    if !f.chain.configured {
        out.push(one(Kind::NoChain, ""));
    } else if f.chain.phase == "down" {
        out.push(one(Kind::ChainDown, &f.chain.error));
    } else if let Some(why) = not_sent(f) {
        out.push(one(Kind::NotSent, &why));
    }
    // The rest of what a working chain process says is its state, not a
    // trouble: it is shown whole in the synchronisation block (`chain_words`).
    if f.transport.configured {
        if f.transport.phase == "down" {
            out.push(one(Kind::DeliveryDown, &f.transport.error));
        } else if !f.transport.problem.is_empty() {
            out.push(one(Kind::DeliveryProblem, &f.transport.problem));
        }
    }
    if f.onion.configured && f.onion.phase == "failed" {
        out.push(one(Kind::AddressTor, &f.onion.problem));
    }
    for why in &f.onion_failed {
        let trouble = one(Kind::TorSend, why);
        if !out.contains(&trouble) {
            out.push(trouble);
        }
    }
    out
}

/// What it is called and what to do about it: two short lines.
pub(crate) fn words(kind: Kind) -> (&'static str, &'static str) {
    match kind {
        Kind::NoAnswer => (
            tr("The wallet process did not answer", "Процесс кошелька не ответил"),
            tr("Wait a few seconds. If it stays, lock the wallet and open it again.", "Подождите несколько секунд. Если не проходит — выйдите и откройте кошелёк снова."),
        ),
        Kind::NoChain => (
            tr("No chain process", "Нет процесса цепи"),
            tr("The program was started without fly-chain: the balance cannot be checked. Start it from its own folder or install it again.", "Программа запущена без fly-chain: баланс проверить нечем. Запустите её из своей папки или установите заново."),
        ),
        Kind::ChainDown => (
            tr("The chain process stopped", "Процесс цепи остановился"),
            tr("The wallet starts it again by itself. If this repeats, check the internet connection and free disk space.", "Кошелёк запускает его снова сам. Если повторяется — проверьте интернет и свободное место на диске."),
        ),
        Kind::NotSent => (
            tr("A transaction is not sent yet", "Транзакция ещё не отправлена"),
            tr("It is sent again by itself. Check the connection. If Tor is closed on this network, you can allow direct sending in the options of the first screen.", "Она отправляется снова сама. Проверьте соединение. Если в этой сети закрыт Tor, прямую отправку можно разрешить в настройках первого экрана."),
        ),
        Kind::DeliveryDown => (
            tr("Message delivery stopped", "Доставка сообщений остановилась"),
            tr("Payments still go by hand (Slatepack). It is started again by itself; Tor may be blocked on this network.", "Платежи по-прежнему можно передать вручную (Slatepack). Она запускается снова сама; возможно, в этой сети закрыт Tor."),
        ),
        Kind::DeliveryProblem => (
            tr("Message delivery is hindered", "Доставке сообщений что-то мешает"),
            tr("The relay or Tor does not answer. Sending is retried; a payment can go by hand meanwhile.", "Не отвечает релей или Tor. Отправка повторяется; платёж пока можно передать вручную."),
        ),
        Kind::AddressTor => (
            tr("Tor for your address does not work", "Tor для вашего адреса не работает"),
            tr("The wallet starts it again by itself. Meanwhile payments to an address go by hand: the Slatepack text. Check the internet connection if this stays.", "Кошелёк запускает его снова сам. Пока платежи на адрес передаются вручную — текстом Slatepack. Если не проходит — проверьте интернет."),
        ),
        Kind::TorSend => (
            tr("A payment did not reach the address over Tor", "Платёж не дошёл до адреса через Tor"),
            tr("The money stays reserved. Open “All payments”, show the payment's text and send it over Tor again or pass it by hand; or cancel the payment under “Waiting for you”.", "Деньги остаются в резерве. Откройте «Все операции», покажите текст платежа и отправьте его через Tor ещё раз или передайте вручную; либо отмените платёж в «Ждут вас»."),
        ),
    }
}

/// A trouble as it was seen: when it began and whether it is still there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub at: u64,
    pub trouble: Trouble,
    pub open: bool,
}

/// The troubles of this session, oldest first, no more than `KEPT`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Journal {
    entries: Vec<Entry>,
}

/// How many troubles are remembered.
pub(crate) const KEPT: usize = 24;
/// How many of them the main screen shows.
pub(crate) const SHOWN: usize = 3;

impl Journal {
    /// Writes down what is wrong now: a trouble that began is added once,
    /// one that is gone is marked so and kept.
    pub(crate) fn note(&mut self, now: u64, current: &[Trouble]) {
        for entry in &mut self.entries {
            if entry.open && !current.contains(&entry.trouble) {
                entry.open = false;
            }
        }
        for trouble in current {
            if !self.entries.iter().any(|e| e.open && &e.trouble == trouble) {
                self.entries.push(Entry { at: now, trouble: trouble.clone(), open: true });
            }
        }
        let extra = self.entries.len().saturating_sub(KEPT);
        if extra > 0 {
            self.entries.drain(..extra);
        }
    }

    /// The newest first.
    pub(crate) fn newest(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().rev().take(SHOWN)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(phase: &str) -> Part {
        Part { configured: true, phase: phase.into(), starts: 1, ..Part::default() }
    }

    fn at_tip() -> Facts {
        Facts {
            answered: true,
            chain: part("ready"),
            transport: part("ready"),
            state: Some("at_tip".into()),
            wallet_height: Some(4_120_281),
            selected_height: Some(4_120_281),
            status_answered: true,
            confirmed_time: Some(1_795_490_000),
            k_conf: Some(10),
            search: Some(Search { state: "done".into(), next: None, pieces: 310, found: 3, gone: 1 }),
            ..Facts::default()
        }
    }

    fn value(rows: &[Row], label: &str) -> Row {
        rows.iter().find(|r| r.label == label).cloned().unwrap_or(Row { label: String::new(), value: format!("no row {label}"), tone: -1 })
    }

    /// The whole path is shown with the wallet's own numbers.
    #[test]
    fn the_path_is_shown_with_its_numbers() {
        let rows = rows(&at_tip());
        assert_eq!(value(&rows, "Chain process").value, "working");
        assert_eq!(value(&rows, "Chosen tip").value, "block 4 120 281");
        assert_eq!(value(&rows, "Wallet").value, "at the tip, block 4 120 281");
        assert_eq!(value(&rows, "Search for old outputs").value, "finished · found 3 · spent 1");
        assert!(value(&rows, "Time").value.starts_with("confirmed by public nodes, "), "{:?}", value(&rows, "Time"));
        assert_eq!(value(&rows, "Confirmation").value, "after 10 blocks");
        assert_eq!(value(&rows, "Message delivery").value, "working");
        assert!(rows.iter().all(|r| r.tone != 2), "{rows:?}");
    }

    /// Catching up and searching say how much is left; nothing is rounded away.
    #[test]
    fn catching_up_says_how_much_is_left() {
        let mut f = at_tip();
        f.state = Some("behind".into());
        f.wallet_height = Some(4_120_000);
        f.search = Some(Search { state: "reading".into(), next: Some(120), pieces: 310, found: 2, gone: 0 });
        let rows = rows(&f);
        assert_eq!(value(&rows, "Wallet").value, "block 4 120 000 of 4 120 281 · 281 left");
        assert_eq!(value(&rows, "Search for old outputs").value, "piece 120 of 310 · found 2");
    }

    /// What the wallet did not say is a dash or a plain "not yet", never a number.
    #[test]
    fn what_is_not_known_is_not_a_number() {
        let f = Facts { answered: true, chain: part("starting"), state: Some("unknown".into()), status_answered: true, ..Facts::default() };
        let rows = rows(&f);
        assert_eq!(value(&rows, "Chosen tip").value, "not chosen yet: headers are being checked");
        assert_eq!(value(&rows, "Wallet").value, "block — · waiting for the chain");
        assert_eq!(value(&rows, "Time").value, "not confirmed yet");
        assert_eq!(value(&rows, "Time").tone, 2);
        assert_eq!(value(&rows, "Search for old outputs").value, "—");
        assert!(rows.iter().all(|r| r.label != "Confirmation"));
        let silent = super::rows(&Facts::default());
        assert_eq!(silent.len(), 1);
        assert_eq!(value(&silent, "Wallet process").tone, 2);
    }

    /// Each trouble is named from what the wallet process reports.
    #[test]
    fn troubles_come_from_what_the_processes_report() {
        assert!(troubles(&at_tip()).is_empty());
        assert_eq!(troubles(&Facts::default()), vec![Trouble { kind: Kind::NoAnswer, detail: String::new() }]);
        let mut f = at_tip();
        f.chain.configured = false;
        assert_eq!(troubles(&f).first().map(|t| t.kind), Some(Kind::NoChain));
        let mut f = at_tip();
        f.chain.phase = "down".into();
        f.chain.error = "exit 1".into();
        f.transport.problem = "relay refused".into();
        assert_eq!(
            troubles(&f),
            vec![Trouble { kind: Kind::ChainDown, detail: "exit 1".into() }, Trouble { kind: Kind::DeliveryProblem, detail: "relay refused".into() }]
        );
        // a wallet without delivery set up is not a trouble: payments go by hand
        let mut f = at_tip();
        f.transport = Part::default();
        assert!(troubles(&f).is_empty());
        // what a working chain process says about itself is not a trouble
        let mut f = at_tip();
        f.chain.problem = "headers verified to 10; blocks applied to the tip, 10".into();
        assert!(troubles(&f).is_empty());
    }

    /// Every trouble has a name and a line of help, in both languages.
    #[test]
    fn every_trouble_has_help() {
        for kind in [Kind::NoAnswer, Kind::NoChain, Kind::ChainDown, Kind::NotSent, Kind::DeliveryDown, Kind::DeliveryProblem] {
            let (what, help) = words(kind);
            assert!(!what.is_empty() && help.len() > 20 && help.ends_with('.'), "{kind:?}");
        }
    }

    /// A trouble is written down once when it begins, kept when it is gone,
    /// and written again if it comes back; the list does not grow without end.
    #[test]
    fn the_journal_keeps_what_happened() {
        let down = Trouble { kind: Kind::ChainDown, detail: "exit 1".into() };
        let mut journal = Journal::default();
        journal.note(10, std::slice::from_ref(&down));
        journal.note(20, std::slice::from_ref(&down));
        assert_eq!(journal.len(), 1);
        journal.note(30, &[]);
        assert_eq!(journal.newest().map(|e| (e.at, e.open)).collect::<Vec<_>>(), vec![(10, false)]);
        journal.note(40, std::slice::from_ref(&down));
        assert_eq!(journal.newest().map(|e| (e.at, e.open)).collect::<Vec<_>>(), vec![(40, true), (10, false)]);
        for i in 0..100u64 {
            journal.note(100u64.saturating_add(i.saturating_mul(2)), &[]);
            journal.note(101u64.saturating_add(i.saturating_mul(2)), std::slice::from_ref(&down));
        }
        assert_eq!(journal.len(), KEPT);
        assert_eq!(journal.newest().count(), SHOWN);
    }

    /// The chain process's account of itself is shown statement by
    /// statement, and only while the process works.
    #[test]
    fn the_chain_process_is_quoted_statement_by_statement() {
        let mut f = at_tip();
        f.chain.problem = "headers verified to 4120367 from a release starting point (4115520); collecting the state at 4119000: 12 of 310 pieces; no block has been applied yet; ".into();
        assert_eq!(
            chain_words(&f),
            vec!["headers verified to 4120367 from a release starting point (4115520)", "collecting the state at 4119000: 12 of 310 pieces", "no block has been applied yet"]
        );
        f.chain.phase = "down".into();
        assert!(chain_words(&f).is_empty());
        assert!(chain_words(&Facts::default()).is_empty());
    }

    /// The state of both Tors is said in so many words, and a transaction
    /// that could not be sent is a trouble with the chain process's reason.
    #[test]
    fn what_came_to_the_address_is_shown_only_while_it_listens() {
        let mut f = at_tip();
        f.onion = Part { configured: true, phase: "listening".into(), ..Part::default() };
        assert_eq!(address_words(&f), None);
        f.onion.problem = "came to the address: 1 handed to the wallet".into();
        assert_eq!(address_words(&f).as_deref(), Some("came to the address: 1 handed to the wallet"));
        // the address still reads as working: the count is no trouble
        assert!(address_line(&f).1);
        f.onion.problem = "something else".into();
        assert_eq!(address_words(&f), None);
        f.onion.phase = "up".into();
        f.onion.problem = "came to the address: 1 handed to the wallet".into();
        assert_eq!(address_words(&f), None);
    }

    /// The count of what came to the address is said in Russian part by
    /// part, with the same numbers; what a foreign request began with is
    /// shown as it came.
    #[test]
    fn what_came_to_the_address_is_said_in_russian_with_the_same_numbers() {
        assert_eq!(
            address_words_ru("came to the address: 2 handed to the wallet, 1 left without the wallet's answer, 9 not a wallet's request, the last of them began: GET /a, b HTTP/1.1, 5 silent, 1 malformed, 3 too large, 4 cut short, 7 to another port (last: 443)"),
            "пришло на адрес: 2 передано кошельку, 1 осталось без ответа кошелька, 9 не запрос кошелька, последний из них начинался: GET /a, b HTTP/1.1, 5 молча, 1 с неверной формой, 3 слишком большие, 4 оборваны, 7 на другой порт (последний: 443)"
        );
        // what is not the process's count is not touched
        assert_eq!(address_words_ru("something else"), "something else");
        assert_eq!(address_words_ru("came to the address: x silent, 2 unknown"), "пришло на адрес: x silent, 2 unknown");
    }

    #[test]
    fn the_state_of_tor_is_explicit() {
        let (messages, transactions) = tor_lines(&at_tip(), false);
        assert_eq!(messages, ("Tor for messages: connected".to_string(), true));
        assert_eq!(transactions, ("Tor for transactions: connects when you send; never directly".to_string(), true));
        assert!(tor_lines(&at_tip(), true).1 .0.contains("you allowed it"));
        let mut f = at_tip();
        f.transport.phase = "starting".into();
        assert_eq!(tor_lines(&f, false).0, ("Tor for messages: connecting…".to_string(), false));
        // without a message key the transport is not started: that is said, and "Problems" is not pointed at
        f.transport.phase = "none".into();
        assert_eq!(tor_lines(&f, false).0, ("Tor for messages: not started — create a message key under My details".to_string(), false));
        f.transport.phase = "down".into();
        assert!(!tor_lines(&f, false).0 .1);
        f.transport = Part::default();
        assert_eq!(tor_lines(&f, false).0 .0, "Tor for messages: not set up — payments go by hand");
        let mut f = at_tip();
        f.chain.problem = "a transaction is not sent: Tor: no route; tried again, never from this computer's address without your agreement; headers verified to 10 from a release starting point (5)".into();
        assert_eq!(tor_lines(&f, false).1, ("Tor for transactions: the last sending failed, trying again — see Problems".to_string(), false));
        assert_eq!(
            troubles(&f),
            vec![Trouble { kind: Kind::NotSent, detail: "Tor: no route; tried again, never from this computer's address without your agreement".into() }]
        );
        assert!(!tor_lines(&Facts::default(), false).0 .1 && !tor_lines(&Facts::default(), false).1 .1);
    }

    /// О22: the Tor for the wallet's address says where it stands, and a
    /// payment that did not get through is a trouble with its reason.
    #[test]
    fn the_tor_for_the_address_is_explicit() {
        let mut f = at_tip();
        assert_eq!(address_line(&f), ("Tor for your address: not set up — payments to an address go by hand".to_string(), false));
        f.onion.configured = true;
        f.onion.phase = "starting".into();
        assert_eq!(address_line(&f), ("Tor for your address: connecting…".to_string(), false));
        f.onion.phase = "up".into();
        assert!(address_line(&f).0.contains("being announced"));
        f.onion.problem = "the address is being announced in Tor".into();
        assert!(address_line(&f).0.contains("being announced"));
        f.onion.problem = "the address cannot be reached through Tor now".into();
        assert!(address_line(&f).0.contains("not reachable yet"));
        f.onion.phase = "listening".into();
        f.onion.problem.clear();
        assert!(address_line(&f).1);
        assert!(troubles(&f).is_empty());
        f.onion.phase = "failed".into();
        f.onion.problem = "Tor did not come up".into();
        assert_eq!(address_line(&f), ("Tor for your address: not working — see Problems".to_string(), false));
        assert_eq!(troubles(&f), vec![Trouble { kind: Kind::AddressTor, detail: "Tor did not come up".into() }]);
        f.onion.phase = "listening".into();
        f.onion_failed = vec!["Tor did not reach the wallet at this address".into(), "Tor did not reach the wallet at this address".into()];
        // the same reason twice is one line
        assert_eq!(troubles(&f), vec![Trouble { kind: Kind::TorSend, detail: "Tor did not reach the wallet at this address".into() }]);
        assert!(words(Kind::TorSend).1.contains("reserved"));
        assert!(!address_line(&Facts::default()).1);
    }

    #[test]
    fn numbers_are_spaced_by_threes() {
        assert_eq!(spaced(0), "0");
        assert_eq!(spaced(999), "999");
        assert_eq!(spaced(1000), "1 000");
        assert_eq!(spaced(4_120_281), "4 120 281");
    }
}
