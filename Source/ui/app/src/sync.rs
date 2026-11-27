//! What the main screen says about following the chain, and the list of
//! troubles with two lines of help each (interface, О14 and О15).
//!
//! Everything here is worked out from what the wallet process already
//! answers (`host.status`, `paycore.wallet.chain_status`,
//! `paycore.search.status`): nothing is guessed, and
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
    /// The wallet supplied its balance and chain snapshot in this refresh.
    pub status_answered: bool,
    pub confirmed_time: Option<u64>,
    pub k_conf: Option<u64>,
    pub search: Option<Search>,
    /// The owner switched Tor off (O42): nothing of it is started.
    pub tor_off: bool,
    /// The owner switched Nostr off: the message program is not started.
    pub nostr_off: bool,
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
        return (tr("not set", "не задана").into(), 2);
    }
    let (word, tone) = match part.phase.as_str() {
        "ready" => (tr("working", "работает"), 1),
        "starting" => (tr("starting", "запускается"), 0),
        "down" => (tr("stopped", "остановлена"), 2),
        _ => (tr("not started", "не запущена"), 0),
    };
    if part.starts > 1 {
        (fill(tr("{} · started {} times", "{} · запусков: {}"), &[word, &part.starts.to_string()]), tone.max(if part.phase == "ready" { 1 } else { 2 }))
    } else {
        (word.into(), tone)
    }
}

/// The whole path, top to bottom, in the order it is walked.
/// 0.4.6: what the chain process says of the history before its starting
/// point. Only a build that carries the proof of history says anything; the
/// others have no such line. "Checked" is said for one statement only -
/// anything else the process may say of it is "not checked".
pub(crate) fn history_row(f: &Facts) -> Option<Row> {
    if !f.answered || f.chain.phase != "ready" {
        return None;
    }
    let detail = &f.chain.problem;
    let history = detail.split("; ").find_map(|part| part.trim().strip_prefix("history:"));
    let imported = detail.split(';').next()?.split_once("imported starting point: GSHP1 sample verified for this checkpoint (")
        .and_then(|(_, tail)| tail.strip_suffix(')')).and_then(|height| height.parse::<u64>().ok());
    if let Some(height) = imported {
        // The exact provenance survives truncation of the later history field.
        if history.is_none_or(|h| "sampled".starts_with(h.trim())) {
            return Some(row(tr("History before the starting point", "История до стартовой точки"),
                fill(tr("Imported checkpoint at block {}. Its GSHP1 history sample was verified on this device.",
                    "Импортирована точка на блоке {}. Выборка истории GSHP1 проверена на этом устройстве."), &[&spaced(height)]), 1));
        }
    }
    // The host can truncate the final history field. The selected compact
    // point also carries its provenance at the start of the chain report.
    let compact = "locally saved after sequential verification from genesis";
    let said = history
        .or_else(|| f.chain.problem.contains(" from a locally saved point: headers checked from network genesis (").then_some(compact))?;
    // K202: the words come last and may be cut at the length limit: words
    // that are not one of the four whole say nothing, never "not passed"
    let (value, tone) = match said.trim() {
        "sequentially verified from network genesis" => (tr("Headers checked from genesis. Historical transactions were not replayed.", "Заголовки проверены от первого блока. Проверка истории транзакций не проводилась."), 1),
        "locally saved after sequential verification from genesis" => (tr("Started from this wallet’s compact point after its own header check from genesis.", "Запуск с компактной точки этого кошелька после собственной проверки заголовков от первого блока."), 1),
        "sampled" => (tr("Release starting point. History up to it was checked by sampling its work.", "Точка из выпуска. История до неё проверена выборкой по накопленной работе."), 1),
        "sampled to the program's point" => (
            tr("checked by sampling its work up to the program's point; from there checked by the wallet that made your point", "проверена выборкой работы до точки программы; дальше — кошельком, который сделал вашу точку"),
            1,
        ),
        "not proved for this point" => (
            tr("not checked: the proof in the program is for another starting point", "не проверена: доказательство в программе — для другой стартовой точки"),
            0,
        ),
        "the proof did not pass" => (tr("not checked: the proof in the program did not pass", "не проверена: доказательство в программе не прошло проверку"), 2),
        _ => return None,
    };
    Some(row(tr("History before the starting point", "История до стартовой точки"), value.into(), tone))
}

pub(crate) fn rows(f: &Facts) -> Vec<Row> {
    if !f.answered && !f.status_answered {
        return vec![row(tr("Wallet", "Кошелёк"), tr("does not answer", "не отвечает").into(), 2)];
    }
    let mut out = Vec::with_capacity(8);
    let (value, tone) = phase_words(&f.chain);
    out.push(row(tr("Network check", "Проверка сети"), value, tone));
    out.extend(history_row(f));
    if f.chain.phase == "ready" {
        let detail = &f.chain.problem;
        if let Some((_, tail)) = detail.split_once("headers checked from network genesis (") {
            if let Some(height) = tail.split_once(')').and_then(|(h, _)| h.parse::<u64>().ok()) {
                out.push(row(tr("Local checkpoint", "Локальная точка"), spaced(height), 0));
            }
        }
        if let Some(work) = detail.split_once("; work=").and_then(|(_, tail)| tail.split_once(';'))
            .and_then(|(value, _)| value.parse::<u64>().ok()) {
            out.push(row(tr("Verified header work", "Проверенная работа заголовков"), spaced(work), 0));
        }
    }

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
                    tr("part {} of {} · found {}", "часть {} из {} · найдено {}"),
                    &[&s.next.map_or_else(|| spaced(s.pieces), spaced), &spaced(s.pieces), &spaced(s.found)],
                ),
                0,
            ),
            "done" => (fill(tr("finished · found {} · spent {}", "закончен · найдено {} · потрачено {}"), &[&spaced(s.found), &spaced(s.gone)]), 1),
            _ => (tr("not needed", "не нужен").into(), 1),
        },
    };
    out.push(row(tr("Search for old money", "Поиск давних денег"), value, tone));

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

/// What the chain process said, taken apart: every statement it is known
/// to make (`fly-chain`, `feed.rs::describe` and `accept.rs`) becomes a
/// stage with its numbers; whatever else it says is kept whole in `rest`,
/// so that nothing it said is lost and nothing is guessed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Said {
    stored: bool,
    headers: Option<u64>,
    nodes_at: Option<u64>,
    collecting: Option<(u64, u64)>,
    collected: bool,
    blocks: Option<(u64, bool)>,
    no_block: bool,
    confirmed: Option<bool>,
    tip_why: Option<String>,
    nodes: Option<String>,
    rest: Vec<String>,
}

fn leading_number(text: &str) -> Option<u64> {
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Why the tip is not confirmed, in the user's language. A statement that
/// is not one of the known ones comes back as `None`.
fn tip_why_words(said: &str) -> Option<(String, i32)> {
    let known: [(&str, &str, i32); 14] = [
        ("not at the tip yet", "ещё не у вершины", 3),
        ("asking public nodes about the tip", "спрашиваю публичные ноды", 3),
        ("public nodes have not been asked yet", "публичные ноды ещё не спрошены", 3),
        ("the time is not confirmed yet", "время ещё не подтверждено", 3),
        ("the time is not confirmed: too few public nodes answered", "время не подтверждено: ответило слишком мало публичных нод", 2),
        ("the time is not confirmed: public nodes disagree about it", "время не подтверждено: публичные ноды называют разное", 2),
        ("this computer's clock is far from the time of public nodes: check the clock", "часы этого компьютера далеко от времени публичных нод: проверьте часы", 2),
        ("public nodes name a time before one confirmed earlier", "публичные ноды называют время раньше уже подтверждённого", 2),
        ("no secure channel to public nodes: no tip is confirmed", "нет защищённого канала к публичным нодам: вершина не подтверждена", 2),
        ("no public nodes are listed for this network: no tip is confirmed", "для этой сети нет списка публичных нод: вершина не подтверждена", 2),
        ("too many unsettled claims of more work: no tip is confirmed", "слишком много неразрешённых заявлений о большей работе: вершина не подтверждена", 2),
        ("a public node names more work than is verified here", "публичная нода называет больше работы, чем проверено здесь", 2),
        ("the list of public nodes is too small to confirm a tip", "список публичных нод слишком мал, чтобы подтвердить вершину", 2),
        ("the numbers for asking public nodes ran out: no tip is confirmed", "кончились числа для опроса публичных нод: вершина не подтверждена", 2),
    ];
    if let Some((en, ru, tone)) = known.iter().find(|(en, _, _)| *en == said) {
        return Some((tr(en, ru).to_string(), *tone));
    }
    if let Some(counts) = said.strip_prefix("public nodes did not confirm the tip (").and_then(|s| s.strip_suffix(" named it)")) {
        if let Some(((answered, needed), confirming)) = counts.split_once(" needed, ")
            .and_then(|(left, right)| Some((left.split_once(" answered, ")?, right))) {
            if [answered, needed, confirming].iter().all(|n| n.parse::<u64>().is_ok()) {
                return Some((fill(tr("public nodes did not confirm the tip ({} answered, {} needed, {} named it)",
                    "публичные ноды не подтвердили вершину (ответили: {}, требуется: {}, указали эту вершину: {})"),
                    &[answered, needed, confirming]), 2));
            }
        }
    }
    // Unrecognized diagnostics may carry an operator name.
    let about_the_tip = said.starts_with("public node ") || said.starts_with("public nodes did not confirm the tip") || said.ends_with(": no tip is confirmed");
    about_the_tip.then(|| (said.to_string(), 2))
}

fn said(problem: &str) -> Said {
    let mut out = Said::default();
    for part in problem.split("; ").map(str::trim).filter(|part| !part.is_empty()) {
        if part == "verifying the stored headers" {
            out.stored = true;
        } else if let Some(rest) = part.strip_prefix("headers verified to ") {
            out.headers = leading_number(rest);
            if out.headers.is_none() {
                out.rest.push(part.to_string());
            }
        } else if let Some(rest) = part.strip_prefix("nodes are at about ") {
            out.nodes_at = leading_number(rest);
        } else if let Some(rest) = part.strip_prefix("collecting the state at ") {
            let counts = rest.split_once(": ").and_then(|(_, counts)| counts.strip_suffix(" pieces")).and_then(|counts| counts.split_once(" of "));
            match counts.and_then(|(done, all)| Some((done.parse().ok()?, all.parse().ok()?))) {
                Some(counts) => out.collecting = Some(counts),
                None => out.rest.push(part.to_string()),
            }
        } else if part.starts_with("the state at ") && part.ends_with(" is collected and checked") {
            out.collected = true;
        } else if let Some(rest) = part.strip_prefix("blocks applied to ") {
            let (rest, at_tip) = rest.strip_prefix("the tip, ").map_or((rest, false), |rest| (rest, true));
            match leading_number(rest) {
                Some(height) => out.blocks = Some((height, at_tip)),
                None => out.rest.push(part.to_string()),
            }
        } else if part == "no block has been applied yet" {
            out.no_block = true;
        } else if let Some(rest) = part.strip_prefix("the tip is confirmed by public nodes") {
            out.confirmed = Some(!rest.is_empty());
        } else if part.starts_with("no node is connected") || part.starts_with("no node address is known") {
            out.nodes = Some(part.to_string());
        } else if part.starts_with("history:") || "history:".starts_with(part) {
            // K202: said in a line of its own (`history_row`), never as a trouble
        } else if out.tip_why.is_none() && tip_why_words(part).is_some() {
            out.tip_why = Some(part.to_string());
        } else {
            out.rest.push(part.to_string());
        }
    }
    out
}

/// The stages of following the network, in the order they happen, each
/// with where it stands: 0 not begun, 3 under way, 1 done, 2 needs
/// attention. Made from what the chain process says of itself and from
/// the wallet's own numbers; a stage nobody has spoken of is "not begun",
/// never "done".
pub(crate) fn stages(f: &Facts) -> Vec<Row> {
    if !f.answered && !f.status_answered {
        return vec![row(tr("Wallet", "Кошелёк"), tr("does not answer", "не отвечает").into(), 2)];
    }
    if !f.chain.configured {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(7);
    let working = f.chain.phase == "ready";
    if !working {
        let (value, tone) = phase_words(&f.chain);
        out.push(row(tr("Network check", "Проверка сети"), value, if tone == 2 { 2 } else { 3 }));
    }
    let said = if working { said(&f.chain.problem) } else { Said::default() };
    if let Some(nodes) = &said.nodes {
        let words = if nodes.starts_with("no node address is known") {
            tr("no node address is known: the names of the network's nodes did not resolve", "адреса нод неизвестны: имена нод сети не нашлись").to_string()
        } else if nodes.starts_with("no node is connected yet") {
            tr("no node is connected yet", "пока не подключена ни одна нода").to_string()
        } else {
            tr("no node is connected", "не подключена ни одна нода").to_string()
        };
        out.push(row(tr("Nodes", "Ноды"), words, if nodes.starts_with("no node is connected yet") { 3 } else { 2 }));
    }
    let (value, tone) = match (said.stored, said.headers, said.nodes_at) {
        (true, _, _) => (tr("checking the stored ones", "проверяются сохранённые").to_string(), 3),
        (_, Some(at), Some(nodes)) if nodes > at => (fill(tr("{} of about {}", "{} из примерно {}"), &[&spaced(at), &spaced(nodes)]), 3),
        (_, Some(at), _) => (fill(tr("verified to {}", "проверены до {}"), &[&spaced(at)]), 1),
        _ => ("—".into(), 0),
    };
    out.push(row(tr("Block headers", "Заголовки блоков"), value, tone));
    let (value, tone) = match (said.collecting, said.collected || said.blocks.is_some()) {
        (Some((done, all)), _) => (fill(tr("part {} of {}", "часть {} из {}"), &[&spaced(done), &spaced(all)]), 3),
        (None, true) => (tr("collected and checked", "собрано и проверено").to_string(), 1),
        (None, false) => ("—".into(), 0),
    };
    out.push(row(tr("Network state", "Состояние сети"), value, tone));
    let (value, tone) = match (said.blocks, said.headers) {
        (Some((height, true)), _) => (fill(tr("to the tip, {}", "до вершины, {}"), &[&spaced(height)]), 1),
        (Some((height, false)), Some(headers)) if headers >= height => (
            fill(tr("{} of {} · {} left", "{} из {} · осталось {}"), &[&spaced(height), &spaced(headers), &spaced(headers.saturating_sub(height))]),
            3,
        ),
        (Some((height, false)), _) => (fill(tr("to {}", "до {}"), &[&spaced(height)]), 3),
        (None, _) if said.no_block => (tr("not applied yet", "ещё не применялись").to_string(), 0),
        (None, _) => ("—".into(), 0),
    };
    out.push(row(tr("Blocks", "Блоки"), value, tone));
    // The host's progress text was gathered before the wallet snapshot. It
    // may explain a compatible result, but cannot select or revoke a tip.
    let selected = f.selected_height.is_some() && f.confirmed_time.is_some();
    let reason = said.tip_why.as_deref().filter(|why| compatible_tip_reason(f, why)).and_then(tip_why_words);
    let (value, tone) = match (selected, reason) {
        (true, _) if said.confirmed == Some(true) && said.headers == f.selected_height => (
            tr("confirmed, with a caveat: a claim of more work went unsettled not long ago", "подтверждена, с оговоркой: недавно осталось неразрешённым заявление о большей работе").to_string(),
            2,
        ),
        (true, _) => (tr("confirmed by public nodes", "подтверждена публичными нодами").into(), 1),
        (false, Some(why)) => why,
        (false, None) if f.status_answered && f.confirmed_time.is_none() =>
            (tr("time is not confirmed", "время не подтверждено").into(), 2),
        (false, None) if f.status_answered =>
            (tr("waiting for public nodes to confirm the tip", "ждём подтверждения вершины публичными нодами").into(), 2),
        _ => ("—".into(), 0),
    };
    out.push(row(tr("Tip", "Вершина"), value, tone));
    let (value, tone) = match (f.state.as_deref(), f.wallet_height, f.selected_height) {
        (Some("at_tip"), Some(w), _) => (fill(tr("at the tip, block {}", "на вершине, блок {}"), &[&spaced(w)]), 1),
        (Some("behind"), Some(w), Some(s)) => (fill(tr("block {} of {} · {} left", "блок {} из {} · осталось {}"), &[&spaced(w), &spaced(s), &spaced(s.saturating_sub(w))]), 3),
        (Some("behind"), Some(w), None) => (fill(tr("block {}", "блок {}"), &[&spaced(w)]), 3),
        _ => (tr("waiting for the chain", "ждёт цепь").to_string(), 0),
    };
    out.push(row(tr("Wallet", "Кошелёк"), value, tone));
    if let Some(search) = &f.search {
        if search.state == "reading" {
            let at = search.next.map_or_else(|| spaced(search.pieces), spaced);
            out.push(row(tr("Search for old money", "Поиск давних денег"), fill(tr("part {} of {} · found {}", "часть {} из {} · найдено {}"), &[&at, &spaced(search.pieces), &spaced(search.found)]), 3));
        }
    }
    out
}

/// What the chain process says beyond the stages, as it said it: shown
/// under "details" so that nothing is hidden.
pub(crate) fn chain_rest(f: &Facts) -> Vec<String> {
    if !f.answered || f.chain.phase != "ready" {
        return Vec::new();
    }
    said(&f.chain.problem).rest
}

/// Clock failures from an earlier poll cannot explain a snapshot with a valid clock.
fn compatible_tip_reason(f: &Facts, why: &str) -> bool {
    f.selected_height.is_none() && (f.confirmed_time.is_none() ||
        !(why.starts_with("the time ") || why.starts_with("this computer's clock ") || why.starts_with("public nodes name a time ")))
}

/// The chain process's own account of itself, one statement to a line:
/// how far the headers are verified and from which point, the pieces of
/// the state, the blocks applied, whether the tip is confirmed and, if
/// not, why. Nothing when the process is not working or says nothing.
pub(crate) fn chain_words(f: &Facts) -> Vec<String> {
    if !f.answered || f.chain.phase != "ready" {
        return Vec::new();
    }
    f.chain.problem.split("; ").map(str::trim).filter(|part| {
        if part.starts_with("the tip is confirmed by public nodes") {
            return f.selected_height.is_some() && f.confirmed_time.is_some() && said(&f.chain.problem).headers == f.selected_height;
        }
        !part.is_empty() && (tip_why_words(part).is_none() || compatible_tip_reason(f, part))
    }).map(str::to_string).collect()
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
pub(crate) fn not_sent(f: &Facts) -> Option<String> {
    let said = f.chain.problem.strip_prefix(NOT_SENT)?;
    let end = said.find("; headers verified").unwrap_or(said.len());
    Some(said.get(..end).unwrap_or(said).to_string())
}

/// O60: whether Tor looks unable to carry a transaction to the network
/// now, said before a payment is signed. The Tor for transactions starts
/// only with a sending, so the signs are indirect: an earlier transaction
/// the chain process says it could not send, or a Tor of this wallet that
/// is down. `None`: nothing speaks against it, or Tor is switched off.
pub(crate) fn tor_doubt(f: &Facts) -> Option<&'static str> {
    if f.tor_off {
        return None;
    }
    if not_sent(f).is_some() {
        return Some(tr("An earlier payment could not be sent through Tor and is still waiting", "Прежний платёж не удалось отправить через Tor, он всё ещё ждёт"));
    }
    if (f.transport.configured && f.transport.phase == "down") || (f.onion.configured && f.onion.phase == "failed") {
        return Some(tr("Tor is not working on this device now", "Tor на этом устройстве сейчас не работает"));
    }
    None
}

/// The state of the two Tors in plain words, each with whether it is well:
/// the one that carries messages and payments to contacts (the delivery
/// process) and the one that carries transactions to the network (the
/// chain process starts it with the first payment). `direct` is the
/// owner's consent to send a transaction without Tor when Tor fails.
pub(crate) fn tor_lines(f: &Facts, direct: bool) -> ((String, bool), (String, bool)) {
    let messages = if f.nostr_off {
        (tr("Messages (Nostr): switched off — payments to contacts go by hand", "Сообщения (Nostr): выключены — платежи контактам передаются вручную"), false)
    } else if f.tor_off {
        (tr("Messages (Nostr): do not work without Tor — payments go by hand", "Сообщения (Nostr): без Tor не работают — платежи передаются вручную"), false)
    } else if !f.answered {
        (tr("Tor for messages: unknown — the wallet does not answer", "Tor для сообщений: неизвестно — кошелёк не отвечает"), false)
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
        (tr("Tor for transactions: the network check is missing", "Tor для транзакций: нет проверки сети"), false)
    } else if f.tor_off {
        (tr("Tor is switched off: transactions go to the network directly, the node sees your address", "Tor выключен: транзакции идут в сеть напрямую, нода видит ваш адрес"), false)
    } else if not_sent(f).is_some() {
        (tr("Tor for transactions: the last sending failed, trying again — see Problems", "Tor для транзакций: последняя отправка не прошла, идут повторы — см. «Неполадки»"), false)
    } else if direct {
        (tr("Tor for transactions: connects when you send; directly only if Tor fails — you allowed it", "Tor для транзакций: подключается при отправке; напрямую — только если Tor не сработал, вы это разрешили"), true)
    } else {
        (tr("Tor for transactions: connects when you send; never directly", "Tor для транзакций: подключается при отправке; напрямую — никогда"), true)
    };
    ((messages.0.to_string(), messages.1), (transactions.0.to_string(), transactions.1))
}

/// How each of the three Tors stands, for its mark beside the line: 0 not
/// in use, 3 coming up, 1 working, 2 needs attention. The same marks as
/// the stages of synchronisation, so that "starting" is not shown like
/// "broken" (О35). In the order: messages, transactions, your address.
pub(crate) fn tor_tones(f: &Facts) -> (i32, i32, i32) {
    if !f.answered {
        return (2, 2, 2);
    }
    let messages = if f.tor_off || f.nostr_off || !f.transport.configured {
        0
    } else {
        match f.transport.phase.as_str() {
            "ready" if f.transport.problem.is_empty() => 1,
            "starting" => 3,
            "none" => 0,
            _ => 2,
        }
    };
    // switched off by the owner, the direct way shows the computer's address: said in the colour of a warning
    let transactions = if !f.chain.configured {
        0
    } else if f.tor_off || not_sent(f).is_some() {
        2
    } else {
        1
    };
    let address = if f.tor_off || !f.onion.configured {
        0
    } else {
        match f.onion.phase.as_str() {
            "listening" => 1,
            "up" | "starting" | "none" => 3,
            _ => 2,
        }
    };
    (messages, transactions, address)
}

/// The third Tor, said outright: the one that carries payments to a Grin
/// address and takes them at the wallet's own.
pub(crate) fn address_line(f: &Facts) -> (String, bool) {
    let (words, good) = if f.tor_off {
        (tr("Your address: does not work without Tor — payments to an address go by hand", "Ваш адрес: без Tor не работает — платежи на адрес передаются вручную"), false)
    } else if !f.answered {
        (tr("Tor for your address: unknown — the wallet does not answer", "Tor для вашего адреса: неизвестно — кошелёк не отвечает"), false)
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
    /// O66: the chain process cannot start because another one holds its files.
    ChainHeld,
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

/// O67: how far the chain is checked above the starting point the chain
/// process began from, as that process says itself ("headers verified to
/// N from a ... starting point (S)"). `None`: it does not say so now.
pub(crate) fn point_gap(f: &Facts) -> Option<u64> {
    if !f.answered || f.chain.phase != "ready" {
        return None;
    }
    let number_after = |mark: &str| -> Option<u64> {
        let rest = f.chain.problem.split_once(mark)?.1;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    let checked = number_after("headers verified to ")?;
    let start = number_after("starting point (")?;
    checked.checked_sub(start)
}

/// O67: below this many blocks a new starting point saves little.
pub(crate) const POINT_LITTLE: u64 = 20_000;
/// O67: above this many blocks a new starting point is offered.
pub(crate) const POINT_OLD: u64 = 30_000;

/// O67: what is said next to the button that makes a starting point,
/// by how far the present one lies below the checked chain.
pub(crate) fn point_hint(gap: Option<u64>) -> String {
    let Some(gap) = gap else { return String::new() };
    let blocks = spaced(gap);
    if gap < POINT_LITTLE {
        crate::fill(tr("The present point is {} blocks below the checked chain: a new one would save almost nothing now. It pays off past 20 000 blocks.", "Нынешняя точка на {} блоков ниже проверенной цепи: новая сейчас почти ничего не даст. Она окупается после 20 000 блоков."), &[&blocks])
    } else if gap > POINT_OLD {
        crate::fill(tr("The present point is {} blocks below the checked chain: a new one will make the next opening noticeably faster.", "Нынешняя точка на {} блоков ниже проверенной цепи: с новой следующий вход будет заметно быстрее."), &[&blocks])
    } else {
        crate::fill(tr("The present point is {} blocks below the checked chain: a new one would save some time at the next opening.", "Нынешняя точка на {} блоков ниже проверенной цепи: новая немного ускорит следующий вход."), &[&blocks])
    }
}

/// How the chain process says that another one has its files (`fly-chain`, `node.rs`).
const CHAIN_HELD: &str = "another chain process has the header file open";

/// O66: whether starting the wallet's processes anew is offered for this
/// trouble: where the wallet does not answer, and where the files of the
/// chain are held by a process of an earlier run.
pub(crate) fn restart_offered(kind: Kind) -> bool {
    matches!(kind, Kind::NoAnswer | Kind::ChainHeld)
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
    } else if f.chain.problem.contains(CHAIN_HELD) || f.chain.error.contains(CHAIN_HELD) {
        // the chain process stays up and says so; it does not try again by itself
        out.push(one(Kind::ChainHeld, ""));
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
            tr("The wallet does not answer", "Кошелёк не отвечает"),
            tr("Wait a few seconds. If it stays, lock the wallet and open it again.", "Подождите несколько секунд. Если не проходит — выйдите и откройте кошелёк снова."),
        ),
        Kind::NoChain => (
            tr("The network check is missing", "Нет проверки сети"),
            tr("A part of the program is missing, so the balance cannot be checked. Start the program from its own folder or install it again.", "Не хватает части программы, поэтому баланс проверить нечем. Запустите программу из её папки или установите заново."),
        ),
        Kind::ChainDown => (
            tr("The network check stopped", "Проверка сети остановилась"),
            tr("The wallet starts it again by itself. If this repeats, check the internet connection and free disk space.", "Кошелёк запускает её снова сам. Если повторяется — проверьте интернет и свободное место на диске."),
        ),
        Kind::ChainHeld => (
            tr("Another GrinSight process holds the files of the network check", "Файлы проверки сети держит другой процесс GrinSight"),
            tr("This wallet is open in another window, or a process of the last run has not ended yet — it happens when the wallet is opened again right after it was closed. Close the other window if there is one, then press “Restart the wallet”: its processes are started anew and the password is asked for again. One wallet is opened in one place at a time.", "Этот кошелёк открыт в другом окне, или ещё не завершился процесс прошлого запуска — так бывает, если открыть кошелёк сразу после закрытия. Закройте другое окно, если оно есть, и нажмите «Перезапустить кошелёк»: его процессы запустятся заново, пароль спросят снова. Один кошелёк открывают в одном месте."),
        ),
        Kind::NotSent => (
            tr("A transaction is not sent yet", "Транзакция ещё не отправлена"),
            tr("It is sent again by itself. Check the connection. Open the payment in Recent payments: there you can send it to the network again now. If Tor is closed on this network: try Tor bridges, allow direct sending in the options of the first screen, or switch Tor off — the node then sees your address.", "Она отправляется снова сама. Проверьте соединение. Откройте платёж в «Последних операциях»: там его можно отправить в сеть ещё раз сейчас. Если в этой сети закрыт Tor: попробуйте мосты Tor, разрешите прямую отправку в опциях первого экрана или выключите Tor — тогда нода увидит ваш адрес."),
        ),
        Kind::DeliveryDown => (
            tr("Message delivery stopped", "Доставка сообщений остановилась"),
            tr("Payments still go by hand (Slatepack). It is started again by itself; Tor may be blocked on this network.", "Платежи по-прежнему можно передать вручную (Slatepack). Она запускается снова сама; возможно, в этой сети закрыт Tor."),
        ),
        Kind::DeliveryProblem => (
            tr("Message delivery is hindered", "Доставке сообщений что-то мешает"),
            tr("The delivery server or Tor does not answer. Sending is retried; a payment can go by hand meanwhile.", "Не отвечает сервер доставки или Tor. Отправка повторяется; платёж пока можно передать вручную."),
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
    /// O67: the distance from the starting point is read from the chain
    /// process's own words, and what is said about a new point goes by it.
    /// 0.4.6: the line about the history before the starting point.
    #[test]
    fn the_history_before_the_point_has_a_line_only_when_the_chain_speaks_of_it() {
        let says = |text: &str| Facts { answered: true, chain: Part { configured: true, phase: "ready".into(), problem: text.into(), ..Part::default() }, ..Facts::default() };
        let plain = "headers verified to 4121046 from a release starting point (4115520); blocks applied to the tip, 4121046; the tip is confirmed by public nodes";
        assert_eq!(history_row(&says(plain)), None, "a build without the proof has no such line");
        let with = |words: &str| says(&format!("{plain}; history: {words}"));
        let line = |words: &str| history_row(&with(words)).map(|r| (r.value, r.tone));
        assert_eq!(line("sequentially verified from network genesis").map(|r| r.1), Some(1));
        assert_eq!(line("sequentially verified"), None);
        assert_eq!(line("sampled"), Some(("Release starting point. History up to it was checked by sampling its work.".to_string(), 1)));
        assert_eq!(line("locally saved after sequential verification from genesis"), Some(("Started from this wallet’s compact point after its own header check from genesis.".to_string(), 1)));
        assert_eq!(line("locally saved"), None);
        let short = says("headers verified to 90 from a locally saved point: headers checked from network genesis (88)");
        assert_eq!(history_row(&short).map(|r| (r.value,r.tone)), line("locally saved after sequential verification from genesis"));
        let imported = "headers verified to 4122005 from an imported starting point: GSHP1 sample verified for this checkpoint (4122000)";
        for suffix in ["", "; history: sampled", "; history: sam"] {
            let entry = history_row(&says(&format!("{imported}{suffix}"))).unwrap();
            assert_eq!(entry.tone, 1);
            assert!(entry.value.starts_with("Imported checkpoint at block ") && entry.value.contains("GSHP1"));
        }
        assert_eq!(line("sampled to the program's point"), Some(("checked by sampling its work up to the program's point; from there checked by the wallet that made your point".to_string(), 1)));
        assert_eq!(line("not proved for this point"), Some(("not checked: the proof in the program is for another starting point".to_string(), 0)));
        assert_eq!(line("the proof did not pass"), Some(("not checked: the proof in the program did not pass".to_string(), 2)));
        // cut short at the length limit, or anything else: no line, never "checked"
        for odd in ["sampl", "sampled to the prog", "the proof did", "", "sampled and more"] {
            assert_eq!(line(odd), None, "{odd}");
        }
        // the words are never a trouble, whole or cut, and the tip before them is read
        let f = with("sampled");
        assert!(chain_rest(&f).is_empty(), "{:?}", chain_rest(&f));
        assert!(chain_rest(&says(&format!("{plain}; hist"))).is_empty());
        assert!(chain_rest(&with("sampled to the prog")).is_empty());
        assert_eq!(said(&f.chain.problem).confirmed, Some(false));
        assert_eq!(rows(&f).len(), rows(&says(plain)).len() + 1);
        assert_eq!(point_gap(&f), point_gap(&says(plain)));
        // a chain process that is not working says nothing that counts
        assert_eq!(history_row(&Facts { chain: Part { phase: "down".into(), ..f.chain.clone() }, ..f }), None);
    }


    #[test]
    fn autonomous_history_details_do_not_grant_freshness_or_read_a_truncated_number() {
        let mut f = at_tip();
        f.selected_height = None;
        f.state = Some("unknown".into());
        f.chain.problem = "headers verified to 25 from a local starting point: headers checked from network genesis (10); work=12345; no block has been applied yet".into();
        let r = rows(&f);
        assert_eq!(value(&r, "Verified header work").value, "12 345");
        assert_eq!(value(&r, "Local checkpoint").value, "10");
        assert_ne!(value(&r, "Chosen tip").tone, 1);
        f.chain.problem = "headers verified to 25; work=123".into();
        assert!(!rows(&f).iter().any(|r| r.label == "Verified header work"));
    }

    #[test]
    fn the_starting_point_is_weighed_by_its_distance() {
        let says = |words: &str| Facts { answered: true, chain: Part { configured: true, phase: "ready".into(), problem: words.into(), ..Part::default() }, ..Facts::default() };
        assert_eq!(point_gap(&says("headers verified to 4121046 from a release starting point (4115520); blocks applied to the tip, 4121046")), Some(5_526));
        assert_eq!(point_gap(&says("a transaction is not sent: Tor: no route; headers verified to 4150000 from your own starting point (4119120)")), Some(30_880));
        assert_eq!(point_gap(&says("headers verified to 10 from a release starting point (50)")), None, "a point above what is checked");
        assert_eq!(point_gap(&says("asking public nodes about the tip")), None);
        let down = Facts { chain: Part { phase: "down".into(), ..says("headers verified to 9 from a release starting point (5)").chain }, ..says("") };
        assert_eq!(point_gap(&down), None);
        assert_eq!(point_hint(None), "");
        assert!(point_hint(Some(19_999)).contains("almost nothing") && point_hint(Some(19_999)).contains("19 999"));
        assert!(point_hint(Some(20_000)).contains("some time"));
        assert!(point_hint(Some(30_000)).contains("some time"));
        assert!(point_hint(Some(30_001)).contains("noticeably faster"));
    }

    /// O66: a chain process that cannot start because another one holds
    /// its files is its own trouble, with its own words, and the restart
    /// is offered for it; another reason the chain process is down is not.
    #[test]
    fn held_chain_files_are_a_trouble_of_their_own() {
        let part = |phase: &str, error: &str| Part { configured: true, phase: phase.into(), error: error.into(), ..Part::default() };
        let held = Facts { answered: true, chain: part("down", "the chain process stopped: another chain process has the header file open"), ..Facts::default() };
        assert_eq!(troubles(&held), vec![Trouble { kind: Kind::ChainHeld, detail: String::new() }]);
        let other = Facts { answered: true, chain: part("down", "no disk space"), ..Facts::default() };
        assert_eq!(troubles(&other), vec![Trouble { kind: Kind::ChainDown, detail: "no disk space".into() }]);
        // the chain process itself stays up and says it as its state: the same trouble
        let up = Facts { answered: true, chain: Part { configured: true, phase: "ready".into(), problem: "another chain process has the header file open".into(), ..Part::default() }, ..Facts::default() };
        assert_eq!(troubles(&up), vec![Trouble { kind: Kind::ChainHeld, detail: String::new() }]);
        // a chain process that is not set up is another trouble, whatever stale words there are
        let unset = Facts { answered: true, chain: Part { problem: "another chain process has the header file open".into(), ..Part::default() }, ..Facts::default() };
        assert_eq!(troubles(&unset), vec![Trouble { kind: Kind::NoChain, detail: String::new() }]);
        assert!(words(Kind::ChainHeld).1.contains("Restart the wallet"));
        let offered: Vec<bool> = [Kind::NoAnswer, Kind::ChainHeld, Kind::ChainDown, Kind::NoChain, Kind::NotSent, Kind::DeliveryDown, Kind::DeliveryProblem, Kind::AddressTor, Kind::TorSend].into_iter().map(restart_offered).collect();
        assert_eq!(offered, [true, true, false, false, false, false, false, false, false]);
    }

    /// O60: the doubt about Tor is said when an earlier transaction waits
    /// for it or a Tor of the wallet is down - and never with Tor switched
    /// off, or when nothing speaks against it.
    #[test]
    fn a_doubt_about_tor_is_said_before_signing() {
        let part = |phase: &str| Part { configured: true, phase: phase.into(), ..Part::default() };
        let well = Facts { answered: true, chain: part("ready"), transport: part("ready"), onion: part("listening"), ..Facts::default() };
        assert_eq!(tor_doubt(&well), None);
        let waiting = Facts { chain: Part { problem: format!("{NOT_SENT}Tor did not start; headers verified to 5"), ..part("ready") }, ..well.clone() };
        assert_eq!(tor_doubt(&waiting), Some("An earlier payment could not be sent through Tor and is still waiting"));
        let down = Facts { transport: part("down"), ..well.clone() };
        let failed = Facts { onion: part("failed"), ..well.clone() };
        assert_eq!((tor_doubt(&down), tor_doubt(&failed)), (Some("Tor is not working on this device now"), Some("Tor is not working on this device now")));
        // a part that is not set up says nothing of Tor
        let unset = Facts { transport: Part { phase: "down".into(), ..Part::default() }, ..well.clone() };
        assert_eq!(tor_doubt(&unset), None);
        for off in [waiting, down, failed] {
            assert_eq!(tor_doubt(&Facts { tor_off: true, ..off }), None);
        }
    }

    #[test]
    fn the_path_is_shown_with_its_numbers() {
        let rows = rows(&at_tip());
        assert_eq!(value(&rows, "Network check").value, "working");
        assert_eq!(value(&rows, "Chosen tip").value, "block 4 120 281");
        assert_eq!(value(&rows, "Wallet").value, "at the tip, block 4 120 281");
        assert_eq!(value(&rows, "Search for old money").value, "finished · found 3 · spent 1");
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
        assert_eq!(value(&rows, "Search for old money").value, "part 120 of 310 · found 2");
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
        assert_eq!(value(&rows, "Search for old money").value, "—");
        assert!(rows.iter().all(|r| r.label != "Confirmation"));
        let silent = super::rows(&Facts::default());
        assert_eq!(silent.len(), 1);
        assert_eq!(value(&silent, "Wallet").tone, 2);
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

    fn stage(f: &Facts, label: &str) -> (String, i32) {
        stages(f).into_iter().find(|r| r.label == label).map_or(("no stage".to_string(), -1), |r| (r.value, r.tone))
    }

    fn chain_says(text: &str) -> Facts {
        Facts {
            answered: true,
            chain: Part { configured: true, phase: "ready".into(), problem: text.into(), ..Part::default() },
            ..Facts::default()
        }
    }

    /// Every stage of following the network is shown with where it stands,
    /// from the first word of the chain process to the tip: a stage nobody
    /// spoke of is not begun, one with numbers still to go is under way,
    /// and done is said only when the process said so.
    #[test]
    fn the_stages_of_following_the_network_are_each_shown_as_they_stand() {
        let labels = |f: &Facts| stages(f).into_iter().map(|r| r.label).collect::<Vec<_>>();
        // the process is starting: it is the stage, and nothing after it has begun
        let mut f = chain_says("");
        f.chain.phase = "starting".into();
        assert_eq!(labels(&f), ["Network check", "Block headers", "Network state", "Blocks", "Tip", "Wallet"]);
        assert_eq!(stage(&f, "Network check").1, 3);
        for later in ["Block headers", "Network state", "Blocks", "Tip", "Wallet"] {
            assert_eq!(stage(&f, later).1, 0, "{later}");
        }
        // the stored headers are being checked again
        let f = chain_says("verifying the stored headers");
        assert_eq!(stage(&f, "Block headers"), ("checking the stored ones".into(), 3));
        assert_eq!(stage(&f, "Network state").1, 0);
        // headers under way, no node yet
        let f = chain_says("headers verified to 4115520 from a release starting point: public nodes of two operators named it when it was made (4115520); no block has been applied yet; not at the tip yet; no node is connected yet (15 known)");
        assert_eq!(labels(&f), ["Nodes", "Block headers", "Network state", "Blocks", "Tip", "Wallet"]);
        assert_eq!(stage(&f, "Nodes"), ("no node is connected yet".into(), 3));
        assert_eq!(stage(&f, "Block headers"), ("verified to 4 115 520".into(), 1));
        assert_eq!(stage(&f, "Blocks"), ("not applied yet".into(), 0));
        assert_eq!(stage(&f, "Tip"), ("not at the tip yet".into(), 3));
        let f = chain_says("headers verified to 4117568 from a release starting point (4115520); no block has been applied yet; not at the tip yet; nodes are at about 4121085");
        assert_eq!(stage(&f, "Block headers"), ("4 117 568 of about 4 121 085".into(), 3));
        // the state is being collected
        let f = chain_says("headers verified to 4121045 from a release starting point (4115520); collecting the state at 4117680: 219 of 308 pieces; no block has been applied yet; asking public nodes about the tip");
        assert_eq!(stage(&f, "Block headers"), ("verified to 4 121 045".into(), 1));
        assert_eq!(stage(&f, "Network state"), ("part 219 of 308".into(), 3));
        assert_eq!(stage(&f, "Tip"), ("asking public nodes about the tip".into(), 3));
        let f = chain_says("headers verified to 4121045 from a release starting point (4115520); the state at 4117680 is collected and checked; no block has been applied yet");
        assert_eq!(stage(&f, "Network state"), ("collected and checked".into(), 1));
        assert_eq!(stage(&f, "Tip").1, 0);
        // blocks under way: the state they stand on goes without saying
        let mut f = chain_says("headers verified to 4121046 from a release starting point (4115520); blocks applied to 4118401; the tip is confirmed by public nodes");
        f.state = Some("behind".into());
        f.wallet_height = Some(4_118_000);
        assert_eq!(stage(&f, "Network state"), ("collected and checked".into(), 1));
        assert_eq!(stage(&f, "Blocks"), ("4 118 401 of 4 121 046 · 2 645 left".into(), 3));
        assert_eq!(stage(&f, "Tip"), ("—".into(), 0), "progress text alone cannot establish the selected tip");
        assert_eq!(stage(&f, "Wallet"), ("block 4 118 000".into(), 3));
        // everything done
        let mut f = chain_says("headers verified to 4121046 from a release starting point (4115520); blocks applied to the tip, 4121046; the tip is confirmed by public nodes");
        f.state = Some("at_tip".into());
        f.wallet_height = Some(4_121_046);
        f.selected_height = Some(4_121_046);
        f.confirmed_time = Some(1_800_000_000);
        assert!(stages(&f).iter().all(|r| r.tone == 1), "{:?}", stages(&f));
        assert_eq!(stage(&f, "Blocks"), ("to the tip, 4 121 046".into(), 1));
        assert_eq!(stage(&f, "Wallet"), ("at the tip, block 4 121 046".into(), 1));
        assert!(chain_rest(&f).is_empty());
        // the wallet behind a chosen tip
        f.state = Some("behind".into());
        f.wallet_height = Some(4_120_000);
        assert_eq!(stage(&f, "Wallet"), ("block 4 120 000 of 4 121 046 · 1 046 left".into(), 3));
    }

    /// What needs attention is marked so, in words of its own; what the
    /// process says that is not a stage is kept whole and apart; and what
    /// is not understood is never turned into "done".
    #[test]
    fn trouble_is_marked_and_what_is_not_a_stage_is_kept_as_said() {
        let f = chain_says("headers verified to 4121046 from a release starting point (4115520); blocks applied to the tip, 4121046; the time is not confirmed: too few public nodes answered; no node is connected (15 known; last attempt: no connection)");
        assert_eq!(stage(&f, "Tip"), ("the time is not confirmed: too few public nodes answered".into(), 2));
        assert_eq!(stage(&f, "Nodes"), ("no node is connected".into(), 2));
        let mut f = chain_says("headers verified to 5 from a point (1); blocks applied to the tip, 5; the tip is confirmed by public nodes, with a caveat: a claim of more work went unsettled not long ago");
        f.selected_height = Some(5);
        f.confirmed_time = Some(1_800_000_000);
        assert_eq!(stage(&f, "Tip").1, 2);
        let f = chain_says("headers verified to 5 from a point (1); blocks applied to 3; public node node.example names more work than is verified here");
        assert_eq!(stage(&f, "Tip"), ("public node node.example names more work than is verified here".into(), 2));
        let f = chain_says("headers verified to 5 from a point (1); blocks applied to 3; this computer's clock is far from the time of public nodes: check the clock");
        assert_eq!(stage(&f, "Tip").1, 2);
        // not a stage: kept as it was said, and no stage is made of it
        let mut f = chain_says("the transaction was not sent: no node took it; headers verified to 5 from a point (1); blocks applied to the tip, 5; the tip is confirmed by public nodes; signs: one, two");
        f.selected_height = Some(5);
        f.confirmed_time = Some(1_800_000_000);
        assert_eq!(chain_rest(&f), ["the transaction was not sent: no node took it", "signs: one, two"]);
        assert!(stages(&f).iter().filter(|r| r.label != "Wallet").all(|r| r.tone == 1));
        assert_eq!(stage(&f, "Wallet"), ("waiting for the chain".into(), 0));
        // words nobody knows: no stage claims anything
        let f = chain_says("headers verified to many; collecting the state at 7: some of 9 pieces; blocks applied to somewhere; something new");
        for label in ["Block headers", "Network state", "Blocks", "Tip"] {
            assert_eq!(stage(&f, label), ("—".into(), 0), "{label}");
        }
        assert_eq!(chain_rest(&f), ["headers verified to many", "collecting the state at 7: some of 9 pieces", "blocks applied to somewhere", "something new"]);
        // a process that failed says one thing; it is not a stage
        let f = chain_says("the header file is damaged");
        assert_eq!(chain_rest(&f), ["the header file is damaged"]);
        assert_eq!(stage(&f, "Block headers").1, 0);
        // no chain process at all: no stages; no answer: only that
        assert!(stages(&Facts { answered: true, ..Facts::default() }).is_empty());
        assert_eq!(stages(&Facts::default()).len(), 1);
    }

    /// A Tor that is coming up is marked as coming up, not as broken; one
    /// that is not in use is marked so; only real trouble asks for attention.
    #[test]
    fn a_tor_that_is_starting_is_not_marked_like_one_that_is_broken() {
        let part = |phase: &str, problem: &str| Part { configured: true, phase: phase.into(), problem: problem.into(), ..Part::default() };
        let with = |transport: Part, onion: Part| Facts { answered: true, chain: part("ready", ""), transport, onion, ..Facts::default() };
        assert_eq!(tor_tones(&Facts::default()), (2, 2, 2));
        assert_eq!(tor_tones(&Facts { answered: true, ..Facts::default() }), (0, 0, 0));
        assert_eq!(tor_tones(&with(part("starting", ""), part("starting", ""))), (3, 1, 3));
        assert_eq!(tor_tones(&with(part("ready", ""), part("up", "your address is being announced"))), (1, 1, 3));
        assert_eq!(tor_tones(&with(part("ready", ""), part("listening", ""))), (1, 1, 1));
        assert_eq!(tor_tones(&with(part("ready", "relays refuse"), part("down", "no Tor"))), (2, 1, 2));
        assert_eq!(tor_tones(&with(part("down", "x"), part("none", ""))), (2, 1, 3));
        assert_eq!(tor_tones(&with(part("none", ""), part("listening", ""))), (0, 1, 1));
    }

    /// O42: what the owner switched off is said as switched off - not as
    /// broken, not as "not set up" - and Tor off says outright that the
    /// node sees the address; the marks follow.
    #[test]
    fn what_the_owner_switched_off_is_said_so() {
        let on = Facts { answered: true, chain: Part { configured: true, phase: "ready".into(), ..Part::default() }, transport: Part { configured: true, phase: "ready".into(), ..Part::default() }, onion: Part { configured: true, phase: "listening".into(), ..Part::default() }, ..Facts::default() };
        assert_eq!(tor_tones(&on), (1, 1, 1));
        // the programs are not started: the wallet process says "not configured"
        let bare = Facts { transport: Part::default(), onion: Part::default(), ..on.clone() };
        let no_tor = Facts { tor_off: true, ..bare.clone() };
        let ((messages, _), (transactions, well)) = tor_lines(&no_tor, false);
        assert!(messages.contains("do not work without Tor"), "{messages}");
        assert!(transactions.contains("switched off") && transactions.contains("the node sees your address") && !well, "{transactions}");
        assert!(address_line(&no_tor).0.contains("does not work without Tor"));
        assert_eq!(tor_tones(&no_tor), (0, 2, 0));
        // the consent to the direct way does not soften it
        assert_eq!(tor_lines(&no_tor, true).1 .0, transactions);
        let no_nostr = Facts { nostr_off: true, transport: Part::default(), ..on.clone() };
        let ((messages, _), (transactions, well)) = tor_lines(&no_nostr, false);
        assert!(messages.contains("Nostr") && messages.contains("switched off"), "{messages}");
        assert!(transactions.contains("never directly") && well, "{transactions}");
        assert_eq!(tor_tones(&no_nostr), (0, 1, 1));
        // both off: Nostr is said as switched off, not as waiting for Tor
        let both = Facts { nostr_off: true, ..no_tor };
        assert!(tor_lines(&both, false).0 .0.contains("switched off"));
    }
}
