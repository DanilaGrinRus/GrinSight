//! The interface of GrinSight (library: the desktop program and the
//! Android app share it).
//!
//! With `--host <fly-paycore-host> --profile <folder> [host options]` it
//! starts the wallet process and shows the real wallet: the password goes to
//! the host, the screens are filled from `paycore.*` answers. Without
//! `--host` it shows the screens on sample data. Text from others, amounts
//! and addresses go through `fly-safe-display` before they reach a screen.
//! The interface holds no keys.
//!
//! `fly-ui --snapshot <folder> [...]` draws every screen in every theme
//! without a window (software renderer) and writes BMP files: for checking
//! the screens on a machine without a display. With `--host` it creates a
//! Testnet profile with a throwaway password in the given profile folder if
//! there is none, opens it and draws what the host says.
// `deny`, not `forbid`: the code Slint generates allows `unsafe` inside itself;
// our own code still may not use it.
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

#[allow(clippy::all, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod ui {
    slint::include_modules!();
}

mod files;
#[cfg(test)]
#[allow(clippy::all, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod keys_tests;
mod live;
mod qr;
mod sync;
mod tor;

use fly_safe_display::{address, amount, foreign_line, NAME_CHARS, NANO};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use ui::{App, ChatLine, Contact, Device, Op, OpLine, Problem, Settings, SyncRow, Theme, ThemeName, Waiting};

/// Sample words for drawing the creation screen. Not a wallet: made-up
/// words in the shape of a phrase.
const SAMPLE_WORDS: [&str; 24] = [
    "образец", "не", "кошелёк", "слово", "четыре", "пять", "шесть", "семь", "восемь", "девять", "десять", "одиннадцать",
    "двенадцать", "тринадцать", "четырнадцать", "пятнадцать", "шестнадцать", "семнадцать", "восемнадцать", "девятнадцать", "двадцать", "двадцать1", "двадцать2", "двадцать3",
];

/// Fills the windows over the main screen with sample values, for snapshots.
fn fill_sample_sheets(app: &App) {
    app.set_contact_names(model(vec![name(tr("Anna", "Аня")), name(tr("Paul", "Павел")), name(tr("“Coffee shop”", "«Кофейня»"))]));
    app.set_address_full(SAMPLE_ADDRESS.into());
    app.set_out_title(tr("Hand it to the recipient", "Передайте получателю").into());
    app.set_out_note(tr("Send this text to the recipient any way you like. They paste it into their wallet and send a reply back — paste the reply below.", "Отправьте этот текст получателю любым способом. Он вставит его в свой кошелёк и пришлёт ответ — вставьте ответ ниже.").into());
    app.set_out_text("BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.".into());
    app.set_out_wants_reply(true);
    app.set_sign_amount(amount(NANO / 2).into());
    app.set_sign_fee(amount(23_500_000).into());
    app.set_sign_total(amount((NANO / 2).saturating_add(23_500_000)).into());
    app.set_sign_who(name(tr("Anna", "Аня")));
    app.set_sign_who_note("".into());
    let groups: Vec<SharedString> = match address(SAMPLE_ADDRESS) {
        Ok(a) => a.groups.into_iter().map(SharedString::from).collect(),
        Err(_) => Vec::new(),
    };
    app.set_sign_who_groups(model(groups.clone()));
    app.set_sign_can_cancel(true);
    app.set_rel_note(tr("A payment of 0.50 GRIN was prepared before this wallet was restored from an older copy. The wallet no longer knows whether it was signed after that copy was taken, so it will not sign it and keeps the money in reserve.", "Платёж на 0.50 GRIN был подготовлен до того, как этот кошелёк восстановили из более старой копии. Кошелёк больше не знает, подписывали ли его после той копии, поэтому не подпишет его и держит деньги в резерве.").into());
    app.set_inv_amount(amount(NANO.saturating_mul(3) / 2).into());
    app.set_inv_fee(amount(23_500_000).into());
    app.set_inv_total(amount((NANO.saturating_mul(3) / 2).saturating_add(23_500_000)).into());
    app.set_inv_until(tr("The invoice can be paid before block 4117000.", "Счёт можно оплатить до блока 4117000.").into());
    app.set_in_amount(amount(NANO).into());
    app.set_in_from(tr("An address that is not in your contacts", "Адрес не из ваших контактов").into());
    app.set_in_from_note(tr("Check the address with the sender some other way.", "Сверьте адрес с отправителем по другому каналу.").into());
    app.set_in_from_groups(model(groups));
    app.set_words(model(SAMPLE_WORDS.iter().map(|w| SharedString::from(*w)).collect()));
    app.set_chat_name(name(tr("Anna", "Аня")));
    let line = |mine: bool, text: &str, when: &str, state: &str, warn: bool| ChatLine {
        mine,
        text: fly_safe_display::foreign_text(text, fly_safe_display::MESSAGE_CHARS).text.into(),
        when: when.into(),
        state: state.into(),
        warn,
    };
    app.set_chat_lines(model(vec![
        line(false, tr("Hi! Can you send 0.5 for lunch?\nhttps://example.com — a link is shown as text only", "Привет! Скинешь 0.5 за обед?\nhttps://example.com — ссылка только текстом"), tr("2 h ago", "2 ч назад"), "", false),
        line(true, tr("Sure, sending now", "Да, сейчас отправлю"), tr("2 h ago", "2 ч назад"), tr("accepted for delivery", "принято к доставке"), false),
        line(false, tr("Got it, thanks 🙂", "Пришло, спасибо 🙂"), tr("1 h ago", "1 ч назад"), "", false),
        line(true, tr("Great", "Отлично"), tr("just now", "только что"), tr("waiting to be delivered", "ждёт доставки"), false),
        line(true, tr("This went out while the network was down", "Это ушло, когда сеть лежала"), "21.11.2026", tr("not sent: the delivery window closed", "не отправлено: окно доставки закрылось"), true),
    ]));
    app.set_all_ops(model(vec![
        OpLine { who: name(tr("Anna", "Аня")), sub: tr("waiting for your signature", "ждёт вашей подписи").into(), amount: format!("−{}", amount(NANO / 2)).into(), tone: 2, show: true },
        OpLine { who: name(tr("Paul", "Павел")), sub: tr("in block 4 118 590", "в блоке 4 118 590").into(), amount: format!("+{}", amount(2 * NANO)).into(), tone: 1, show: false },
    ]));
    app.set_identity_made(true);
    app.set_ask(model(vec![3, 11, 20]));
}

/// The language of the program's own messages; the screens follow Slint's
/// bundled translation, switched together with this.
static RUSSIAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One of a message's two wordings, in the chosen language.
pub(crate) fn tr(en: &'static str, ru: &'static str) -> &'static str {
    if RUSSIAN.load(std::sync::atomic::Ordering::Relaxed) {
        ru
    } else {
        en
    }
}

/// `{}` in `template` replaced by `args` in order.
pub(crate) fn fill(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len().saturating_add(32));
    let mut args = args.iter();
    for (i, part) in template.split("{}").enumerate() {
        if i > 0 {
            out.push_str(args.next().copied().unwrap_or(""));
        }
        out.push_str(part);
    }
    out
}

thread_local! {
    /// The note on the login screen in both wordings, so a change of
    /// language changes it too.
    static NOTE: std::cell::RefCell<(&'static str, &'static str)> = const { std::cell::RefCell::new(("", "")) };
}

/// Puts a note on the login screen in the chosen language.
pub(crate) fn note(app: &App, en: &'static str, ru: &'static str) {
    NOTE.with(|n| *n.borrow_mut() = (en, ru));
    app.set_login_note(tr(en, ru).into());
}

/// «Send directly if Tor fails»: the wallet process gets `--chain-direct-post`.
static DIRECT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn set_direct(on: bool) {
    DIRECT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// The two parts the owner can switch off (O42, K189): Tor - no payments
/// to an address, no messages, transactions straight to the network - and
/// Nostr - no messages and no payments to contacts. Off means the program
/// of that part is not started at all.
static TOR_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static NOSTR_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Confirmations after which an incoming payment is called received, as
/// the owner chose (K190); 0: not chosen, the wallet's own number stands.
static CONFIRMATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn set_confirmations(count: u64) {
    CONFIRMATIONS.store(count.min(1000), std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn confirmations() -> u64 {
    CONFIRMATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn set_tor_off(off: bool) {
    TOR_OFF.store(off, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn tor_off() -> bool {
    TOR_OFF.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn set_nostr_off(off: bool) {
    NOSTR_OFF.store(off, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn nostr_off() -> bool {
    NOSTR_OFF.load(std::sync::atomic::Ordering::Relaxed)
}

/// The wallet process's arguments as the owner's choices make them, from
/// the arguments the program has for everything switched on. Nostr off:
/// no message program. Tor off: no message program either (it speaks
/// through Tor), no program for the address, and the chain program is told
/// to bring no Tor up. The consent to the direct way is passed as it is.
pub(crate) fn chosen_args(base: &[String], direct: bool, tor_off: bool, nostr_off: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(base.len().saturating_add(2));
    let mut it = base.iter();
    while let Some(arg) = it.next() {
        let dropped = match arg.as_str() {
            "--transport" | "--relay" => tor_off || nostr_off,
            "--onion" => tor_off,
            "--chain-direct-post" | "--chain-no-tor" => {
                // said anew below, never twice
                continue;
            }
            _ => false,
        };
        if dropped {
            // the value goes with its name
            let _ = it.next();
        } else {
            out.push(arg.clone());
        }
    }
    if out.iter().any(|a| a == "--chain") {
        if tor_off {
            out.push("--chain-no-tor".into());
        }
        if direct {
            out.push("--chain-direct-post".into());
        }
    }
    out
}

/// The same with the choices as they stand now.
pub(crate) fn args_now(base: &[String]) -> Vec<String> {
    chosen_args(base, direct(), tor_off(), nostr_off())
}

fn direct() -> bool {
    DIRECT.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_language(russian: bool) {
    RUSSIAN.store(russian, std::sync::atomic::Ordering::Relaxed);
    // "" is the source language (English)
    let _ = slint::select_bundled_translation(if russian { "ru" } else { "" });
}

/// Where the language and the theme are kept: `ui.txt` next to the profile
/// folder (in the portable layout `data\ui.txt`), never inside it.
fn settings_path(args: &Args) -> Option<PathBuf> {
    let at = args.host_args.iter().position(|a| a == "--profile")?;
    let profile = Path::new(args.host_args.get(at.saturating_add(1))?);
    Some(profile.parent()?.join("ui.txt"))
}

fn theme_word(name: ThemeName) -> &'static str {
    match name {
        ThemeName::Emerald => "emerald",
        ThemeName::Ice => "ice",
        ThemeName::Honey => "honey",
        ThemeName::Mono => "mono",
    }
}

/// Reads the saved choices (English and Ice when there are none) and makes
/// the buttons save them again.
fn wire_settings(app: &App, path: Option<PathBuf>) {
    let mut russian = false;
    if let Some(text) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) {
        for line in text.lines().take(16) {
            match line.trim() {
                "lang=ru" => russian = true,
                "direct=on" => set_direct(true),
                "tor=off" => set_tor_off(true),
                "nostr=off" => set_nostr_off(true),
                word if word.starts_with("received=") => {
                    if let Some(count) = word.strip_prefix("received=").and_then(|n| n.parse::<u64>().ok()).filter(|n| (1..=1000).contains(n)) {
                        set_confirmations(count);
                    }
                }
                "delivery=hand" => app.global::<Settings>().set_by_hand(true),
                "theme=emerald" => app.global::<Theme>().set_name(ThemeName::Emerald),
                "theme=ice" => app.global::<Theme>().set_name(ThemeName::Ice),
                "theme=honey" => app.global::<Theme>().set_name(ThemeName::Honey),
                "theme=mono" => app.global::<Theme>().set_name(ThemeName::Mono),
                _ => {}
            }
        }
    }
    app.global::<Settings>().set_russian(russian);
    set_language(russian);
    let weak = app.as_weak();
    app.global::<Settings>().on_save(move || {
        let Some(app) = weak.upgrade() else { return };
        let russian = app.global::<Settings>().get_russian();
        set_language(russian);
        // what the program wrote once, again in the new language
        fill_common(&app);
        let (en, ru) = NOTE.with(|n| *n.borrow());
        if !en.is_empty() && !app.get_login_note().is_empty() {
            app.set_login_note(tr(en, ru).into());
        }
        if let Some(path) = &path {
            let text = format!(
                "lang={}\ntheme={}\ndirect={}\ndelivery={}\ntor={}\nnostr={}\n{}",
                if russian { "ru" } else { "en" },
                theme_word(app.global::<Theme>().get_name()),
                if direct() { "on" } else { "off" },
                if app.global::<Settings>().get_by_hand() { "hand" } else { "tor" },
                if tor_off() { "off" } else { "on" },
                if nostr_off() { "off" } else { "on" },
                // only once chosen: until then the wallet's own number stands
                if confirmations() == 0 { String::new() } else { format!("received={}\n", confirmations()) }
            );
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(path, text);
        }
    });
}

/// The program's version: the one line every build takes its number from.
/// The scripts that pack the Windows installer, the APK and the Linux and
/// macOS packages read it here, so the window and the package it came in
/// cannot name different versions.
pub const APP_VERSION: &str = "0.4.4";

/// Shows the synchronisation block and the troubles of this session.
pub(crate) fn show_sync(app: &App, facts: &sync::Facts, journal: &sync::Journal) {
    let rows: Vec<SyncRow> = sync::rows(facts).into_iter().map(|r| SyncRow { label: r.label.into(), value: r.value.into(), tone: r.tone }).collect();
    app.set_sync_rows(model(rows));
    // the stages of following the network, each as it stands, and what else the chain process says
    let stages: Vec<SyncRow> = sync::stages(facts).into_iter().map(|r| SyncRow { label: r.label.into(), value: r.value.into(), tone: r.tone }).collect();
    app.set_sync_stages(model(stages));
    app.set_sync_rest(model(sync::chain_rest(facts).into_iter().map(SharedString::from).collect()));
    // the state of both Tors, said outright
    let (messages, transactions) = sync::tor_lines(facts, direct());
    app.set_tor_on(!facts.tor_off);
    app.set_nostr_on(!facts.nostr_off);
    app.set_tor_line(messages.0.into());
    app.set_tx_line(transactions.0.into());
    app.set_tx_good(transactions.1);
    let tones = sync::tor_tones(facts);
    app.set_tor_tone(tones.0);
    app.set_tx_tone(tones.1);
    app.set_addr_tone(tones.2);
    let address = sync::address_line(facts);
    app.set_addr_line(address.0.into());
    app.set_addr_good(address.1);
    let mut words = sync::chain_words(facts);
    words.extend(sync::address_words(facts));
    app.set_sync_words(model(words.into_iter().map(SharedString::from).collect()));
    let now = live::unix_now();
    let problems: Vec<Problem> = journal
        .newest()
        .map(|e| {
            let (what, help) = sync::words(e.trouble.kind);
            let when = live::when(e.at, now);
            Problem {
                when: if e.open { when.into() } else { fill(tr("{} · gone", "{} · прошло"), &[&when]).into() },
                what: what.into(),
                detail: e.trouble.detail.clone().into(),
                help: help.into(),
                open: e.open,
            }
        })
        .collect();
    let hidden = journal.len().saturating_sub(problems.len());
    app.set_problems_more(if hidden > 0 { fill(tr("and {} earlier", "и ещё {} раньше"), &[&hidden.to_string()]) } else { String::new() }.into());
    app.set_problems(model(problems));
}

/// Made-up facts for the sample screens only.
fn sample_facts() -> sync::Facts {
    let part = |phase: &str| sync::Part { configured: true, phase: phase.into(), starts: 1, ..sync::Part::default() };
    sync::Facts {
        answered: true,
        chain: sync::Part { problem: "headers verified to 4118626 from a release starting point: public nodes of two operators named it when it was made (4115520); blocks applied to the tip, 4118626; the tip is confirmed by public nodes".into(), ..part("ready") },
        transport: part("ready"),
        onion: part("listening"),
        onion_failed: Vec::new(),
        state: Some("at_tip".into()),
        wallet_height: Some(4_118_626),
        selected_height: Some(4_118_626),
        status_answered: true,
        confirmed_time: Some(1_795_480_000),
        k_conf: Some(10),
        search: Some(sync::Search { state: "done".into(), next: None, pieces: 310, found: 3, gone: 1 }),
        tor_off: false,
        nostr_off: false,
    }
}

fn sample_journal() -> sync::Journal {
    let mut journal = sync::Journal::default();
    let trouble = sync::Trouble { kind: sync::Kind::DeliveryProblem, detail: "relay wss://relay.floonet.dev: no answer".into() };
    let now = live::unix_now();
    journal.note(now.saturating_sub(1500), std::slice::from_ref(&trouble));
    journal.note(now.saturating_sub(900), &[]);
    journal
}

/// A made-up address of the right form, for the sample screens only.
const SAMPLE_ADDRESS: &str = "grin16ftxnj66xzq76xgk2958h5jy0qjgmwafcchw2ujts6thug24msxj6pathw";

fn name(text: &str) -> SharedString {
    foreign_line(text, NAME_CHARS).text.into()
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::from(Rc::new(VecModel::from(items)))
}

pub(crate) fn fill_common(app: &App) {
    app.set_app_version(format!("v{APP_VERSION}").into());
    // a QR code is drawn the same way on every screen, the sample ones too
    live::wire_qr(app);
    // the sample screens show the send window with every way offered
    app.set_tor_address(true);
    app.set_send_to(-2);
    app.set_version(fill(tr("GrinSight {} · a wallet for people", "GrinSight {} · кошелёк для людей"), &[APP_VERSION]).into());
    app.set_start_point(tr("Built in: 4 115 520 · named by 5 operators", "Вшитая 4 115 520 · её назвали 5 операторов").into());
    app.set_own_nodes(tr("None · up to 4, they get transactions first", "Не заданы · до 4, получат транзакции первыми").into());
}

fn fill_sample(app: &App) {
    fill_common(app);
    app.set_wallet_name(name("55555"));
    app.set_network("MAINNET".into());
    app.set_balance(amount(24_137_000_000).into());
    app.set_balance_note(fill(tr("can be spent · in reserve {} · in all {}", "можно тратить · в резерве {} · всего {}"), &[&amount(NANO / 2), &amount(24_697_000_000)]).into());
    app.set_incoming(fill(tr("Coming in: {} GRIN · waiting for a block", "Входит {} GRIN · ждёт блока"), &[&amount(60_000_000)]).into());
    app.set_verified(tr("to the tip, 4 118 626 · confirmed by Grincoin.org and Grin.money", "до вершины 4 118 626 · её подтвердили Grincoin.org и Grin.money").into());
    let groups: Vec<SharedString> = match address(SAMPLE_ADDRESS) {
        Ok(a) => a.groups.into_iter().map(SharedString::from).collect(),
        Err(_) => vec![tr("address with a mistake", "адрес с ошибкой").into()],
    };
    app.set_address_groups(model(groups));
    app.set_phrase("star-toad-swan-halo-mint-lamb".into());

    app.set_waiting(model(vec![
        Waiting { who: name(tr("Anna", "Аня")), what: fill(tr("replied to the payment of {} GRIN — your signature is needed", "ответила на платёж {} GRIN — нужна ваша подпись"), &[&amount(NANO / 2)]).into(), action: tr("Sign", "Подписать").into(), second: "".into() },
        Waiting { who: tr("Incoming", "Входящий").into(), what: fill(tr("{} GRIN from grin18z5…9h2ykv — accept?", "{} GRIN от grin18z5…9h2ykv — принять?"), &[&amount(NANO)]).into(), action: tr("Accept", "Принять").into(), second: tr("Decline", "Отклонить").into() },
    ]));
    app.set_contacts(model(vec![
        Contact { initial: tr("A", "А").into(), name: name(tr("Anna", "Аня")), last: tr("waiting for a signature", "ждёт подписи").into(), attention: true },
        Contact { initial: tr("P", "П").into(), name: name(tr("Paul", "Павел")), last: tr("Thanks, it arrived", "Спасибо, дошло").into(), attention: false },
        Contact { initial: tr("C", "К").into(), name: name(tr("“Coffee shop”", "«Кофейня»")), last: tr("invoice paid", "счёт оплачен").into(), attention: false },
    ]));
    app.set_ops(model(vec![
        Op { who: name(tr("Anna", "Аня")), sub: tr("waiting for your signature", "ждёт вашей подписи").into(), amount: format!("−{}", amount(NANO / 2)).into(), tone: 2, show: true },
        Op { who: tr("Incoming", "Входящий").into(), sub: tr("in the network, waiting for a block", "в сети, ждёт блока").into(), amount: format!("+{}", amount(60_000_000)).into(), tone: 2, show: false },
        Op { who: name(tr("Paul", "Павел")), sub: tr("in block 4 118 590 · proof", "в блоке 4 118 590 · доказательство").into(), amount: format!("+{}", amount(2_000_000_000)).into(), tone: 1, show: false },
        Op { who: name(tr("“Coffee shop”", "«Кофейня»")), sub: tr("invoice paid · in block 4 118 402", "счёт оплачен · в блоке 4 118 402").into(), amount: format!("−{}", amount(120_000_000)).into(), tone: 0, show: false },
    ]));
    app.set_files_path(tr("C:\\Users\\you\\AppData\\Local\\GrinSightLight\\data", "C:\\Users\\вы\\AppData\\Local\\GrinSightLight\\data").into());
    app.set_guard_path(tr("C:\\Users\\you\\AppData\\Local\\GrinSightLight\\guard", "C:\\Users\\вы\\AppData\\Local\\GrinSightLight\\guard").into());
    app.set_tor_line(tr("Tor is connected · messages and transactions go through it", "Tor подключён · сообщения и транзакции идут через него").into());
    show_sync(app, &sample_facts(), &sample_journal());
    app.set_auto_known(true);
    app.set_auto_receive(fill(tr("up to {} GRIN from contacts", "до {} GRIN от контактов"), &[&amount(NANO)]).into());
    let weak = app.as_weak();
    app.on_enter(move |_| {
        if let Some(app) = weak.upgrade() {
            app.set_page(1);
        }
    });
    let weak = app.as_weak();
    app.on_leave(move || {
        if let Some(app) = weak.upgrade() {
            app.set_page(0);
        }
    });
}

/// What the command line asked for.
pub struct Args {
    snapshot: Option<PathBuf>,
    scenario: Option<PathBuf>,
    host: Option<PathBuf>,
    /// Passed to the host as they are (none of them secret).
    host_args: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args { snapshot: None, scenario: None, host: None, host_args: Vec::new() };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--snapshot" => args.snapshot = Some(it.next().ok_or("--snapshot needs a folder")?.into()),
            "--scenario" => args.scenario = Some(it.next().ok_or("--scenario needs a folder")?.into()),
            "--host" => args.host = Some(it.next().ok_or("--host needs a program")?.into()),
            "--profile" | "--guard-dir" | "--transport" | "--relay" | "--chain" | "--chain-peer" | "--onion" => {
                let value = it.next().ok_or(format!("{arg} needs a value"))?;
                args.host_args.push(arg);
                args.host_args.push(value);
            }
            "--chain-direct-post" => args.host_args.push(arg),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.host.is_some() && !args.host_args.iter().any(|a| a == "--profile") {
        return Err("--host needs --profile".into());
    }
    Ok(args)
}

/// The relay a portable copy uses for messages until the user picks another.
const DEFAULT_RELAY: &str = "wss://relay.floonet.dev";

/// The file the Windows installer puts next to the program. With it the
/// wallet's data are not kept in the program's folder.
const INSTALLED_MARK: &str = "installed.txt";

/// Where the wallet's data lie for a program that lies in `base`. A
/// portable copy keeps them next to itself, in `data`. A Mac app must not
/// keep data inside its bundle: Application Support. A copy put in place by
/// the Windows installer (`installed`) keeps them in the user's local
/// application data, so that removing or replacing the program does not
/// touch the wallet. Nothing when the place cannot be told: no wallet is
/// opened then rather than one in an unexpected folder.
fn data_place(base: &Path, os: &str, installed: bool, home: Option<PathBuf>, local: Option<PathBuf>) -> Option<PathBuf> {
    let named = |dir: Option<PathBuf>| dir.filter(|d| d.is_absolute());
    match os {
        "macos" => Some(named(home)?.join("Library").join("Application Support").join("GrinSightLight")),
        "windows" if installed => Some(named(local)?.join("GrinSightLight").join("data")),
        _ => Some(base.join("data")),
    }
}

/// The portable layout (`run-portable.ps1`): started without `--host`, the
/// interface looks for `bin\fly-paycore-host.exe` next to itself and, if it
/// is there, opens the real wallet with its profile in `data\profile`
/// ([`data_place`]), the chain program `bin\fly-chain.exe` and the message
/// program `bin\fly-mailbox.exe` when they are there too. The guard stays
/// where the host keeps it by default — outside this folder, so a copied
/// folder does not carry its own protection against rollback.
fn portable(args: &mut Args) {
    if args.host.is_some() || args.snapshot.is_some() || args.scenario.is_some() {
        return;
    }
    let Some(base) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) else { return };
    let program = |name: &str| {
        let p = base.join("bin").join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        p.is_file().then_some(p)
    };
    let Some(host) = program("fly-paycore-host") else { return };
    let place = data_place(
        &base,
        std::env::consts::OS,
        base.join(INSTALLED_MARK).is_file(),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
    );
    let Some(data) = place else { return };
    args.host = Some(host);
    args.host_args = vec!["--profile".into(), data.join("profile").to_string_lossy().into_owned()];
    if let Some(chain) = program("fly-chain") {
        args.host_args.push("--chain".into());
        args.host_args.push(chain.to_string_lossy().into_owned());
    }
    if let Some(onion) = program("fly-onion") {
        args.host_args.push("--onion".into());
        args.host_args.push(onion.to_string_lossy().into_owned());
    }
    if let Some(mailbox) = program("fly-mailbox") {
        args.host_args.push("--transport".into());
        args.host_args.push(mailbox.to_string_lossy().into_owned());
        args.host_args.push("--relay".into());
        args.host_args.push(DEFAULT_RELAY.into());
    }
}

/// The desktop program: arguments from the command line, the portable
/// layout when started without them.
pub fn desktop_main() {
    let mut args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("fly-ui: {err}");
            std::process::exit(2);
        }
    };
    portable(&mut args);
    if let Some(dir) = &args.scenario {
        match scenario::run(dir, &args) {
            Ok(true) => return,
            Ok(false) => std::process::exit(1),
            Err(err) => {
                eprintln!("scenario: {err}");
                std::process::exit(2);
            }
        }
    }
    if let Some(dir) = &args.snapshot {
        if let Err(err) = snapshot::run(dir, &args) {
            eprintln!("snapshot: {err}");
            std::process::exit(1);
        }
        return;
    }
    run_window(&args);
}

fn missing_host(app: &App) {
    fill_common(app);
    app.set_live(true);
    app.set_verified_chip(SharedString::new());
    app.set_verified_good(false);
    app.set_login_note(tr("A part of the program is missing. Install it again.", "Не хватает части программы. Установите её заново.").into());
}

/// Opens the wallet window.
fn run_window(args: &Args) {
    let Ok(app) = App::new() else {
        eprintln!("fly-ui: the window cannot be made");
        std::process::exit(1);
    };
    app.global::<Device>().set_phone(cfg!(target_os = "android"));
    wire_settings(&app, settings_path(args));
    app.set_direct_post(direct());
    app.set_tor_on(!tor_off());
    app.set_nostr_on(!nostr_off());
    let host_args = args_now(&args.host_args);
    // The host lives as long as the window; dropping it locks the profile.
    let _live = match &args.host {
        Some(host) => match live::Live::start(&app, host, &host_args) {
            Ok(live) => Some(live),
            Err(err) => {
                fill_common(&app);
                app.set_login_note(format!("{} {err}", tr("The wallet did not start:", "Кошелёк не запустился:")).into());
                None
            }
        },
        None => {
            missing_host(&app);
            None
        }
    };
    if app.run().is_err() {
        std::process::exit(1);
    }
}

/// Android: Slint's NativeActivity calls this. The wallet's programs are
/// packed as `lib*.so` files next to this library (the one folder of an
/// app Android lets it run programs from); the profile and the guard live
/// in the app's private storage.
#[cfg(target_os = "android")]
#[allow(unsafe_code)] // `no_mangle` only: the name NativeActivity looks for
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    let data = app.internal_data_path();
    if slint::android::init(app).is_err() {
        return;
    }
    let mut args = Args { snapshot: None, scenario: None, host: None, host_args: Vec::new() };
    if let (Some(dir), Some(data)) = (native_lib_dir(), data) {
        let program = |name: &str| dir.join(format!("lib{name}.so"));
        let text = |p: PathBuf| p.to_string_lossy().into_owned();
        args.host = Some(program("fly_paycore_host"));
        args.host_args = vec![
            "--profile".into(),
            text(data.join("profile")),
            "--guard-dir".into(),
            text(data.join("guard")),
            "--chain".into(),
            text(program("fly_chain")),
            "--onion".into(),
            text(program("fly_onion")),
            "--transport".into(),
            text(program("fly_mailbox")),
            "--relay".into(),
            DEFAULT_RELAY.into(),
        ];
    }
    run_window(&args);
}

/// The folder this library was loaded from (the app's native library
/// folder), read from this process's own memory map.
#[cfg(target_os = "android")]
fn native_lib_dir() -> Option<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|line| line.split_whitespace().last())
        .find(|path| path.ends_with("/libfly_ui.so"))
        .and_then(|path| Path::new(path).parent().map(Path::to_path_buf))
}

mod snapshot {
    use super::*;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType};
    use slint::platform::{Platform, WindowAdapter};
    use slint::PhysicalSize;

    struct Headless(Rc<MinimalSoftwareWindow>);

    impl Platform for Headless {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }

    pub const WIDTH: u32 = 1280;
    pub const HEIGHT: u32 = 960;
    /// Pixels to a point in the pictures: 1, or 2 for pictures that go
    /// into print (`GRINSIGHT_SNAPSHOT_SCALE=2`).
    static SCALE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

    fn scale() -> u32 {
        SCALE.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Height of the pictures in points: the window's own, or enough for
    /// the whole main screen (`GRINSIGHT_SNAPSHOT_TALL`).
    static TALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn height() -> u32 {
        if TALL.load(std::sync::atomic::Ordering::Relaxed) {
            1500
        } else {
            HEIGHT
        }
    }

    pub fn run(dir: &Path, args: &Args) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(Headless(window.clone()))).map_err(|e| e.to_string())?;
        let app = App::new().map_err(|e| e.to_string())?;
        // Kept until the pictures are drawn, then dropped: the host locks.
        // the pictures are English unless asked otherwise: the guides are
        // made in both languages from the same sample
        let russian = std::env::var_os("GRINSIGHT_SNAPSHOT_RU").is_some();
        app.global::<Settings>().set_russian(russian);
        set_language(russian);
        let _host = match &args.host {
            Some(host) => Some(live::snapshot_fill(&app, host, &args.host_args)?),
            None => {
                fill_sample(&app);
                None
            }
        };
        TALL.store(std::env::var_os("GRINSIGHT_SNAPSHOT_TALL").is_some(), std::sync::atomic::Ordering::Relaxed);
        if std::env::var("GRINSIGHT_SNAPSHOT_SCALE").as_deref() == Ok("2") {
            SCALE.store(2, std::sync::atomic::Ordering::Relaxed);
            window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: 2.0 });
        }
        window.set_size(PhysicalSize::new(WIDTH.saturating_mul(scale()), height().saturating_mul(scale())));
        app.show().map_err(|e| e.to_string())?;
        let themes = [
            (ThemeName::Emerald, "emerald"),
            (ThemeName::Ice, "ice"),
            (ThemeName::Honey, "honey"),
            (ThemeName::Mono, "mono"),
        ];
        let tag = if args.host.is_some() { "live-" } else { "" };
        if args.host.is_none() {
            fill_sample_sheets(&app);
            app.global::<Theme>().set_name(ThemeName::Emerald);
            let mut shots: Vec<(i32, i32, i32, &str)> = vec![(2, 0, 0, "create-1"), (2, 1, 0, "create-2-words"), (2, 2, 0, "create-3-check"), (3, 0, 0, "restore")];
            for (sheet, what) in [(1, "send"), (2, "slatepack"), (3, "sign"), (4, "receive"), (5, "incoming"), (6, "contact"), (7, "security"), (10, "invoice"), (11, "release")] {
                shots.push((1, 0, sheet, what));
            }
            shots.push((4, 0, 0, "chat"));
            // the window for Tor bridges, as it stands on the login screen
            app.set_tor_mode(1);
            app.set_tor_program(true);
            shots.push((0, 0, 12, "tor"));
            shots.push((5, 0, 0, "ops"));
            for (page, step, sheet, what) in shots {
                app.set_page(page);
                app.set_create_step(step);
                app.set_sheet(sheet);
                std::thread::sleep(std::time::Duration::from_millis(50));
                slint::platform::update_timers_and_animations();
                draw(&window, &dir.join(format!("{what}.bmp")))?;
            }
            app.set_sheet(0);
            app.set_create_step(0);
            // a phone-sized window: the same screens must fit 430 px
            window.set_size(PhysicalSize::new(430u32.saturating_mul(scale()), 930u32.saturating_mul(scale())));
            app.global::<Device>().set_phone(true);
            app.set_has_profile(false);
            // the phone pictures in Russian: proves the bundled .po is used
            app.global::<Settings>().set_russian(true);
            set_language(true);
            for (page, step, sheet, what) in [(0, 0, 0, "phone-login"), (1, 0, 0, "phone-main"), (1, 0, 3, "phone-sign"), (1, 0, 10, "phone-invoice"), (1, 0, 11, "phone-release"), (1, 0, 1, "phone-send"), (2, 1, 0, "phone-words"), (3, 0, 0, "phone-restore"), (4, 0, 0, "phone-chat")] {
                app.set_page(page);
                app.set_create_step(step);
                app.set_sheet(sheet);
                std::thread::sleep(std::time::Duration::from_millis(50));
                slint::platform::update_timers_and_animations();
                draw(&window, &dir.join(format!("{what}.bmp")))?;
            }
            app.set_sheet(0);
            app.set_create_step(0);
            app.set_page(0);
            app.set_has_profile(true);
            app.global::<Device>().set_phone(false);
            app.global::<Settings>().set_russian(russian);
            set_language(russian);
            window.set_size(PhysicalSize::new(WIDTH.saturating_mul(scale()), height().saturating_mul(scale())));
            // what stands under "Details", with a point just made (O38)
            app.set_page(1);
            app.set_sync_details(true);
            app.set_point_good(true);
            app.set_point_note(fill(tr("Your own starting point is made: block {}. The wallet starts from it at the next unlock.", "Своя стартовая точка сделана: блок {}. Кошелёк начнёт с неё со следующего входа."), &["4 115 760"]).into());
            std::thread::sleep(std::time::Duration::from_millis(50));
            slint::platform::update_timers_and_animations();
            draw(&window, &dir.join("main-details.bmp"))?;
            app.set_sync_details(false);
            app.set_point_note(SharedString::new());
            // with Tor switched off by the owner (O42): the main screen and the options
            let off = sync::Facts { tor_off: true, transport: sync::Part::default(), onion: sync::Part::default(), ..sample_facts() };
            show_sync(&app, &off, &sample_journal());
            for (page, what) in [(1, "main-tor-off"), (0, "login-tor-off")] {
                app.set_page(page);
                std::thread::sleep(std::time::Duration::from_millis(50));
                slint::platform::update_timers_and_animations();
                draw(&window, &dir.join(format!("{what}.bmp")))?;
            }
            show_sync(&app, &sample_facts(), &sample_journal());
        }
        for (theme, name) in themes {
            app.global::<Theme>().set_name(theme);
            for (page, what) in [(0, "login"), (1, "main")] {
                app.set_page(page);
                std::thread::sleep(std::time::Duration::from_millis(50));
                slint::platform::update_timers_and_animations();
                draw(&window, &dir.join(format!("{tag}{what}-{name}.bmp")))?;
            }
        }
        Ok(())
    }

    pub fn draw(window: &Rc<MinimalSoftwareWindow>, path: &Path) -> Result<(), String> {
        let w = usize::try_from(WIDTH.saturating_mul(scale())).map_err(|e| e.to_string())?;
        let h = usize::try_from(height().saturating_mul(scale())).map_err(|e| e.to_string())?;
        let mut pixels = vec![PremultipliedRgbaColor::default(); w.saturating_mul(h)];
        window.request_redraw();
        window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, w);
        });
        write_bmp(path, w, h, &pixels)
    }

    /// 24-bit BMP, rows bottom up, each padded to four bytes.
    fn write_bmp(path: &Path, w: usize, h: usize, pixels: &[PremultipliedRgbaColor]) -> Result<(), String> {
        let row = (w.saturating_mul(3).saturating_add(3) / 4).saturating_mul(4);
        let data = row.saturating_mul(h);
        let file = data.saturating_add(54);
        let mut out = Vec::with_capacity(file);
        let u32le = |v: usize| u32::try_from(v).map(u32::to_le_bytes).map_err(|e| e.to_string());
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&u32le(file)?);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&54u32.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&u32le(w)?);
        out.extend_from_slice(&u32le(h)?);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&24u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&u32le(data)?);
        out.extend_from_slice(&[0; 16]);
        for y in (0..h).rev() {
            let start = y.saturating_mul(w);
            let line = pixels.get(start..start.saturating_add(w)).ok_or("short buffer")?;
            for p in line {
                out.extend_from_slice(&[p.blue, p.green, p.red]);
            }
            out.resize(out.len().saturating_add(row.saturating_sub(w.saturating_mul(3))), 0);
        }
        std::fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn missing_auto_receive_status_is_distinct_from_both_known_settings() -> Result<(), Box<dyn std::error::Error>> {
            let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            slint::platform::set_platform(Box::new(Headless(window)))?;
            let app = App::new()?;
            let setting = |v| crate::live::auto_receive_fixture(&app, v);
            setting(Some(serde_json::json!({"auto_receive_since": null})));
            let off = app.get_auto_receive();
            setting(Some(serde_json::json!({"auto_receive_since": 0})));
            let on = app.get_auto_receive();
            assert_ne!(on, off);
            for missing in [None, Some(serde_json::json!({})), Some(serde_json::json!({"auto_receive_since": "bad"}))] {
                setting(missing);
                assert_ne!(app.get_auto_receive(), off, "missing status must not promise manual receipt");
                assert_ne!(app.get_auto_receive(), on, "missing status must not promise automatic receipt");
            }
            Ok(())
        }

        #[test]
        fn auto_receive_control_requires_a_known_setting() -> Result<(), Box<dyn std::error::Error>> {
            let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            slint::platform::set_platform(Box::new(Headless(window)))?;
            let app = App::new()?;
            assert!(!app.get_auto_known());
            for (info, known, enabled) in [
                (Some(serde_json::json!({"auto_receive_since": null})), true, false),
                (Some(serde_json::json!({"auto_receive_since": 42})), true, true),
                (None, false, false),
            ] {
                crate::live::auto_receive_fixture(&app, info);
                assert_eq!((app.get_auto_known(), app.get_auto_on()), (known, enabled));
            }
            Ok(())
        }

        #[test]
        fn missing_balance_clears_the_previously_shown_amount() -> Result<(), Box<dyn std::error::Error>> {
            let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            slint::platform::set_platform(Box::new(Headless(window)))?;
            let app = App::new()?;
            crate::live::refresh_balance_fixture(&app, true);
            assert!(app.get_balance().contains("123"));
            crate::live::refresh_balance_fixture(&app, false);
            assert_eq!(app.get_balance().as_str(), "—");
            assert!(!app.get_balance_note().is_empty());
            Ok(())
        }

        #[test]
        fn missing_host_never_opens_a_sample_wallet() -> Result<(), Box<dyn std::error::Error>> {
            let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            slint::platform::set_platform(Box::new(Headless(window)))?;
            let app = App::new()?;
            missing_host(&app);
            app.invoke_enter("synthetic".into());
            assert_eq!(app.get_page(), 0);
            assert!(app.get_balance().is_empty());
            assert!(!app.get_verified_good());
            assert!(!app.get_login_note().is_empty());
            Ok(())
        }
    }
}

/// `fly-ui --scenario <folder> --host <fly-paycore-host> --profile <folder>
/// --guard-dir <folder>`: drives the real window logic against the real
/// host without a window, step by step, and writes `scenario.log` and
/// pictures into `<folder>`. Two Testnet profiles are made under the given
/// profile and guard folders (`a`, `b`), which must not exist yet. The
/// words of the throwaway wallet stay in memory: never written to the log
/// or drawn.
mod scenario {
    use super::*;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    use slint::platform::{EventLoopProxy, Platform, WindowAdapter};
    use slint::{EventLoopError, Model, PhysicalSize};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use zeroize::{Zeroize, Zeroizing};

    type Queue = Arc<Mutex<VecDeque<Box<dyn FnOnce() + Send>>>>;

    struct Headless {
        window: Rc<MinimalSoftwareWindow>,
        queue: Queue,
    }

    impl Platform for Headless {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.window.clone())
        }
        fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
            Some(Box::new(Proxy(self.queue.clone())))
        }
    }

    struct Proxy(Queue);

    impl EventLoopProxy for Proxy {
        fn quit_event_loop(&self) -> Result<(), EventLoopError> {
            Ok(())
        }
        fn invoke_from_event_loop(&self, event: Box<dyn FnOnce() + Send>) -> Result<(), EventLoopError> {
            self.0.lock().map_err(|_| EventLoopError::EventLoopTerminated)?.push_back(event);
            Ok(())
        }
    }

    /// A throwaway password for throwaway Testnet profiles.
    const PASSWORD: &str = "scenario-only-not-a-wallet";
    /// An invoice for 1.5 GRIN issued by a throwaway wallet of the core's
    /// own tests; nobody holds its key.
    const INVOICE: &str = "BEGINSLATEPACK. 2qUejGAHXXLSiuy 5Z3DMLkXyC21BdP EhnDjGnXn9GtwXQ PiXYjhmSAsdGRMo 4V3iHdWYaRvA8bm ZASzUNrSXmW6Jxz Khwqmh5c8txZe65 Yi6j4gfFuJhh1zU BbD1ZZraad7ZWtR 6K8AzC7UszUSLPe 79ZwcyB7k52ghun 8fUk3xV7Lyom6ET YqNMSLuvNcHZjE6 66t29GJ6hewhq. ENDSLATEPACK.";
    /// A valid key for a contact: the x coordinate of the curve's generator.
    const NPUB: &str = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d";
    const SLOW: Duration = Duration::from_secs(150);
    const QUICK: Duration = Duration::from_secs(30);

    struct Run {
        queue: Queue,
        window: Rc<MinimalSoftwareWindow>,
        dir: PathBuf,
        lines: Vec<String>,
        failed: usize,
    }

    impl Run {
        /// Runs what the worker threads handed to the window's thread, and
        /// the timers, until `until` holds or the time is up.
        fn pump(&mut self, app: &App, limit: Duration, until: impl Fn(&App) -> bool) -> bool {
            let start = Instant::now();
            loop {
                let jobs: Vec<Box<dyn FnOnce() + Send>> = match self.queue.lock() {
                    Ok(mut q) => q.drain(..).collect(),
                    Err(_) => Vec::new(),
                };
                for job in jobs {
                    job();
                }
                slint::platform::update_timers_and_animations();
                if until(app) {
                    return true;
                }
                if start.elapsed() > limit {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn check(&mut self, what: &str, ok: bool, seen: &str) {
            if !ok {
                self.failed = self.failed.saturating_add(1);
            }
            self.lines.push(format!("{} {what}{}", if ok { "ok  " } else { "FAIL" }, if seen.is_empty() { String::new() } else { format!(" — {seen}") }));
        }

        fn draw(&mut self, name: &str) {
            if let Err(e) = snapshot::draw(&self.window, &self.dir.join(format!("{name}.bmp"))) {
                self.lines.push(format!("     picture {name}: {e}"));
            }
        }
    }

    fn with_profile(args: &[String], sub: &str) -> Vec<String> {
        let mut out = args.to_vec();
        let mut it = out.iter_mut().peekable();
        while let Some(arg) = it.next() {
            if arg == "--profile" || arg == "--guard-dir" {
                if let Some(value) = it.next() {
                    *value = Path::new(value.as_str()).join(sub).to_string_lossy().into_owned();
                }
            }
        }
        out
    }

    fn words_of(app: &App) -> Zeroizing<String> {
        let words: Vec<String> = app.get_words().iter().map(|w| w.to_string()).collect();
        Zeroizing::new(words.join(" "))
    }

    pub fn run(dir: &Path, args: &Args) -> Result<bool, String> {
        let program = args.host.as_ref().ok_or("--scenario needs --host")?;
        if !args.host_args.iter().any(|a| a == "--guard-dir") {
            return Err("--scenario needs --profile and --guard-dir".into());
        }
        let args_a = with_profile(&args.host_args, "a");
        let args_b = with_profile(&args.host_args, "b");
        for pair in [&args_a, &args_b] {
            if let Some(at) = pair.iter().position(|a| a == "--profile") {
                if let Some(p) = pair.get(at.saturating_add(1)) {
                    if Path::new(p).exists() {
                        return Err(format!("{p} exists: the scenario needs fresh folders"));
                    }
                }
            }
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        let queue: Queue = Arc::new(Mutex::new(VecDeque::new()));
        slint::platform::set_platform(Box::new(Headless { window: window.clone(), queue: queue.clone() })).map_err(|e| e.to_string())?;
        let app = App::new().map_err(|e| e.to_string())?;
        window.set_size(PhysicalSize::new(snapshot::WIDTH, snapshot::HEIGHT));
        app.show().map_err(|e| e.to_string())?;
        let mut run = Run { queue, window, dir: dir.to_path_buf(), lines: Vec::new(), failed: 0 };
        // English first: the default of a new install
        live::Live::start(&app, program, &args_a).map(drop)?;
        run.check("English by default", app.get_login_note() == "There is no wallet on this computer yet." || app.get_login_note() == "There is no wallet on this phone yet.", &app.get_login_note());
        // the checks below are written against the Russian wording
        app.global::<Settings>().set_russian(true);
        set_language(true);

        // ---- a new wallet
        let live = live::Live::start(&app, program, &args_a)?;
        run.check("no wallet yet: the login offers to create one", !app.get_has_profile(), &app.get_login_note());
        // ---- the options of the login screen
        app.invoke_open_own();
        app.invoke_save_own("http://plain.example.org".into(), "".into());
        run.check("an own node without https is refused", app.get_sheet() == 9 && !app.get_sheet_error().is_empty(), &app.get_sheet_error());
        app.invoke_save_own("https://node.example.org:3413".into(), "not json".into());
        run.check("a broken own point is refused", !app.get_sheet_error().is_empty(), &app.get_sheet_error());
        app.invoke_save_own("https://node.example.org:3413\n# a note\n".into(), "{\"height\": 1}".into());
        let own_dir = args_a.iter().position(|a| a == "--profile").and_then(|i| args_a.get(i.saturating_add(1))).and_then(|p| Path::new(p).parent().map(Path::to_path_buf)).unwrap_or_default();
        let saved = std::fs::read_to_string(own_dir.join("own-nodes.txt")).unwrap_or_default();
        run.check("own nodes and point are saved next to the profile", saved == "https://node.example.org:3413\n" && own_dir.join("own-point.json").exists() && app.get_sheet_error().is_empty(), &app.get_security_note());
        app.set_sheet(0);
        app.invoke_direct_changed(true);
        run.check("«send directly» starts the wallet process again", live::answers(), "");
        app.invoke_direct_changed(false);
        app.set_testnet(true);
        app.invoke_go_create();
        run.check("create page opens", app.get_page() == 2, "");
        app.invoke_make("".into(), "".into());
        run.check("an empty password is refused", app.get_create_step() == 0 && !app.get_flow_error().is_empty(), &app.get_flow_error());
        app.invoke_make(PASSWORD.into(), "other-password-here".into());
        run.check("different passwords are refused", app.get_create_step() == 0 && !app.get_flow_error().is_empty(), &app.get_flow_error());
        app.set_flow_error("".into());
        app.invoke_make(PASSWORD.into(), PASSWORD.into());
        let made = run.pump(&app, SLOW, |a| a.get_create_step() == 1 || !a.get_flow_error().is_empty());
        run.check("the wallet is made and its words are shown", made && app.get_create_step() == 1, &app.get_flow_error());
        let mut words = words_of(&app);
        let count = words.split_whitespace().count();
        run.check("24 words", count == 24, &count.to_string());
        let ask: Vec<usize> = app.get_ask().iter().filter_map(|n| usize::try_from(n).ok()).collect();
        let distinct = ask.len() == 3 && ask.windows(2).all(|w| w.first() < w.get(1)) && ask.iter().all(|n| (1..=24).contains(n));
        run.check("three different word numbers are asked", distinct, &format!("{ask:?}"));
        app.invoke_check("".into(), "".into(), "".into());
        run.check("the check step opens", app.get_create_step() == 2, "");
        app.invoke_check("x".into(), "y".into(), "z".into());
        run.check("wrong words are refused", app.get_page() == 2 && !app.get_flow_error().is_empty(), &app.get_flow_error());
        let pick = |n: usize| words.split_whitespace().nth(n.saturating_sub(1)).unwrap_or("").to_uppercase();
        let (a1, a2, a3) = (pick(ask.first().copied().unwrap_or(1)), pick(ask.get(1).copied().unwrap_or(2)), pick(ask.get(2).copied().unwrap_or(3)));
        app.invoke_check(format!(" {a1} ").into(), a2.into(), a3.into());
        run.check("the right words (any case, spaces) open the login", app.get_page() == 0 && app.get_flow_error().is_empty(), &app.get_flow_error());
        run.check("the words are gone from the window", app.get_words().row_count() == 0, "");
        run.draw("live-login-after-create");

        // how Tor is reached: directly, until bridges are chosen
        run.check("Tor is reached directly until bridges are chosen", app.get_tor_way() == "Напрямую · мосты нужны там, где Tor блокируют" && live::tor_lines_at_host() == Some(0), &app.get_tor_way());
        app.invoke_open_tor();
        run.check("the window for bridges opens with the choice that is written down", app.get_sheet() == 12 && app.get_tor_mode() == 0, "");
        app.invoke_save_tor(3, "not a bridge".into());
        run.check("a line that is not a bridge line is refused with its number", app.get_sheet_error().starts_with("Строка 1 — не строка моста") && live::tor_lines_at_host() == Some(0), &app.get_sheet_error());
        app.invoke_save_tor(1, "".into());
        run.check(
            "the built-in obfs4 bridges are written down and the wallet process has them",
            app.get_security_note() == "Сохранено. Действует со следующего входа." && app.get_tor_way() == "Через встроенные мосты obfs4: 7" && live::tor_lines_at_host() == Some(7),
            &app.get_tor_way(),
        );
        app.set_tor_mode(1);
        run.draw("live-tor-bridges");
        app.invoke_save_tor(0, "".into());
        run.check("back to directly: the wallet process has no bridge left", app.get_tor_way().starts_with("Напрямую") && live::tor_lines_at_host() == Some(0), &app.get_tor_way());
        app.set_sheet(0);

        // The profile has a wallet instance before its first chain process starts.
        let profile = Path::new(args_a.iter().position(|a| a == "--profile")
            .and_then(|i| args_a.get(i.saturating_add(1))).ok_or("missing test profile")?);
        let instance = std::fs::read_dir(profile).map_err(|e| e.to_string())?
            .filter_map(Result::ok).filter_map(|e| e.file_name().to_str()?.strip_prefix("wallet-").map(str::to_owned))
            .next().ok_or("missing test wallet journal")?;
        let chain_dir = profile.join(format!("chain-{instance}"));
        app.invoke_enter("wrong-password".into());
        run.pump(&app, SLOW, |a| !a.get_busy() && !a.get_login_error().is_empty());
        run.check("a wrong password is refused", app.get_page() == 0 && app.get_login_error() == "Пароль не подошёл", &app.get_login_error());
        app.set_login_error("".into());
        app.invoke_enter(PASSWORD.into());
        let opened = run.pump(&app, SLOW, |a| a.get_page() == 1);
        run.check("the password opens the wallet", opened, &app.get_login_error());
        run.check("own nodes are in the chain folder before the unlock", std::fs::read_to_string(chain_dir.join("own-nodes.txt")).unwrap_or_default() == "https://node.example.org:3413\n", "");
        run.pump(&app, QUICK, |a| !a.get_address_full().is_empty());
        let mine = app.get_address_full().to_string();
        run.check("Testnet wallet with a tgrin1 address", app.get_network() == "TESTNET" && mine.starts_with("tgrin1"), &app.get_network());
        run.check("the main screen names the version", app.get_app_version() == format!("v{APP_VERSION}").as_str(), &app.get_app_version());
        let rows = app.get_sync_rows();
        let first = rows.row_data(0).map(|r| r.value.to_string()).unwrap_or_default();
        run.check("the path of synchronisation is shown; without a chain process it says so", rows.row_count() >= 5 && first == "не задана", &first);
        let trouble = app.get_problems().row_data(0).map(|p| (p.what.to_string(), p.help.to_string(), p.open)).unwrap_or_default();
        run.check("the trouble is listed with a line of help", trouble.0 == "Нет проверки сети" && trouble.1.len() > 20 && trouble.2, &trouble.0);
        run.check("the Tor for the address says where it stands", app.get_addr_line() == "Tor для вашего адреса: не настроен — платежи на адрес передаются вручную" && !app.get_addr_good(), &app.get_addr_line());
        // Slatepack text as a file of the wallet's own folder, next to the profile
        let files = app.global::<ui::Files>();
        let said = files.invoke_save("BEGINSLATEPACK. scenario. ENDSLATEPACK.".into());
        let listed = files.invoke_list();
        let back = files.invoke_load(0);
        run.check("a Slatepack text is saved to the wallet's folder and read back", said.starts_with("Сохранено: ") && said.contains("slatepack") && listed.row_count() == 1 && back == "BEGINSLATEPACK. scenario. ENDSLATEPACK.", &said);
        run.check("an empty text is not saved, a file that is not listed is not read", files.invoke_save("  ".into()) == "Нет текста для сохранения" && files.invoke_load(5).is_empty() && files.invoke_load(-1).is_empty(), "");
        // a QR code of the address; none of a text longer than a code holds
        let qr = app.global::<ui::Qr>();
        let code = qr.invoke_picture(mine.as_str().into()).size();
        let none = qr.invoke_picture("a".repeat(3000).into()).size();
        run.check("the address is drawn as a QR code; too long a text gives none", code.width >= 29 && code.width == code.height && none.width == 0, &code.width.to_string());
        run.draw("live-main");

        // ---- sending without money, and what is refused before the host
        app.set_sheet(1);
        app.invoke_send_prepare("1,0000000001".into(), -1, "".into());
        run.check("finer than a nanogrin is refused", app.get_sheet_error() == "Не больше девяти знаков после точки", &app.get_sheet_error());
        app.invoke_send_prepare("1".into(), -1, "grin1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into());
        run.check("a broken address is refused", app.get_sheet_error().starts_with("Адрес с ошибкой"), &app.get_sheet_error());
        let main_form = fly_safe_display::address(&mine).ok().as_ref().and_then(fly_safe_display::key_of_address).map(|k| fly_safe_display::address_of_key(&k, false)).unwrap_or_default();
        app.invoke_send_prepare("1".into(), -1, main_form.into());
        run.check("a Mainnet address in a Testnet wallet is refused", app.get_sheet_error() == "Это адрес Mainnet, а кошелёк в Testnet", &app.get_sheet_error());
        app.set_sheet_error("".into());
        app.invoke_send_prepare("1".into(), -1, mine.clone().into());
        run.pump(&app, QUICK, |a| !a.get_sheet_busy() && !a.get_sheet_error().is_empty());
        // without a chain process the core refuses to spend before it counts
        let refused = ["Не хватает средств с учётом комиссии", "Кошелёк ещё не принял первый блок. Дождитесь слова «Проверено» на главном экране."];
        run.check("no money or no chain: the wallet refuses and says why", refused.contains(&app.get_sheet_error().as_str()), &app.get_sheet_error());
        // "over Tor, to an address" without an address asks for one before the wallet is asked
        app.set_sheet_error("".into());
        app.invoke_send_prepare("1".into(), -2, "".into());
        run.check("over Tor without an address asks for the address", app.get_sheet_error() == "Впишите адрес получателя grin1…" && !app.get_sheet_busy(), &app.get_sheet_error());
        run.draw("live-send-no-money");
        app.set_sheet(0);

        // ---- receiving a text that is not a payment
        app.set_sheet(4);
        app.set_sheet_error("".into());
        app.invoke_receive_read("BEGINSLATEPACK. not a payment. ENDSLATEPACK.".into());
        run.pump(&app, QUICK, |a| !a.get_sheet_busy() && !a.get_sheet_error().is_empty());
        run.check("a text that is not a payment is refused", app.get_sheet() == 4 && !app.get_sheet_error().is_empty(), &app.get_sheet_error());
        run.draw("live-receive-refused");

        // ---- an invoice: read as an invoice; without a verified chain the
        // wallet will not count what paying takes, and nothing is offered
        // for a signature
        app.set_sheet_error("".into());
        app.invoke_receive_read(INVOICE.into());
        run.pump(&app, QUICK, |a| !a.get_sheet_busy() && (!a.get_sheet_error().is_empty() || a.get_sheet() != 4));
        run.check("an invoice is told from a payment; without a chain the wallet refuses to pay and says why", app.get_sheet() == 4 && app.get_sheet_error().starts_with("Кошелёк сейчас не платит"), &app.get_sheet_error());
        app.invoke_invoice_pay();
        run.pump(&app, Duration::from_millis(300), |_| false);
        run.check("an invoice that was not shown cannot be paid", app.get_sheet() == 4 && !app.get_sheet_busy(), &app.get_sheet_error());
        run.draw("live-invoice-refused");
        app.set_sheet(0);

        // ---- a contact
        app.set_sheet(6);
        app.set_sheet_error("".into());
        app.invoke_contact_add("Тест".into(), "npub1notakey".into(), "".into());
        run.pump(&app, QUICK, |a| !a.get_sheet_busy() && !a.get_sheet_error().is_empty());
        run.check("a broken key is refused", app.get_sheet() == 6 && !app.get_sheet_error().is_empty(), &app.get_sheet_error());
        app.set_sheet_error("".into());
        app.invoke_contact_add("Тест".into(), NPUB.into(), mine.clone().into());
        let saved = run.pump(&app, QUICK, |a| a.get_sheet() == 0 || !a.get_sheet_error().is_empty());
        run.check("a contact is saved", saved && app.get_sheet() == 0, &app.get_sheet_error());
        let listed = run.pump(&app, QUICK, |a| a.get_contact_names().row_count() == 1);
        run.check("the contact is listed", listed && app.get_contact_names().row_data(0).is_some_and(|n| n == "Тест"), "");
        run.draw("live-main-with-contact");

        // ---- the key for messages, a conversation, all payments
        app.invoke_make_identity();
        let made = run.pump(&app, QUICK, |a| a.get_identity_made());
        run.check("a message key is made", made && app.get_phrase().starts_with("npub1"), &app.get_phrase());
        app.invoke_open_chat(0);
        run.check("the conversation opens with the contact's name", app.get_page() == 4 && app.get_chat_name() == "Тест" && app.get_chat_can_write(), &app.get_chat_name());
        app.invoke_chat_send("Привет".into());
        run.pump(&app, QUICK, |a| !a.get_chat_busy() && !a.get_chat_error().is_empty());
        run.check("without delivery a message is refused and says why", app.get_chat_error() == "Доставка через Tor не настроена — отправьте вручную", &app.get_chat_error());
        run.draw("live-chat");
        app.invoke_chat_pay();
        run.check("«Send GRIN» from the conversation picks the contact", app.get_sheet() == 1 && app.get_send_to() == 0, "");
        app.set_sheet(0);
        app.global::<Settings>().set_by_hand(true);
        app.invoke_chat_pay();
        run.check("with «By hand» chosen the payment is not addressed to the contact", app.get_sheet() == 1 && app.get_send_to() == -1, "");
        app.global::<Settings>().set_by_hand(false);
        app.set_sheet(0);
        app.invoke_chat_closed();
        app.set_page(5);
        run.check("all payments open", app.get_page() == 5, "");
        app.set_page(1);
        app.invoke_set_auto(true);
        run.pump(&app, QUICK, |a| a.get_auto_receive() != "выключен: каждый платёж принимаете вы");
        run.pump(&app, Duration::from_secs(4), |_| false);
        run.check("auto-receive stays honestly off without a verified chain", !app.get_auto_on(), &app.get_auto_receive());

        // ---- the password and the words
        const NEW_PASSWORD: &str = "scenario-second-password";
        app.set_sheet(7);
        app.invoke_change_password("wrong-old-password".into(), NEW_PASSWORD.into(), NEW_PASSWORD.into());
        run.pump(&app, SLOW, |a| !a.get_sheet_busy() && !a.get_sheet_error().is_empty());
        run.check("a wrong current password changes nothing", app.get_sheet_error() == "Пароль не подошёл", &app.get_sheet_error());
        app.set_sheet_error("".into());
        app.invoke_change_password(PASSWORD.into(), NEW_PASSWORD.into(), NEW_PASSWORD.into());
        run.pump(&app, SLOW, |a| !a.get_sheet_busy() && (!a.get_security_note().is_empty() || !a.get_sheet_error().is_empty()));
        run.check("the password is changed", app.get_security_note() == "Пароль изменён.", &app.get_sheet_error());
        app.invoke_show_words(NEW_PASSWORD.into());
        run.pump(&app, SLOW, |a| !a.get_sheet_busy() && (a.get_sheet() == 8 || !a.get_sheet_error().is_empty()));
        let shown = words_of(&app);
        run.check("the words shown are the wallet's words", app.get_sheet() == 8 && shown.as_str() == words.as_str(), &app.get_sheet_error());
        app.invoke_words_closed();
        app.set_sheet(0);
        run.check("closing drops the words from the window", app.get_words().row_count() == 0, "");

        app.invoke_leave();
        let locked = run.pump(&app, SLOW, |a| !a.get_busy());
        run.check("leaving locks and shows the login", locked && app.get_page() == 0 && app.get_login_error().is_empty(), "");
        app.invoke_enter(PASSWORD.into());
        run.pump(&app, SLOW, |a| !a.get_busy() && !a.get_login_error().is_empty());
        run.check("the old password no longer opens it", app.get_page() == 0 && app.get_login_error() == "Пароль не подошёл", &app.get_login_error());
        app.set_login_error("".into());
        app.invoke_save_own("".into(), "".into());
        app.set_sheet(0);
        app.invoke_enter(NEW_PASSWORD.into());
        let opened = run.pump(&app, SLOW, |a| a.get_page() == 1);
        run.check("the new password opens it", opened, &app.get_login_error());
        run.check("cleared options leave the chain folder too", !chain_dir.join("own-nodes.txt").exists() && !chain_dir.join("own-point.json").exists(), "");
        app.invoke_leave();
        drop(live);

        // ---- the same words restore the same wallet elsewhere
        let live = live::Live::start(&app, program, &args_b)?;
        run.check("second folder: no wallet yet", !app.get_has_profile(), "");
        app.invoke_go_restore();
        app.invoke_restore("abandon ability able".into(), PASSWORD.into(), PASSWORD.into());
        run.check("three words are refused", app.get_page() == 3 && !app.get_flow_error().is_empty(), &app.get_flow_error());
        app.set_flow_error("".into());
        // a password of one character: the length is the owner's choice
        app.invoke_restore(words.as_str().into(), "1".into(), "1".into());
        let restored = run.pump(&app, SLOW, |a| a.get_page() == 0 || !a.get_flow_error().is_empty());
        run.check("the words restore a wallet, under a password of one character", restored && app.get_page() == 0, &app.get_flow_error());
        words.zeroize();
        app.invoke_enter("1".into());
        run.pump(&app, SLOW, |a| a.get_page() == 1 || !a.get_login_error().is_empty());
        run.pump(&app, QUICK, |a| !a.get_address_full().is_empty());
        run.check("the restored wallet has the same address", app.get_address_full() == mine.as_str(), "");
        run.draw("live-main-restored");
        app.invoke_leave();
        drop(live);

        let passed = run.lines.len().saturating_sub(run.failed);
        run.lines.push(format!("passed {passed}, failed {}", run.failed));
        let text = run.lines.join("\n");
        println!("{text}");
        std::fs::write(dir.join("scenario.log"), text).map_err(|e| e.to_string())?;
        Ok(run.failed == 0)
    }
}

#[cfg(test)]
mod version_tests {
    use super::APP_VERSION;

    /// The version is three numbers with dots between them, and it stands
    /// in the source exactly once, on a line of its own, in the form the
    /// packing scripts look for.
    #[test]
    fn the_version_is_three_numbers_on_the_line_the_scripts_read() {
        let parts: Vec<&str> = APP_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "{APP_VERSION}");
        for part in parts {
            assert!(!part.is_empty() && part.len() <= 2 && part.bytes().all(|b| b.is_ascii_digit()), "{APP_VERSION}");
            assert!(part == "0" || !part.starts_with('0'), "{APP_VERSION}");
        }
        let line = format!("pub const APP_VERSION: &str = \"{APP_VERSION}\";");
        assert_eq!(include_str!("lib.rs").lines().filter(|l| *l == line).count(), 1);
    }

    /// The login screen names the same version.
    #[test]
    fn the_window_names_the_version() {
        let shown = super::fill(super::tr("GrinSight {} · a wallet for people", "GrinSight {} · кошелёк для людей"), &[APP_VERSION]);
        assert!(shown.contains(&format!("GrinSight {APP_VERSION} ")), "{shown}");
    }
}

#[cfg(test)]
mod place_tests {
    use super::data_place;
    use std::path::{Path, PathBuf};

    /// A portable copy keeps the wallet next to itself. A copy the Windows
    /// installer put in place keeps it in the user's local application
    /// data, wherever the program lies; a Mac app in Application Support.
    /// When that place cannot be told there is no place at all, rather
    /// than a wallet in the program's folder.
    #[test]
    fn where_the_wallets_data_lie() {
        let (base, home, local) = if cfg!(windows) {
            (Path::new(r"C:\Programs\Fly"), PathBuf::from(r"C:\Users\u"), PathBuf::from(r"C:\Users\u\AppData\Local"))
        } else {
            (Path::new("/opt/fly"), PathBuf::from("/home/u"), PathBuf::from("/home/u/local"))
        };
        let some = |p: &PathBuf| Some(p.clone());
        assert_eq!(data_place(base, "windows", false, some(&home), some(&local)), Some(base.join("data")));
        assert_eq!(data_place(base, "windows", true, some(&home), some(&local)), Some(local.join("GrinSightLight").join("data")));
        assert_eq!(data_place(base, "windows", true, some(&home), None), None);
        assert_eq!(data_place(base, "windows", true, some(&home), Some(PathBuf::from("relative"))), None);
        assert_eq!(data_place(base, "windows", true, some(&home), Some(PathBuf::new())), None);
        assert_eq!(data_place(base, "linux", false, some(&home), some(&local)), Some(base.join("data")));
        assert_eq!(data_place(base, "linux", true, some(&home), some(&local)), Some(base.join("data")), "the mark means nothing elsewhere");
        assert_eq!(
            data_place(base, "macos", false, some(&home), None),
            Some(home.join("Library").join("Application Support").join("GrinSightLight"))
        );
        assert_eq!(data_place(base, "macos", false, None, some(&local)), None);
    }
}
