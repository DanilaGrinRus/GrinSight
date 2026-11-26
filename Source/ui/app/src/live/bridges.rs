//! O71: the wallet tries the built-in Tor bridges by itself (K201).
//!
//! When Tor looks unable to send, the window to sign offers one more way
//! out: "Try through Tor bridges". The wallet then writes the built-in
//! obfs4 bridges down as the choice, tells the wallet process that the
//! bridges changed - it starts its Tor programs anew, without a lock and
//! without the password - and watches whether a Tor of this wallet comes
//! up. If it does not within [`crate::tor::TRY_WAIT`], Snowflake is tried
//! the same way; if that fails too, the owner's earlier choice is put
//! back. A way that worked stays the choice. Nothing here ever turns
//! bridges into a direct connection that the owner did not choose: the
//! only choice put back is the one the owner had made.
use super::{client, fill, say, spawn, tor_file, tor_way, tr, with, CallError, QUICK};
use crate::sync::Facts;
use crate::tor::{judge, load, save, ways, Mode, Signs, Try, Verdict};
use crate::ui::App;
use serde_json::{json, Value};
use std::time::Instant;

/// The way by its name in the window.
fn name(mode: Mode) -> &'static str {
    match mode {
        Mode::Direct => tr("directly", "напрямую"),
        Mode::Obfs4 => tr("the built-in obfs4 bridges", "встроенные мосты obfs4"),
        Mode::Snowflake => "Snowflake",
        Mode::Own => tr("your own bridges", "свои мосты"),
    }
}

fn trying_words(mode: Mode) -> String {
    fill(
        tr(
            "Trying to reach Tor through {}… This can take up to three minutes. You can wait here or do something else: the payment stays prepared.",
            "Пробуем выйти в Tor через {}… Это может занять до трёх минут. Можно ждать здесь или заняться другим: платёж остаётся подготовленным.",
        ),
        &[name(mode)],
    )
}

fn worked_words(mode: Mode) -> String {
    fill(
        tr(
            "Tor works through {}. This way is saved as your choice; it can be changed under “Tor bridges”.",
            "Tor работает через {}. Этот путь сохранён как ваш выбор; изменить его можно в «Мостах Tor».",
        ),
        &[name(mode)],
    )
}

fn blind_words(mode: Mode) -> String {
    fill(
        tr(
            "Tor is now reached through {}. Nothing in this wallet shows yet whether it works: sign the payment, and if it does not leave, try another way under “Tor bridges”.",
            "Теперь Tor выходит через {}. Проверить, работает ли он, в этом кошельке пока нечем: подпишите платёж, а если он не уйдёт — выберите другой путь в «Мостах Tor».",
        ),
        &[name(mode)],
    )
}

fn failed_words(original: Mode) -> String {
    fill(
        tr(
            "Tor did not come up through the built-in bridges. Your earlier choice is back: {}. Bridges of your own can be set under “Tor bridges”; the other ways out are below.",
            "Через встроенные мосты Tor не поднялся. Прежний выбор возвращён: {}. Свои мосты можно задать в «Мостах Tor»; остальные выходы — ниже.",
        ),
        &[name(original)],
    )
}

/// Whether the button is offered: there is the program for bridges, Tor
/// is not switched off, and the owner's choice leaves a built-in way to try.
pub(super) fn offered() -> bool {
    if crate::tor_off() || !with(|f| f.tor_program) {
        return false;
    }
    tor_file().is_some_and(|path| !ways(load(&path).0).is_empty())
}

fn signs(f: &Facts) -> Signs {
    Signs {
        transport_configured: f.transport.configured,
        transport_ready: f.transport.phase == "ready",
        transport_starts: f.transport.starts,
        onion_configured: f.onion.configured,
        onion_up: f.onion.phase == "up" || f.onion.phase == "listening",
    }
}

/// Tells the wallet process that the bridges changed; `failed` is said if it cannot be told.
fn tell(app: &App, failed: impl FnOnce(&App, &CallError) + Send + 'static) {
    let Some(client) = client() else { return };
    spawn(
        app,
        move || client.call("host.tor.bridges", json!({}), QUICK),
        move |app, out: Result<Value, CallError>| {
            if let Err(e) = &out {
                failed(app, e);
            }
        },
    );
}

fn show(app: &App, note: String, busy: bool) {
    app.set_sign_bridges_note(note.into());
    app.set_sign_bridges_busy(busy);
    tor_way(app);
}

/// Writes `t.now` down as the choice and has the wallet process take it up.
fn start_way(app: &App, t: Try) {
    let Some(path) = tor_file() else { return };
    if !matches!(save(&path, t.now, ""), Ok(Ok(()))) {
        with(|f| f.bridge_try = None);
        return show(app, tr("The choice of bridges could not be written down.", "Выбор мостов не записался.").to_string(), false);
    }
    let now = t.now;
    with(|f| f.bridge_try = Some((t, Instant::now())));
    show(app, trying_words(now), true);
    tell(app, |app, e| {
        // the wallet process was not told: nothing changed, the choice goes back
        let words = say(e);
        let back = put_back(app);
        show(app, if back { words } else { not_back_words() }, false);
    });
}

/// Puts the owner's earlier choice back and ends the try. `false`: the
/// file could not be written, and the way that was tried is still in it.
fn put_back(app: &App) -> bool {
    let Some((t, _)) = with(|f| f.bridge_try.take()) else { return true };
    let written = tor_file().is_some_and(|path| matches!(save(&path, t.original.0, &t.original.1), Ok(Ok(()))));
    tell(app, |_, _| {});
    written
}

/// What is said when the earlier choice could not be written back.
fn not_back_words() -> String {
    tr(
        "Your earlier choice of bridges could not be written back: the way that was tried is still the choice. Set it under “Tor bridges”.",
        "Прежний выбор мостов не записался обратно: выбором остался путь, который пробовался. Задайте его в «Мостах Tor».",
    )
    .to_string()
}

/// The owner's word: try the built-in bridges.
pub(super) fn begin(app: &App) {
    if with(|f| f.bridge_try.is_some()) {
        return;
    }
    let Some(path) = tor_file() else { return };
    let original = load(&path);
    let mut rest = ways(original.0).into_iter();
    let Some(now) = rest.next() else { return };
    let starts = with(|f| f.transport_starts);
    start_way(app, Try { original, now, rest: rest.collect(), starts, seen_down: false });
}

/// Finding 52: a choice the owner saves by hand while the wallet is trying
/// the bridges takes over - the try ends without putting the older choice back.
pub(super) fn manual_saved(app: &App) {
    if with(|f| f.bridge_try.take().is_some()) {
        app.set_sign_bridges_note(String::new().into());
        app.set_sign_bridges_busy(false);
    }
}

/// The owner's word: enough. The earlier choice is put back.
pub(super) fn stop(app: &App) {
    if with(|f| f.bridge_try.is_none()) {
        return;
    }
    let back = put_back(app);
    show(app, if back { String::new() } else { not_back_words() }, false);
}

/// With every reading of the wallet: how the try stands.
pub(super) fn step(app: &App, facts: &Facts) {
    with(|f| f.transport_starts = facts.transport.starts);
    let Some((mut t, since)) = with(|f| f.bridge_try.clone()) else { return };
    match judge(&mut t, &signs(facts), since.elapsed()) {
        Verdict::Wait => {
            let now = t.now;
            with(|f| f.bridge_try = Some((t, since)));
            show(app, trying_words(now), true);
        }
        Verdict::Worked => {
            with(|f| f.bridge_try = None);
            show(app, worked_words(t.now), false);
        }
        Verdict::Blind => {
            with(|f| f.bridge_try = None);
            show(app, blind_words(t.now), false);
        }
        Verdict::GiveUp => {
            let mut rest = t.rest.clone().into_iter();
            match rest.next() {
                Some(next) => start_way(app, Try { original: t.original, now: next, rest: rest.collect(), starts: facts.transport.starts, seen_down: false }),
                None => {
                    let original = t.original.0;
                    let back = put_back(app);
                    show(app, if back { failed_words(original) } else { not_back_words() }, false);
                }
            }
        }
    }
}

/// The wallet locks in the middle of a try: the owner's choice is put
/// back in the file, so that the next unlock starts from what they chose.
pub(super) fn leave() {
    if let Some((t, _)) = with(|f| f.bridge_try.take()) {
        if let Some(path) = tor_file() {
            let _ = save(&path, t.original.0, &t.original.1);
        }
    }
}
