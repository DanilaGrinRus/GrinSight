//! O70: conversations in windows of their own, on a computer.
//!
//! The main window keeps one conversation; each window here keeps one
//! more, with the same page and the same rules of display. At most
//! [`MOST`] are open at once and one contact has one window. They belong
//! to the open wallet: locking it, closing the main window or deleting
//! the contact closes them, so no message stays on the screen behind a
//! locked wallet. A window holds nothing the main window does not: the
//! key of its contact and what the wallet process says of the conversation.
use super::{chat_view, client, model, name_note, say, spawn, tr, unix_now, with, CallError, Said, QUICK};
use crate::ui::{App, ChatWindow, Theme};
use serde_json::{json, Value};
use slint::{ComponentHandle, SharedString};
use std::cell::RefCell;

/// How many conversations may be open in windows of their own.
pub(crate) const MOST: usize = 3;

struct Open {
    key: String,
    window: ChatWindow,
}

thread_local! {
    static OPEN: RefCell<Vec<Open>> = const { RefCell::new(Vec::new()) };
}

/// What an attempt to open a window came to.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Opened {
    /// A new window is on the screen.
    New,
    /// The contact has a window already; it is shown again.
    Already,
    /// [`MOST`] windows are open.
    Full,
    /// There is no such contact, or the window could not be made.
    No,
}

/// The keys of the conversations open in windows, oldest first.
pub(crate) fn keys() -> Vec<String> {
    OPEN.with(|o| o.borrow().iter().map(|w| w.key.clone()).collect())
}

/// Whether a window may be opened for `key`, given the open ones.
fn room(open: &[String], key: &str) -> Opened {
    if open.iter().any(|k| k == key) {
        Opened::Already
    } else if open.len() >= MOST {
        Opened::Full
    } else {
        Opened::New
    }
}

/// Opens the conversation with the contact at `index` in a window of its own.
pub(crate) fn open(app: &App, index: i32) -> Opened {
    let Some(c) = usize::try_from(index).ok().and_then(|i| with(|f| f.contacts.get(i).cloned())) else { return Opened::No };
    match room(&keys(), &c.key) {
        Opened::Already => {
            OPEN.with(|o| {
                if let Some(w) = o.borrow().iter().find(|w| w.key == c.key) {
                    let _ = w.window.show();
                }
            });
            return Opened::Already;
        }
        Opened::Full => return Opened::Full,
        Opened::New | Opened::No => {}
    }
    let Ok(window) = ChatWindow::new() else { return Opened::No };
    window.global::<Theme>().set_name(app.global::<Theme>().get_name());
    window.set_name(c.shown.clone().into());
    window.set_note(name_note(&c, app.get_identity_made()).into());
    window.set_can_write(app.get_identity_made());
    window.set_lines(model(Vec::new()));
    let key = c.key.clone();
    let main = app.as_weak();
    window.on_send(move |words| {
        let Some(app) = main.upgrade() else { return };
        send(&app, key.clone(), words.to_string());
    });
    let key = c.key.clone();
    let main = app.as_weak();
    window.on_pay(move || {
        let Some(app) = main.upgrade() else { return };
        // the contact may have moved in the list since the window opened
        let index = with(|f| f.contacts.iter().position(|c| c.key == key)).and_then(|i| i32::try_from(i).ok());
        if let Some(index) = index {
            app.invoke_contact_pay(index);
        }
    });
    let key = c.key.clone();
    window.window().on_close_requested(move || {
        // the window is dropped after this call has returned, not inside it
        let key = key.clone();
        let _ = slint::invoke_from_event_loop(move || forget(&key));
        slint::CloseRequestResponse::HideWindow
    });
    if window.show().is_err() {
        return Opened::No;
    }
    OPEN.with(|o| o.borrow_mut().push(Open { key: c.key, window }));
    read(app);
    Opened::New
}

/// Drops the window of `key`, if it has one.
fn forget(key: &str) {
    let gone: Vec<Open> = OPEN.with(|o| {
        let mut open = o.borrow_mut();
        let (gone, kept) = std::mem::take(&mut *open).into_iter().partition(|w| w.key == key);
        *open = kept;
        gone
    });
    for w in gone {
        let _ = w.window.hide();
    }
}

/// Closes every window: the wallet locks, or the main window goes.
pub(crate) fn close_all() {
    let gone: Vec<Open> = OPEN.with(|o| std::mem::take(&mut *o.borrow_mut()));
    for w in gone {
        w.window.set_lines(model(Vec::new()));
        let _ = w.window.hide();
    }
}

/// Closes the windows of contacts that are deleted.
pub(crate) fn close_keys(keys: &[String]) {
    for key in keys {
        forget(key);
    }
}

fn each(key: &str, f: impl FnOnce(&ChatWindow)) {
    OPEN.with(|o| {
        if let Some(w) = o.borrow().iter().find(|w| w.key == key) {
            f(&w.window);
        }
    });
}

fn send(app: &App, key: String, words: String) {
    if words.trim().is_empty() {
        return;
    }
    if words.len() > 2000 {
        each(&key, |w| w.set_error(tr("A message is at most 2000 bytes", "Сообщение — не больше 2000 байт").into()));
        return;
    }
    let Some(client) = client() else { return };
    each(&key, |w| {
        w.set_busy(true);
        w.set_error(SharedString::new());
    });
    let to = key.clone();
    spawn(
        app,
        move || client.call("paycore.messages.send", json!({ "key": to, "text": words }), QUICK),
        move |app, out: Result<Value, CallError>| {
            each(&key, |w| {
                w.set_busy(false);
                if let Err(e) = &out {
                    w.set_error(say(e).into());
                }
            });
            if out.is_ok() {
                read(app);
            }
        },
    );
}

/// Reads the conversations of the open windows and shows them; with no
/// window open it asks nothing. Called with every reading of the wallet.
pub(crate) fn read(app: &App) {
    let keys = keys();
    if keys.is_empty() {
        return;
    }
    let Some(client) = client() else { return };
    // what the main window knows by now: the names, the theme, the key for messages
    let made = app.get_identity_made();
    let theme = app.global::<Theme>().get_name();
    let known: Vec<(String, Option<(String, &'static str)>)> = keys
        .iter()
        .map(|k| (k.clone(), with(|f| f.contacts.iter().find(|c| &c.key == k).map(|c| (c.shown.clone(), name_note(c, made))))))
        .collect();
    for (key, contact) in known {
        match contact {
            Some((shown, note)) => each(&key, |w| {
                w.global::<Theme>().set_name(theme);
                w.set_name(shown.into());
                w.set_note(note.into());
                w.set_can_write(made);
            }),
            // the contact is no longer in the wallet
            None => forget(&key),
        }
    }
    spawn(
        app,
        move || {
            keys.into_iter()
                .filter_map(|key| {
                    let list = client.call("paycore.messages.list", json!({ "key": key }), QUICK).ok()?;
                    Some((key, said(&list)))
                })
                .collect::<Vec<(String, Vec<Said>)>>()
        },
        |_, all| {
            let now = unix_now();
            for (key, lines) in all {
                let pays = with(|f| f.plaques.get(&key).cloned().unwrap_or_default());
                each(&key, |w| w.set_lines(model(chat_view(&lines, &pays, now))));
            }
        },
    );
}

/// The messages of one answer of `paycore.messages.list`.
pub(super) fn said(list: &Value) -> Vec<Said> {
    list.get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|m| {
            (
                super::text(m, "dir").as_deref() == Some("out"),
                m.get("at").and_then(Value::as_u64).unwrap_or(0),
                super::text(m, "text").unwrap_or_default(),
                super::text(m, "state").unwrap_or_default(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_three_windows_and_one_for_a_contact() {
        let k = |n: &str| n.to_string();
        assert_eq!(room(&[], "a"), Opened::New);
        assert_eq!(room(&[k("a")], "a"), Opened::Already);
        assert_eq!(room(&[k("a"), k("b")], "c"), Opened::New);
        assert_eq!(room(&[k("a"), k("b"), k("c")], "d"), Opened::Full);
        // the contact that has a window is shown it again even when no more may open
        assert_eq!(room(&[k("a"), k("b"), k("c")], "b"), Opened::Already);
        assert_eq!(MOST, 3);
    }

    #[test]
    fn a_window_reads_messages_as_the_main_one_does() {
        let list = json!({ "messages": [
            { "dir": "out", "at": 5, "text": "one", "state": "relay_accepted" },
            { "dir": "in", "at": 7, "text": "two" },
            "not a message",
        ]});
        assert_eq!(
            said(&list),
            vec![(true, 5, "one".to_string(), "relay_accepted".to_string()), (false, 7, "two".to_string(), String::new()), (false, 0, String::new(), String::new())]
        );
        assert!(said(&json!({})).is_empty());
    }
}
