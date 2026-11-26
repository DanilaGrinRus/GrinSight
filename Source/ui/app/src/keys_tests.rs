//! The keyboard under a Cyrillic layout: Ctrl+V arrives as Ctrl+«м», and a
//! text field must still paste (and select, copy and cut).

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Clipboard, Key, Platform, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, PhysicalSize, SharedString};
use std::cell::RefCell;
use std::rc::Rc;

slint::slint! {
    #[edition = "1.19"]
    import { Field, TextBox } from "../ui/flows.slint";
    export component KeysProbe inherits Window {
        in-out property <string> plain;
        in-out property <string> secret;
        in-out property <string> large;
        VerticalLayout {
            a := Field { text <=> root.plain; }
            b := Field { secret: true; text <=> root.secret; }
            c := TextBox { text <=> root.large; box-height: 60px; }
        }
        public function focus-plain() { a.focus-it(); }
        public function focus-secret() { b.focus-it(); }
    }
}

/// A window with nothing behind it, for tests that only read what is shown.
pub(crate) struct Plain(pub Rc<MinimalSoftwareWindow>);

impl Platform for Plain {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

struct WithClipboard {
    window: Rc<MinimalSoftwareWindow>,
    held: Rc<RefCell<String>>,
}

impl Platform for WithClipboard {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
    fn set_clipboard_text(&self, text: &str, clipboard: Clipboard) {
        if matches!(clipboard, Clipboard::DefaultClipboard) {
            *self.held.borrow_mut() = text.to_string();
        }
    }
    fn clipboard_text(&self, clipboard: Clipboard) -> Option<String> {
        matches!(clipboard, Clipboard::DefaultClipboard).then(|| self.held.borrow().clone())
    }
}

fn press(window: &MinimalSoftwareWindow, text: &str) {
    let text = SharedString::from(text);
    window.window().dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    window.window().dispatch_event(WindowEvent::KeyReleased { text });
}

fn with_control(window: &MinimalSoftwareWindow, text: &str) {
    let control = SharedString::from(Key::Control);
    window.window().dispatch_event(WindowEvent::KeyPressed { text: control.clone() });
    press(window, text);
    window.window().dispatch_event(WindowEvent::KeyReleased { text: control });
}

/// Ctrl+«м» pastes, Ctrl+«ф» selects all, Ctrl+«с» copies and Ctrl+«ч» cuts,
/// in either case of the letter; the Latin keys work as before. A password
/// field pastes but gives nothing away to the clipboard.
#[test]
fn the_cyrillic_layout_pastes_copies_and_cuts() -> Result<(), Box<dyn std::error::Error>> {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    let held = Rc::new(RefCell::new(String::new()));
    slint::platform::set_platform(Box::new(WithClipboard { window: window.clone(), held: held.clone() }))?;
    let probe = KeysProbe::new()?;
    window.set_size(PhysicalSize::new(600, 400));
    probe.show()?;

    // paste
    *held.borrow_mut() = "one two three".into();
    probe.invoke_focus_plain();
    with_control(&window, "м");
    assert_eq!(probe.get_plain(), "one two three");
    with_control(&window, "М");
    assert_eq!(probe.get_plain(), "one two threeone two three");
    with_control(&window, "v");
    assert_eq!(probe.get_plain(), "one two threeone two threeone two three");

    // select all, cut: the field is empty and the clipboard holds it
    *held.borrow_mut() = String::new();
    with_control(&window, "ф");
    with_control(&window, "ч");
    assert_eq!(probe.get_plain(), "");
    assert_eq!(held.borrow().as_str(), "one two threeone two threeone two three");

    // copy leaves the text where it is
    *held.borrow_mut() = "abc".into();
    with_control(&window, "м");
    *held.borrow_mut() = String::new();
    with_control(&window, "ф");
    with_control(&window, "с");
    assert_eq!(probe.get_plain(), "abc");
    assert_eq!(held.borrow().as_str(), "abc");

    // without Ctrl the letters are letters
    press(&window, "м");
    assert_eq!(probe.get_plain(), "м");

    // a password field: pasting works, copying and cutting give nothing
    *held.borrow_mut() = "pass phrase".into();
    probe.invoke_focus_secret();
    with_control(&window, "м");
    assert_eq!(probe.get_secret(), "pass phrase");
    *held.borrow_mut() = "untouched".into();
    with_control(&window, "ф");
    with_control(&window, "с");
    with_control(&window, "ч");
    assert_eq!(held.borrow().as_str(), "untouched");
    assert_eq!(probe.get_secret(), "pass phrase");
    Ok(())
}

/// O74: "Copy the words" puts the words on the clipboard as one line; the
/// clipboard is emptied later only if it still holds them, never when the
/// owner has put something else there meanwhile.
#[test]
fn the_words_go_to_the_clipboard_and_are_taken_back() -> Result<(), Box<dyn std::error::Error>> {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    let held = Rc::new(RefCell::new(String::new()));
    slint::platform::set_platform(Box::new(WithClipboard { window: window.clone(), held: held.clone() }))?;
    let app = crate::ui::App::new()?;
    window.set_size(PhysicalSize::new(900, 700));
    app.show()?;
    let line = "one two three four";
    app.set_words_line(line.into());
    app.invoke_copy_words();
    assert_eq!(held.borrow().as_str(), line);
    app.invoke_clear_copied_words();
    assert_eq!(held.borrow().as_str(), " ", "the words are gone from the clipboard");
    // copied, then the owner copies something of their own: that stays
    app.invoke_copy_words();
    *held.borrow_mut() = "something else".into();
    app.invoke_clear_copied_words();
    assert_eq!(held.borrow().as_str(), "something else");
    // nothing copied: nothing is touched
    *held.borrow_mut() = "untouched".into();
    app.invoke_clear_copied_words();
    assert_eq!(held.borrow().as_str(), "untouched");
    // no words shown: nothing to copy
    app.set_words_line("".into());
    app.invoke_copy_words();
    app.invoke_clear_copied_words();
    assert_eq!(held.borrow().as_str(), "untouched");
    Ok(())
}
