//! The language setting is shared by Slint and messages from Rust.
use std::sync::atomic::{AtomicUsize, Ordering};

const CODES: [&str; 7] = ["en", "ru", "de", "fr", "zh", "ko", "ja"];
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
include!(concat!(env!("OUT_DIR"), "/messages.rs"));

pub(crate) fn known(code: &str) -> Option<&'static str> {
    CODES.iter().copied().find(|candidate| *candidate == code)
}

pub(crate) fn set(code: &str) {
    let index = CODES.iter().position(|candidate| *candidate == code).unwrap_or(0);
    ACTIVE.store(index, Ordering::Relaxed);
}

fn translate(index: usize, en: &'static str, ru: &'static str) -> &'static str {
    match index {
        0 => en,
        1 => ru,
        _ => MESSAGES.binary_search_by_key(&en, |(source, _)| *source).ok()
            .and_then(|row| MESSAGES.get(row))
            .and_then(|(_, variants)| variants.get(index.saturating_sub(2)))
            .copied().unwrap_or(en),
    }
}

pub(crate) fn tr(en: &'static str, ru: &'static str) -> &'static str {
    translate(ACTIVE.load(Ordering::Relaxed), en, ru)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognised_languages_have_wallet_messages() {
        assert_eq!(known("unknown"), None);
        for (i, code) in CODES.iter().enumerate() {
            assert_eq!(known(code), Some(*code));
            if i > 1 {
                assert_ne!(translate(i, "not set", "не задана"), "not set");
            }
        }
    }

    #[test]
    fn first_open_offers_languages_and_remembers_each_selection() -> Result<(), Box<dyn std::error::Error>> {
        // Slint's event loop and bundled translation are process-wide.
        const CHILD: &str = "GRINSIGHT_LANGUAGE_PICKER_TEST";
        if std::env::var_os(CHILD).is_none() {
            let run = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "language::tests::first_open_offers_languages_and_remembers_each_selection", "--nocapture"])
                .env(CHILD, "1").output()?;
            assert!(run.status.success() && String::from_utf8_lossy(&run.stdout).contains("1 passed"),
                "{} {}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr));
            return Ok(());
        }
        use crate::{App, Settings};
        use slint::ComponentHandle;
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let dir = std::env::temp_dir().join(format!("grinsight-lang-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let path = dir.join("ui.txt");
        let app = App::new()?;
        crate::wire_settings(&app, Some(path.clone()));
        assert!(app.global::<Settings>().get_choose_language());
        assert!(!path.exists());
        for code in CODES {
            let settings = app.global::<Settings>();
            settings.set_choose_language(true);
            settings.invoke_select_language(code.into());
            assert!(!settings.get_choose_language());
            assert_eq!(settings.get_language().as_str(), code);
            assert!(std::fs::read_to_string(&path)?.lines().any(|line| line == format!("lang={code}")));
            let reopened = App::new()?;
            crate::wire_settings(&reopened, Some(path.clone()));
            assert!(!reopened.global::<Settings>().get_choose_language());
            assert_eq!(reopened.global::<Settings>().get_language().as_str(), code);
        }
        std::fs::write(&path, "lang=ru\ntheme=honey\n")?;
        let old = App::new()?;
        crate::wire_settings(&old, Some(path.clone()));
        assert_eq!(old.global::<Settings>().get_language().as_str(), "ru");
        assert_eq!(old.global::<crate::Theme>().get_name(), crate::ThemeName::Honey);
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&dir)?;
        Ok(())
    }
}
