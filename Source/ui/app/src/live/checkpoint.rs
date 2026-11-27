//! Select or save one public checkpoint with a native Windows dialog. Keep the picker
//! separate from the host request: a lock ends the UI session while a picker
//! is open, just as it does while waiting for any other callback.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action { Import = 1, Export = 2 }

#[cfg(windows)]
fn pick(action: Action) -> Result<Option<String>, ()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let system = std::env::var_os("SystemRoot").ok_or(())?;
    let shell = Path::new(&system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    // The command is fixed. The filename is returned as JSON data, never
    // interpolated into a command. Hide the console, not the file dialogs.
    let output = Command::new(shell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command",
            include_str!("pick-checkpoint.ps1")])
        .env("GRINSIGHT_CHECKPOINT_ACTION", if action == Action::Export { "save" } else { "open" })
        .env("GRINSIGHT_POINT_TITLE", match action {
            Action::Import => tr("Select a .gshp file or checkpoint.json", "Выберите файл .gshp или checkpoint.json"),
            Action::Export => tr("Save checkpoint to a new .gshp file", "Сохранить точку в новый файл .gshp"),
        })
        .creation_flags(0x08000000)
        .output().map_err(|_| ())?;
    if !output.status.success() { return Err(()); }
    serde_json::from_slice(&output.stdout).map_err(|_| ())
}

fn receipt(value: &Value) -> Option<(u64, u64)> {
    if value.get("imported")?.as_bool()? && value.get("locked")?.as_bool()? {
        let hash = value.get("hash")?.as_str()?;
        let samples = value.get("samples")?.as_u64()?;
        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && samples > 0 {
            return Some((value.get("height")?.as_u64()?, samples));
        }
    }
    None
}

#[cfg(windows)]
fn finish(app: &App, out: Result<Value, CallError>) {
    app.set_checkpoint_file_action(0);
    if let Some((height, samples)) = out.as_ref().ok().and_then(receipt) {
        app.invoke_leave();
        app.set_login_note(fill(tr(
            "Checkpoint saved at block {}. GSHP1 samples verified: {}. Unlock to continue.",
            "Сохранена точка на блоке {}. Проверено образцов GSHP1: {}. Войдите для продолжения."
        ), &[&height.to_string(), &samples.to_string()]).into());
        return;
    }
    match out {
        Err(CallError::Rpc { name, .. }) if name == "checkpoint_import_refused_locked" => {
            app.invoke_leave();
            app.set_login_error(tr("Import refused. Check the checkpoint file, wallet network and current starting point, then unlock to try again.",
                "Импорт отклонён. Проверьте файл точки, сеть кошелька и текущую стартовую точку. Для повтора войдите снова.").into());
        }
        Err(CallError::Rpc { .. }) => app.set_bootstrap_feedback(tr(
            "Import refused. Check the checkpoint file and the open profile.",
            "Импорт отклонён. Проверьте файл точки и открытый профиль.").into()),
        _ => {
            // A lost or malformed reply can arrive after installation and lock.
            app.invoke_leave();
            app.set_login_error(tr("Import outcome unknown. Unlock and check the starting point in Details.",
                "Результат импорта неизвестен. Войдите и проверьте стартовую точку в разделе «Подробнее».").into());
        }
    }
}

fn export_message(out: Result<Value, CallError>) -> String {
    match out {
        Ok(v) => {
            if v.get("exported").and_then(Value::as_bool) == Some(true) {
                if let Some(height) = v.get("height").and_then(Value::as_u64) {
                    return fill(tr("Checkpoint for block {} saved.", "Файл точки для блока {} сохранён."), &[&height.to_string()]);
                }
            }
            tr("Could not confirm the export. Check the chosen folder.", "Не удалось подтвердить экспорт. Проверьте выбранную папку.").into()
        }
        Err(CallError::Rpc { name, .. }) if name == "checkpoint_export_unavailable" =>
            tr("This profile has no checkpoint ready to export. Import one or finish a check from the first block.",
                "В этом профиле пока нет точки для экспорта. Импортируйте её или завершите проверку от первого блока.").into(),
        Err(CallError::Rpc { name, .. }) if name == "checkpoint_export_refused" =>
            tr("Could not create the file. Choose a new filename in a writable folder.",
                "Не удалось создать файл. Выберите новое имя в доступной для записи папке.").into(),
        _ => tr("Could not confirm the export. Check the chosen folder.", "Не удалось подтвердить экспорт. Проверьте выбранную папку.").into(),
    }
}

#[cfg(windows)]
fn select(app: &App, action: Action) {
    if app.get_page() == 0 || app.get_sheet() != 16 || app.get_busy() ||
        app.get_checkpoint_file_action() != 0 || app.get_bootstrap_submitting() || app.get_search_submitting() { return; }
    app.set_checkpoint_file_action(action as i32);
    app.set_bootstrap_feedback(SharedString::new());
    spawn(app, move || pick(action), move |app, picked| {
        if app.get_sheet() != 16 { app.set_checkpoint_file_action(0); return; }
        let path = match picked {
            Ok(Some(path)) => path,
            Ok(None) => { app.set_checkpoint_file_action(0); return; }
            Err(()) => {
                app.set_checkpoint_file_action(0);
                app.set_bootstrap_feedback(tr("The Windows file dialog could not open. Try again.",
                    "Не удалось открыть окно выбора файла Windows. Попробуйте ещё раз.").into());
                return;
            }
        };
        let Some(host) = client() else {
            app.set_checkpoint_file_action(0);
            app.set_bootstrap_feedback(tr("Wallet service is unavailable.", "Служба кошелька недоступна.").into());
            return;
        };
        let params = json!({"file_path":path});
        match action {
            Action::Import => spawn(app, move || host.call("host.import_checkpoint", params, SLOW), finish),
            Action::Export => spawn(app, move || host.call("host.export_checkpoint", params, SLOW), |app, result| {
                app.set_checkpoint_file_action(0);
                app.set_bootstrap_feedback(export_message(result).into());
            }),
        }
    });
}

pub(super) fn wire(app: &App) {
    app.set_import_available(cfg!(windows));
    #[cfg(windows)] {
        let weak = app.as_weak();
        app.on_import_checkpoint(move || { if let Some(app) = weak.upgrade() { select(&app, Action::Import); } });
        let weak = app.as_weak();
        app.on_save_checkpoint(move || { if let Some(app) = weak.upgrade() { select(&app, Action::Export); } });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_feedback_requires_a_saved_height_and_explains_refusals() {
        let saved = export_message(Ok(json!({"exported":true,"height":4122000})));
        assert!(saved.contains("4122000"));
        assert_ne!(saved, export_message(Ok(json!({"exported":true}))));
        let error = |name:&str| Err(CallError::Rpc {code:-1, name:name.into(),message:String::new()});
        assert_ne!(export_message(error("checkpoint_export_refused")), export_message(error("checkpoint_export_unavailable")));
    }
    #[test]
    fn only_a_verified_and_locked_import_receipt_can_report_success() {
        let good = json!({"imported":true,"locked":true,"height":4122000,"hash":"7".repeat(64),"samples":420});
        assert_eq!(receipt(&good), Some((4122000,420)));
        for (field, invalid) in [("imported", json!(false)), ("locked", json!(false)),
            ("height", json!("4122000")), ("hash", json!("123")), ("samples", json!(0))] {
            let mut bad = good.clone();
            bad[field] = invalid;
            assert_eq!(receipt(&bad), None);
        }
    }

    #[test]
    #[cfg(windows)]
    fn import_distinguishes_a_refusal_after_lock_from_a_completed_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
        let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
            slint::platform::software_renderer::RepaintBufferType::NewBuffer,
        );
        slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
        let app = App::new()?;
        let locks = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = locks.clone();
        app.on_leave(move || observed.set(observed.get() + 1));
        finish(&app, Err(CallError::Rpc {code:-1, name:"invalid_params".into(),message:String::new()}));
        assert_eq!(locks.get(),0);
        assert!(!app.get_bootstrap_feedback().is_empty());
        finish(&app, Err(CallError::Rpc {code:-1, name:"checkpoint_import_refused_locked".into(),message:String::new()}));
        assert_eq!(locks.get(),1);
        assert!(!app.get_login_error().is_empty());
        assert!(app.get_login_note().is_empty());
        finish(&app, Ok(json!({"imported":true,"locked":true,"height":4122000,"hash":"7".repeat(64),"samples":420})));
        assert_eq!(locks.get(),2);
        assert!(app.get_login_note().contains("4122000") && app.get_login_note().contains("420"));
        Ok(())
    }
}
