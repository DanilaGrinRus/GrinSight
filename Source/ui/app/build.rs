//! Use the same PO catalogues for Slint widgets and runtime wallet messages.
use std::{collections::BTreeMap, env, error::Error, fmt::Write, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let config = slint_build::CompilerConfiguration::new()
        .with_bundled_translations("lang")
        .with_default_translation_context(slint_build::DefaultTranslationContext::None);
    if let Err(err) = slint_build::compile_with_config("ui/app.slint", config) {
        println!("cargo:warning=slint: {err}");
        std::process::exit(1);
    }
    println!("cargo:rerun-if-changed=lang");
    let mut table = BTreeMap::new();
    for language in ["de", "fr", "zh", "ko", "ja"] {
        let path = PathBuf::from("lang").join(language).join("LC_MESSAGES/fly-ui.po");
        let catalog = rspolib::pofile(path.as_path())?;
        for entry in catalog.entries {
            if entry.comment.as_deref() != Some("runtime") { continue; }
            let translated = entry.msgstr.ok_or("missing translation")?;
            if translated.is_empty() || translated.matches("{}").count() != entry.msgid.matches("{}").count() {
                return Err(format!("Invalid {language} translation for {}", entry.msgid).into());
            }
            table.entry(entry.msgid).or_insert_with(Vec::new).push(translated);
        }
    }
    if table.is_empty() { return Err("Missing runtime translations".into()); }
    let mut text = String::from("const MESSAGES: &[(&str, [&str; 5])] = &[\n");
    for (src, variants) in table {
        if variants.len() != 5 { return Err(format!("Incomplete translations for {src}").into()); }
        writeln!(text, "({src:?}, {variants:?}),")?;
    }
    text.push_str("];\n");
    fs::write(PathBuf::from(env::var_os("OUT_DIR").ok_or("missing output directory")?).join("messages.rs"), text)?;
    Ok(())
}
