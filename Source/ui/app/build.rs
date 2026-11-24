//! Compiles the .slint files into Rust. The screens are written in English;
//! the Russian text is bundled from lang/ru/LC_MESSAGES/fly-ui.po and chosen
//! at run time (the language button, saved with the settings).
fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_bundled_translations("lang")
        .with_default_translation_context(slint_build::DefaultTranslationContext::None);
    if let Err(err) = slint_build::compile_with_config("ui/app.slint", config) {
        println!("cargo:warning=slint: {err}");
        std::process::exit(1);
    }
    println!("cargo:rerun-if-changed=lang");
}
