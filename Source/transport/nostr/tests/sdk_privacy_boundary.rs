//! Source-bound regression guard for the local SDK fork, not a whole-app log audit.
use std::{fs, path::Path};

fn inspect(dir: &Path, sites: &mut usize) {
    for entry in fs::read_dir(dir).expect("SDK source is available") {
        let entry = entry.expect("SDK entry");
        let kind = entry.file_type().expect("SDK entry type");
        assert!(!kind.is_symlink(), "SDK source must not contain links");
        if kind.is_dir() {
            inspect(&entry.path(), sites);
        } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let source = fs::read_to_string(entry.path()).expect("SDK Rust source");
            for forbidden in ["tracing::", "log::", "#[instrument", "#[tracing"] {
                assert!(!source.contains(forbidden), "unreviewed SDK logging path: {forbidden}");
            }
            *sites += source.matches("crate::fly_private_log!").count();
        }
    }
}

#[test]
fn pinned_sdk_forks_have_no_upstream_tracing_calls() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for (dir, expected) in [("nostr-relay-pool-0.44.3-privacy", 49), ("nostr-sdk-0.44.1-privacy", 10)] {
        let root = repo.join("vendor").join(dir).join("src");
        let lib = fs::read_to_string(root.join("lib.rs")).unwrap();
        assert!(lib.contains("macro_rules! fly_private_log { ($($arg:tt)*) => {{}}; }"));
        let mut sites = 0;
        inspect(&root, &mut sites);
        assert_eq!(sites, expected, "SDK fork changed; review privacy boundary");
    }
}
