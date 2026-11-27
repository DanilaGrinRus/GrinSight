use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../chain/headers/points")
        .join(name)
}
fn run(command: &str, net: &str, args: &[&Path]) -> bool {
    Command::new(env!("CARGO_BIN_EXE_grin-proof-provider"))
        .args([command, net])
        .args(args)
        .output()
        .expect("launch provider")
        .status
        .success()
}

#[test]
fn imports_the_real_pair_preserves_the_previous_publication_and_rejects_mismatches() {
    let test = tempfile::tempdir().unwrap();
    let out = test.path().join("publication");
    let point = fixture("main.json");
    let history = fixture("main.history");
    assert!(run("bundle", "main", &[&point, &history, &out]));
    assert!(run("check", "main", &[&out]));
    assert!(!run("check", "test", &[&out]));
    let manifest = out.join("manifest.json");
    let good = fs::read(&manifest).unwrap();
    assert!(run("bundle", "main", &[&point, &history, &out]));
    assert_eq!(good, fs::read(&manifest).unwrap());
    assert_eq!(1, fs::read_dir(out.join("objects")).unwrap().count());

    let incomplete = test.path().join("truncated.proof");
    fs::write(&incomplete, b"GSHP1").unwrap();
    assert!(!run("bundle", "main", &[&point, &incomplete, &out]));
    assert!(!run(
        "bundle",
        "main",
        &[&fixture("mainnet-4110480.json"), &history, &out]
    ));
    assert_eq!(good, fs::read(&manifest).unwrap());

    let mut changed: Value = serde_json::from_slice(&good).unwrap();
    changed["total_work"] = 0.into();
    fs::write(&manifest, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(!run("check", "main", &[&out]));
    changed["method"] = "Verified".into();
    fs::write(&manifest, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(!run("check", "main", &[&out]));

    fs::write(&manifest, &good).unwrap();
    let object = fs::read_dir(out.join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(object.join("history.proof"), b"x").unwrap();
    assert!(!run("check", "main", &[&out]));
    fs::write(&manifest, vec![b' '; 4097]).unwrap();
    assert!(!run("check", "main", &[&out]));
}

#[test]
fn corrupt_source_cannot_publish() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("broken.bin");
    fs::write(&input, [0, 3, 0, 1]).unwrap();
    let out = dir.path().join("public");
    let result = Command::new(env!("CARGO_BIN_EXE_grin-proof-provider"))
        .args(["generate", "main"])
        .arg(&input)
        .arg("300")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!out.join("manifest.json").exists());
}
