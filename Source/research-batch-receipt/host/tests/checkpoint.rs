use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata")
}

fn verify(network: &str, point: &Path, proof: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_research-grin-batch-receipt"))
        .arg("verify")
        .arg(network)
        .arg(point)
        .arg(proof)
        .output()
        .unwrap()
}

#[test]
fn both_recursive_checkpoints_verify_with_only_their_own_two_files() {
    for height in ["h6", "h8"] {
        let dir = root().join(height);
        let result = verify(
            "main",
            &dir.join("checkpoint.bin"),
            &dir.join("history.receipt"),
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn verifier_checks_image_binding_network_and_the_exact_recursive_point() {
    let h6 = root().join("h6");
    let h8 = root().join("h8");
    let point = h6.join("checkpoint.bin");
    let proof = h6.join("history.receipt");
    assert!(!verify("test", &point, &proof).status.success());
    assert!(!verify("main", &point, &h8.join("history.receipt"))
        .status
        .success());
    let mut changed = fs::read(&point).unwrap();
    changed[8] ^= 1;
    let dir = std::env::temp_dir().join(format!("grin-batch-checkpoint-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let changed_file = dir.join("point.bin");
    fs::write(&changed_file, changed).unwrap();
    let result = verify("main", &changed_file, &proof);
    fs::remove_file(changed_file).unwrap();
    fs::remove_dir(dir).unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("checkpoint names another program"));
}
