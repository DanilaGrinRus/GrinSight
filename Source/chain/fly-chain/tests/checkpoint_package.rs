//! Boundaries and backwards compatibility of the portable checkpoint format.
#![cfg(feature = "history-proof")]
use fly_chain::{check_exported_pair, import_checkpoint_file, pack_checkpoint, pack_profile_checkpoint};
use fly_chain_headers::{checkpoint::MAX_RECORD_LEN, proof, Net};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn single_file_replaces_renaming_and_preserves_the_original_payloads() {
    let files = tempdir().unwrap();
    let target = tempdir().unwrap();
    let point = files.path().join("checkpoint.json");
    let history = files.path().join("history.proof");
    let bundle = files.path().join("Mainnet export.gshp");
    fs::write(&point, fly_chain_headers::baked_point(Net::Main).unwrap().record).unwrap();
    fs::write(&history, proof::baked_history(Net::Main).unwrap()).unwrap();
    assert_eq!(pack_profile_checkpoint(Net::Main, target.path(), &bundle).unwrap(), None);
    let verified = pack_checkpoint(Net::Main, &point, &history, &bundle).unwrap();
    assert_eq!(check_exported_pair(Net::Main, &bundle).unwrap(), verified);
    assert_eq!(check_exported_pair(Net::Main, &point).unwrap(), verified);
    assert!(check_exported_pair(Net::Test, &bundle).is_err());
    let original = fs::read(&bundle).unwrap();
    assert!(pack_checkpoint(Net::Main, &point, &history, &bundle).is_err());
    assert_eq!(fs::read(&bundle).unwrap(), original);
    let legacy = tempdir().unwrap();
    assert_eq!(import_checkpoint_file(Net::Main, legacy.path(), &point).unwrap(), verified);
    fs::remove_file(&history).unwrap();
    assert!(import_checkpoint_file(Net::Main, target.path(), &point).is_err());
    fs::remove_file(&point).unwrap();
    assert_eq!(import_checkpoint_file(Net::Main, target.path(), &bundle).unwrap(), verified);
    let second_copy = files.path().join("from-recipient.gshp");
    assert_eq!(pack_profile_checkpoint(Net::Main, target.path(), &second_copy).unwrap(), Some(verified));
    assert_eq!(fs::read(second_copy).unwrap(), original);
    assert!(pack_profile_checkpoint(Net::Main, target.path(), &target.path().join("inside.gshp")).is_err());
    let damaged = files.path().join("damaged.gshp");
    let mut wrong = original;
    *wrong.last_mut().unwrap() ^= 1;
    fs::write(&damaged, wrong).unwrap();
    assert!(import_checkpoint_file(Net::Main, target.path(), &damaged).is_err());
    assert_eq!(import_checkpoint_file(Net::Main, target.path(), &bundle).unwrap(), verified);
}

#[test]
fn malformed_packages_cannot_install_a_point() {
    let files = tempdir().unwrap();
    let target = tempdir().unwrap();
    let bad = files.path().join("bad.gshp");
    for (magic, point_len, proof_len, total_payload) in [
        (b"GSHPACK2", 1, 1, 2),
        (b"GSHPACK1", 0, 1, 1),
        (b"GSHPACK1", 1, 0, 1),
        (b"GSHPACK1", u32::MAX, u32::MAX, 0),
        (b"GSHPACK1", MAX_RECORD_LEN as u32 + 1, 1, 0),
        (b"GSHPACK1", 1, proof::MAX_PROOF as u32 + 1, 0),
        (b"GSHPACK1", 1, 1, 1),
        (b"GSHPACK1", 1, 1, 3),
    ] {
        let mut file = fs::File::create(&bad).unwrap();
        file.write_all(magic).unwrap();
        file.write_all(&point_len.to_be_bytes()).unwrap();
        file.write_all(&proof_len.to_be_bytes()).unwrap();
        file.write_all(&vec![0; total_payload]).unwrap();
        drop(file);
        assert!(import_checkpoint_file(Net::Main, target.path(), &bad).is_err());
    }
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
}
