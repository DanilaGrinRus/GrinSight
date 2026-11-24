//! The program as a product is built: without the test network.
#![cfg(not(feature = "test-net"))]
use std::process::Command;

const FLY: &str = env!("CARGO_BIN_EXE_fly-chain");

/// The network of automated tests, with its tiny proofs of work and its
/// starting point read from a file, is not in the product.
#[test]
fn the_product_does_not_serve_the_test_network() {
    let dir = std::env::temp_dir().join(format!("fly-chain-product-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("start.json"), b"{}").unwrap();
    let out = Command::new(FLY)
        .args(["headers", "--network", "automated", "--seconds", "2", "--data"])
        .arg(&dir)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "fly-chain: the network of automated tests is not served by this program"
    );
    assert!(out.stdout.is_empty());
}

/// The real networks start from the point compiled in, which this build
/// has as a release point (ed. 0.35: Mainnet 4 115 520, Testnet 3 345 840),
/// unless the user left a point of their own
/// in the data directory; one that does not pass its check stops the
/// program instead of being passed over.
#[test]
fn the_point_of_a_real_network() {
    use fly_chain::{starting_point, PointKind, OWN_POINT_FILE};
    use fly_chain_headers::{baked_point, Net};
    let dir = std::env::temp_dir().join(format!("fly-chain-point-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for net in [Net::Main, Net::Test] {
        let point = starting_point(net, &dir).unwrap();
        assert_eq!(point.kind, PointKind::Release);
        assert!(!point.kind.provisional());
        assert_eq!(point.record, baked_point(net).unwrap().record);
    }
    // the user's point: the Mainnet record, for Mainnet
    let main = baked_point(Net::Main).unwrap().record;
    std::fs::write(dir.join(OWN_POINT_FILE), main).unwrap();
    let point = starting_point(Net::Main, &dir).unwrap();
    assert_eq!((point.kind, point.record.as_slice()), (PointKind::Own, main));
    assert!(!point.kind.provisional());
    assert_eq!(starting_point(Net::Test, &dir).err().as_deref(), Some("your own starting point is for another network"));
    let mut long = main.to_vec();
    long.resize(fly_chain_headers::checkpoint::MAX_RECORD_LEN + 1, b' ');
    std::fs::write(dir.join(OWN_POINT_FILE), long).unwrap();
    assert_eq!(starting_point(Net::Main, &dir).err().as_deref(), Some("your own starting point does not pass its check"));
    // the network of automated tests is not served, own point or not
    assert_eq!(
        starting_point(Net::Automated, &dir).err().as_deref(),
        Some("the network of automated tests is not served by this program")
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!PointKind::Release.provisional());
    assert!(PointKind::Release.note().starts_with("release starting point"));
}
