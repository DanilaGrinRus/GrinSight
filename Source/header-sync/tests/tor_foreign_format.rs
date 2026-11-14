//! Tor foreign API wire format against the real grin-wallet 5.5.1 code.
//!
//! `grinsight-tor` answers the foreign API with the JSON the GrinSight wallet
//! core produced. This test checks that this JSON is exactly the format
//! grin-wallet itself speaks:
//!
//! * the fixtures are the doctest request/answer bytes of grin-wallet 5.5.1
//!   (`api/src/foreign_rpc.rs`, commit f097811);
//! * the S2 / I3 answers parse as `grin_wallet_libwallet::VersionedSlate`
//!   (the vendored crate is the one `header-sync` already uses for the wallet);
//! * our own `slate_from_json` / `slate_to_json` read and write that same
//!   format (S1 in, S2 out, I2 in, I3 out), with the state and the fields kept.
//!
//! The `grinsight-tor` unit tests on their side assert that `handle_foreign`
//! returns exactly these expected JSON values, so the two halves meet.

use grin_wallet_libwallet::{Slate, SlateState, SlateVersion, VersionedSlate};
use serde_json::Value;

const GW: &str = include_str!("../../tor/grinsight-tor/tests/fixtures/grin_wallet_5_5_1_foreign.json");

fn fixture() -> Value {
    serde_json::from_str(GW).expect("fixture JSON")
}

fn as_slate(v: &Value) -> Slate {
    let versioned: VersionedSlate = serde_json::from_value(v.clone()).expect("VersionedSlate from grin-wallet JSON");
    Slate::upgrade(versioned).expect("V4 upgrade")
}

fn as_json(slate: &Slate) -> Value {
    let v = VersionedSlate::into_version(slate.clone(), SlateVersion::V4).expect("V4");
    serde_json::to_value(v).expect("JSON")
}

#[test]
fn grin_wallet_5_5_1_answers_parse_as_versioned_slate() {
    let f = fixture();
    let s2 = &f["blocks"]["receive_tx_response"]["result"]["Ok"];
    let i3 = &f["blocks"]["finalize_tx_response"]["result"]["Ok"];

    let s2_slate = as_slate(s2);
    assert_eq!(s2_slate.state, SlateState::Standard2);
    let i3_slate = as_slate(i3);
    assert_eq!(i3_slate.state, SlateState::Invoice3);
    // ... and our serializer writes exactly those states back.
    assert_eq!(as_json(&s2_slate)["sta"], "S2");
    assert_eq!(as_json(&i3_slate)["sta"], "I3");
}

#[test]
fn our_slate_json_io_speaks_the_grin_wallet_format() {
    let f = fixture();
    for (name, state) in [
        ("receive_tx_request", SlateState::Standard1),
        ("receive_tx_response", SlateState::Standard2),
        ("finalize_tx_request", SlateState::Invoice2),
        ("finalize_tx_response", SlateState::Invoice3),
    ] {
        let text = if name.ends_with("_request") && name != "check_version_request" {
            f["blocks"][name]["params"][0].to_string()
        } else {
            f["blocks"][name]["result"]["Ok"].to_string()
        };
        // grin-wallet's bytes -> our parser.
        let slate = grinsight_state::receive::slate_from_json(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(slate.state, state, "{name}");
        // our serializer -> VersionedSlate -> back.
        let out = grinsight_state::receive::slate_to_json(&slate).unwrap_or_else(|e| panic!("{name}: {e}"));
        let v: VersionedSlate = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{name}: {e}"));
        let back = Slate::upgrade(v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back.state, state, "{name}");
        assert_eq!(back.id, slate.id, "{name}");
        assert_eq!(back.offset, slate.offset, "{name}");
    }
    // The fields grin-wallet's S2 carries survive our JSON round trip.
    let s2 = &f["blocks"]["receive_tx_response"]["result"]["Ok"];
    let slate = grinsight_state::receive::slate_from_json(&s2.to_string()).unwrap();
    let out: Value = serde_json::from_str(&grinsight_state::receive::slate_to_json(&slate).unwrap()).unwrap();
    assert_eq!(out["sta"], "S2");
    assert_eq!(out["id"], s2["id"]);
    assert_eq!(out["off"], s2["off"]);
    assert_eq!(out["proof"]["rsig"], s2["proof"]["rsig"]);
    assert_eq!(out["sigs"][0]["part"], s2["sigs"][0]["part"]);
}
