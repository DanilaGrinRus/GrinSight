# Independent native oracle for Mainnet batch checkpoints

The reference path reads the public framed fixture from canonical Mainnet genesis and applies the native `GenesisVerifier` to each header. It independently constructs every byte of the batch journal, including work deltas in the newest-first difficulty window, the full tip header and the header-PMMR frontier. The compact reader uses only a previously authenticated point and the next raw header. It calls upstream Grin PoW and difficulty functions with the restored rolling state. The pinned-image receipt verifier must authenticate the point before the reader uses it. A peak commitment alone cannot authenticate the separate difficulty rows.

Run from `Source/chain/headers` on Windows:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'grin-batch-native-build'
cargo test --offline --locked --release --example batch-oracle
cargo build --offline --locked --release --example batch-oracle
$oracle = Join-Path $env:CARGO_TARGET_DIR 'release/examples/batch-oracle.exe'
$fixture = 'tests/mainnet/first-4100-headers.bin'
$batch = '../../research-batch-receipt'
foreach ($h in @(6, 8)) {
    python -B ../../tools-audit/batch-oracle-accept.py --oracle $oracle --fixture $fixture --image "$batch/image-id.hex" --height $h --point "$batch/testdata/h$h/checkpoint.bin"
    if ($LASTEXITCODE) { throw "Native comparison failed at height $h" }
}
```

To create an independent reference before the receipt exists, run `batch-oracle export PINNED_IMAGE_HEX FRAMED_FIXTURE HEIGHT NEW_FILE`. It refuses to overwrite a file. To reproduce continuation alone use `batch-oracle resume PINNED_IMAGE_HEX AUTHENTICATED_POINT NEXT_WIRE_HEADER`. The accompanying Python script starts a separate process for each continuation with only the point and next header in its directory. It compares the result with the next archived header's hash/work and the following header's previous root, then tests rejection of a skipped height.

| Height | Size | DAA rows | Peaks | SHA-256 of the native reference |
|---:|---:|---:|---:|---|
| 6 | 805 bytes | 7 | 3 | `d3c4281bb7e3befce393d1438c62d9d86fb5a1ca4a32fd12656d1df51f095fe2` |
| 8 | 815 bytes | 9 | 2 | `473267ad7ec512d760ec9c01c62efa33d5d13c8cbeeed5263ad38f6a93763156` |

These values use the program ID `788cf6e861d3f84aeae041abd472ff5ece0f0c3a9fabcd1e8c27a8aa55cdb290`. The resulting roots after H7 and H9 are `36dc063f1066cdfddd1d34072d4bb49841305d634b2a4431305290cd4021a57e` and `6f653a3297730745e4c67686084fd4619fdb51a63fa0ec8af2bd34212887841b`. They are also the commitments carried by H8 and H10 respectively.

Both genuine receipt journals in `testdata/h6` and `testdata/h8` matched every byte of the independently generated references. Both separate-process continuations passed with the supplied next header, and both skipped-height cases failed as required. The receipt SHA-256 values are `8e2ca95c21c3f3a61e5d1bc1a084d658631183002eaddffd7cc2867047f93d5f` for H6 and `8f4a797a23d9a5ca036b01faeb91e014636962c045c574084abff11e56dbe6af` for H8.

The Rust tests round-trip all 227 compact boundaries, H3 through H229 inclusive, against a continuous native replay. They check the first dropped DAA row at H61, rejection of damaged points and a wrong successor, the first primary C31 at H230 and the C29 following it. The native checker can validate that C31, but the batch guest covers only all-C29 history. After the last primary leaves the 61-row window at H330, the reference still refuses to export C29-only ancestry. None of these checks establishes that an old branch is the current best chain.
