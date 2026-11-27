# Native reference for the first two linked Mainnet header statements

The oracle uses the wallet's native `GenesisVerifier`, Grin 5.5.2 PoW and upstream difficulty adjustment. It shares no receipt or guest code. Its `export` mode reads the public fixture through H3, checks its exact genesis against the compiled Mainnet genesis, and exports two files into a new directory. Its `resume` mode reads a 1,104-byte H2 checkpoint and one 400-byte successor. It replays the two embedded headers against the compiled genesis, compares the entire reconstructed checkpoint, then checks H3. This replay is possible specifically because H2 includes the H1 journal. A general resume from an arbitrary height needs a bounded rolling consensus state.

From the worktree root in PowerShell:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'grin-linked-native-build'
cargo build --manifest-path Source/chain/headers/Cargo.toml --locked --offline --release --example linked-oracle
$oracle = Join-Path $env:CARGO_TARGET_DIR 'release/examples/linked-oracle.exe'
$fixture = 'Source/chain/headers/tests/mainnet/first-4100-headers.bin'
python -B Source/tools-audit/linked-oracle-accept.py --oracle $oracle --fixture $fixture
```

To compare a verified receipt's full journal, add `--guest-point PATH_TO_CHECKPOINT_BIN`. Use the separate receipt verifier to authenticate the receipt itself. Each continuation or rejection case launches the native executable in a fresh process with only the point and next header in its working directory. The oracle never opens a network connection.

| Mainnet height | Timestamp | Total work | Required work increment | Achieved PoW | C29 scaling | Header PMMR size |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1547573885 | 34359738368 | 17179869184 | 41268913667 | 1840 | 3 |
| 2 | 1547573937 | 42949672960 | 8589934592 | 91637840336 | 1840 | 4 |
| 3 | 1547574887 | 48916910435 | 5967237475 | 14671771345 | 1839 | 7 |

At H2 the two available difficulty rows are genesis and H1. Grin pads the 61-row window with 59 entries using the 5,799-second interval, including genesis work in the sum. The clamped span is 7,200 seconds. The two peaks after H2 are `d3cf8afdf907266d022e0c3b035c3fc74fa941e5b3ccc4e2e1ea978333d004d5` and `77859a5798cb4bde54cd81bb223a6eb658edffdda623b01a966d91a206014e9d`. Bagging at size 4 gives `d2cc273a5ef57cb0a5f2a2e22683465503d644996a17b05e1813643c516fb2df`, the previous root carried by H3.

The full native H2 checkpoint SHA-256 is `9cff59d82d292efbf3d312261226c0bac565040d4d555457165d3d04cc26b92d`. The checked H3 hash is `0000021a57cc6ad5fce868b9cc12e196faa0b235691681069c7c6ac7fad69949` and the resulting root is `f86f12725fe8a31585161ca9b934c6b0e8dcc0875904e85d850467256272a81b`.

The offline suite accepts the canonical continuation and rejects 15 changes covering the H2 network, difficulty, root, both peaks, H1 timestamp and root; H3 predecessor, previous root, work, scaling and PoW; a repeated H2; trailing point bytes and a truncated successor. These are historical header checks. The suite makes no freshness, block-body or wallet-balance determination.

The run with `--guest-point Source/research-linked-receipt/testdata/checkpoint.bin` passed all 17 checks against the linked receipt with SHA-256 `513de59d6e228977419f5c77001e081982a57c0316d286461d8609cc5ebe4bbc`. All 1,104 public journal bytes matched the native reference. The next header used to exercise the continuation had SHA-256 `68e251a15c328157f072156d55394cfcdaf8fe3c6ca0baf8a2d12ba155589f31`. An additional check of the archived H4 header found the same root in its `prev_root` field as the native result at H3.
