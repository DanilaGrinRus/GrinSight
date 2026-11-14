# Build GrinSight web-core (Emscripten spike)

This is the first browser-core spike, not the final wallet API.

It proves that the same Rust verification/key code that runs natively can be
compiled for WebAssembly with the existing C dependencies:

- `croaring-sys` (PMMR / Cuckoo bitmaps);
- `grin_secp256k1zkp` (keys, commitments, signatures);
- **no LMDB / store**: the `web` feature of `grinsight-state`/libwallet removes
  `grin_store`, `heed` and `lmdb-master-sys` from the browser dependency graph.

## Prerequisites

- Emscripten SDK (`emsdk install latest && emsdk activate latest`).
- Rust target: `rustup target add wasm32-unknown-emscripten`.
- Emscripten's `emcc` must be used for C objects. `-fPIC` is required because
  the Rust target emits an Emscripten side module.

## Build

```powershell
$env:EMSDK = 'C:\DHW\.toolchain\emsdk'
& "$env:EMSDK\emsdk_env.ps1"
rustup target add wasm32-unknown-emscripten
.\build_wasm.ps1
```

Output: `target\wasm32-unknown-emscripten\release\grinsight_web_core.wasm`.

## ABI

Raw C ABI, 32-bit pointers, no `wasm-bindgen` yet:

| Export | Meaning |
|---|---|
| `gs_abi_version() -> i32` | ABI version (`1`) |
| `gs_header_hash(out, cap) -> i32` | Blake2b hash of the test genesis header into `out`; returns 32 |
| `gs_test_address(out, cap) -> i32` | Floonet slatepack address for a fixed test seed; returns its byte length |
| `gs_copy(src, len, out, cap) -> i32` | copy helper for JS tests |

The Wasm module is currently an Emscripten **side module** (imports memory,
table, pthread/libc symbols). The browser graph has no LMDB/store. It needs a generated Emscripten JS runtime (or a
different target) before the Flutter web client can load it. This is the next
integration task, not a finished browser bundle.

### Executed Wasm vector (2026-11-12)

A C harness links the Rust staticlib with `emcc` and calls the same exports:

```powershell
emcc test\harness.c target\wasm32-unknown-emscripten\release\libgrinsight_web_core.a `
  -O0 -g -o test\harness-debug.js `
  -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=16777216 -sINITIAL_MEMORY=67108864 `
  -sEXIT_RUNTIME=1 -sNODERAWFS=1
node test\harness-debug.js
```

The executed Wasm result matches native exactly. The `web` feature build has **0**
`grin_store`/`heed`/`lmdb` entries in `cargo tree`; native default tests still pass:
`77 passed / 2 ignored` in both modes. `grinsight-state` has a local bitmap
accumulator for the web build, while the native build keeps `grin_chain`.

```
ABI=1
HEADER_HASH_LEN=32
HEADER_HASH=2d71d7996a0cf2eda1c357eb11e713e1ef7930de5d293a839c4e4d40e37d3e1d
ADDRESS_LEN=64
ADDRESS=tgrin1c2cdgqt0z0gcfxapxmt8xq25v8v2upynsn67gafvpkjmlzvqxrwqdwrqpa
```

`-O2` with the default stack hit `memory access out of bounds`; 16 MiB stack /
64 MiB initial memory made the vector deterministic. That is a real iPhone
memory/layout constraint to profile before the full core is loaded.

## Native reference vectors

`cargo test --offline -- --nocapture` prints:

```
HEADER_HASH=2d71d7996a0cf2eda1c357eb11e713e1ef7930de5d293a839c4e4d40e37d3e1d
ADDRESS=tgrin1c2cdgqt0z0gcfxapxmt8xq25v8v2upynsn67gafvpkjmlzvqxrwqdwrqpa
```

These vectors must match the Wasm exports before any wallet state is trusted.



## Browser module (executed)

`build_browser.ps1` links the same Rust staticlib into an Emscripten ES module
(`browser/grinsight_core.js` + `.wasm`, ~284 KB). The JS wrapper
`browser/grinsight_api.mjs` calls the ABI; Node executed it and printed the same
header/address vectors. This removes the C-harness dependency for integration.

Still required: Worker load in Flutter Web, `Storage`/`Transport`, full
PIBD/UTXO/sign vector.

## S1 signing: PASS in native and Wasm

`gs_test_s1` builds a real S1 from fixed test key material through
`grinsight_state::receive::build_send`: commitment, input, signing context,
slatepack armor. Wasm execution:

```text
S1_LEN=2055
S1_PREFIX=BEGINSLATEPACK.
```

The length varies slightly because slatepack armor is randomized; success,
prefix and a length in the expected range are checked. This required patching
the vendored `getrandom`/`rand_os`/`rand 0.5` Emscripten entropy path to use
Emscripten's `getentropy` (WASI `random_get`, backed by browser
`crypto.getRandomValues` / Node `crypto.randomBytes`). No deterministic or
insecure RNG is used in the browser path.

Current artifacts:

- `grinsight_web_core.wasm` — 868 604 bytes, SHA-256
  `4AF1F750649706C469D9F293A96DFDC4961F3C1520FE2BD5A1A413037E26F8C5`
- browser `grinsight_core.wasm` — 846 507 bytes, SHA-256
  `000A090F16594EAD14C05C185FF5720C0421B3D8075E274C8CE458130D4C8282`

Still not a wallet API: Storage/Transport, sync, worker and gateway are next.


## Header checkpoint (Floonet): PASS in Wasm

`gs_checkpoint_height` parses and verifies the shipped **Floonet** checkpoint via
`load_checkpoint_text` (no filesystem): header bytes/hash/height, peaks, root,
leaves/size, PoW. Result:

```text
CHECKPOINT_HEIGHT=4095360
```

Updated artifacts:

- core `grinsight_web_core.wasm` — 1 383 850 bytes, SHA-256
  `2028178BF8BDCBFABB18D3C47A09B7D85EF04AF3A44DEF2A4E0B3F91D15BA4E1`
- browser `grinsight_core.wasm` — 1 284 546 bytes, SHA-256
  `EFF426EC4F0C13E5399B3C05CBC3E84E18C2AE07613F3E5C9211C0A7ABD012B5`
- PWA `core/grinsight_core.wasm` — same hash.

This checks the checkpoint, not a live header chain yet; P2P/Transport and
Storage are still missing.


## Storage boundary

`grinsight-state::storage::Storage` is now the core storage contract:
`get/put/remove/list_prefix`, keys validated against traversal. `MemoryStorage`
is used by tests and by the Wasm checkpoint vector; `FileStorage` remains for
native only. `headers::load_checkpoint_storage`,
`write_checkpoint_storage` and `read_state_headers_storage` use it. The Wasm
checkpoint test goes through `MemoryStorage`, so the browser path no longer
needs a filesystem abstraction for this step.


## Recent header history: PASS in Wasm

`gs_restore_recent` loads the checkpoint through `MemoryStorage`, parses the
shipped `release/recent-headers.bin`, and calls `Verifier::restore_recent`
(linkage, timestamps, total difficulty, PoW, WTEMA difficulty chain ending at
the checkpoint). Wasm result:

```text
CHECKPOINT_HEIGHT=3318854
RECENT_HEADERS=62
```

This is still a shipped checkpoint + history vector, not a live P2P chain.


## Host storage bridge (localStorage)

`gs_storage_selftest` uses the `Storage` trait backed by Emscripten `EM_JS` and
browser `localStorage`. Executed result:

```text
STORAGE={"ok":true,"value":"storage-ok"}
```

This is a small-value adapter (checkpoint/selftest), not the 670 MB state store.
`localStorage` is **not available in Web Workers**; the real worker path needs
IndexedDB/OPFS. No keys or seed material is written by this test.


## Floonet correction (2026-11-12)

The earlier `release/checkpoint.rwm` was **MAINNET** (`height=4095360`),
despite the WebApp targeting Floonet. The browser core and PWA now use
`checkpoints/floonet/checkpoint.rwm` + `recent-headers.bin`
(`CHECKPOINT_HEIGHT=3318854`, `RECENT_HEADERS=62`). The mainnet file is no
longer used by the WebApp.


## Live Floonet header verification

`gs_verify_headers` takes the `recent-headers.bin`-shaped packet of raw headers
from the gateway, restores the Floonet checkpoint's recent history, and calls
`Verifier::validate_and_append`. Live result:

```text
LIVE_HEADERS_WASM_VERIFY=PASS tip=3318859
```

The gateway only transports bytes; the Wasm core does the PoW/linkage/difficulty
check. This is the first end-to-end Floonet header path, still limited to a local
peer and 5 headers.


## Full live Floonet chain: PASS in Wasm

Stateful ABI: `gs_chain_start` (Floonet checkpoint 3318854) → repeated
`gs_chain_append(batch)` → `gs_chain_tip`. Gateway pagination uses the last
header hash as locator. Executed against a local Floonet node:

```text
LIVE_CHAIN_WASM_VERIFY=PASS start=3318854 tip=3333291 batches=29
```

14k+ headers verified (PoW, linkage, difficulty) by the Wasm core, not the
gateway. This is still local-peer data; public peers and PIBD/UTXO are next.


## PIBD -> UTXO fixture: PASS in Wasm

`gs_utxo_fixture` parses an embedded PIBD archive fixture: archive header,
`BitmapSegment` wire, output segments; it calls `OutputState::from_segments`
(bitmap/output root checks) and returns the UTXO count.

```text
UTXO_FIXTURE=2251
```

This fixture is **synthetic testnet**, not live Floonet. It proves the
bitmap/output/UTXO path in the browser core; live PIBD segment transport is the
next step. The fixture is a public test vector, not wallet/user data.


## Verified header lookup

`gs_chain_header(height)` returns a raw header only after it was appended to the
stateful verifier. Full live chain run retrieved the archive header 3332880
(415 bytes); the PIBD archive was targeted for the next step.
