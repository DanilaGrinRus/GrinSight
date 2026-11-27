# Mainnet genesis to height one, offline receipt

This research CLI proves a single Grin Mainnet header transition in RISC Zero 3.1.0. It accepts a publicly witnessed first successor of the exact shipped Mainnet genesis. The receiver needs the verifier binary and two small files. It reads no historical header dump, wallet state or network service.

## Relation and limits

The guest embeds the exact 400-byte genesis header. Its BLAKE2b serialization, header hash, indexed leaf and epoch constants follow Grin. For its 400-byte successor the guest checks height 1, v1, parent hash and header PMMR root, increasing timestamp within January 2019, zero cumulative offset, sizes of three positions each in the output and kernel PMMRs, and HF1 secondary C29 proof. It decodes 42 canonical strictly increasing nonces, computes Grin's Cuckaroo v1 endpoints with the vendored Grin SipHash, verifies a single 42-edge cycle, checks first-window DMA difficulty, secondary scaling and attained work. It derives the child hash and the two-leaf header PMMR root. The guest contains no expected hash or packed proof of block one.

This is a deliberately restricted subset of valid first successors. Genesis PoW, bodies, transactions, UTXOs, balance, arbitrary heights, forks after height one and later hard forks are outside the proved statement. Genesis is the public network definition. The statement confers no freshness or best-chain status. The research point is unsuitable as a wallet startup checkpoint. The public journal exposes the complete header. On this one-block example the proof is larger than the original witness. Neither full-history compactness nor production proof generation time has been measured.

## Build and reproduce

The Debian environment needs the RISC Zero Rust toolchain (`rustc +risc0`), the 3.1.0 `r0vm` and the locked Cargo dependencies in its offline registry. The build uses the sibling vendored Grin `core/src/pow/siphash.rs`. The measured guest compiler was `rustc 1.97.0-dev (e638c6cfe 2026-07-15)`. The supplied image ID identifies the exact measured guest build.

```sh
bash build.sh
tool=/var/tmp/grinsight-genesis-receipt/host/release/research-grin-receipt
"$tool" prove ../chain/headers/tests/mainnet/first-4100-headers.bin /tmp/unused-genesis-result
"$tool" verify main /tmp/unused-genesis-result/checkpoint.bin /tmp/unused-genesis-result/history.receipt
"$tool" verify main testdata/checkpoint.bin testdata/history.receipt
python3 reject-mutated-headers.py "$tool" ../chain/headers/tests/mainnet/first-4100-headers.bin
```

Run these commands from this directory. `prove` requires a new output directory. The input uses two-byte big-endian frame lengths. Only its first two frames are consumed. To reproduce the measured run, frame zero must exactly equal the canonical Mainnet genesis. The child is supplied to the guest as the witness.

The verifier uses a build-time image ID, embedded in the trusted program, and checks a real Succinct receipt and the exact entire public journal. Receipt encoding uses bincode 1.3.3 fixed-width encoding with trailing bytes rejected and a 2 MiB limit. The RISC Zero verifier is built with `disable-dev-mode`. The producer explicitly requests succinct proving, checks the returned proof and stages both public files before presenting them together. For a trusted product integration an independently reviewed verifier and pinned image are essential.

## Public checkpoint encoding

All integers are big endian. Ranges are half-open byte offsets.

| Bytes | Data |
| --- | --- |
| 0..8 | ASCII `GSZ1MH01`, research Mainnet h1 format |
| 8..16 | Height |
| 16..48 | Mainnet genesis hash |
| 48..448 | Exact successor header in Grin's 400-byte wire encoding |
| 448..480 | Successor hash |
| 480..488 | Total difficulty |
| 488..520 | Header PMMR peak and root after the successor (two leaves, three positions) |

## Recorded run

The real producer generated and locally verified its receipt in 133.540 s wall time in Debian WSL. A fresh verifier process returned in 0.018 s for the supplied files. Cryptographic proving can generate different receipt bytes across runs. The digest below identifies this recorded sample.

| Artifact or field | Result |
| --- | --- |
| Guest image ID | `401af3666aa946a7e03427dd74b376ef6b5bfbfdd0bfef157e6afcb0d957271a` |
| Raw guest ELF SHA-256 | `405f8144cd963285bf1c8427faaeed95e8f9eab48a01026c0e4dfa1a5945b562` |
| checkpoint.bin | 520 bytes, SHA-256 `01842ec5e415a613b32f0c67af95fb82c3449dfce29aca9dea992a3b209be04f` |
| history.receipt | 224266 bytes, SHA-256 `a40daf1b8097dd617f90f1aa8bf4743b76c101e87a7e142ab7a20c6de5ac8fdf` |
| Confirmed height and hash | 1, `000000bf7e67a6c9323f26e1eb26fa73f73640349710ea5a9f589c12a812a4b5` |
| Total difficulty | 34359738368 |
| Header PMMR root | `d3cf8afdf907266d022e0c3b035c3fc74fa941e5b3ccc4e2e1ea978333d004d5` |

The independent native Grin genesis-header verifier agreed on the child ID, total difficulty and PMMR root. All eight invalid-witness tests through the real prover refused their inputs and produced no result directory. The cases alter version, height, parent, previous header PMMR root, cumulative difficulty, secondary scale, graph and proof cycle.

