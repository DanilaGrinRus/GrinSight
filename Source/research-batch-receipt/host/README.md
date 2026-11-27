# Composing bounded mainnet batches

The producer takes a previously verified checkpoint and one to eight consecutive 400-byte C29 headers. Parents can use the pinned height-two program or this same batch program. The receipt verifier pins the batch image both when verifying the proof and when reading the self-image field in its journal. An unconditional succinct receipt, the complete public journal and the mainnet schema must agree. There is no public input carrying a chain tip or current time.

The guest implements an early-mainnet subset at heights 3–1000 and timestamps before February 2019. It accepts version 1 and secondary C29 PoW. The real chain contains a primary block at height 230, so a continuous mainnet proof with this program stops before it. The journal carries the current tip, rolling difficulty context, PMMR frontier, and self-image. Each accepted batch replaces its predecessor as the input for the next batch.

## Verify

With the verifier executable already built, only the two files in one checkpoint directory are needed. The default Rust host build is verifier-only.

```sh
research-grin-batch-receipt verify main checkpoint.bin history.receipt
```

## Reproduce on a Linux CPU

From the parent `research-batch-receipt` directory with the RISC Zero Rust guest toolchain, cached Cargo dependencies and local `r0vm` 3.1.0 installed:

```sh
bash build.sh
export RAYON_NUM_THREADS=12
python3 prove-fixture.py ../research-linked-receipt/testdata 3 4 /var/tmp/grinsight-batch-receipt/rebuild-h6
python3 prove-fixture.py /var/tmp/grinsight-batch-receipt/rebuild-h6 7 2 /var/tmp/grinsight-batch-receipt/rebuild-h8
bash test-assumptions.sh
```

Choose a fresh output directory for each proof. The producer measures the SDK call and reports segment and cycle counts. The fixture runner also measures end-to-end wall time and peak RSS of the prover process tree. `BATCH_RESEARCH_TARGET` selects the build area and `BATCH_HOST_TARGET` can select a compiled host cache. Local guest execution and proof construction use no external proving service.

## Measurements

Both runs used WSL Debian, the same 12-thread CPU configuration, a segment limit of 2²⁰ cycles, and an existing verified parent. Verification times include process startup and file reads, with 11 separate processes per point and no concurrent prover.

| Parent → tip | Headers | Wall time | Segments | Total cycles | User cycles | Peak RSS (KiB) | Point + receipt (bytes) | Median verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| H2 → H6 | 4 | 649.354 s | 5 | 4,325,376 | 3,953,564 | 9,620,540 | 805 + 224,836 | 18.98 ms |
| H6 → H8 | 2 | 346.299 s | 3 | 2,359,296 | 2,051,691 | 9,620,228 | 815 + 224,856 | 18.72 ms |

Two automated verifier tests passed. Five separate negative runs covered a missing parent receipt, substitution of an H2 proof for a batch proof, a changed parent journal, a different genuine same-program receipt, and unassisted guest execution with the authentic input bytes. No rejected run produced a checkpoint.
