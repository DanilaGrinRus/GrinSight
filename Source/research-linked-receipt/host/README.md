# Historical H1 to H2 composition

The verifier authenticates a mainnet checkpoint at height two. It accepts a 1,104-byte point and a RISC Zero 3.1.0 succinct receipt. The expected image ID is compiled from `../image-id.hex`. Full receipt verification requires an unconditional successful claim and binds the complete journal to the supplied point.

## Verify

Build the verifier with the locked offline registry in an environment that contains the listed dependencies. It builds without the proving feature on Windows and Linux. Given the compiled executable, the only input files are the point and its receipt.

```sh
research-grin-linked-receipt verify main checkpoint.bin history.receipt
```

## Reproduce on Linux

Start in the parent `research-linked-receipt` directory. The Linux producer requires the RISC Zero guest toolchain, the offline Rust registry, and the local RISC Zero 3.1.0 CPU prover `r0vm`. The fixture uses the existing H1 point and receipt and the third framed header of the public `first-4100-headers.bin` vector.

```sh
bash build.sh
RAYON_NUM_THREADS=4 bash prove-fixture.sh /var/tmp/grinsight-linked-receipt/new-result
bash test-assumptions.sh
```

The producer verifies the H1 receipt against its own pinned H1 image and requires equality with the supplied H1 point. It supplies that receipt as an assumption for the guest. The local prover resolves the assumption and the host verifies the resulting receipt against the separately pinned H2 image before publishing the two output files. A missing H1 receipt, an unrelated H1 journal, and direct guest execution without an assumption are covered by the negative test.

A successful proof establishes this historical two-block statement. Freshness, current chain selection, additional heights, and wallet balances require their own checks.
