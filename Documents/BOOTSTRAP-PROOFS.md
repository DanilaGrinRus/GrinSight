# Autonomous bootstrap 0.4.7A — proof provider and independent history

**Decision.** A downloaded GSHP1 is a candidate. A provider can demonstrate the structure, binding and sampled checks of its candidate. It cannot establish its freshness, all historical consensus transitions, or the wallet's selected chain. The provider is a separate operator tool with no wallet, signing, chain-selection, balance or status API. An installation must work with zero providers. The independently checkable history path uses the canonical network genesis and sequential consensus validation. Wallet state requires its own PIBD and block checks.

## Scope of the evidence

The baseline is commit `be41231cd7ab73f158f8219e3fc44d1c3fe781f6`. `Source/chain/headers/src/sample.rs` constructs a domain-separated binary tree of work and draws points from a hash-derived seed. The seed binds the network, point hash, lower boundary, tree and sample count. `proof.rs::check` verifies adjacent headers at the point, a PMMR path for the preceding header, the count and total of work leaves, and each sample. A sample checks its weighted interval, a header run and inclusion in the header PMMR under the candidate point. The checker uses Grin PoW, the historical DAA rule on early runs and WTEMA where applicable. Many headers outside the runs remain unchecked. The first-work constant binds the expected genesis difficulty. It does not replay a prefix from the exact genesis bytes. Some other checked context includes header fields whose Grin ID alone is insufficient: standalone checkpoint checks and the exact serialized point comparison matter.

The Grin consensus header commits to the preceding header PMMR. It does not commit to this separate weighted tree. Its claimed total and the valid membership samples constrain portions of that tree. These constraints do not supply a proof that every leaf represents the correct per-header work of the whole history, or that every unexamined transition is valid. `checkpoint::check` validates a point's local context and frontier. A PMMR path from an earlier point in a later candidate proves inclusion within the candidate, not validation of all intervening headers. The operator tool deliberately accepts only `History::Sampled` for the **exact** point; the existing `History::Extended` result is insufficient for this file format.

For a fixed genuinely work-weighted distribution and independent uniform samples, missing an invalid set of weight fraction f in all m draws has probability (1−f)^m. With f = 0.02, m = 420, this idealized value is about 0.000207. No general lower bound on f for a consensus-invalid history, adversarial root choice, query budget, or reduction binding this tree to the consensus sequence has been established. These draws are deterministic once the provider chooses its public inputs. The idealized calculation gives no adversarial acceptance probability for GSHP1. A verifier's fresh randomness after an authenticated commitment can improve the challenge model; it cannot establish completeness of omitted weights by itself. Comparing candidates by advertised total difficulty after successful sampling would inherit this gap. No product decision compares such candidates.

## Alternatives and the actual trust boundary

| Mechanism | Assumptions and security evidence | Resources and compatibility |
|---|---|---|
| Sequential from genesis | Exact genesis, consensus PoW/hash assumptions and correct implementation. No probabilistic omission of headers. Select among actually verified candidate histories. A valid isolated history can be stale. Full header validity does not verify all historic transactions. | Standard Grin peers. O(n) headers and PoW checks; rolling DAA window and logarithmic PMMR frontier. Restart journal and tail/state have separate storage costs. |
| Existing GSHP1 | Hash binding of observed openings and PoW checks of sampled runs. No established adversarial acceptance bound or minimum attack cost. Authentication of a mirror or human approval of its hash would add a separate trust assumption. | No node modification. Optional operator builds a complete PMMR and work tree. On the provider the 64-bit offset index alone uses approximately 8 bytes per header; the underlying trees also scale with n. Wallet-size artifact example and timings below. |
| Superblock count rev. 5.4 | The local theorem starts from an already trusted S, counts qualified C32 blocks across a fixed global grid and compares competitors. It assumes a bounded race and its work/orphan model; missing qualifying data, variable historical algorithms or unavailable honest competitors preclude transplanting its bound to arbitrary genesis bootstrap. | The checked tail is at least 5,760 blocks and one base window of work. The maximum gap across all candidates is 240,000. Parameters m=2,870, c=0.860 are for that conditional theorem. A multi-million-header initial history exceeds the stated domain. Discovering all heights from ordinary peers can cost a full header pass. No new SB implementation here. |
| Interactive / hybrid | Fresh challenges require transcript binding, a defensible distribution and competing-branch policy. Combining two conditional/non-proven bounds does not repair missing assumptions. Failure probability, attack cost and bandwidth on Grin unknown. | Interactive service sees timing and requests; extra rounds, mirror caching constraints. No wallet addresses, commitments or keys should enter the transcript. |
| Recursive proof / STARK / zkVM | Could prove a defined sequential header transition with hard-coded network genesis, all historical consensus rules, PMMR, final hash/height/work and proof system assumptions. Requires circuit/program equivalence, domain/version binding and aggregation soundness. Even a valid proof of that relation says nothing about the freshest visible chain. | No Grin consensus change in principle. Full-history proving time, RAM, proof size, trusted setup if any, finality and Android verification have not been demonstrated by this work. A single-header experiment does not establish these figures. |

The conclusions for Grin are based on its specific commitments. General algorithm references: [FlyClient](https://eprint.iacr.org/2019/226), [Non-Interactive Proofs of Proof-of-Work](https://eprint.iacr.org/2017/963). Local research used: “Теорема о подсчёте суперблоков — сводка.md” rev. 5.4 and `strict_bound_v18.py` in the DHW research archive. Their assumptions and parameter domain concern their own protocol. This work establishes no impossibility theorem for all future compact Grin proofs. A5 compact acceptance remains disabled pending a construction with a reviewed bound and practical cross-platform measurements.

## Provider protocol

`Source/tools-proof-provider` writes a static directory. Manifest v1 uses schema `grinsight.proof-provider.v1`, method `GSHP1-research-candidate`, network, canonical genesis hash, height, header hash, total work, and SHA-256 and exact byte length of both members. The location for the immutable pair is computed locally:

    id = hex(SHA256(ASCII("GrinSight provider objects v1\n" + checkpoint_sha256 + "\n" + proof_sha256)))
    manifest.json
    objects/<id>/checkpoint.json
    objects/<id>/history.proof

Digest hex is lowercase. A manifest, digest or TLS certificate is not authority to promote the wallet's starting point. Checkers enforce 4 KiB for the manifest, 64 KiB for the checkpoint and 64 MiB for the proof before the costly proof check. Only ordinary artifact files are read. No arbitrary URLs or destination paths appear in the manifest. Opaque fields, altered declared work, mismatched networks, pairs for different checkpoints, or incomplete data fail checks.

The writer serializes updates with a local OS lock, stages each generation in the same filesystem, verifies written object bytes, then replaces the manifest using a same-directory temporary file and atomic rename. Readers pin one manifest and its immutable objects. A process crash may leave an unreferenced object or stage directory; the prior pointer still names complete data. The initial publication may have no manifest until complete. Same candidate is idempotent. A lower candidate, conflicting candidate at the same height, or previously damaged publication requires a separate output directory. The operator can deliberately select a new publication for a deep reorg. This is operator publishing policy, never a chain-selection rule. Keep old referenced objects for in-flight readers. No power-loss durability or Byzantine local-storage guarantee is claimed.

## Run without external services

Build `grin-proof-provider` using a Rust toolchain with stable file locking, from `Source/tools-proof-provider`. Use the same offline vendor arrangement as the base tree:

    cargo build --release --locked --offline
    cargo test --release --locked --offline
    python -B -m unittest -v test_operator

If the release checkout omits the directory source, supply the base's trusted vendor directory with Cargo's `--config "source.core-vendored.directory='C:/DHW/GrinFlySight/core-v0.2/vendor-crates'"`. The release test binary uses temporary directories; set TMP and TEMP to an accessible scratch directory on Windows if required. For the following commands, place the executable on PATH.

1. Run your compatible ordinary node; its local Foreign API must already be accessible to you. `export_headers.py` accepts only IPv4 loopback, issues only `get_tip` and `get_header`, bounds response size and checks links and the returned header hash. It accepts an explicit optional Foreign API credential file. It does not access wallet secrets. A full JSON export is deliberately simple and may take a long time. The output is atomically replaced only after the end still matches the node. Input from a verified, stopped autonomous scanner can instead be a copy of its same-format `autonomous-headers-v1.bin`. Frames are u16 big-endian length and Grin's serialized header including the exact genesis.
2. Produce a research candidate from a completed export, at an available height with usable post-HF4 checkpoint context:

       python export_headers.py /work/headers.bin --port 3413 --to 4115520
       grin-proof-provider generate main /work/headers.bin 4115520 /work/public
       grin-proof-provider check main /work/public

   For a node requiring authentication, pass `--secret-file` pointing to its local node credential. Keep credentials, input dumps, and wallet files outside the publication directory. Testnet uses `test` and that node's API port. The generator replays the selected prefix with the shared GenesisVerifier, creates a deterministic checkpoint with release_time=0, builds the same GSHP1 as `fly-prove`, then checks the serialized checkpoint and proof again. The operational generation limit is 16 million headers. It bounds operator input, not Grin consensus or wallet lifetime. Mobile devices should not run this generator by default.
3. A mirror can import an existing pair without a dump:

       grin-proof-provider bundle main ../chain/headers/points/main.json ../chain/headers/points/main.history /work/public
       grin-proof-provider check main /work/public

   This checks just the sampled evidence. It does not upgrade a mirror's claim to full genesis replay.
4. For updates, atomically replace the completed export, then run a one-shot scheduled task or the optional local poller:

       python refresh.py /absolute/path/to/grin-proof-provider main /work/headers.bin /work/public --depth 1440 --interval 86400

   `--depth` selects a publication height only. The example's 1,440 is an operator choice. `--once` performs one refresh and returns its exit status. The poller rereads a changed export, retries on the next interval after failure and leaves the last publication readable. A byte-identical export across a poller restart can incur regeneration. Neither export nor regeneration is incremental in this version.
5. Expose only the manifest and immutable object files via static read-only hosting, your own Onion service, or offline copying. Configure short/no cache for the current manifest and immutable caching for object URLs. Do not expose the node's administrative API. A downloader must pin one manifest and apply bounds before allocating. Local import works without networking; no new Grin P2P message is required or deployed. No public host, Tor service, keys or live deployment are created by this task. No compact-provider client is enabled in the wallet. The configured channel can learn IP/timing; an offline mirror avoids this and Tor can hide the direct origin, not all timing information.

## Evidence and outstanding checks

On Windows x64 the release-mode suite mines a real short automated-network history from genesis through DMA and WTEMA. It generates two successive point/proof pairs at heights 17 and 18, retains the old object through replacement, verifies the selected publication, and refuses to replace it with the older generation. Integration tests run the executable on the 0.4.6 mainnet checkpoint and 420-sample GSHP1, exercise idempotence, a wrong network, truncation, mismatch of point/manifest, changed work or method, excess manifest length and damaged bytes. Four Python tests check bounded header packing, indexed frame boundaries, complete output, and retaining the prior export on a changing chain. These are offline runs, with no keys or payments.

One local Windows x64 release-mode run using the 0.4.6 pair at mainnet height 4,115,520 yielded the following. CPU is process time; memory is observed peak process working set. These are artifact checks, not whole wallet sync figures.

| Stage | Wall | CPU | Peak working set | Network |
|---|---:|---:|---:|---:|
| Bundle a supplied checkpoint and GSHP1 | 361 ms | 344 ms | 26,566,656 bytes | 0 bytes |
| Independent process, reread and check the published manifest and objects | 375 ms | 359 ms | 26,509,312 bytes | 0 bytes |

The point is 9,391 bytes, the proof 8,285,016 bytes, total published file content 8,294,970 bytes. A previous research report at a **different height**, 4,123,321, recorded 13.2 s for proof generation and 0.663 s for read/check with the original generator; that historical report is not a new timing of the full genesis-replay generator. Production-scale regeneration, network mirror availability, live export/update, physical power-loss behavior and Android resource costs are unmeasured here. The provider's largest full-history inputs are operator workloads. A compact standalone acceptance proof, fresh-chain guarantee under full isolation, and a human cryptographic audit remain open.
