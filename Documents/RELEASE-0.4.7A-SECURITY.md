# GrinSight 0.4.7A · release security review

This is a local engineering review of the release candidate. Independent human cryptographic review remains open.

## Wallet and interface

The UI reads the balance, selected height, wallet height and time evidence from one wallet observation. A positive readiness message also requires an available balance and completion of the search for old outputs. The same badge is used above the balance and in Details, including the narrow layout. The two colours are independent of the user's theme. The recovery help uses a static, incomplete three-word example. It receives no text from the recovery input.

The receiving preference still applies to saved contacts. The display example no longer suggests an amount threshold. Replies from a relay, successful delivery and synchronisation messages do not select a chain tip.

The 0.4.6 upgrade check used production Windows executables and an isolated funded test fixture. The address, available and reserved outputs, operation identifiers and saved signed bytes survived two opens. Old unsigned exchanges retain their reserve and their old signing session expires. The acceptance record distinguishes isolated tests and public Mainnet observations. [Acceptance](BOOTSTRAP-0.4.7A-ACCEPT.md)

## Dependencies

On 28 November 2026 the six runtime component lockfiles were compared with the [RustSec advisory database at c5279d0](https://github.com/RustSec/advisory-db/tree/c5279d0). The six components are the chain process, wallet host, UI, Tor address service, mailbox and bridge helper. Tools and optional transitive crates can appear in a lockfile even when absent from a particular executable. The inventory covered 1,109 distinct name/version/source tuples. It matched 10 vulnerability advisories, 2 soundness advisories and 18 maintenance notices. These counts are advisory matches, not proofs of exploitability or of safety.

| Component in the lockfiles | Review finding |
| --- | --- |
| `curve25519-dalek 3.2.0`, `crypto-bigint 0.5.5` | Timing findings remain open. The older X25519 dependency is used by the Slatepack encryption stack. Reachability of the specific affected scalar operation for secret input has not been established. |
| `zip 0.5.13` (five advisories) | The chain adapter returns `Ok(false)` for legacy txhashset archive writes. This wallet gets chain state from PIBD segments. The Windows portable has a separate, allowlisted package extractor. |
| `rsa 0.9.10`, `libsqlite3-sys 0.38.2`, `url 2.5.8` | Pinned transitive dependencies. Earlier review traced the first two into the Tor stack. A source search found no direct `Url::origin()` call in the wallet, chain or mailbox entry points. This does not rule out an indirect call. |
| `lru 0.16.4`, `rand 0.7.3` | Soundness advisories remain in the dependency report. |

The comparison can be repeated with Python 3.11+ and a checkout of that database:

```text
python Source/tools-audit/check_release_dependencies.py PATH_TO_ADVISORY_DB EMPTY_OUTPUT_DIRECTORY
```

## Scope and limits

A full local check from genesis and importing a checkpoint with a GSHP1 sample have different trust assumptions. Public time and quorum can temporarily be unavailable. Existing user Mainnet profiles and funds were excluded from the engineering runs. Mainnet transfers described in the release notes were performed by the owner. The review provides no guarantee against compromise of the device or rollback of its entire storage.
