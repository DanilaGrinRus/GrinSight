# Mathematical Explanation of GrinSight

GrinSight can be viewed as a system that builds a local copy of the state and verifies it against cryptographic commitments in blockchain headers.

Let $H_h$ denote the block header at height $h$, and let $S_h$ denote the state of the unspent output set at the same height.

## 1. Verifying the Header Chain

GrinSight receives a sequence of headers from peers:

$$
H_{h_0}, H_{h_0+1}, \ldots, H_n
$$

Here, $H_{h_0}$ is the starting point for verification: a pinned checkpoint or a header reached by verifying from genesis.

For each subsequent header, the client checks that it is correctly linked to the preceding chain and satisfies the applicable rules, including difficulty and proof-of-work rules. Schematically:

$$
\operatorname{ValidHeader}(H_i, H_{i-1}, \text{history}) = \text{true}
$$

The **accumulated work**, not just height, is considered when comparing verified branches:

$$
\operatorname{Work}(C) = \sum_{H_i \in C} \operatorname{work}(H_i)
$$

This does not prove that the client has seen every branch in the network: the result depends on the available peers. Multiple peers from different `/16` networks reduce reliance on a single source but do not prove their independence.

## 2. Reconstructing State with PIBD

At archive height $a$, the header contains a commitment to the output state: `output_root`. Peers provide PIBD segments from which GrinSight reconstructs its local representation of the state:

$$
\widehat{S}_a = \operatorname{Reconstruct}(\text{bitmap segments}, \text{output segments})
$$

The notation $\widehat{S}_a$ denotes the state reconstructed by the client from the received data. The client verifies the segments and compares the calculated root with the header:

$$
\operatorname{OutputRoot}(\widehat{S}_a) \stackrel{?}{=} H_a.\operatorname{output\_root}
$$

If the check fails, the state cannot be considered verified against that header. If it passes, the data is bound to the header’s `output_root`, assuming correct verification and the cryptographic assumptions of the scheme.

This is a **schematic expression**: Grin’s actual root is more complex than a simple hash of an output list and involves PMMR and bitmap structures.

## 3. Updating from the Archive to the Tip

Let $B_i$ be the block at height $i$. Starting from the archive state, GrinSight applies subsequent blocks in order:

$$
\widehat{S}_i = \operatorname{ApplyBlock}(\widehat{S}_{i-1}, B_i)
$$

After each step, it compares the resulting roots with the corresponding verified header. In simplified form:

$$
\operatorname{OutputRoot}(\widehat{S}_i) \stackrel{?}{=} H_i.\operatorname{output\_root}
$$

$$
\operatorname{KernelRoot}(\widehat{S}_i) \stackrel{?}{=} H_i.\operatorname{kernel\_root}
$$

This advances the state from archive height $a$ to the verified tip $n$. On a later run, the saved state can allow updates to resume without a complete reconstruction, provided the saved data passes the necessary checks.

## 4. Finding Wallet Outputs and Calculating the Balance

From the unspent outputs, the wallet identifies those belonging to its keys. It uses rangeproof data and checks its binding to the corresponding root.

Denote the set of outputs found for the wallet by:

$$
W_n = \{o \in \widehat{S}_n \mid \operatorname{OwnedByWallet}(o)\}
$$

The total verified balance can then be represented as:

$$
\operatorname{Balance}_n = \sum_{o \in W_n} \operatorname{value}(o)
$$

**The total balance and the balance available to spend may differ.** Selecting funds also takes into account, for example, coinbase maturity, confirmations, and reserved outputs:

$$
\operatorname{Spendable}_n = \sum_{\substack{o \in W_n \\ \operatorname{EligibleToSpend}(o,n)}} \operatorname{value}(o)
$$

## 5. Payment and Confirmation

To make a payment, the wallet selects eligible inputs. The amounts must satisfy:

$$
\sum \operatorname{inputs} = \sum \operatorname{outputs} + \operatorname{fee}
$$

Some outputs may represent change. Once created and signed, the transaction is sent to peers. Its inclusion in a block and subsequent status are tracked using verifiable chain data, including the kernel.

This equation explains the balance of amounts; it does not replace Grin’s cryptographic transaction checks.

## Main Relationship and Trust Boundaries

$$
\boxed{\text{verified header chain} \;\longrightarrow\; \text{verified state} \;\longrightarrow\; \text{balance and payment status}}
$$

The result applies to **the chain the client was able to obtain and verify**. Root verification protects against data that does not match the selected headers, but does not by itself prove that a client isolated from honest peers has seen the globally canonical tip.
