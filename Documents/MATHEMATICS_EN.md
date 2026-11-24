# Mathematical Explanation of GrinSight

GrinSight builds a local copy of the part of the chain state it needs and verifies it against the commitments in block headers. This text describes version 0.4.3.

Let $H_h$ denote the block header at height $h$, and $S_h$ the state after block $h$: the unspent outputs, their range proofs and the kernels, each committed to by a root in $H_h$.

## 1. The Starting Point

A light wallet cannot check the chain from the first block, so it starts from a header $H_s$ built into the program (mainnet: $s = 4{,}115{,}520$). The record of the point carries $H_s$, the two headers before it and the peaks of the header MMR under the root written in $H_s$. The program checks that everything in the record follows from one hash:

$$
\operatorname{ValidPoint}(\text{record}) \;\Longrightarrow\; \text{the only thing taken on trust is } \operatorname{hash}(H_s)
$$

This check cannot be replaced by anything computed on the device. You can put a point of your own instead of the built-in one.

## 2. Verifying the Header Chain

From peers the wallet receives

$$
H_{s+1}, H_{s+2}, \ldots, H_n
$$

and checks each one with the node's own functions: the version for the height, strictly growing time, proof of work, difficulty, the commitment to the previous headers.

$$
\operatorname{ValidHeader}(H_i, H_{i-1}, \text{peaks}_{i-1}) = \text{true}
$$

The file of headers is not trusted either: it is verified again from the point each time it is opened. Branches are compared by **accumulated work**, not height:

$$
\operatorname{Work}(C) = \sum_{H_i \in C} \operatorname{work}(H_i)
$$

A branch replaces the end of the chain only when it carries strictly more work. This does not prove that the wallet has seen every branch in the network.

## 3. Choosing the Tip

A chain of valid headers is not yet the chain everyone else is on. Before a tip is *selected*, public nodes of different named operators are asked over HTTPS what their tip is and what the time is. The tip is selected when their answers agree with the verified chain, and the time of the answers gives a clock that does not depend on the device:

$$
\operatorname{Selected}(H_n) = \operatorname{ValidChain}(H_s \ldots H_n) \;\wedge\; \operatorname{Confirmed}_{\text{operators}}(H_n) \;\wedge\; \operatorname{TimeConfirmed}
$$

The operators do not sign anything and are not trusted with the balance; they can only refuse a tip, not invent one that passes section 2. Operators that collude, or a network that shows the wallet only chosen nodes, remain outside what this check can exclude.

## 4. The State at the Archive Point

Nodes hand out the state at an archive header $H_a$ ($a < n$) in PIBD segments. The wallet collects the bitmap of unspent outputs and the output identifiers and checks them against the roots in $H_a$:

$$
\operatorname{Root}(\widehat{S}_a) = \operatorname{root}(H_a)
$$

A peer can neither add an output that is not under the root nor hide one that is.

## 5. From the Archive Point to the Tip

Each block $B_i$ for $a < i \le n$ is applied to the state and the result is compared with the next header:

$$
\widehat{S}_i = \operatorname{Apply}(\widehat{S}_{i-1}, B_i), \qquad \operatorname{Root}(\widehat{S}_i) = \operatorname{root}(H_i)
$$

Only a block that passed this check is handed to the wallet process.

## 6. The Wallet's Outputs and the Balance

Among the outputs the wallet finds its own with its keys; no server is asked. Outputs created before the wallet's first block are found by a separate search through the archive, which can still be running when the balance is first shown.

$$
W_n = \{o \in \widehat{S}_n \mid \operatorname{OwnedByWallet}(o)\}, \qquad \operatorname{Spendable}_n = \sum_{\substack{o \in W_n \\ \operatorname{EligibleToSpend}(o,n)}} \operatorname{value}(o)
$$

Eligibility takes into account maturity, confirmations and outputs reserved for prepared payments.

## 7. Payment and Confirmation

$$
\sum \operatorname{inputs} = \sum \operatorname{outputs} + \operatorname{fee}
$$

The transaction is built and signed in the wallet process and handed to the chain process, which sends it through Tor. A payment counts as confirmed when its kernel is in a block of the selected chain and $k = 10$ more blocks stand on it. The equation explains the balance of amounts; it does not replace Grin's cryptographic checks.

## 8. Rollback of the Wallet Itself

The wallet's journal can be replaced with an older copy of itself. A small record kept outside the profile (the *guard*) remembers how far the journal has gone. If the journal is behind the guard, payments prepared before the copy was taken are locked: the wallet can no longer tell whether they were signed.

## Main Relationship and Trust Boundaries

$$
\boxed{\text{starting point} \;\longrightarrow\; \text{verified headers} \;\longrightarrow\; \text{selected tip} \;\longrightarrow\; \text{verified state} \;\longrightarrow\; \text{balance and payment status}}
$$

What is taken on trust:

- the hash of the starting point;
- that the public nodes asked about the tip are not all controlled by one party, and that the network lets the wallet reach them;
- the implementation: there has been no independent audit by a human.

Headers before the starting point are not checked. Verification from the first block is not part of this version.
