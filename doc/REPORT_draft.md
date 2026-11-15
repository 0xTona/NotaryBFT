# Lab 01 Report: NotaryBFT (draft, convert to REPORT.pdf, max 10 pages)

> Draft prepared by Member 3. Sections marked **[TODO M1]** / **[TODO M2]** need input from the owners.
> Do not paste source code into the final report.

## 1. Team members

| Member | Student ID | Responsibility |
|--------|-----------|----------------|
| Member 1 | [TODO] | Consensus engine, locking rules 1-7, Byzantine injection, T1/T6/T7 |
| Member 2 | [TODO] | Simulator, unreliable links, header-first P2P, logging, T2/T5/T8 |
| Member 3 | [TODO] | Crypto, state/execution, genesis, test CLI, T3/T4, README, packaging |

## 2. Project structure

See README "Project structure". Insert the folder tree figure here.

## 3. Introduction

Purpose: a minimal Layer 1 chain for document notarization that keeps finality under an unreliable,
partially synchronous network with n = 3f + 1 validators (baseline n = 10, f = 3, quorum 7).

Main design choices:
- Python 3.11, single-process discrete-event simulator with a virtual clock (determinism).
- Ed25519 signatures, SHA-256 hashing, canonical JSON encoding, explicit domain separation.
- Tendermint-style PREVOTE/PRECOMMIT with locking; round-robin proposer; increasing timeouts.
- Header-first propagation, outbound token bucket, temporary blocking of overactive peers.

## 4. System design

Diagram (to draw): Client → `Node.submit_transaction` → mempool → proposer builds block
→ HEADER gossip → GET_BODY / BODY → Rule 3 validation (`validate_block_proposal` → `Executor`)
→ PREVOTE → lock → PRECOMMIT → finalize → `committed_state` + ledger → logs.

### 4.1 Cryptography layer (Member 3)
- Identity = 32-byte Ed25519 public key as 64 lowercase hex characters; one spelling per key.
- Signed bytes: `u32_be(len(domain)) || domain || canonical_json(payload)`, domain ∈
  {`TX:<chain>`, `HEADER:<chain>`, `VOTE:<chain>`}. The length prefix removes boundary ambiguity.
- Payloads: TX = (sender, doc_id, doc_hash, nonce); HEADER = (chain_id, height, round, parent_hash,
  state_root, txs_hash, proposer, timestamp); VOTE = (chain_id, height, round, phase, block_hash, validator_id).
- Canonical encoding: sorted keys, no whitespace, ASCII escapes; floats/bytes rejected.

### 4.2 State and execution (Member 3)
- Keys: `<sender>/nonce` → decimal uint64, `<sender>/docs/<doc_id>` → `0x<hex digest>`.
- Rules: canonical sender, doc_id in `[A-Za-z0-9._-]{1,128}` (no `/`, so writes cannot leave the
  sender's namespace), valid TX-domain signature, nonce = previous + 1. All checks run before any write.
- Block execution runs on a clone of the parent state; any failing tx or a state-root/txs-hash mismatch
  rejects the whole block and leaves committed state untouched. Each tx yields a receipt.
- Commitment: binary Merkle tree, keys sorted by UTF-8 bytes, leaf `H(0x00‖len(k)‖k‖len(v)‖v)`,
  inner `H(0x01‖L‖R)`, unpaired node promoted, empty root `H("")` (RFC 6962 style).

### 4.3 Consensus **[TODO M1]**
### 4.4 Network and logging **[TODO M2]**

## 5. Implementation notes

### 5.1 Guards realized by Member 3
- Mempool admission (`Node.submit_transaction`): format, signature/domain, pending duplicate and
  already-committed nonce are refused with a `REJECT_TX` log line.
- Incoming votes are checked (chain, phase, membership, VOTE-domain signature) before counting and
  rejected with a `REJECT_VOTE` log line (T3 evidence).
- Typed signing helpers (`sign_vote`, `verify_vote_signature`, ...) bind each message type to its domain.

### 5.2 Non-trivial bugs and fixes
1. **Interpreter-dependent vote encoding.** `Phase` was a `(str, Enum)`. Since Python 3.11,
   `str(Phase.PREVOTE)` returns `"Phase.PREVOTE"`, so vote payloads and log lines depended on the Python
   version, and the T8 log had no `[PREVOTE]` events. Fix: pin `__str__`/`__format__` to the value and encode
   `phase.value` in the signed payload.
2. **Ambiguous Merkle leaves.** Leaves were `H("k=v")`, so `{"a=b": "c"}` and `{"a": "b=c"}` had the same
   root, and the odd last leaf was duplicated (CVE-2012-2459 pattern). Fix: length-prefixed leaves, 0x00/0x01
   domain prefixes, promotion of the unpaired node.
3. **Non-canonical identities/signatures.** Uppercase hex keys or signatures also verified, giving several
   spellings (and tx hashes) for one logical message. Fix: accept lowercase hex only.
4. **Lagging nodes lost the next proposal.** A node still finishing height h rejected the header for h+1
   that a faster proposer had already broadcast (`height mismatch`), and nothing resent it, so the node
   stalled even with no faults (T1 failed for seeds 6-10). Fix: accept headers up to 2 heights ahead and
   buffer the block in the engine until that height starts (Rule 3 is checked then).
5. **Late proposal never committed.** If the body arrived after the precommit quorum, the engine stored
   it but never re-checked the quorum. Fix: on every proposal, check buffered precommits for its hash; if a
   quorum names a block we do not have, request it (`GET_HEADER` → `HEADER` → `GET_BODY` → `BODY`, retried
   every 0.5 s, header-first preserved).
6. **Lock split deadlock.** A reproposal was re-signed with the new round, which changed its hash. Validators
   locked on the old hash could then never prevote it, so a split such as 5 locked / 5 unlocked stalled the
   height forever (T8, seed 1). Fix (Tendermint): repropose the *same* block; the HEADER message carries
   `proposal_round`, accepted only from that round's proposer.
7. **Decided nodes stop voting.** Nodes that finalized h left too few voters for the rest, whose precommits
   had been dropped (T8, seed 10). Fix: each node keeps the 2f + 1 precommits that finalized each height
   (commit certificate) and, when a validator sends a vote for an older height, sends it those signed
   precommits (throttled to once per second per peer and height).

Validation: 0 failures over seeds 1-30 (n = 10), seeds 1-8 for n = 13 and 16, and seeds 1-10 with the
file-driven topology; regression tests in `tests/test_liveness.py`.

## 6. Testing and results

Single entry point: `python -m tests.run_e2e --all` (pytest suites + T1-T8). Fill in the observed column
from the latest run (n = 10, seed 42):

| Test | Expected | Observed |
|------|----------|----------|
| Unit: crypto, state | domain/context checks, ownership, replay, Merkle | [fill] |
| Unit: consensus, block validation, network | rules 1-7, Rule 3 cases, rate limit, header-first | [fill] |
| T1 | same chain and state hash | [fill] |
| T2 | no double counting / forks | [fill] |
| T3 | rejected, reason logged | [fill] |
| T4 | applied at most once | [fill] |
| T5 | safety; 0 drops within Δ after `T_stabilize`; liveness | [fill] |
| T6 | timeout, chain continues | [fill] |
| T7 | no conflicting finalization | [fill] |
| T8 | byte-identical logs and state hash (give SHA-256) | [fill] |

Anomalies / discussion: [TODO]

## 7. References
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA). https://www.rfc-editor.org/rfc/rfc8032
- RFC 6962, Certificate Transparency (Merkle tree hashing). https://www.rfc-editor.org/rfc/rfc6962
- E. Buchman, J. Kwon, Z. Milosevic, "The latest gossip on BFT consensus" (Tendermint), 2018. https://arxiv.org/abs/1807.04938
- C. Dwork, N. Lynch, L. Stockmeyer, "Consensus in the presence of partial synchrony", JACM 1988.
- `cryptography` library documentation. https://cryptography.io
- Course material: Lab 01 specification and lecture slides (Department of Knowledge Engineering).
