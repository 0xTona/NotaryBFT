# NotaryBFT: Lab 01 Layer 1 Blockchain Simulator

A minimal Layer 1 blockchain for **document notarization**. Validators reach BFT finality with a
Tendermint-style two-phase protocol (PREVOTE / PRECOMMIT with locking) over a deterministic,
simulated unreliable network. Baseline: **n = 10 validators, f = 3, quorum = 2f + 1 = 7**.

## Requirements

- Python 3.11+
- Packages: `cryptography` (Ed25519) and `pytest`

```powershell
python -m pip install -r requirements.txt
```

There is no build step. All commands below run from the repository root.

## Running the tests (single entry point)

```powershell
# Everything: all pytest suites + scenarios T1..T8
python -m tests.run_e2e --all

# Only the pytest unit/integration suites
python -m tests.run_e2e --unit

# One or more scenarios
python -m tests.run_e2e --scenario T1
python -m tests.run_e2e --scenario T3 T4 T8
```

Exit code is `0` when every selected check passes, `1` when any fails and `2` on an invalid configuration.
Pytest can also be used directly: `python -m pytest -q`.

### Configuration flags

| Flag | Meaning | Default |
|------|---------|---------|
| `--nodes N` | Validator count; must satisfy n ≥ 8 and n = 3f + 1 (10, 13, 16, ...). f and the quorum are derived | 10 (from `config/genesis.json`) |
| `--seed S` | Simulation seed (network randomness and validator keys) | 42 |
| `--t-stabilize T` | Stabilization instant `T_stabilize` (s) | per scenario |
| `--delta D` | Post-stabilization delivery bound Δ (s) | per scenario (0.2) |
| `--drop-rate p` / `--duplicate-rate p` | Fault probabilities before stabilization | per scenario |
| `--min-delay` / `--max-delay` | Link latency range (s) | 0.05 / 0.15 |
| `--byzantine K` | Equivocating validators in T7 (0..f) | f |
| `--max-time T` | Virtual-time limit per scenario (s) | per scenario |
| `--topology FILE` | Use a file-driven latency matrix, e.g. `config/network_topology.json` | off |
| `--genesis FILE` | Chain ID, validator count, key seed template | `config/genesis.json` |
| `--log-dir DIR` | Where scenario logs are written | `logs/` |

Network flags are overrides: when given they apply to every selected scenario, otherwise each
scenario uses its own fault profile. Example:

```powershell
python -m tests.run_e2e --scenario T5 --nodes 13 --seed 7 --t-stabilize 3 --delta 0.25 --drop-rate 0.3
```

### Scenarios

| ID | Scenario | What is checked |
|----|----------|-----------------|
| T1 | Normal run | All nodes finalize the same 3-block chain and the same state root |
| T2 | 40% duplicated, reordered messages | At most one counted vote per validator; no conflicting finalization |
| T3 | Bad signatures / wrong domain | Votes (TX-domain, tampered, forged, wrong chain), a VOTE-domain header and bad transactions are rejected, and the reason is logged (`REJECT_VOTE`, `REJECT_HEADER`, `REJECT_TX`) |
| T4 | Replayed / duplicate transaction | Duplicate and post-finalization replays are refused; the tx is applied exactly once; a block containing the replay fails validation |
| T5 | Drops and delay before `T_stabilize` | Safety checked after every event; 0 drops and delivery within Δ after stabilization; all nodes finalize 2 heights |
| T6 | Silent proposer | `TIMEOUT_PROPOSE` fires, the next proposer's block is finalized in a later round |
| T7 | f equivocating validators | No conflicting finalization among honest nodes |
| T8 | Same seed twice | Byte-identical logs and identical final state root |

Logs go to `logs/<scenario>.log` (T8 writes `T8_run1.log` and `T8_run2.log`). Line format:

```
[TIMESTAMP] [NODE_ID] [EVENT_TYPE] [HEIGHT] [ROUND] [DETAILS]
```

## Project structure

```text
config/    genesis.json (chain ID, validator set size), network_topology.json (latency matrix)
src/
  crypto/     Ed25519 keys, canonical encoding, domain-separated signing (TX:/HEADER:/VOTE:<chain_id>)
  core/       data types, key-value state + Merkle root, block executor, genesis loader
  consensus/  Tendermint-style engine, locking/vote rules 1-7, proposer rotation and timeouts
  byzantine/  equivocation, silent proposer, invalid block and replay injectors
  network/    discrete-event simulator, unreliable links, header-first P2P, rate limiting
  logging/    deterministic structured logger
tests/     unit tests (crypto, state, consensus, block validation, network), scenario tests, run_e2e.py
scripts/   pack_submission.py
logs/      generated scenario logs
```

## Design summary

- **Identities and signatures**: Ed25519. Signed bytes are `u32(len(domain)) || domain || canonical_json(payload)`
  with domain `TX:<chain_id>`, `HEADER:<chain_id>` or `VOTE:<chain_id>`; a signature from one context never
  verifies in another. Votes sign chain ID, height, round, phase, block hash and validator ID.
- **Canonical encoding**: JSON with sorted keys, no whitespace, ASCII escapes; only `None/bool/int/str/list/dict`
  are allowed (floats and raw bytes are rejected).
- **State**: `<sender>/nonce` and `<sender>/docs/<doc_id>` → `0x<digest>`. A transaction writes only its own
  sender's keys; nonces must increase by exactly 1, so a transaction applies at most once.
- **State commitment**: binary Merkle tree over keys sorted by UTF-8 bytes, leaf
  `SHA256(0x00 || len(k) || k || len(v) || v)`, inner `SHA256(0x01 || L || R)`, unpaired node promoted,
  empty root `SHA256("")`.
- **Consensus, network and logging**: see the module docstrings in `src/consensus`, `src/network` and `src/logging`.

## Packaging the submission

1. Run `python -m tests.run_e2e --all` so `logs/` is populated.
2. Put the final `REPORT.pdf` in the repository root.
3. Build the archive with the confirmed name (same name for the root folder and the zip):

```powershell
python scripts/pack_submission.py --ids <ID1> <ID2> <ID3> --confirmed-naming
```

The script refuses placeholder IDs and, for fewer than five IDs, requires `--confirmed-naming`
(only after the instructor has approved the three-member name). Output: `dist/Lab01_<IDs>.zip`.
