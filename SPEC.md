# Canary — Go Build Spec (v0.1, prototype)

> Originally drafted as "ECPoW"; renamed to Canary (including the consensus hash tags, which
> required regenerating `reference/test_vectors.json`). This document is the single source of truth
> for the Go build. The Python reference in `reference/` is the **consensus oracle**: where this text
> and `reference/canary.py` disagree, the Python behaviour wins and the disagreement is a spec bug to report.

## 0. What we are building

A minimal, standalone blockchain node in Go whose proof of work is **solving an elliptic-curve
discrete log on a fresh toy curve every block**. Difficulty is a single integer: the bit-size `b`
of the curve's prime group order `n`. The chain doubles as a public benchmark of ECDLP-solving
capacity: the current `b` is "how large a discrete log the network solves per block interval."

Deliverable: one Go module producing one binary, `canary`, with subcommands for running a node,
mining, verifying chains and running conformance tests.

### In scope (v0.1)
- Consensus library (header format, curve derivation, puzzle, difficulty, validation).
- Chain storage, fork choice by cumulative work, reorgs.
- Parallel Pollard-rho miner.
- Peer-to-peer block relay over libp2p (§9).
- Local HTTP JSON API with benchmark stats.
- Conformance against `reference/test_vectors.json`.

### Out of scope (v0.1)
- Transactions, UTXO set, scripts, signatures, wallets, mempool. In v0.1 a block carries a list of
  **opaque byte strings** (`txs`); only the first is conventionally a coinbase. No coin accounting.
- Bitcoin wire/Core compatibility.
- Mainnet launch. Mainnet params are defined but the prototype profile is the default.

## 1. Ground rules for the implementer

1. **Go 1.25.7+ (required by go-libp2p), standard library only** for everything consensus (`crypto/sha256`, `math/big`,
   `encoding/binary`). Third-party deps are allowed only outside `internal/consensus`, and only if
   clearly justified.
2. **Consensus code is deterministic integer arithmetic.** No floats, no randomness, no map-iteration
   order dependence, no `big.Int.ProbablyPrime` (see §3.3).
3. **Test-vector first.** Milestone 1 is not done until every vector in `reference/test_vectors.json`
   passes. Never edit the vectors to make tests pass.
4. Keep miner/search code (non-consensus) separate from validation code (consensus). A block is valid
   iff `ValidateBlock` says so — how it was found is irrelevant.
5. If the spec is ambiguous, read `reference/canary.py`, match it, and leave a `// SPEC:` comment.

## 2. Parameters

| Name | Prototype (default) | Mainnet | Meaning |
|---|---|---|---|
| `Tau` | 10 s | 600 s | Target block interval |
| `Epoch` | 64 | 2016 | Blocks per difficulty epoch |
| `GenesisBits` | 36 | 64 | `b` for height 0 |
| `MinBits` | 32 | 32 | Lower clamp on `b` |
| `MaxBits` | 240 | 240 | Upper clamp on `b` |
| `MaxCurveCtr` | 2^20 | 2^20 | `curve_ctr` must be `< MaxCurveCtr` |
| `MaxStep` | 4 | 4 | Max change of `b` per retarget |
| `TimewarpSlack` | 600 s | 600 s | See §5 |
| `MTPWindow` | 11 | 11 | Median-time-past window |
| `FutureLimit` | 7200 s | 7200 s | Max seconds ahead of local clock (live blocks only) |
| Network name | `prototype` | `mainnet` | Namespaces libp2p protocol IDs and the gossip topic (§9) |
| Default P2P port | 18555 | 8555 | |
| Default API port | 18556 | 8556 | |

## 3. Primitives

### 3.1 Notation
- `H(x)` = SHA-256(x). `H2(x)` = SHA-256(SHA-256(x)).
- `‖` = byte concatenation.
- `u32le(x)` = 4-byte little-endian. `le32(x)` = 32-byte little-endian unsigned integer.
- `intBE(bytes)` = bytes read as unsigned **big-endian** integer (used only on hash outputs).
- `tag(name)` = ASCII `"canary/" + name` followed by one `0x00` byte. Tags used: `p`, `a`, `b`, `G`, `P`.
- `isqrt(x)` = ⌊√x⌋ (use `big.Int.Sqrt`).
- All hex in JSON is **raw byte order** (no Bitcoin-style reversal).

### 3.2 Elliptic curves
`E(a,b,p)`: `y² = x³ + a·x + b` over F_p, affine coordinates, identity `O`. Standard affine add /
double / negate; scalar multiplication by double-and-add. Implement with `math/big` in consensus.
Points are `(x, y)` with `0 ≤ x, y < p`, plus a distinguished identity.

### 3.3 Primality — `IsPrime(n)` (consensus-defined Baillie–PSW)
Must match `reference/canary.py:is_prime` exactly:
1. `n < 2` → false.
2. For each small prime `q` in `[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47]`: if `q | n` return `n == q`.
3. Strong Miller–Rabin to base 2. Fail → false.
4. If `n` is a perfect square → false.
5. **Strong Lucas test with Selfridge "Method A" parameters**: first `D` in `5, −7, 9, −11, 13, …`
   with Jacobi(D, n) = −1 (if Jacobi = 0 and |D| ≠ n → composite); `P = 1`, `Q = (1 − D)/4`.
   Write `n + 1 = d·2^s` with `d` odd; compute `U_d, V_d` by the binary method; prime if
   `U_d ≡ 0` or `V_{d·2^r} ≡ 0 (mod n)` for some `0 ≤ r < s`.

**Do not use `big.Int.ProbablyPrime(0)` in consensus.** Go's BPSW uses an *extra strong* Lucas test
with different parameters; it is a fine cross-check in tests but is not the consensus function.

`NextPrime3Mod4(x)` = smallest `y ≥ x` with `y ≡ 3 (mod 4)` and `IsPrime(y)`
(start at `x + ((3 − x) mod 4)`, step by 4).

### 3.4 `HashToCurve(msg, p, a, b)` (try-and-increment)
```
for i = 0, 1, 2, ...:
    I = u32le(i)
    x = intBE( H(msg ‖ I ‖ 0x00) ‖ H(msg ‖ I ‖ 0x01) ) mod p        // 512-bit integer, reduced
    r = (x³ + a·x + b) mod p
    if r == 0 or r^((p−1)/2) mod p != 1: continue                   // need a nonzero square
    y = r^((p+1)/4) mod p                                           // valid since p ≡ 3 mod 4
    if (y & 1) != (H(msg ‖ I ‖ 0x02)[0] & 1): y = p − y
    return (x, y)
```

## 4. Block format

### 4.1 Header (144 bytes, fixed)
| Offset | Field | Size | Encoding |
|---|---|---|---|
| 0 | `version` | 4 | u32le, = 1 |
| 4 | `prev_hash` | 32 | raw bytes: `H2(previous header)`; all-zero for genesis |
| 36 | `merkle_root` | 32 | raw bytes (§4.3) |
| 68 | `time` | 4 | u32le Unix seconds |
| 72 | `bits` | 4 | u32le, the bit-size `b` |
| 76 | `curve_ctr` | 4 | u32le |
| 80 | `n` | 32 | le32, claimed prime group order |
| 112 | `k` | 32 | le32, solution |

- `preHeader` = bytes `[0, 112)` (everything except `k`).
- `blockHash` = `H2(all 144 bytes)`. Identifies and links blocks; carries no work.

### 4.2 Block
`header (144 bytes)` ‖ `varint(len(txs))` ‖ for each tx: `varint(len(tx))` ‖ `tx bytes`.
`varint` = Bitcoin CompactSize. v0.1 limits: 1 ≤ `len(txs)` ≤ 1000, each tx ≤ 100 000 bytes,
serialized block ≤ 1 000 000 bytes.

### 4.3 Merkle root
Bitcoin-style: leaves `H2(tx)`; while more than one node, duplicate the last node if the count is odd,
then pair-hash `H2(left ‖ right)`. Root of a one-tx block = `H2(tx0)`.

### 4.4 Coinbase convention (not enforced in v0.1)
`"coinbase|" ‖ u32le(height) ‖ "|" ‖ minerAddressUTF8 ‖ "|" ‖ extra`. The miner identity binds to the
puzzle via `merkle_root` → `preHeader` → `P` (this is what makes a broadcast `k` unstealable).

## 5. Consensus rules

### 5.1 Curve derivation — `DeriveCurve(prevHash, b, ctr)`
```
seed = prevHash ‖ u32le(b) ‖ u32le(ctr)
N    = 2^(b−1)
p    = NextPrime3Mod4( N + intBE(H(tag("p") ‖ seed)) mod 2^(b−2) )
a    = intBE(H(tag("a") ‖ seed)) mod p
b'   = intBE(H(tag("b") ‖ seed)) mod p
if a == 0 or b' == 0 or (4a³ + 27b'²) mod p == 0:  curve is INVALID (no G)
G    = HashToCurve(tag("G") ‖ seed, p, a, b')
```
(`b'` is the curve coefficient, not the bit-size `b`.)

### 5.2 Curve/order validity — all must hold
1. Curve not invalid per §5.1.
2. `IsPrime(n)`.
3. `bitLength(n) == b`.
4. `(n − p − 1)² ≤ 4p` (Hasse interval).
5. `n ≠ p` (not anomalous).
6. `n·G == O`.
7. `p^j mod n ≠ 1` for all `j = 1..100` (embedding degree > 100).

Checks 2, 4 and 6 together prove `#E = n` without point counting: `G` has prime order `n`, `n | #E`,
and the Hasse interval (width 4√p) contains only one multiple of `n` because `n ≈ p ≫ 4√p`.
**Any** `curve_ctr < MaxCurveCtr` that passes is valid; validators must not require the smallest.

### 5.3 Puzzle
`P = HashToCurve(tag("P") ‖ H2(preHeader), p, a, b')`. Valid iff `1 ≤ k < n` and `k·G == P`.

### 5.4 Difficulty — `NextBits(chain)` for the block at height `h = len(chain)`
```
if h == 0:                return GenesisBits
prev = chain[h−1].bits
if h mod Epoch != 0:      return prev
s        = max(h − 1 − Epoch, 0)
actual   = chain[h−1].time − chain[s].time          // signed; may be ≤ 0
expected = (h − 1 − s) · Tau
actual   = clamp(actual, expected/4, 4·expected)    // integer division
actual   = max(actual, 1)
d        = RetargetDelta(expected, actual, MaxStep)
return clamp(prev + d, MinBits, MaxBits)
```
`RetargetDelta` = round(log₂((expected/actual)²)) clamped to ±MaxStep, integers only:
```
A = expected⁴ ; B = actual⁴
for d = MaxStep down to −MaxStep:
    e = 2d − 1
    if e ≥ 0: ok = A ≥ B << e
    else:     ok = (A << −e) ≥ B
    if ok: return d
return −MaxStep
```
(Rationale: rho work ∝ √n, so a work ratio r needs log₂(r²) more bits of n.)

### 5.5 Full block validation — `ValidateBlock(chain, blk, now)`
In this order (order matters only for which error is reported; vectors don't require exact strings):
1. `prev_hash == blockHash(chain tip)` (zero bytes for genesis).
2. `bits == NextBits(chain)`.
3. `0 ≤ curve_ctr < MaxCurveCtr`.
4. `len(txs) ≥ 1` and `merkle_root == MerkleRoot(txs)`; size limits of §4.2.
5. If chain non-empty: `time > median(last min(11, h) times)` where median = sorted[len/2].
6. If `h mod Epoch == 0` and chain non-empty: `time ≥ chain[h−1].time − TimewarpSlack`.
7. Live blocks only (not when replaying stored/vector chains): `time ≤ now + FutureLimit`.
8. Curve/order validity (§5.1–5.2).
9. Puzzle (§5.3).

### 5.6 Work and fork choice
`work(block) = isqrt(n)`. Chain work = sum over blocks. Nodes follow the valid chain with the most
cumulative work; ties → keep the first seen.

## 6. Mining (non-consensus; any method is fine)

### 6.1 Curve search
For `ctr = 0, 1, …`: derive the curve; cheap pre-filter: skip if `x³+ax+b` has a root mod p
(⇒ 2-torsion ⇒ even order), via `gcd(x^p − x, f)` over F_p[x]; find `m` in the Hasse interval with
`m·G = O` by baby-step giant-step (~4·p^¼ group ops); accept the first `ctr` where `m` passes §5.2.
Expected a few dozen candidates; reference takes ~0.2 s at 36–48 bits.

### 6.2 Pollard rho (distinguished points)
- `R = 32` partitions. Random table `R_j = c_j·G + d_j·P` shared by all workers of one solve.
- Walk state `X = α·G + β·P`, start random. Step: `j = X.x mod 32`, `X += R_j`, `α += c_j`, `β += d_j` (mod n).
- Distinguished if `X.x & (2^t − 1) == 0`, `t = max(2, bitLength(n)/4 − 3)`. Abandon a walk after `20·2^t` steps.
- Collect DPs in a map keyed by `x`. On a hit with equal `y`: `k = (α₁−α₂)/(β₂−β₁)`; with negated `y`:
  `k = −(α₁+α₂)/(β₁+β₂)` (mod n). Skip if the denominator is 0. Verify `k·G == P` before accepting.
- Run `--threads` goroutines; DPs flow over a channel to a collector; cancel via `context.Context`
  when solved or when a new tip arrives.
- A new block tip aborts the current solve. Restart on new transactions is optional (v0.1 has none).

### 6.3 Performance notes (optional, measure first)
`math/big` is fine for correctness. Expected rho cost ≈ √(πn/4) group ops (36 bits ≈ 2^18). A miner
fast path using fixed-width arithmetic (e.g. `math/bits` 128-bit Montgomery for p < 2^63) is welcome
**in the miner only**; results must be re-verified with the consensus `ValidateBlock` before broadcast.

## 7. Storage
- Data dir layout: `<datadir>/blocks.dat` (append-only, records = `u32le(len) ‖ block bytes`),
  `<datadir>/params.json` (the consensus params the directory was created with; opening it with
  different params is an error), `<datadir>/node.key` (libp2p identity), `<datadir>/peers.json`.
- A torn final record (short, or zero-filled after power loss) is truncated on startup; any other
  undecodable record is corruption.
- On startup, replay `blocks.dat` through validation (skip rule 7) to rebuild the block index.
- Block index in memory: `hash → {header, height, cumulativeWork, parent}`; keep side-chain blocks so
  reorgs work. Persist every valid block, including side-chain ones.

## 8. Chain manager
- `AddBlock(blk)`: if parent unknown → orphan pool (cap 100, evict oldest). Validate against the
  chain ending at its parent. If its cumulative work exceeds the tip's, reorg: switch the active chain
  to it. Then try connecting orphans whose parent is now known.
- Emit tip-change events (miner restarts, API, P2P announce).

## 9. P2P (libp2p)
Networking uses go-libp2p (TCP and QUIC transports, Noise, yamux) and go-libp2p-pubsub. This is
the justified third-party dependency of §1; nothing in `internal/consensus` depends on it. `<net>`
below is the network name from §2, so nodes of different networks never exchange messages.

- **Identity.** A persistent Ed25519 key in `<datadir>/node.key`. Peer IDs are not a trust
  boundary (§9.1).
- **Status** `/canary/<net>/status/1.0.0`: the dialer opens a stream on every new connection and
  writes its status; the listener replies with its own. Status =
  `u32le version ‖ u32le height ‖ 32B tipHash ‖ u8 len ‖ cumulativeWork (big-endian, len bytes)`,
  where height is the active chain length. Whichever side sees more cumulative work on the other
  starts a sync. Nodes repeat the exchange with every peer periodically (default 15 s) to catch
  blocks missed by gossip.
- **Sync** `/canary/<net>/sync/1.0.0`: the requester writes a block locator
  `u8 count ‖ count × 32B hash` (newest first: the last 10 active blocks, then exponentially
  sparser back to genesis, at most 32) and closes its write side. The responder finds the first
  locator hash on its active chain and replies `u32le count ‖ count × (u32le len ‖ block)` with
  the active blocks after it (from genesis if none match), at most 500 blocks and 8 MB. The
  requester repeats while it receives full batches that make progress.
- **Gossip.** GossipSub topic `/canary/<net>/blocks/1.0.0`; a message is one serialized block and
  its message ID is `SHA-256(data)`, so the same block from different publishers is one message.
  The topic validator runs `AddBlock`: invalid → reject and ban the sender; unknown parent → ignore
  and sync from the sender; duplicate → ignore; otherwise accept (and forward). A node publishes
  every block it mines.
- **Peers.** Ban (disconnect, refuse connections for 10 min) any peer that sends an invalid block or
  undecodable block bytes via gossip or sync. Max 16 peers (connection manager, and inbound
  connections refused at the limit). Static `--peers` multiaddrs plus the addresses saved in
  `peers.json` at shutdown; static peers are redialled when the node has no connections. Liveness
  uses libp2p's built-in ping.

### 9.1 Cryptographic assumptions
- Consensus security rests on SHA-256 only (hashing, merkle roots, curve and puzzle derivation).
  Grover's algorithm leaves about 128-bit preimage security, which is sufficient. The puzzle curves are
  meant to be broken and are not a security assumption.
- P2P identities (Ed25519) and transport key exchange are classical and quantum-vulnerable; go-libp2p
  offers no post-quantum key type. This is acceptable because they protect nothing consensus-critical:
  every block is validated regardless of sender, bans are only DoS mitigation, and relayed data is
  public.
- **Future transactions must use post-quantum signatures from day one** (e.g. SLH-DSA / FIPS 205,
  which relies only on hash security, or ML-DSA / FIPS 204). A chain that measures progress towards
  breaking elliptic curves must not secure its own coins with them. The current block and transaction
  size limits (§4.2) will need revisiting for those signature sizes.

## 10. HTTP API (localhost only by default)
| Method | Path | Returns |
|---|---|---|
| GET | `/tip` | `{height, hash, bits, time, cumulativeWork}` |
| GET | `/block/{height or hash}` | block JSON (§11 format) |
| GET | `/stats` | `{bits, epoch, blocksInEpoch, avgInterval, capacityOpsPerSec, secp256k1Distance}` where capacity = √(πn/4)/avgInterval averaged over current epoch, distance = 256 − bits |
| GET | `/peers` | connected peers |
| POST | `/submitblock` | body = block hex; validates and relays |

## 11. JSON chain format (interop with the Python reference)
```json
{"params": {...}, "blocks": [{"hash": "...", "header_hex": "...", "version": 1, "prev_hash": "...",
  "merkle_root": "...", "time": 0, "bits": 36, "curve_ctr": 0, "n": "decimal", "k": "decimal",
  "txs": ["hex", ...]}]}
```
`header_hex` + `txs` are authoritative; other fields are informational. `params` keys:
`tau, epoch, genesis_bits, min_bits, max_bits, max_curve_ctr, max_step, timewarp_slack, mtp_window, future_limit`.

## 12. CLI
```
canary node    [--datadir DIR] [--listen MULTIADDR,...] [--api 127.0.0.1:18556]
              [--peers MULTIADDR/p2p/ID,...] [--mine] [--miner-address STR] [--threads N]
              [--profile prototype|mainnet]
canary mine    --chain FILE.json [--blocks N] [--threads N] [--miner-address STR]   # offline, like reference
canary verify  FILE.json                                                             # prints cumulative work
canary export  --datadir DIR FILE.json
canary vectors [reference/test_vectors.json]                                         # conformance run
```

## 13. Suggested layout
```
cmd/canary/main.go
internal/consensus/   params.go hash.go prime.go curve.go h2c.go header.go block.go merkle.go
                      difficulty.go validate.go work.go  (+ *_test.go, vectors_test.go)
internal/miner/       curvesearch.go rho.go miner.go
internal/chain/       index.go manager.go store.go
internal/p2p/         wire.go gater.go identity.go node.go
internal/node/        node.go   (chain + p2p + mining loop)
internal/api/         server.go
internal/chainjson/   format.go
reference/            canary.py gen_vectors.py test_vectors.json   (do not modify)
```

## 14. Test vectors — `reference/test_vectors.json`
| Key | Contents | Test |
|---|---|---|
| `params` | prototype params | Load into `Params` |
| `primality[]` | `{n, prime}` and `{next_prime_3mod4_of, result}` | `IsPrime`, `NextPrime3Mod4`; also cross-check with `ProbablyPrime(0)` in tests |
| `retarget_delta[]` | `{expected, actual_clamped, delta}` | `RetargetDelta(expected, actual_clamped, 4) == delta` |
| `curves[]` | `{prev_hash, bits, curve_ctr, p, a, b, G}`; entries with `"valid": true` also have `n` | `DeriveCurve` reproduces `p,a,b,G` (`G` null ⇒ invalid curve); valid entries pass §5.2; miner search finds the same first `curve_ctr` |
| `hash_to_curve[]` | `{msg, p, a, b, x, y}` | `HashToCurve` |
| `chain.blocks[]` | 70 blocks, genesis at 36 bits, retarget to 40 at height 64 | Full replay validates; `cumulative_work` matches; block hashes match |
| `invalid_blocks` | `parent_height` + `cases[] {name, header_hex, txs, reason}` | Each case, validated on top of `chain.blocks[0..parent_height]`, is rejected. `reason` is informative only |

Regenerate only via `python3 reference/gen_vectors.py` (re-mines; output differs run to run but is
always self-consistent). The checked-in file is canonical.

## 15. Milestones and acceptance criteria
Work in this order; each milestone ends with green `go test ./...` and `go vet ./...`.

**M1 — Consensus library.** All of §3–§5 in `internal/consensus`. `canary vectors` passes every
primality, retarget, curve, hash-to-curve and chain vector, and rejects every invalid case.
Fuzz test: header deserialize/serialize round-trip; `ValidateBlock` never panics on random bytes.

**M2 — Offline mining + JSON interop.** `canary mine --chain x.json --blocks 10` produces a chain that
`canary verify` accepts **and** that `python3 reference/canary.py verify x.json` accepts. Curve search
for each `"valid": true` curve vector returns the same `curve_ctr`. Rho solves 36-bit blocks in a few
seconds on a laptop with `--threads` = cores.

**M3 — Storage + chain manager.** Restart-safe datadir; reorg test: build two forks in-process,
feed the heavier one second, tip switches; orphan handling test.

**M4 — P2P.** Integration test spinning up 3 nodes on localhost (one mining): all converge on the same
tip within 30 s; a node started later syncs from scratch; a peer sending an invalid block is dropped.

**M5 — API + stats.** Endpoints of §10; `/stats` numbers sanity-checked against a known chain.

## 16. Known limitations (by design for v0.1)
- Mining is not progress-free; larger miners win super-linearly. Accepted (benchmark goal).
- No transactions or coin accounting yet; `txs` are opaque.
- Whole-bit difficulty: block times can oscillate ≈ ±20% between epochs.
- Inherited assumptions: timestamps can be gamed within MTP/future limits as in Bitcoin.
