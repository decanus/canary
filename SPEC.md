# Canary — Go Build Spec (v0.2, prototype)

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

### In scope (v0.2)
- Consensus library (header format, curve derivation, puzzle, difficulty, validation).
- **Accounts and coins (v0.2):** account-model state (balance, nonce) committed by a state root in
  every header, transfers signed with post-quantum SLH-DSA, issuance proportional to work (§4.4,
  §5.7–§5.8).
- Chain storage, fork choice by cumulative work, reorgs.
- Parallel Pollard-rho miner.
- Peer-to-peer block relay over libp2p (§9).
- Local HTTP JSON API with benchmark stats.
- Conformance against `reference/test_vectors.json`.

### Out of scope (v0.2)
- Scripts, smart contracts, multisig, coinbase maturity.
- Wallet, mempool and transaction relay are the next steps after the v0.2 consensus changes.
- Bitcoin wire/Core compatibility.
- Mainnet launch. Mainnet params are defined but the prototype profile is the default.

## 1. Ground rules for the implementer

1. **Go 1.25.7+ (required by go-libp2p), standard library only** for everything consensus (`crypto/sha256`, `math/big`,
   `encoding/binary`), with one exception: SLH-DSA verification uses
   `github.com/cloudflare/circl/sign/slhdsa` (the Go standard library has no SLH-DSA). The Python
   reference implements SLH-DSA itself and is checked against the NIST ACVP vectors. Third-party deps are allowed only outside `internal/consensus`, and only if
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

### 4.1 Header (176 bytes, fixed)
| Offset | Field | Size | Encoding |
|---|---|---|---|
| 0 | `version` | 4 | u32le, = 2 |
| 4 | `prev_hash` | 32 | raw bytes: `H2(previous header)`; all-zero for genesis |
| 36 | `merkle_root` | 32 | raw bytes (§4.3) |
| 68 | `state_root` | 32 | raw bytes: root of the account state *after* this block (§5.7) |
| 100 | `time` | 4 | u32le Unix seconds |
| 104 | `bits` | 4 | u32le, the bit-size `b` |
| 108 | `curve_ctr` | 4 | u32le |
| 112 | `n` | 32 | le32, claimed prime group order |
| 144 | `k` | 32 | le32, solution |

- `preHeader` = bytes `[0, 144)` (everything except `k`).
- `blockHash` = `H2(all 176 bytes)`. Identifies and links blocks; carries no work.

### 4.2 Block
`header (176 bytes)` ‖ `varint(len(txs))` ‖ for each tx: `varint(len(tx))` ‖ `tx bytes`.
`varint` = Bitcoin CompactSize. Limits: 1 ≤ `len(txs)` ≤ 1000, each tx ≤ 100 000 bytes,
serialized block ≤ 1 000 000 bytes.

### 4.3 Merkle root
Bitcoin-style: leaves `H2(tx)`; while more than one node, duplicate the last node if the count is odd,
then pair-hash `H2(left ‖ right)`. Root of a one-tx block = `H2(tx0)`.

### 4.4 Transactions
All integers are little-endian; `u128` is 16 bytes. Every byte of a transaction is significant:
lengths are exact, and unknown `kind` or `scheme` values, or trailing bytes, are invalid.

**Keys and addresses.** Scheme `1` = SLH-DSA-SHA2-128s (FIPS 205; public key 32 B, signature
7 856 B). `address = H(tag("addr") ‖ u8 scheme ‖ pubkey)` (32 bytes). The scheme byte leaves room
for future schemes; it is part of the address so the same key bytes can never mean two things.

**Coinbase** (`kind = 0`), exactly once, as `txs[0]` (55–119 bytes):
`u8 kind=0 ‖ u32 height ‖ 32B to ‖ u128 amount ‖ u8 extraLen ‖ extra` with `extraLen ≤ 64`.
`height` must equal the block height. The recipient binds to the puzzle via `merkle_root` →
`preHeader` → `P`, which is what makes a broadcast `k` unstealable.

**Transfer** (`kind = 1`, 7 962 bytes):
`u8 kind=1 ‖ u8 scheme=1 ‖ 32B pubkey ‖ 32B to ‖ u128 amount ‖ u128 fee ‖ u64 nonce ‖ sig`.
- `body` = the transfer without `sig`; `digest = H(tag("tx") ‖ genesisHash ‖ body)`, where
  `genesisHash` is the `blockHash` of the chain's height-0 block (replay protection across chains).
- `sig` is the FIPS 205 *pure* SLH-DSA signature of the 32-byte `digest` with an empty context
  string (i.e. over `M' = 0x00 ‖ 0x00 ‖ digest`). Hedged and deterministic signatures both verify.
- The genesis block may contain only its coinbase.

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
8. `version == 2`; every tx decodes (§4.4); `txs[0]` is the only coinbase and its `height` is `h`;
   no transfers in the genesis block.
9. Curve/order validity (§5.1–5.2).
10. Puzzle (§5.3).
11. State transition (§5.7) succeeds from the parent's state and the result's root equals
    `state_root`. (After the puzzle so that expensive signature checks cost the sender a solved
    block.)

### 5.6 Work and fork choice
`work(block) = isqrt(n)`. Chain work = sum over blocks. Nodes follow the valid chain with the most
cumulative work; ties → keep the first seen.

### 5.7 Accounts and state
State maps `address → (balance u128, nonce u64)`; an absent account is `(0, 0)`, and an account
that returns to `(0, 0)` is removed. The state before genesis is empty. A block is applied to its
parent's state as follows:

1. For each transfer, in block order: `from = address(scheme, pubkey)`; the signature verifies
   (§4.4); `nonce == state[from].nonce`; `amount + fee ≤ state[from].balance`. Then
   `state[from] = (balance − amount − fee, nonce + 1)` and `state[to].balance += amount`. Any
   failure, or a result above `2^128 − 1` (balance) or `2^64 − 1` (nonce), invalidates the block.
   Self-transfers are allowed.
2. The coinbase must pay exactly `amount == reward + Σ fees` (§5.8). It is credited **after** all
   transfers, so a block cannot spend its own reward.

**State root**: a compact sparse Merkle tree keyed by the 256 address bits, most significant bit
first (bit `i` = `(addr[i/8] >> (7 − i mod 8)) & 1`):
```
leaf(a)      = H(tag("leaf") ‖ address ‖ u128 balance ‖ u64 nonce)
node(L, R)   = H(tag("node") ‖ L ‖ R)
root(S, d)   = 32 zero bytes                              if S is empty
             = leaf(a)                                    if S = {a}
             = node(root(S0, d+1), root(S1, d+1))         otherwise, S0/S1 = accounts with bit d = 0/1
state_root   = root(all accounts, 0)
```
The root is independent of insertion order, and inclusion and absence proofs are possible later
without a format change.

### 5.8 Issuance
`reward(block) = work(block) = isqrt(n)` base units. Fees go to the miner. Hence **total supply
equals cumulative chain work**: one unit of currency is one unit of discrete-log work. Rewards grow
about 2× per 2 bits of difficulty, which is why amounts are `u128`.

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

### 8.1 Mempool (non-consensus)
- Transfers are queued per sender in nonce order with no gaps, starting at the account nonce, and
  a sender's queued transfers must be affordable together. Limits: 5 000 transfers, 64 per sender;
  when full, the lowest-fee queue tail is evicted for a higher fee.
- A transfer with the same sender and nonce replaces a queued one only with a strictly higher fee.
- On every tip change, mined and no longer valid transfers are dropped. (Transfers from blocks a
  reorg removes are not re-queued in v0.2.)
- Miners select by fee across senders, nonce order within a sender, re-checked against the exact
  state they mine on.

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
- **Transactions.** GossipSub topic `/canary/<net>/txs/1.0.0`; a message is one serialized
  transfer. The validator adds it to the mempool: bad encoding or signature → reject and ban the
  sender; state-dependent failures (nonce, balance, pool full) → ignore, since honest nodes can
  briefly disagree about state; otherwise accept and forward.
- **Peers.** Ban (disconnect, refuse connections for 10 min) any peer that sends an invalid block,
  undecodable block bytes, or a badly encoded or badly signed transfer. Max 16 peers (connection manager, and inbound
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
- **Transactions use post-quantum signatures from day one:** SLH-DSA-SHA2-128s (FIPS 205), whose
  security rests only on SHA-256, the same assumption as the rest of consensus. A chain that
  measures progress towards breaking elliptic curves must not secure its own coins with them.

## 10. HTTP API (localhost only by default)
| Method | Path | Returns |
|---|---|---|
| GET | `/tip` | `{height, hash, genesis, bits, time, cumulativeWork, mempool}` |
| GET | `/account/{addr}` | `{address, balance, nonce, nextNonce}`; `nextNonce` counts mempool transfers |
| POST | `/tx` | body = transfer hex; adds it to the mempool and relays it → `{id}` (`H2(tx)`) |
| GET | `/block/{height or hash}` | block JSON (§11 format) |
| GET | `/stats` | `{bits, epoch, blocksInEpoch, avgInterval, capacityOpsPerSec, secp256k1Distance}` where capacity = √(πn/4)/avgInterval averaged over current epoch, distance = 256 − bits |
| GET | `/peers` | connected peers |
| POST | `/submitblock` | body = block hex; validates and relays |

## 11. JSON chain format (interop with the Python reference)
```json
{"params": {...}, "blocks": [{"hash": "...", "header_hex": "...", "version": 2, "prev_hash": "...",
  "merkle_root": "...", "state_root": "...", "time": 0, "bits": 36, "curve_ctr": 0,
  "n": "decimal", "k": "decimal", "txs": ["hex", ...]}]}
```
`header_hex` + `txs` are authoritative; other fields are informational. `params` keys:
`tau, epoch, genesis_bits, min_bits, max_bits, max_curve_ctr, max_step, timewarp_slack, mtp_window, future_limit`.

## 12. CLI
```
canary node    [--datadir DIR] [--listen MULTIADDR,...] [--api 127.0.0.1:18556]
              [--peers MULTIADDR/p2p/ID,...] [--mine --miner-address ADDR] [--threads N]
              [--profile prototype|mainnet]
canary mine    --chain FILE.json --miner-address ADDR [--blocks N] [--threads N]   # offline, like reference
canary keygen  --out FILE                                                           # SLH-DSA key, prints address
canary address --key FILE
canary balance [--api URL] ADDR
canary send    --key FILE --to ADDR --amount N [--fee N] [--api URL]                # sign + submit
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
internal/node/        node.go   (chain + mempool + p2p + API + mining loop)
internal/mempool/     pool.go
internal/wallet/      key.go
internal/api/         server.go client.go
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
| `keys[]` | `{sk_seed, sk_prf, pk_seed, pubkey, address}` | SLH-DSA keygen from seeds and `address` |
| `state_roots[]` | `{accounts [[address, balance, nonce]], root}` | `StateRoot` |
| `transactions[]` | transfers `{genesis_hash, tx, sender, to, amount, fee, nonce, digest, valid_signature}` and a coinbase | Decode, re-encode, digest, signature check |
| `chain` | 70 blocks (genesis at 36 bits, retarget to 40 at height 64) with transfers in blocks 3, 4 and 69; `cumulative_work`, `supply`, final `state` | Full replay validates; hashes, work, supply (= work) and state match |
| `invalid_blocks.cases[]` | `{name, parent_height, header_hex, txs, reason}` | Each case, validated on `chain.blocks[0..parent_height]` and its state, is rejected (`reason` is informative). State-rule cases carry a valid puzzle so they fail only at rule 11 |

The Python SLH-DSA is separately checked against NIST ACVP vectors (`reference/test_slhdsa.py`,
`reference/testdata/`).

Regenerate only via `cd reference && python3 gen_vectors.py` (re-mines and re-signs, about 10
minutes; output differs run to run but is always self-consistent). The checked-in file is canonical.

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

**A1 — Accounts (consensus, v0.2).** §4.4 and §5.7–§5.8 in the Python reference (with its own
SLH-DSA, passing the NIST ACVP vectors) and in Go; regenerated vectors pass in both; a Go-signed
transfer in a Go-mined chain verifies in Python.

**A2 — Wallet, mempool and transaction relay.** Key management and transfer creation in the CLI, a
mempool with nonce ordering and fee priority, a GossipSub transaction topic, and miners including
mempool transfers.

## 16. Known limitations (by design for v0.2)
- The state root is recomputed from scratch each block (O(accounts · log accounts) hashes); an
  incremental tree is an implementation change, not a format change.
- No coinbase maturity: a reorg can undo rewards that were already spent.
- Mining is not progress-free; larger miners win super-linearly. Accepted (benchmark goal).
- SLH-DSA signing is slow (about 3 s per signature in Go, 7 s in the Python reference);
  verification is fast (about 2.5 ms in Go). Signatures dominate block space: about 125 transfers per
  1 MB block.
- Whole-bit difficulty: block times can oscillate ≈ ±20% between epochs.
- Inherited assumptions: timestamps can be gamed within MTP/future limits as in Bitcoin.
