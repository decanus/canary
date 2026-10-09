# Canary

Canary is a minimal blockchain node whose proof of work is **solving an elliptic-curve discrete
logarithm on a fresh toy curve every block**.

Each block derives a new curve from the previous block hash, and the miner must find `k` such that
`k·G = P`, where `P` is a point hashed from the block's own header. Difficulty is a single integer:
the bit-size `b` of the curve's prime group order `n`. Because the cost of the best generic attack
(Pollard rho) is about √n, the current `b` is a public, continuously updated measurement of
how large a discrete log the network can solve per block interval. It's a canary for ECDLP
capacity, and `256 − b` is the distance to secp256k1.

> **Status:** prototype, milestone M1 of 5 (consensus library) is done. There are no transactions,
> coins or wallets; a block carries opaque byte strings. Not for production use.

## How it works

| Step | What happens | Spec |
|---|---|---|
| Curve | `seed = prev_hash ‖ bits ‖ curve_ctr` is hashed into a prime `p ≡ 3 (mod 4)` of `b` bits and coefficients `a, b`. A base point `G` is hashed onto the curve. | §5.1 |
| Order | The miner searches `curve_ctr` until the curve has a **prime** order `n` of exactly `b` bits, and puts `n` in the header. Validators check `n` cheaply (`n` prime, `n·G = O`, Hasse bound, not anomalous, embedding degree > 100) without point counting. | §5.2 |
| Puzzle | `P = HashToCurve(H2(header without k))`. The solution `k` goes in the header. Because `P` commits to the merkle root, and so to the coinbase, a broadcast `k` can't be stolen by another miner. | §5.3 |
| Difficulty | Every `Epoch` blocks, `b` moves by `round(log₂((expected/actual)²))`, clamped to ±4, since rho work ∝ √n. | §5.4 |
| Fork choice | `work(block) = isqrt(n)`; the valid chain with the most cumulative work wins. | §5.6 |

The block header is a fixed 144 bytes: version, prev hash, merkle root, time, bits, curve
counter, `n` and `k`. Blocks are linked by `H2(header)`, which carries no work itself.

## Repository layout

```
cmd/canary/             CLI entry point
internal/consensus/     consensus rules: hashing, BPSW primality, curves, hash-to-curve,
                        header/block encoding, merkle, difficulty, validation, work
internal/chainjson/     chain JSON format shared with the Python reference
internal/conformance/   runner for reference/test_vectors.json
reference/              Python reference implementation (the consensus oracle) and vectors
SPEC.md                 build spec, the source of truth
```

Consensus code is standard library only, uses deterministic integer arithmetic and no
`big.Int.ProbablyPrime`, because Go's BPSW uses a different Lucas test from the consensus one
(see SPEC.md §3.3).

## Usage

Requires Go 1.22+. The Python reference needs Python 3.8+ and no dependencies.

```sh
go test ./...                                    # unit, vector and fuzz-seed tests
go run ./cmd/canary vectors                      # conformance run against reference/test_vectors.json
go run ./cmd/canary verify chain.json            # validate a chain file, print cumulative work

python3 reference/canary.py mine chain.json -n 5 # mine with the reference miner
python3 reference/canary.py verify chain.json    # cross-check with the reference
```

Fuzzing:

```sh
go test ./internal/consensus -fuzz FuzzValidateBlock
go test ./internal/consensus -fuzz FuzzBlockRoundTrip
```

## Parameters

| | Prototype (default) | Mainnet |
|---|---|---|
| Target block interval | 10 s | 600 s |
| Epoch | 64 blocks | 2016 blocks |
| Genesis bits | 36 | 64 |
| Bits range | 32–240 | 32–240 |
| Network magic | `0xCA4A2701` | `0xCA4A2700` |

## Roadmap

- [x] **M1** Consensus library, passing all reference vectors
- [ ] **M2** Offline mining (curve search + parallel Pollard rho) and JSON interop with the reference
- [ ] **M3** Block storage, chain manager, reorgs
- [ ] **M4** TCP peer-to-peer block relay
- [ ] **M5** Local HTTP API with benchmark stats

## Known limitations

These are by design for v0.1:

- Mining isn't progress-free, so larger miners win super-linearly. That's acceptable for a
  benchmark chain.
- Difficulty moves in whole bits, so block times can swing by about ±20% between epochs.
- Timestamps can be gamed within the median-time-past and future limits, as in Bitcoin.
