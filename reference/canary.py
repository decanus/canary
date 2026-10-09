#!/usr/bin/env python3
"""
Canary reference implementation (prototype profile).

Proof of work = solve an elliptic-curve discrete log on a fresh toy curve per block.
Difficulty = one integer: the bit-size b of the curve's group order n.

Consensus-relevant pieces (must match the spec bit for bit):
  serialization, H/H2, is_prime (BPSW), next_prime_3mod4, derive_curve,
  hash_to_curve, check_curve, puzzle_point, retarget_delta, next_bits,
  block_work, validate_block / validate_chain.

Non-consensus pieces (any method is fine):
  find_curve (point counting via BSGS), rho miner, CLI.

Pure Python 3.8+, no dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import random
import struct
import sys
import time
from dataclasses import dataclass, field
from math import isqrt

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Params:
    tau: int = 10                # target block time, seconds
    epoch: int = 64              # retarget interval, blocks
    genesis_bits: int = 36       # starting bit-size of n
    min_bits: int = 32
    max_bits: int = 240
    max_curve_ctr: int = 1 << 20
    max_step: int = 4            # max bits change per retarget
    timewarp_slack: int = 600    # first block of epoch >= prev time - slack
    mtp_window: int = 11
    future_limit: int = 2 * 3600


PROTOTYPE = Params()
MAINNET = Params(tau=600, epoch=2016, genesis_bits=64)

# ---------------------------------------------------------------------------
# Hashing and serialization
# ---------------------------------------------------------------------------


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def H2(b: bytes) -> bytes:
    return H(H(b))


def tag(name: str) -> bytes:
    return b"canary/" + name.encode() + b"\x00"


def u32(x: int) -> bytes:
    return struct.pack("<I", x)


def int_be(b: bytes) -> int:
    return int.from_bytes(b, "big")


def le32(x: int) -> bytes:
    return x.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Primality: Baillie-PSW (consensus-defined)
# ---------------------------------------------------------------------------

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def _jacobi(a: int, n: int) -> int:
    assert n > 0 and n % 2 == 1
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def _mr_base2(n: int) -> bool:
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    x = pow(2, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(s - 1):
        x = x * x % n
        if x == n - 1:
            return True
    return False


def _strong_lucas(n: int) -> bool:
    # Selfridge method A: first D in 5, -7, 9, -11, ... with jacobi(D, n) = -1
    D = 5
    while True:
        j = _jacobi(D, n)
        if j == -1:
            break
        if j == 0 and abs(D) != n:
            return False
        D = -D - 2 if D > 0 else -D + 2
    P, Q = 1, (1 - D) // 4
    d, s = n + 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def half(x: int) -> int:
        if x % 2:
            x += n
        return (x // 2) % n

    U, V, Qk = 1, P, Q % n
    for bit in bin(d)[3:]:
        U, V = U * V % n, (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if bit == "1":
            U, V = half(P * U + V), half(D * U + P * V)
            Qk = Qk * Q % n
    if U == 0 or V == 0:
        return True
    for _ in range(s - 1):
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if V == 0:
            return True
    return False


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    if not _mr_base2(n):
        return False
    r = isqrt(n)
    if r * r == n:
        return False
    return _strong_lucas(n)


def next_prime_3mod4(x: int) -> int:
    y = x + ((3 - x) % 4)
    while not is_prime(y):
        y += 4
    return y


# ---------------------------------------------------------------------------
# Elliptic curve arithmetic (short Weierstrass, affine, None = infinity)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int
    G: tuple

    def on_curve(self, P) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


def ec_neg(C: Curve, P):
    return None if P is None else (P[0], (-P[1]) % C.p)


def ec_add(C: Curve, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    p = C.p
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + C.a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def ec_mul(C: Curve, k: int, P):
    R = None
    if k < 0:
        k, P = -k, ec_neg(C, P)
    while k:
        if k & 1:
            R = ec_add(C, R, P)
        P = ec_add(C, P, P)
        k >>= 1
    return R


def hash_to_curve(msg: bytes, p: int, a: int, b: int):
    i = 0
    while True:
        ib = u32(i)
        x = int_be(H(msg + ib + b"\x00") + H(msg + ib + b"\x01")) % p
        r = (x * x * x + a * x + b) % p
        if r != 0 and pow(r, (p - 1) // 2, p) == 1:
            y = pow(r, (p + 1) // 4, p)
            if (y & 1) != (H(msg + ib + b"\x02")[0] & 1):
                y = p - y
            return (x, y)
        i += 1


# ---------------------------------------------------------------------------
# Curve derivation and validity (consensus)
# ---------------------------------------------------------------------------


def curve_seed(prev_hash: bytes, bits: int, ctr: int) -> bytes:
    return prev_hash + u32(bits) + u32(ctr)


def derive_curve(prev_hash: bytes, bits: int, ctr: int) -> Curve:
    seed = curve_seed(prev_hash, bits, ctr)
    N = 1 << (bits - 1)
    p = next_prime_3mod4(N + int_be(H(tag("p") + seed)) % (1 << (bits - 2)))
    a = int_be(H(tag("a") + seed)) % p
    b = int_be(H(tag("b") + seed)) % p
    if a == 0 or b == 0 or (4 * a ** 3 + 27 * b * b) % p == 0:
        G = None  # invalid curve; check_curve rejects it
    else:
        G = hash_to_curve(tag("G") + seed, p, a, b)
    return Curve(p, a, b, G)


EMBEDDING_MIN = 100


def check_curve(C: Curve, n: int, bits: int) -> str | None:
    """Return None if (C, n) passes every consensus check, else a reason."""
    p, a, b = C.p, C.a, C.b
    if a == 0 or b == 0 or (4 * a ** 3 + 27 * b * b) % p == 0 or C.G is None:
        return "singular or excluded curve"
    if not is_prime(n):
        return "n not prime"
    if n.bit_length() != bits:
        return "n has wrong bit length"
    if (n - p - 1) ** 2 > 4 * p:
        return "n outside Hasse interval"
    if n == p:
        return "anomalous curve"
    if ec_mul(C, n, C.G) is not None:
        return "n*G != O"
    t = 1
    for _ in range(EMBEDDING_MIN):
        t = t * p % n
        if t == 1:
            return "embedding degree too small"
    return None


# ---------------------------------------------------------------------------
# Curve search (miner side, non-consensus): BSGS order of G in Hasse interval
# ---------------------------------------------------------------------------


def _has_2torsion(p: int, a: int, b: int) -> bool:
    """True if x^3+ax+b has a root mod p (=> #E even => not prime order)."""
    # compute x^p mod f, f = x^3 + a x + b, polys as [c0, c1, c2]
    def mulmod(u, v):
        r = [0] * 5
        for i in range(3):
            for j in range(3):
                r[i + j] = (r[i + j] + u[i] * v[j]) % p
        for d in (4, 3):  # x^3 = -a x - b
            c = r[d]
            if c:
                r[d] = 0
                r[d - 2] = (r[d - 2] - c * a) % p
                r[d - 3] = (r[d - 3] - c * b) % p
        return r[:3]

    res, base, e = [1, 0, 0], [0, 1, 0], p
    while e:
        if e & 1:
            res = mulmod(res, base)
        base = mulmod(base, base)
        e >>= 1
    g = [res[0], (res[1] - 1) % p, res[2]]  # x^p - x mod f
    # gcd(g, f) nontrivial?  f monic cubic, g degree <= 2
    def polymod(u, v):
        u = u[:]
        while len(u) >= len(v) and any(u):
            if u[-1] == 0:
                u.pop()
                continue
            c = u[-1] * pow(v[-1], -1, p) % p
            s = len(u) - len(v)
            for i in range(len(v)):
                u[s + i] = (u[s + i] - c * v[i]) % p
            u.pop()
        while u and u[-1] == 0:
            u.pop()
        return u

    def trim(u):
        u = u[:]
        while u and u[-1] == 0:
            u.pop()
        return u

    A, B = [b % p, a % p, 0, 1], trim(g)
    if not B:
        return True  # x^p - x divisible by f: all roots in F_p
    while B:
        A, B = B, polymod(A, B)
    return len(A) > 1


def order_in_hasse(C: Curve) -> int | None:
    """Find m in the Hasse interval with m*G = O via baby-step giant-step."""
    p = C.p
    r = isqrt(4 * p) + 1
    lo, hi = p + 1 - r, p + 1 + r
    m = isqrt(hi - lo) + 1
    baby = {}
    P = None
    for j in range(m + 1):
        if P is None:
            if j:
                return j  # tiny order; never prime-size here
        else:
            baby.setdefault(P[0], (j, P[1]))
        P = ec_add(C, P, C.G)
    step = ec_mul(C, m, C.G)
    S = ec_mul(C, lo, C.G)
    for i in range((hi - lo) // m + 2):
        base = lo + i * m
        if S is None:
            return base
        hit = baby.get(S[0])
        if hit:
            j, yj = hit
            # S = base*G. If S == -jG then (base+j)G=O ; if S == jG then (base-j)G=O
            cand = base + j if S[1] != yj else base - j
            if lo <= cand <= hi and ec_mul(C, cand, C.G) is None:
                return cand
        S = ec_add(C, S, step)
    return None


def find_curve(prev_hash: bytes, bits: int, params: Params = PROTOTYPE):
    for ctr in range(params.max_curve_ctr):
        C = derive_curve(prev_hash, bits, ctr)
        if C.G is None or _has_2torsion(C.p, C.a, C.b):
            continue
        n = order_in_hasse(C)
        if n is None:
            continue
        if check_curve(C, n, bits) is None:
            return ctr, C, n
    raise RuntimeError("no valid curve found")


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------

HEADER_SIZE = 144


@dataclass
class Header:
    version: int
    prev_hash: bytes
    merkle_root: bytes
    time: int
    bits: int
    curve_ctr: int
    n: int
    k: int

    def pre_header(self) -> bytes:
        return (u32(self.version) + self.prev_hash + self.merkle_root + u32(self.time)
                + u32(self.bits) + u32(self.curve_ctr) + le32(self.n))

    def serialize(self) -> bytes:
        return self.pre_header() + le32(self.k)

    def hash(self) -> bytes:
        return H2(self.serialize())

    @classmethod
    def deserialize(cls, b: bytes) -> "Header":
        assert len(b) == HEADER_SIZE
        v, = struct.unpack_from("<I", b, 0)
        t, bits, ctr = struct.unpack_from("<III", b, 68)
        return cls(v, b[4:36], b[36:68], t, bits, ctr,
                   int.from_bytes(b[80:112], "little"), int.from_bytes(b[112:144], "little"))


@dataclass
class Block:
    header: Header
    txs: list = field(default_factory=list)  # list of bytes; txs[0] = coinbase

    def to_json(self) -> dict:
        h = self.header
        return {
            "hash": h.hash().hex(),            # raw byte order (no Bitcoin-style reversal)
            "header_hex": h.serialize().hex(),
            "version": h.version, "prev_hash": h.prev_hash.hex(),
            "merkle_root": h.merkle_root.hex(), "time": h.time, "bits": h.bits,
            "curve_ctr": h.curve_ctr, "n": str(h.n), "k": str(h.k),
            "txs": [t.hex() for t in self.txs],
        }

    @classmethod
    def from_json(cls, d: dict) -> "Block":
        return cls(Header.deserialize(bytes.fromhex(d["header_hex"])),
                   [bytes.fromhex(t) for t in d["txs"]])


def merkle_root(txs: list) -> bytes:
    layer = [H2(t) for t in txs]
    if not layer:
        return b"\x00" * 32
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [H2(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def coinbase(height: int, miner: str, extra: bytes = b"") -> bytes:
    return b"coinbase|" + u32(height) + b"|" + miner.encode() + b"|" + extra


def puzzle_point(C: Curve, h: Header):
    return hash_to_curve(tag("P") + H2(h.pre_header()), C.p, C.a, C.b)


def block_work(h: Header) -> int:
    return isqrt(h.n)


# ---------------------------------------------------------------------------
# Difficulty (consensus)
# ---------------------------------------------------------------------------


def retarget_delta(expected: int, actual: int, max_step: int = 4) -> int:
    """
    Round(log2((expected/actual)^2)) clamped to [-max_step, max_step], integers only.
    Work scales as sqrt(n); n-bits change = 2*log2(work ratio).
    Picks the largest d with (expected/actual)^4 >= 2^(2d-1).
    """
    A, B = expected ** 4, actual ** 4
    for d in range(max_step, -max_step - 1, -1):
        e = 2 * d - 1
        if (A >= B << e) if e >= 0 else ((A << -e) >= B):
            return d
    return -max_step


def next_bits(chain: list, params: Params) -> int:
    """bits required for block at height len(chain)."""
    h = len(chain)
    if h == 0:
        return params.genesis_bits
    prev = chain[-1].header.bits
    if h % params.epoch != 0:
        return prev
    s = max(h - 1 - params.epoch, 0)
    actual = chain[h - 1].header.time - chain[s].header.time
    expected = (h - 1 - s) * params.tau
    actual = max(expected // 4, min(actual, 4 * expected))
    actual = max(actual, 1)
    d = retarget_delta(expected, actual, params.max_step)
    return max(params.min_bits, min(params.max_bits, prev + d))


# ---------------------------------------------------------------------------
# Validation (consensus)
# ---------------------------------------------------------------------------


class Invalid(Exception):
    pass


def validate_block(chain: list, blk: Block, params: Params = PROTOTYPE,
                   now: int | None = None) -> None:
    h = blk.header
    height = len(chain)
    prev_hash = chain[-1].header.hash() if chain else b"\x00" * 32
    if h.prev_hash != prev_hash:
        raise Invalid("prev_hash mismatch")
    if h.bits != next_bits(chain, params):
        raise Invalid(f"bits {h.bits} != required {next_bits(chain, params)}")
    if not (0 <= h.curve_ctr < params.max_curve_ctr):
        raise Invalid("curve_ctr out of range")
    if not blk.txs or merkle_root(blk.txs) != h.merkle_root:
        raise Invalid("merkle_root mismatch")
    # timestamps
    if chain:
        window = [b.header.time for b in chain[-params.mtp_window:]]
        mtp = sorted(window)[len(window) // 2]
        if h.time <= mtp:
            raise Invalid("time <= median time past")
        if height % params.epoch == 0 and h.time < chain[-1].header.time - params.timewarp_slack:
            raise Invalid("timewarp rule")
    if now is not None and h.time > now + params.future_limit:
        raise Invalid("time too far in future")
    # curve + order
    C = derive_curve(h.prev_hash, h.bits, h.curve_ctr)
    reason = check_curve(C, h.n, h.bits)
    if reason:
        raise Invalid("curve: " + reason)
    # puzzle
    if not (1 <= h.k < h.n):
        raise Invalid("k out of range")
    P = puzzle_point(C, h)
    if ec_mul(C, h.k, C.G) != P:
        raise Invalid("k*G != P")


def validate_chain(blocks: list, params: Params = PROTOTYPE) -> int:
    chain = []
    work = 0
    for blk in blocks:
        validate_block(chain, blk, params)
        chain.append(blk)
        work += block_work(blk.header)
    return work


# ---------------------------------------------------------------------------
# Miner: parallel Pollard rho with distinguished points (non-consensus)
# ---------------------------------------------------------------------------

R_PARTITIONS = 32


def _rho_worker(p, a, b, G, P, n, walk_seed, dp_bits, worker_id, out_q, stop):
    C = Curve(p, a, b, G)
    rng = random.Random(walk_seed)
    table = []
    for _ in range(R_PARTITIONS):
        ca, cb = rng.randrange(n), rng.randrange(n)
        table.append((ec_add(C, ec_mul(C, ca, G), ec_mul(C, cb, P)), ca, cb))
    mask = (1 << dp_bits) - 1
    max_len = 20 << dp_bits
    lrng = random.Random(os.urandom(16))
    batch = []
    while not stop.is_set():
        x_a, x_b = lrng.randrange(1, n), lrng.randrange(1, n)
        X = ec_add(C, ec_mul(C, x_a, G), ec_mul(C, x_b, P))
        for _ in range(max_len):
            if X is None:
                break
            if X[0] & mask == 0:
                batch.append((X[0], X[1], x_a, x_b))
                if len(batch) >= 8:
                    out_q.put(batch)
                    batch = []
                break
            R, ra, rb = table[X[0] % R_PARTITIONS]
            X = ec_add(C, X, R)
            x_a = (x_a + ra) % n
            x_b = (x_b + rb) % n
    if batch:
        out_q.put(batch)


def _solve_collision(n, d1, d2):
    (x1, y1, a1, b1), (x2, y2, a2, b2) = d1, d2
    if y1 == y2:   # a1 + b1 k = a2 + b2 k
        num, den = a1 - a2, b2 - b1
    else:          # a1 + b1 k = -(a2 + b2 k)
        num, den = -(a1 + a2), b1 + b2
    if den % n == 0:
        return None
    return num * pow(den, -1, n) % n


def rho_solve(C: Curve, P, n: int, workers: int = 1, verbose: bool = False) -> int:
    dp_bits = max(2, n.bit_length() // 4 - 3)
    walk_seed = int.from_bytes(os.urandom(8), "big")
    ctx = mp.get_context("fork") if hasattr(os, "fork") else mp.get_context()
    out_q, stop = ctx.Queue(), ctx.Event()
    procs = [ctx.Process(target=_rho_worker, daemon=True,
                         args=(C.p, C.a, C.b, C.G, P, n, walk_seed, dp_bits, i, out_q, stop))
             for i in range(workers)]
    for pr in procs:
        pr.start()
    seen = {}
    try:
        while True:
            for dp in out_q.get():
                prev = seen.get(dp[0])
                if prev is None:
                    seen[dp[0]] = dp
                    continue
                k = _solve_collision(n, prev, dp)
                if k is not None and ec_mul(C, k, C.G) == P:
                    if verbose:
                        print(f"    rho: {len(seen)} distinguished points", file=sys.stderr)
                    return k
    finally:
        stop.set()
        for pr in procs:
            pr.join(timeout=1)
            if pr.is_alive():
                pr.terminate()


def mine_block(chain: list, miner: str, params: Params = PROTOTYPE, workers: int = 1,
               timestamp: int | None = None, verbose: bool = True) -> Block:
    height = len(chain)
    prev_hash = chain[-1].header.hash() if chain else b"\x00" * 32
    bits = next_bits(chain, params)
    t0 = time.time()
    ctr, C, n = find_curve(prev_hash, bits, params)
    t1 = time.time()
    if timestamp is None:
        timestamp = int(time.time())
    if chain:
        window = [b.header.time for b in chain[-params.mtp_window:]]
        timestamp = max(timestamp, sorted(window)[len(window) // 2] + 1)
    txs = [coinbase(height, miner)]
    h = Header(1, prev_hash, merkle_root(txs), timestamp, bits, ctr, n, 0)
    P = puzzle_point(C, h)
    h.k = rho_solve(C, P, n, workers, verbose)
    t2 = time.time()
    if verbose:
        print(f"block {height:4d}  bits={bits}  ctr={ctr:<4d} curve {t1-t0:5.2f}s  "
              f"rho {t2-t1:6.2f}s  hash={h.hash().hex()[:16]}", file=sys.stderr)
    return Block(h, txs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load(path):
    with open(path) as f:
        return [Block.from_json(d) for d in json.load(f)["blocks"]]


def _save(path, blocks, params):
    with open(path, "w") as f:
        json.dump({"params": params.__dict__, "blocks": [b.to_json() for b in blocks]}, f, indent=1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Canary reference node/miner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mine", help="mine blocks onto a chain file")
    m.add_argument("chain")
    m.add_argument("-n", "--blocks", type=int, default=10)
    m.add_argument("-w", "--workers", type=int, default=os.cpu_count() or 1)
    m.add_argument("--miner", default="miner-address")
    m.add_argument("--epoch", type=int, default=PROTOTYPE.epoch)
    m.add_argument("--tau", type=int, default=PROTOTYPE.tau)
    m.add_argument("--genesis-bits", type=int, default=PROTOTYPE.genesis_bits)
    v = sub.add_parser("verify", help="validate a chain file")
    v.add_argument("chain")
    args = ap.parse_args(argv)

    if args.cmd == "mine":
        params = Params(tau=args.tau, epoch=args.epoch, genesis_bits=args.genesis_bits)
        blocks = []
        if os.path.exists(args.chain):
            with open(args.chain) as f:
                params = Params(**json.load(f)["params"])
            blocks = _load(args.chain)
        for _ in range(args.blocks):
            blk = mine_block(blocks, args.miner, params, args.workers)
            validate_block(blocks, blk, params)
            blocks.append(blk)
            _save(args.chain, blocks, params)
    else:
        with open(args.chain) as f:
            params = Params(**json.load(f)["params"])
        work = validate_chain(_load(args.chain), params)
        print(f"valid chain, cumulative work {work}")


if __name__ == "__main__":
    main()
