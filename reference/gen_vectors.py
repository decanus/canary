#!/usr/bin/env python3
"""Generate test_vectors.json from the Python reference (prototype profile)."""

import copy
import json
import sys

import canary as E

P = E.PROTOTYPE
GENESIS_TIME = 1791590400   # 2026-10-10T00:00:00Z
TIME_STEP = 2               # faster than tau=10 -> first retarget clamps to +4 bits
CHAIN_LEN = P.epoch + 6     # crosses one retarget


def h(b): return b.hex()


def primes_section():
    cases = [0, 1, 2, 3, 4, 5, 9, 15, 17, 25, 561, 1105, 7919, 2047, 1373653, 25326001,
             3215031751, 2152302898747, 3474749660383, 341550071728321,
             2**61 - 1, 2**89 - 1, 2**127 - 1, (2**61 - 1) * (2**31 - 1),
             2**64 + 13, 2**64 - 59, 2**128 - 159, 2**127 + 45]
    return [{"n": str(n), "prime": E.is_prime(n)} for n in cases] + \
        [{"next_prime_3mod4_of": str(x), "result": str(E.next_prime_3mod4(x))}
         for x in [0, 10, 2**35, 2**47 + 12345, 2**63]]


def retarget_section():
    out = []
    for exp, act in [(100, 1), (100, 25), (100, 35), (100, 50), (100, 59), (100, 60), (100, 71),
                     (100, 84), (100, 85), (100, 100), (100, 118), (100, 119), (100, 141),
                     (100, 168), (100, 169), (100, 200), (100, 400), (100, 10**6),
                     (630, 160), (630, 2520), (20150, 20150)]:
        a = max(exp // 4, min(act, 4 * exp))
        out.append({"expected": exp, "actual_clamped": a, "delta": E.retarget_delta(exp, a)})
    return out


def curves_section():
    out = []
    for prev, bits, ctr in [(b"\x00" * 32, 36, 0), (b"\x00" * 32, 36, 1), (bytes(range(32)), 40, 7),
                            (b"\xff" * 32, 48, 3), (b"\xab" * 32, 64, 0)]:
        C = E.derive_curve(prev, bits, ctr)
        out.append({"prev_hash": h(prev), "bits": bits, "curve_ctr": ctr,
                    "p": str(C.p), "a": str(C.a), "b": str(C.b),
                    "G": None if C.G is None else [str(C.G[0]), str(C.G[1])]})
    # one fully valid curve per size via search (order included)
    for prev, bits in [(b"\x00" * 32, 36), (bytes(range(32)), 40), (b"\xff" * 32, 48)]:
        ctr, C, n = E.find_curve(prev, bits)
        out.append({"prev_hash": h(prev), "bits": bits, "curve_ctr": ctr, "p": str(C.p),
                    "a": str(C.a), "b": str(C.b), "G": [str(C.G[0]), str(C.G[1])],
                    "n": str(n), "valid": True,
                    "note": "first valid curve_ctr (reference search order)"})
    return out


def h2c_section():
    C = E.derive_curve(b"\x00" * 32, 36, 0)
    out = []
    for msg in [b"", b"abc", E.tag("P") + b"\x00" * 32]:
        x, y = E.hash_to_curve(msg, C.p, C.a, C.b)
        out.append({"msg": h(msg), "p": str(C.p), "a": str(C.a), "b": str(C.b),
                    "x": str(x), "y": str(y)})
    return out


def invalid_section(chain):
    """Mutations of the last block; each must be rejected."""
    base_chain, blk = chain[:-1], chain[-1]
    out = []

    def case(name, mutate):
        b = copy.deepcopy(blk)
        mutate(b)
        b.header.merkle_root = b.header.merkle_root if name != "steal_k" else E.merkle_root(b.txs)
        try:
            E.validate_block(base_chain, b, P)
            raise SystemExit(f"mutation {name} unexpectedly valid")
        except E.Invalid as e:
            out.append({"name": name, "header_hex": h(b.header.serialize()),
                        "txs": [h(t) for t in b.txs], "reason": str(e)})

    case("k_plus_one", lambda b: setattr(b.header, "k", b.header.k + 1))
    case("k_zero", lambda b: setattr(b.header, "k", 0))
    case("steal_k", lambda b: b.txs.__setitem__(0, E.coinbase(len(base_chain), "thief")))
    case("wrong_bits", lambda b: setattr(b.header, "bits", b.header.bits + 1))
    case("wrong_n", lambda b: setattr(b.header, "n", b.header.n + 2))
    case("wrong_ctr", lambda b: setattr(b.header, "curve_ctr", b.header.curve_ctr + 1))
    case("bad_prev", lambda b: setattr(b.header, "prev_hash", b"\x01" * 32))
    case("merkle_mismatch", lambda b: setattr(b.header, "merkle_root", b"\x02" * 32))
    case("time_le_mtp", lambda b: setattr(b.header, "time", base_chain[-6].header.time))
    return out


def main():
    chain = []
    for i in range(CHAIN_LEN):
        blk = E.mine_block(chain, "miner-address", P, workers=2,
                           timestamp=GENESIS_TIME + i * TIME_STEP)
        E.validate_block(chain, blk, P)
        chain.append(blk)
    work = E.validate_chain(chain, P)
    vectors = {
        "profile": "prototype",
        "params": P.__dict__,
        "primality": primes_section(),
        "retarget_delta": retarget_section(),
        "curves": curves_section(),
        "hash_to_curve": h2c_section(),
        "chain": {"cumulative_work": str(work),
                  "blocks": [b.to_json() for b in chain]},
        "invalid_blocks": {"parent_height": CHAIN_LEN - 2, "cases": invalid_section(chain)},
    }
    with open(sys.argv[1] if len(sys.argv) > 1 else "test_vectors.json", "w") as f:
        json.dump(vectors, f, indent=1)
    print("bits per height:", [b.header.bits for b in chain][P.epoch - 2:], file=sys.stderr)


if __name__ == "__main__":
    main()
