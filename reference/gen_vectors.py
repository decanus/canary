#!/usr/bin/env python3
"""Generate test_vectors.json from the Python reference (prototype profile, v0.2).

Mines a 70-block chain with transfers between three accounts. Signing in pure Python is slow
(about 7 s per signature), so a full run takes several minutes.
"""

import copy
import json
import sys

import canary as E
import slhdsa

P = E.PROTOTYPE
GENESIS_TIME = 1791590400   # 2026-10-10T00:00:00Z
TIME_STEP = 2               # faster than tau=10 -> first retarget clamps to +4 bits
CHAIN_LEN = P.epoch + 6     # crosses one retarget


def h(b): return b.hex()


def key(name: str):
    """Deterministic test key: seeds derived from the name."""
    seed = E.H(b"canary-test-key/" + name.encode())
    sk_seed, sk_prf, pk_seed = seed[:16], seed[16:], E.H(seed)[:16]
    sk, pk = slhdsa.keygen(sk_seed, sk_prf, pk_seed)
    return {"name": name, "sk_seed": sk_seed, "sk_prf": sk_prf, "pk_seed": pk_seed,
            "sk": sk, "pk": pk, "addr": E.address(pk)}


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


def keys_section(keys):
    return [{"name": k["name"], "sk_seed": h(k["sk_seed"]), "sk_prf": h(k["sk_prf"]),
             "pk_seed": h(k["pk_seed"]), "pubkey": h(k["pk"]), "address": h(k["addr"])}
            for k in keys]


def state_root_section(keys):
    a, b, c = (k["addr"] for k in keys)
    cases = [
        {},
        {a: (1, 0)},
        {a: (5, 2), b: (0, 1)},
        {a: (2**128 - 1, 2**64 - 1), b: (7, 0), c: (123456789, 3)},
        # Two addresses sharing their first 8 bits exercise the one-sided split.
        {b"\x80" + b"\x00" * 31: (1, 0), b"\x80" + b"\x01" + b"\x00" * 30: (2, 0)},
    ]
    return [{"accounts": [[h(k), str(bal), str(nonce)] for k, (bal, nonce) in sorted(st.items())],
             "root": h(E.state_root(st))} for st in cases]


def transfer(frm, to, amount, fee, nonce, genesis_hash):
    tx = E.Transfer(frm["pk"], to["addr"], amount, fee, nonce)
    print(f"signing {frm['name']} -> {to['name']} nonce={nonce} ...", file=sys.stderr)
    return E.sign_transfer(tx, frm["sk"], genesis_hash)


def mine_custom(chain, txs_raw, state_root):
    """A block with arbitrary txs and state_root but a valid puzzle, so that it fails only at the
    state transition."""
    height = len(chain)
    prev_hash = chain[-1].header.hash()
    bits = E.next_bits(chain, P)
    ctr, C, n = E.find_curve(prev_hash, bits, P)
    window = [b.header.time for b in chain[-P.mtp_window:]]
    t = sorted(window)[len(window) // 2] + 1
    hd = E.Header(E.VERSION, prev_hash, E.merkle_root(txs_raw), state_root, t, bits, ctr, n, 0)
    hd.k = E.rho_solve(C, E.puzzle_point(C, hd), n, 2)
    return E.Block(hd, txs_raw)


def invalid_section(chain, states, keys, signed):
    alice, bob, carol = keys
    out = []

    def add(name, parent_height, blk):
        base = chain[:parent_height + 1]
        try:
            E.validate_block(base, blk, P, state=states[parent_height] if parent_height >= 0 else {})
            raise SystemExit(f"case {name} unexpectedly valid")
        except E.Invalid as e:
            out.append({"name": name, "parent_height": parent_height,
                        "header_hex": h(blk.header.serialize()),
                        "txs": [h(t) for t in blk.txs], "reason": str(e)})

    # Mutations of the last block (which contains a transfer).
    last_parent = CHAIN_LEN - 2

    def mutate(name, fn, remerkle=False):
        b = copy.deepcopy(chain[-1])
        fn(b)
        if remerkle:
            b.header.merkle_root = E.merkle_root(b.txs)
        add(name, last_parent, b)

    def steal(b):
        cb = E.decode_tx(b.txs[0])
        cb.to = E.H(b"thief")
        b.txs[0] = cb.serialize()

    mutate("k_plus_one", lambda b: setattr(b.header, "k", b.header.k + 1))
    mutate("k_zero", lambda b: setattr(b.header, "k", 0))
    mutate("steal_k", steal, remerkle=True)
    mutate("wrong_bits", lambda b: setattr(b.header, "bits", b.header.bits + 1))
    mutate("wrong_n", lambda b: setattr(b.header, "n", b.header.n + 2))
    mutate("wrong_ctr", lambda b: setattr(b.header, "curve_ctr", b.header.curve_ctr + 1))
    mutate("bad_prev", lambda b: setattr(b.header, "prev_hash", b"\x01" * 32))
    mutate("merkle_mismatch", lambda b: setattr(b.header, "merkle_root", b"\x02" * 32))
    mutate("time_le_mtp", lambda b: setattr(b.header, "time", chain[-7].header.time))
    mutate("bad_version", lambda b: setattr(b.header, "version", 1))
    mutate("no_coinbase", lambda b: b.txs.pop(0), remerkle=True)
    mutate("two_coinbases", lambda b: b.txs.append(b.txs[0]), remerkle=True)
    mutate("truncated_transfer", lambda b: b.txs.__setitem__(1, b.txs[1][:-1]), remerkle=True)

    # Genesis must not contain transfers (rule 8: no mining needed).
    g = copy.deepcopy(chain[0])
    g.txs.append(signed[0].serialize())
    g.header.merkle_root = E.merkle_root(g.txs)
    add("transfer_in_genesis", -1, g)

    # State-transition failures, each re-mined with a valid puzzle on top of block 5.
    ph = 5
    base, st = chain[:ph + 1], states[ph]
    genesis_hash = chain[0].header.hash()

    def state_case(name, transfers, coinbase_extra=0, root=None):
        reward_holder = E.Coinbase(ph + 1, alice["addr"], 0)
        raw = [reward_holder.serialize()] + [t.serialize() for t in transfers]
        # Coinbase amount depends on n, which depends only on the parent and bits.
        bits = E.next_bits(base, P)
        _, _, n = E.find_curve(base[-1].header.hash(), bits, P)
        fees = sum(t.fee for t in transfers)
        cb = E.Coinbase(ph + 1, alice["addr"], E.isqrt(n) + fees + coinbase_extra)
        raw[0] = cb.serialize()
        if root is None:
            try:
                root = E.state_root(E.apply_txs(st, [cb] + list(transfers), E.isqrt(n), genesis_hash))
            except E.Invalid:
                root = E.state_root(st)
        add(name, ph, mine_custom(base, raw, root))

    bob_nonce = st.get(bob["addr"], (0, 0))[1]
    bad_sig = copy.deepcopy(transfer(bob, carol, 1, 1, bob_nonce, genesis_hash))
    good_sig = copy.deepcopy(bad_sig)
    bad_sig.sig = bytes([bad_sig.sig[0] ^ 1]) + bad_sig.sig[1:]
    state_case("bad_signature", [bad_sig])
    state_case("bad_nonce", [transfer(bob, carol, 1, 1, bob_nonce + 1, genesis_hash)])
    bob_bal = st.get(bob["addr"], (0, 0))[0]
    state_case("overspend", [transfer(bob, carol, bob_bal, 1, bob_nonce, genesis_hash)])
    state_case("coinbase_overpay", [], coinbase_extra=1)
    state_case("wrong_state_root", [good_sig], root=b"\x03" * 32)
    other = copy.deepcopy(good_sig)
    E.sign_transfer(other, bob["sk"], b"\x42" * 32)  # signed for a different chain
    state_case("replayed_from_other_chain", [other])
    return out


def tx_section(signed, genesis_hash):
    out = []
    for tx in signed:
        out.append({"genesis_hash": h(genesis_hash), "tx": h(tx.serialize()),
                    "sender": h(tx.sender()), "to": h(tx.to), "amount": str(tx.amount),
                    "fee": str(tx.fee), "nonce": str(tx.nonce),
                    "digest": h(E.tx_digest(genesis_hash, tx)), "valid_signature": True})
    bad = copy.deepcopy(signed[0])
    bad.sig = bad.sig[:-1] + bytes([bad.sig[-1] ^ 0x80])
    out.append({"genesis_hash": h(genesis_hash), "tx": h(bad.serialize()),
                "digest": h(E.tx_digest(genesis_hash, bad)), "valid_signature": False})
    cb = E.Coinbase(7, signed[0].to, 123456, b"extra")
    out.append({"tx": h(cb.serialize()), "coinbase": True, "height": 7, "to": h(cb.to),
                "amount": "123456", "extra": h(cb.extra)})
    return out


def main():
    keys = [key("alice"), key("bob"), key("carol")]
    alice, bob, carol = keys
    chain, states = [], []
    state = {}
    signed = []
    plan = {}  # height -> list of (from, to, amount, fee)
    plan[3] = [(alice, bob, 50_000, 7)]
    plan[4] = [(bob, carol, 20_000, 3), (alice, carol, 1, 0)]
    plan[CHAIN_LEN - 1] = [(carol, bob, 5, 1)]
    for i in range(CHAIN_LEN):
        transfers = []
        for frm, to, amount, fee in plan.get(i, []):
            nonce = state.get(frm["addr"], (0, 0))[1] + sum(1 for t in transfers if t.pubkey == frm["pk"])
            transfers.append(transfer(frm, to, amount, fee, nonce, chain[0].header.hash()))
        signed += transfers
        blk = E.mine_block(chain, alice["addr"], P, workers=2,
                           timestamp=GENESIS_TIME + i * TIME_STEP, state=state, transfers=transfers)
        state = E.validate_block(chain, blk, P, state=state)
        chain.append(blk)
        states.append(state)
    work, final = E.validate_chain(chain, P)
    supply = sum(bal for bal, _ in final.values())
    assert supply == work, "supply must equal cumulative work"
    genesis_hash = chain[0].header.hash()
    vectors = {
        "profile": "prototype",
        "params": P.__dict__,
        "primality": primes_section(),
        "retarget_delta": retarget_section(),
        "curves": curves_section(),
        "hash_to_curve": h2c_section(),
        "keys": keys_section(keys),
        "state_roots": state_root_section(keys),
        "transactions": tx_section(signed, genesis_hash),
        "chain": {"cumulative_work": str(work), "supply": str(supply),
                  "state": [[h(a), str(b), str(n)] for a, (b, n) in sorted(final.items())],
                  "blocks": [b.to_json() for b in chain]},
        "invalid_blocks": {"cases": invalid_section(chain, states, keys, signed)},
    }
    with open(sys.argv[1] if len(sys.argv) > 1 else "test_vectors.json", "w") as f:
        json.dump(vectors, f, indent=1)
    print("bits per height:", [b.header.bits for b in chain][P.epoch - 2:], file=sys.stderr)


if __name__ == "__main__":
    main()
