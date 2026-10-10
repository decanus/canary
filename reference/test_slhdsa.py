#!/usr/bin/env python3
"""Check reference/slhdsa.py against the NIST ACVP vectors in testdata/ (SHA2-128s subset).

Usage: python3 test_slhdsa.py [--sign]    (--sign also runs the slow signature-generation cases)
"""

import json
import os
import sys
import time

import slhdsa

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    with open(os.path.join(HERE, "testdata", "slhdsa_sha2_128s_acvp.json")) as f:
        v = json.load(f)
    x = bytes.fromhex
    fails = 0

    for i, t in enumerate(v["keyGen"]):
        sk, pk = slhdsa.keygen(x(t["skSeed"]), x(t["skPrf"]), x(t["pkSeed"]))
        if sk != x(t["sk"]) or pk != x(t["pk"]):
            print(f"FAIL keyGen #{i}")
            fails += 1
    print(f"keyGen: {len(v['keyGen'])} cases")

    n = 0
    for i, t in enumerate(v["verify"]):
        if t["preHash"] == "preHash":
            continue  # Canary uses pure SLH-DSA only
        msg, sig, pk = x(t["message"]), x(t["signature"]), x(t["pk"])
        if t["interface"] == "internal":
            ok = slhdsa.verify_internal(msg, sig, pk)
        else:
            ok = slhdsa.verify(msg, sig, pk, x(t["context"]))
        n += 1
        if ok != t["testPassed"]:
            print(f"FAIL verify #{i}: got {ok}, want {t['testPassed']}")
            fails += 1
    print(f"verify: {n} cases")

    if "--sign" in sys.argv:
        for i, t in enumerate(v["sigGen"]):
            sk, msg = x(t["sk"]), x(t["message"])
            rnd = None if t["deterministic"] else x(t["additionalRandomness"])
            t0 = time.time()
            if t["interface"] == "internal":
                sig = slhdsa.sign_internal(msg, sk, rnd)
            else:
                sig = slhdsa.sign(msg, sk, x(t["context"]), rnd)
            if sig != x(t["signature"]):
                print(f"FAIL sigGen #{i}")
                fails += 1
            print(f"sigGen #{i} ({t['interface']}, deterministic={t['deterministic']}): {time.time() - t0:.1f}s")

    if fails:
        sys.exit(f"{fails} failures")
    print("all SLH-DSA vectors passed")


if __name__ == "__main__":
    main()
