"""
SLH-DSA-SHA2-128s (FIPS 205), pure Python, for the Canary consensus reference.

A direct transcription of FIPS 205 (Algorithms 1-25) for the one parameter set Canary uses.
It favours clarity over speed: verification takes tens of milliseconds and signing tens of
seconds. Checked against the NIST ACVP vectors by test_slhdsa.py.

Public API:
  keygen(sk_seed, sk_prf, pk_seed) -> (sk, pk)      # slh_keygen_internal
  sign(msg, sk, ctx=b"", addrnd=None) -> sig        # pure slh_sign; deterministic if addrnd is None
  verify(msg, sig, pk, ctx=b"") -> bool             # pure slh_verify
  sign_internal / verify_internal                   # Algorithms 19 / 20
"""

from __future__ import annotations

import hashlib
import hmac

# Parameters for SLH-DSA-SHA2-128s (FIPS 205, Table 2).
N = 16          # security parameter (bytes)
FULL_H = 63     # total hypertree height
D = 7           # layers
HP = 9          # h' = height of each XMSS tree
A = 12          # FORS tree height
K = 14          # FORS trees
LG_W = 4
W = 1 << LG_W
M = 30          # digest bytes
LEN1 = (8 * N) // LG_W   # 32
LEN2 = 3
LEN = LEN1 + LEN2        # 35

PK_BYTES = 2 * N
SK_BYTES = 4 * N
SIG_BYTES = N + K * (1 + A) * N + (FULL_H + D * LEN) * N   # 7856

# Address types (FIPS 205, Section 4.2).
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = range(7)


class Adrs:
    """32-byte address (FIPS 205, Section 4.2)."""

    __slots__ = ("b",)

    def __init__(self, b: bytes | None = None):
        self.b = bytearray(b) if b is not None else bytearray(32)

    def copy(self) -> "Adrs":
        return Adrs(self.b)

    def _set(self, off: int, length: int, v: int) -> None:
        self.b[off:off + length] = v.to_bytes(length, "big")

    def set_layer(self, l: int) -> None: self._set(0, 4, l)
    def set_tree(self, t: int) -> None: self._set(4, 12, t)

    def set_type_and_clear(self, t: int) -> None:
        self._set(16, 4, t)
        self.b[20:32] = bytes(12)

    def set_keypair(self, i: int) -> None: self._set(20, 4, i)
    def get_keypair(self) -> int: return int.from_bytes(self.b[20:24], "big")
    def set_chain(self, i: int) -> None: self._set(24, 4, i)
    def set_tree_height(self, z: int) -> None: self._set(24, 4, z)
    def set_hash(self, i: int) -> None: self._set(28, 4, i)
    def set_tree_index(self, i: int) -> None: self._set(28, 4, i)
    def get_tree_index(self) -> int: return int.from_bytes(self.b[28:32], "big")

    def compressed(self) -> bytes:
        """ADRSc for the SHA2 instantiations (Section 11.2)."""
        b = self.b
        return bytes(b[3:4] + b[8:16] + b[19:20] + b[20:32])


# Hash functions for SHA2, security category 1 (Section 11.2.1).
_PAD = bytes(64 - N)


def _sha(pk_seed: bytes, adrs: Adrs, data: bytes) -> bytes:
    return hashlib.sha256(pk_seed + _PAD + adrs.compressed() + data).digest()[:N]


def F(pk_seed, adrs, m): return _sha(pk_seed, adrs, m)
def Hh(pk_seed, adrs, m): return _sha(pk_seed, adrs, m)
def T(pk_seed, adrs, m): return _sha(pk_seed, adrs, m)
def PRF(pk_seed, sk_seed, adrs): return _sha(pk_seed, adrs, sk_seed)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return hmac.new(sk_prf, opt_rand + msg, hashlib.sha256).digest()[:N]


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    c = 0
    while len(out) < length:
        out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:length]


def H_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    inner = hashlib.sha256(r + pk_seed + pk_root + msg).digest()
    return _mgf1(r + pk_seed + inner, M)


def base_2b(x: bytes, b: int, out_len: int) -> list:
    """Algorithm 4."""
    out, total, bits, i = [], 0, 0, 0
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) | x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) & ((1 << b) - 1))
    return out


# WOTS+ (Section 5).

def chain(x: bytes, i: int, s: int, pk_seed: bytes, adrs: Adrs) -> bytes:
    for j in range(i, i + s):
        adrs.set_hash(j)
        x = F(pk_seed, adrs, x)
    return x


def _wots_digits(msg: bytes) -> list:
    digits = base_2b(msg, LG_W, LEN1)
    csum = sum(W - 1 - d for d in digits)
    csum <<= (8 - (LEN2 * LG_W) % 8) % 8
    return digits + base_2b(csum.to_bytes((LEN2 * LG_W + 7) // 8, "big"), LG_W, LEN2)


def _wots_sk(sk_seed, pk_seed, adrs: Adrs, i: int) -> bytes:
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_keypair(adrs.get_keypair())
    sk_adrs.set_chain(i)
    return PRF(pk_seed, sk_seed, sk_adrs)


def _wots_compress(pk_seed, adrs: Adrs, tmp: list) -> bytes:
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_keypair(adrs.get_keypair())
    return T(pk_seed, pk_adrs, b"".join(tmp))


def wots_pkgen(sk_seed, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 6."""
    tmp = []
    for i in range(LEN):
        sk = _wots_sk(sk_seed, pk_seed, adrs, i)
        adrs.set_chain(i)
        tmp.append(chain(sk, 0, W - 1, pk_seed, adrs))
    return _wots_compress(pk_seed, adrs, tmp)


def wots_sign(msg, sk_seed, pk_seed, adrs: Adrs) -> list:
    """Algorithm 7."""
    sig = []
    for i, d in enumerate(_wots_digits(msg)):
        sk = _wots_sk(sk_seed, pk_seed, adrs, i)
        adrs.set_chain(i)
        sig.append(chain(sk, 0, d, pk_seed, adrs))
    return sig


def wots_pk_from_sig(sig: list, msg, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 8."""
    tmp = []
    for i, d in enumerate(_wots_digits(msg)):
        adrs.set_chain(i)
        tmp.append(chain(sig[i], d, W - 1 - d, pk_seed, adrs))
    return _wots_compress(pk_seed, adrs, tmp)


# XMSS (Section 6).

def xmss_node(sk_seed, i: int, z: int, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 9."""
    if z == 0:
        adrs.set_type_and_clear(WOTS_HASH)
        adrs.set_keypair(i)
        return wots_pkgen(sk_seed, pk_seed, adrs)
    lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hh(pk_seed, adrs, lnode + rnode)


def xmss_sign(msg, sk_seed, idx: int, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 10."""
    auth = [xmss_node(sk_seed, (idx >> j) ^ 1, j, pk_seed, adrs) for j in range(HP)]
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_keypair(idx)
    return b"".join(wots_sign(msg, sk_seed, pk_seed, adrs)) + b"".join(auth)


def xmss_pk_from_sig(idx: int, sig: bytes, msg, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 11."""
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_keypair(idx)
    wsig = [sig[i * N:(i + 1) * N] for i in range(LEN)]
    auth = [sig[(LEN + j) * N:(LEN + j + 1) * N] for j in range(HP)]
    node = wots_pk_from_sig(wsig, msg, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_index(idx)
    for k in range(HP):
        adrs.set_tree_height(k + 1)
        if (idx >> k) & 1 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node = Hh(pk_seed, adrs, node + auth[k])
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = Hh(pk_seed, adrs, auth[k] + node)
    return node


# Hypertree (Section 7).

XMSS_SIG_BYTES = (HP + LEN) * N


def ht_sign(msg, sk_seed, pk_seed, idx_tree: int, idx_leaf: int) -> bytes:
    """Algorithm 12."""
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    sig = xmss_sign(msg, sk_seed, idx_leaf, pk_seed, adrs)
    out = sig
    root = xmss_pk_from_sig(idx_leaf, sig, msg, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        out += sig
        if j < D - 1:
            root = xmss_pk_from_sig(idx_leaf, sig, root, pk_seed, adrs)
    return out


def ht_verify(msg, sig_ht: bytes, pk_seed, idx_tree: int, idx_leaf: int, pk_root) -> bool:
    """Algorithm 13."""
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    node = xmss_pk_from_sig(idx_leaf, sig_ht[:XMSS_SIG_BYTES], msg, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        part = sig_ht[j * XMSS_SIG_BYTES:(j + 1) * XMSS_SIG_BYTES]
        node = xmss_pk_from_sig(idx_leaf, part, node, pk_seed, adrs)
    return node == pk_root


# FORS (Section 8).

def fors_skgen(sk_seed, pk_seed, adrs: Adrs, idx: int) -> bytes:
    """Algorithm 14."""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(FORS_PRF)
    sk_adrs.set_keypair(adrs.get_keypair())
    sk_adrs.set_tree_index(idx)
    return PRF(pk_seed, sk_seed, sk_adrs)


def fors_node(sk_seed, i: int, z: int, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 15."""
    if z == 0:
        sk = fors_skgen(sk_seed, pk_seed, adrs, i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        return F(pk_seed, adrs, sk)
    lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hh(pk_seed, adrs, lnode + rnode)


def fors_sign(md: bytes, sk_seed, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 16."""
    out = b""
    for i, idx in enumerate(base_2b(md, A, K)):
        out += fors_skgen(sk_seed, pk_seed, adrs, (i << A) + idx)
        for j in range(A):
            s = (idx >> j) ^ 1
            out += fors_node(sk_seed, (i << (A - j)) + s, j, pk_seed, adrs)
    return out


def fors_pk_from_sig(sig: bytes, md: bytes, pk_seed, adrs: Adrs) -> bytes:
    """Algorithm 17."""
    roots = []
    for i, idx in enumerate(base_2b(md, A, K)):
        part = sig[i * (A + 1) * N:(i + 1) * (A + 1) * N]
        sk, auth = part[:N], [part[(j + 1) * N:(j + 2) * N] for j in range(A)]
        adrs.set_tree_height(0)
        adrs.set_tree_index((i << A) + idx)
        node = F(pk_seed, adrs, sk)
        for j in range(A):
            adrs.set_tree_height(j + 1)
            if (idx >> j) & 1 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = Hh(pk_seed, adrs, node + auth[j])
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = Hh(pk_seed, adrs, auth[j] + node)
        roots.append(node)
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(FORS_ROOTS)
    pk_adrs.set_keypair(adrs.get_keypair())
    return T(pk_seed, pk_adrs, b"".join(roots))


# SLH-DSA (Sections 9-10).

FORS_SIG_BYTES = K * (A + 1) * N
MD_BYTES = (K * A + 7) // 8                      # 21
TREE_BYTES = (FULL_H - FULL_H // D + 7) // 8      # 7
LEAF_BYTES = (FULL_H // D + 7) // 8               # 2


def _split_digest(digest: bytes):
    md = digest[:MD_BYTES]
    idx_tree = int.from_bytes(digest[MD_BYTES:MD_BYTES + TREE_BYTES], "big") % (1 << (FULL_H - FULL_H // D))
    off = MD_BYTES + TREE_BYTES
    idx_leaf = int.from_bytes(digest[off:off + LEAF_BYTES], "big") % (1 << (FULL_H // D))
    return md, idx_tree, idx_leaf


def keygen(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes):
    """Algorithm 18 (slh_keygen_internal). Returns (sk, pk) as byte strings."""
    adrs = Adrs()
    adrs.set_layer(D - 1)
    pk_root = xmss_node(sk_seed, 0, HP, pk_seed, adrs)
    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


def sign_internal(msg: bytes, sk: bytes, addrnd: bytes | None = None) -> bytes:
    """Algorithm 19. Deterministic (opt_rand = PK.seed) when addrnd is None."""
    sk_seed, sk_prf, pk_seed, pk_root = sk[:N], sk[N:2 * N], sk[2 * N:3 * N], sk[3 * N:]
    opt_rand = pk_seed if addrnd is None else addrnd
    r = PRF_msg(sk_prf, opt_rand, msg)
    md, idx_tree, idx_leaf = _split_digest(H_msg(r, pk_seed, pk_root, msg))
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_keypair(idx_leaf)
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    return r + sig_fors + ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)


def verify_internal(msg: bytes, sig: bytes, pk: bytes) -> bool:
    """Algorithm 20."""
    if len(sig) != SIG_BYTES or len(pk) != PK_BYTES:
        return False
    pk_seed, pk_root = pk[:N], pk[N:]
    r, sig_fors, sig_ht = sig[:N], sig[N:N + FORS_SIG_BYTES], sig[N + FORS_SIG_BYTES:]
    md, idx_tree, idx_leaf = _split_digest(H_msg(r, pk_seed, pk_root, msg))
    adrs = Adrs()
    adrs.set_tree(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_keypair(idx_leaf)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


def _pure(msg: bytes, ctx: bytes) -> bytes:
    if len(ctx) > 255:
        raise ValueError("context too long")
    return bytes([0, len(ctx)]) + ctx + msg


def sign(msg: bytes, sk: bytes, ctx: bytes = b"", addrnd: bytes | None = None) -> bytes:
    """Algorithm 22 (pure slh_sign)."""
    return sign_internal(_pure(msg, ctx), sk, addrnd)


def verify(msg: bytes, sig: bytes, pk: bytes, ctx: bytes = b"") -> bool:
    """Algorithm 24 (pure slh_verify)."""
    if len(ctx) > 255:
        return False
    return verify_internal(_pure(msg, ctx), sig, pk)
