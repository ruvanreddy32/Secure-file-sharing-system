"""
securecloud/rlwe.py — Ring-LWE public-key encryption of the AES file key (paper §II, §IV).

The paper encrypts the AES file key K "using RLWE encryption" following
Mishra & Jena [24], which builds on the ring-LWE toolkit of Lyubashevsky,
Peikert and Regev [25].  The parameters of [24] are not given in the paper,
so we implement the LPR ring-LWE encryption scheme in the form used by
de Clercq, Sinha Roy, Vercauteren and Verbauwhede, "Efficient Software
Implementation of Ring-LWE Encryption", DATE 2015 (§II-A), with their
published parameter sets:

    P1 = (n=256, q=7681,  sigma = 11.31 / sqrt(2*pi))   medium-term security
    P2 = (n=512, q=12289, sigma = 12.18 / sqrt(2*pi))   long-term security

Ring R_q = Z_q[x] / (x^n + 1).  chi = discrete Gaussian with std. dev. sigma.

    KeyGen:  a <- U(R_q);  r1, r2 <- chi
             p = r1 - a*r2                     public key (a, p), private key r2
    Enc(m):  e1, e2, e3 <- chi;  m_bar = encode(m)
             c1 = a*e1 + e2
             c2 = p*e1 + e3 + m_bar
    Dec:     m' = c1*r2 + c2 = r1*e1 + r2*e2 + e3 + m_bar;  m = decode(m')

Implementation choices (documented in IMPLEMENTATION_LIMITATIONS.md):

* Polynomial products are computed with an exact integer negacyclic
  convolution (numpy) instead of the NTT.  The ring product, and therefore
  every ciphertext and key, is mathematically identical; only speed differs.
* The discrete Gaussian is sampled by inversion over a cumulative table
  (tail cut at 12 sigma, 128-bit precision) driven by ``os.urandom``.
  de Clercq et al. use Knuth–Yao; both sample the same distribution.  This
  pure-Python sampler is **not constant-time**.
* Encoding: each key bit is placed in two coefficients (i and i + n/2) as
  bit * floor(q/2) and decoded by summing the two centred distances.  With a
  single coefficient per bit the per-key failure rate of these parameter sets
  is ~1e-2 (see tests); the 2x redundancy lowers it to well below 1e-5.
  A 256-bit AES key needs 2 ciphertexts under P1 and 1 under P2.
"""

from __future__ import annotations

import base64
import bisect
import json
import math
import os
from dataclasses import dataclass
from decimal import Decimal, getcontext
from typing import Dict, List, Optional, Tuple

import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class RLWEError(Exception):
    """Raised for malformed Ring-LWE keys or ciphertexts."""


@dataclass(frozen=True)
class RLWEParams:
    name: str
    n: int
    q: int
    s: float  # Gaussian parameter; sigma = s / sqrt(2*pi)

    @property
    def sigma(self) -> float:
        return self.s / math.sqrt(2 * math.pi)

    @property
    def bits_per_ciphertext(self) -> int:
        return self.n // 2  # 2x redundancy


PARAMS: Dict[str, RLWEParams] = {
    "P1": RLWEParams("P1", 256, 7681, 11.31),
    "P2": RLWEParams("P2", 512, 12289, 12.18),
}
DEFAULT_PARAMS = "P2"


# ---------------------------------------------------------------------------
# Discrete Gaussian sampler (cumulative distribution table, CSPRNG driven)
# ---------------------------------------------------------------------------

_CDT_BITS = 128
_CDT_CACHE: Dict[str, Tuple[List[int], int]] = {}


def _cdt(params: RLWEParams) -> Tuple[List[int], int]:
    """Cumulative table over z in [-T, T], scaled to 2**128."""
    if params.name not in _CDT_CACHE:
        getcontext().prec = 60
        sigma = Decimal(params.s) / (Decimal(2) * Decimal(math.pi)).sqrt()
        tail = math.ceil(12 * params.sigma)
        weights = [(-(Decimal(z * z)) / (2 * sigma * sigma)).exp() for z in range(-tail, tail + 1)]
        total = sum(weights)
        scale = Decimal(2) ** _CDT_BITS
        cum, acc = [], Decimal(0)
        for w in weights:
            acc += w
            cum.append(int(acc / total * scale))
        cum[-1] = 2 ** _CDT_BITS
        _CDT_CACHE[params.name] = (cum, tail)
    return _CDT_CACHE[params.name]


def sample_gaussian(params: RLWEParams) -> np.ndarray:
    """Return n integers drawn from the discrete Gaussian chi (centred at 0)."""
    cum, tail = _cdt(params)
    raw = os.urandom(16 * params.n)
    out = np.empty(params.n, dtype=np.int64)
    for i in range(params.n):
        r = int.from_bytes(raw[16 * i: 16 * i + 16], "little")
        out[i] = bisect.bisect_right(cum, r) - tail
    return out


def sample_uniform(params: RLWEParams) -> np.ndarray:
    """Return a polynomial with coefficients uniform in [0, q) (rejection sampling)."""
    limit = (65536 // params.q) * params.q
    coeffs: List[int] = []
    while len(coeffs) < params.n:
        buf = np.frombuffer(os.urandom(4 * params.n), dtype="<u2")
        coeffs.extend(int(v) % params.q for v in buf if v < limit)
    return np.array(coeffs[: params.n], dtype=np.int64)


# ---------------------------------------------------------------------------
# Ring arithmetic in Z_q[x]/(x^n + 1)
# ---------------------------------------------------------------------------

def poly_mul(a: np.ndarray, b: np.ndarray, params: RLWEParams) -> np.ndarray:
    """Negacyclic product a*b mod (x^n + 1, q), exact in int64."""
    n, q = params.n, params.q
    full = np.convolve(np.mod(a, q), np.mod(b, q))  # degree <= 2n-2, max n*q^2 < 2^63
    res = full[:n].copy()
    res[: n - 1] -= full[n:]                        # x^n = -1
    return np.mod(res, q)


def poly_add(*polys: np.ndarray, q: int) -> np.ndarray:
    return np.mod(sum(polys), q)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

@dataclass
class RLWEPublicKey:
    params: RLWEParams
    a: np.ndarray
    p: np.ndarray


@dataclass
class RLWEPrivateKey:
    params: RLWEParams
    r2: np.ndarray
    public: RLWEPublicKey


def generate_keypair(param_name: str = DEFAULT_PARAMS) -> RLWEPrivateKey:
    """KeyGen: a <- U(R_q), r1, r2 <- chi, p = r1 - a*r2."""
    params = _params(param_name)
    a = sample_uniform(params)
    r1 = sample_gaussian(params)
    r2 = sample_gaussian(params)
    p = np.mod(r1 - poly_mul(a, r2, params), params.q)
    return RLWEPrivateKey(params, np.mod(r2, params.q), RLWEPublicKey(params, a, p))


# ---------------------------------------------------------------------------
# Single-ciphertext encryption of n/2 bits
# ---------------------------------------------------------------------------

def _encode(bits: List[int], params: RLWEParams) -> np.ndarray:
    half = params.n // 2
    m = np.zeros(params.n, dtype=np.int64)
    for i, bit in enumerate(bits):
        if bit:
            m[i] = m[i + half] = params.q // 2
    return m


def _decode(m_prime: np.ndarray, params: RLWEParams, nbits: int) -> List[int]:
    q, half = params.q, params.n // 2
    centred = np.mod(m_prime, q)
    centred = np.where(centred > q // 2, centred - q, centred)
    dist = np.abs(centred)
    return [int(dist[i] + dist[i + half] > q // 2) for i in range(nbits)]


def encrypt_bits(bits: List[int], pub: RLWEPublicKey) -> Tuple[np.ndarray, np.ndarray]:
    params = pub.params
    if len(bits) > params.bits_per_ciphertext:
        raise ValueError("Too many bits for one ciphertext")
    e1, e2, e3 = (sample_gaussian(params) for _ in range(3))
    c1 = poly_add(poly_mul(pub.a, e1, params), e2, q=params.q)
    c2 = poly_add(poly_mul(pub.p, e1, params), e3, _encode(bits, params), q=params.q)
    return c1, c2


def decrypt_bits(c1: np.ndarray, c2: np.ndarray, priv: RLWEPrivateKey, nbits: int) -> List[int]:
    params = priv.params
    m_prime = poly_add(poly_mul(c1, priv.r2, params), c2, q=params.q)
    return _decode(m_prime, params, nbits)


# ---------------------------------------------------------------------------
# Key encapsulation of the AES file key (bytes in, bytes out)
# ---------------------------------------------------------------------------

def _to_bits(data: bytes) -> List[int]:
    return [(byte >> k) & 1 for byte in data for k in range(8)]


def _from_bits(bits: List[int]) -> bytes:
    return bytes(sum(bits[i + k] << k for k in range(8)) for i in range(0, len(bits), 8))


def encrypt_key(file_key: bytes, pub: RLWEPublicKey) -> bytes:
    """Encrypt *file_key* (e.g. 32-byte AES key) and return the encrypted-key file bytes."""
    bits = _to_bits(file_key)
    per = pub.params.bits_per_ciphertext
    cts = []
    for start in range(0, len(bits), per):
        c1, c2 = encrypt_bits(bits[start: start + per], pub)
        cts.append({"c1": _pack(c1), "c2": _pack(c2)})
    doc = {
        "format": "RLWE-ENCRYPTED-KEY-v1",
        "params": pub.params.name,
        "key_bytes": len(file_key),
        "ciphertexts": cts,
    }
    return json.dumps(doc, indent=1).encode()


def decrypt_key(encrypted_key_file: bytes, priv: RLWEPrivateKey) -> bytes:
    """Recover the file key from bytes produced by :func:`encrypt_key`."""
    try:
        doc = json.loads(encrypted_key_file)
        if doc["format"] != "RLWE-ENCRYPTED-KEY-v1":
            raise RLWEError("Unknown encrypted-key format")
        if doc["params"] != priv.params.name:
            raise RLWEError(f"Key file uses {doc['params']}, private key uses {priv.params.name}")
        nbits = 8 * int(doc["key_bytes"])
        per = priv.params.bits_per_ciphertext
        bits: List[int] = []
        for ct in doc["ciphertexts"]:
            take = min(per, nbits - len(bits))
            c1, c2 = _unpack(ct["c1"], priv.params), _unpack(ct["c2"], priv.params)
            bits.extend(decrypt_bits(c1, c2, priv, take))
    except (ValueError, KeyError, TypeError) as exc:
        raise RLWEError(f"Malformed encrypted-key file: {exc}") from exc
    if len(bits) != nbits:
        raise RLWEError("Encrypted-key file is truncated")
    return _from_bits(bits)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _pack(poly: np.ndarray) -> str:
    return base64.b64encode(np.asarray(poly, dtype="<u2").tobytes()).decode()


def _unpack(text: str, params: RLWEParams) -> np.ndarray:
    arr = np.frombuffer(base64.b64decode(text, validate=True), dtype="<u2").astype(np.int64)
    if arr.shape != (params.n,) or np.any(arr >= params.q):
        raise RLWEError("Polynomial has wrong length or out-of-range coefficients")
    return arr


def _params(name: str) -> RLWEParams:
    if name not in PARAMS:
        raise RLWEError(f"Unknown Ring-LWE parameter set {name!r}; choose from {sorted(PARAMS)}")
    return PARAMS[name]


def public_key_to_bytes(pub: RLWEPublicKey) -> bytes:
    return json.dumps({
        "format": "RLWE-PUBLIC-KEY-v1", "params": pub.params.name,
        "a": _pack(pub.a), "p": _pack(pub.p),
    }, indent=1).encode()


def public_key_from_bytes(data: bytes) -> RLWEPublicKey:
    try:
        doc = json.loads(data)
        if doc["format"] != "RLWE-PUBLIC-KEY-v1":
            raise RLWEError("Not a Ring-LWE public key")
        params = _params(doc["params"])
        return RLWEPublicKey(params, _unpack(doc["a"], params), _unpack(doc["p"], params))
    except (ValueError, KeyError, TypeError) as exc:
        raise RLWEError(f"Malformed public key: {exc}") from exc


def private_key_to_bytes(priv: RLWEPrivateKey, passphrase: Optional[bytes] = None) -> bytes:
    """Serialize the private key; if *passphrase* is given, wrap it with scrypt + AES-256-GCM."""
    body = json.dumps({
        "params": priv.params.name, "r2": _pack(priv.r2),
        "public": json.loads(public_key_to_bytes(priv.public)),
    }).encode()
    if passphrase is None:
        return json.dumps({"format": "RLWE-PRIVATE-KEY-v1", "encrypted": False,
                           "body": base64.b64encode(body).decode()}, indent=1).encode()
    salt, nonce = os.urandom(16), os.urandom(12)
    kek = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase)
    blob = AESGCM(kek).encrypt(nonce, body, b"RLWE-PRIVATE-KEY-v1")
    return json.dumps({"format": "RLWE-PRIVATE-KEY-v1", "encrypted": True,
                       "kdf": "scrypt-n32768-r8-p1",
                       "salt": base64.b64encode(salt).decode(),
                       "nonce": base64.b64encode(nonce).decode(),
                       "body": base64.b64encode(blob).decode()}, indent=1).encode()


def private_key_from_bytes(data: bytes, passphrase: Optional[bytes] = None) -> RLWEPrivateKey:
    try:
        doc = json.loads(data)
        if doc["format"] != "RLWE-PRIVATE-KEY-v1":
            raise RLWEError("Not a Ring-LWE private key")
        body = base64.b64decode(doc["body"])
        if doc["encrypted"]:
            if passphrase is None:
                raise RLWEError("Private key is passphrase-protected")
            kek = Scrypt(salt=base64.b64decode(doc["salt"]), length=32,
                         n=2 ** 15, r=8, p=1).derive(passphrase)
            body = AESGCM(kek).decrypt(base64.b64decode(doc["nonce"]), body, b"RLWE-PRIVATE-KEY-v1")
        inner = json.loads(body)
        params = _params(inner["params"])
        pub = public_key_from_bytes(json.dumps(inner["public"]).encode())
        return RLWEPrivateKey(params, _unpack(inner["r2"], params), pub)
    except RLWEError:
        raise
    except Exception as exc:  # wrong passphrase -> InvalidTag, bad JSON, ...
        raise RLWEError(f"Cannot load Ring-LWE private key: {exc}") from exc
