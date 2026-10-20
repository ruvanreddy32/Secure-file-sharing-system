"""
evaluation/rlwe_failure_rate.py — Empirical Ring-LWE decryption-failure rate for the
P1/P2 parameter sets, comparing

    single : one coefficient per bit, threshold decoding (|m'| > q/4 -> 1)
    double : this implementation's encoding (two coefficients per bit, summed distances)

on the same ciphertexts (n/2 random bits per ciphertext).

    python -m evaluation.rlwe_failure_rate --trials 2000
"""

from __future__ import annotations

import argparse
import json
import os

import numpy as np

from securecloud import rlwe


def run(name: str, trials: int):
    p = rlwe.PARAMS[name]
    sk = rlwe.generate_keypair(name)
    half = p.n // 2
    bit_err_single = bit_err_double = 0
    ct_err_single = ct_err_double = 0
    for _ in range(trials):
        bits = [int(b) & 1 for b in os.urandom(half)]
        c1, c2 = rlwe.encrypt_bits(bits, sk.public)
        m = rlwe.poly_add(rlwe.poly_mul(c1, sk.r2, p), c2, q=p.q)
        centred = np.where(m > p.q // 2, m - p.q, m)
        single = [int(abs(centred[i]) > p.q // 4) for i in range(half)]       # coefficient i only
        double = rlwe._decode(m, p, half)
        e1 = int(sum(a != b for a, b in zip(single, bits)))
        e2 = int(sum(a != b for a, b in zip(double, bits)))
        bit_err_single += e1
        bit_err_double += e2
        ct_err_single += e1 > 0
        ct_err_double += e2 > 0
    total_bits = trials * half
    return {"params": name, "n": p.n, "q": p.q, "trials": trials, "bits": total_bits,
            "single_bit_errors": bit_err_single, "single_bit_error_rate": bit_err_single / total_bits,
            "single_256bit_key_failure_est": 1 - (1 - bit_err_single / total_bits) ** 256,
            "double_bit_errors": bit_err_double, "double_ciphertext_failures": ct_err_double}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    args = ap.parse_args()
    print(json.dumps([run("P1", args.trials), run("P2", args.trials)], indent=2))


if __name__ == "__main__":
    main()
