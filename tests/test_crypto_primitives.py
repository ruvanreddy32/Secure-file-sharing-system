"""AES-256-GCM, Ring-LWE and RSA signature unit tests (paper §III-C, §IV)."""

import os

import numpy as np
import pytest

from securecloud import aes_cipher, rlwe, signature


# --------------------------------------------------------------------------- AES-256
class TestAES:
    def test_key_is_256_bit_and_random(self):
        k1, k2 = aes_cipher.generate_file_key(), aes_cipher.generate_file_key()
        assert len(k1) == 32 and k1 != k2

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4096, 100_000])
    def test_roundtrip(self, size):
        key, pt = aes_cipher.generate_file_key(), os.urandom(size)
        ct = aes_cipher.encrypt_bytes(pt, key)
        assert len(ct) == size + aes_cipher.HEADER_SIZE + aes_cipher.TAG_SIZE
        assert aes_cipher.decrypt_bytes(ct, key) == pt

    def test_same_plaintext_gives_different_ciphertexts(self):
        key = aes_cipher.generate_file_key()
        assert aes_cipher.encrypt_bytes(b"x" * 64, key) != aes_cipher.encrypt_bytes(b"x" * 64, key)

    def test_ciphertext_hides_plaintext(self):
        key = aes_cipher.generate_file_key()
        assert b"SECRET-MARKER" not in aes_cipher.encrypt_bytes(b"SECRET-MARKER" * 10, key)

    def test_wrong_key_rejected(self):
        ct = aes_cipher.encrypt_bytes(b"hello", aes_cipher.generate_file_key())
        with pytest.raises(aes_cipher.DecryptionError):
            aes_cipher.decrypt_bytes(ct, aes_cipher.generate_file_key())

    def test_modified_ciphertext_rejected(self):
        key = aes_cipher.generate_file_key()
        ct = bytearray(aes_cipher.encrypt_bytes(b"hello world", key))
        ct[-1] ^= 1
        with pytest.raises(aes_cipher.DecryptionError):
            aes_cipher.decrypt_bytes(bytes(ct), key)

    def test_bad_key_length(self):
        with pytest.raises(ValueError):
            aes_cipher.encrypt_bytes(b"x", b"short")


# --------------------------------------------------------------------------- Ring-LWE
def _naive_negacyclic(a, b, n, q):
    res = [0] * n
    for i in range(n):
        for j in range(n):
            k = i + j
            if k < n:
                res[k] += int(a[i]) * int(b[j])
            else:
                res[k - n] -= int(a[i]) * int(b[j])
    return [x % q for x in res]


class TestRingLWE:
    @pytest.mark.parametrize("name", ["P1", "P2"])
    def test_parameters_match_de_clercq_2015(self, name):
        p = rlwe.PARAMS[name]
        assert (p.n, p.q) == {"P1": (256, 7681), "P2": (512, 12289)}[name]
        assert p.q % (2 * p.n) == 1           # NTT-friendly prime, x^n+1 splits
        assert p.sigma == pytest.approx(p.s / np.sqrt(2 * np.pi))

    def test_poly_mul_matches_schoolbook(self):
        p = rlwe.RLWEParams("toy", 16, 7681, 11.31)
        a, b = rlwe.sample_uniform(p), rlwe.sample_uniform(p)
        assert list(rlwe.poly_mul(a, b, p)) == _naive_negacyclic(a, b, p.n, p.q)

    def test_x_to_the_n_is_minus_one(self):
        p = rlwe.PARAMS["P1"]
        x = np.zeros(p.n, dtype=np.int64)
        x[p.n - 1] = 1                               # x^(n-1)
        x1 = np.zeros(p.n, dtype=np.int64)
        x1[1] = 1                                    # x
        prod = rlwe.poly_mul(x, x1, p)               # x^n = -1
        assert prod[0] == p.q - 1 and not prod[1:].any()

    @pytest.mark.parametrize("name", ["P1", "P2"])
    def test_gaussian_sampler_statistics(self, name):
        p = rlwe.PARAMS[name]
        s = np.concatenate([rlwe.sample_gaussian(p) for _ in range(100)])
        assert abs(s.mean()) < 0.1
        assert s.std() == pytest.approx(p.sigma, rel=0.05)

    def test_uniform_sampler_range(self):
        p = rlwe.PARAMS["P2"]
        u = np.concatenate([rlwe.sample_uniform(p) for _ in range(20)])
        assert u.min() >= 0 and u.max() < p.q
        assert abs(u.mean() - (p.q - 1) / 2) < p.q * 0.03

    @pytest.mark.parametrize("name,expected_cts", [("P1", 2), ("P2", 1)])
    def test_key_roundtrip(self, name, expected_cts):
        import json
        sk = rlwe.generate_keypair(name)
        for _ in range(25):
            key = os.urandom(32)
            enc = rlwe.encrypt_key(key, sk.public)
            assert len(json.loads(enc)["ciphertexts"]) == expected_cts
            assert rlwe.decrypt_key(enc, sk) == key

    def test_public_key_relation(self):
        """p = r1 - a*r2  =>  p + a*r2 must be a small (Gaussian) polynomial r1."""
        sk = rlwe.generate_keypair("P2")
        p = sk.params
        r1 = rlwe.poly_add(sk.public.p, rlwe.poly_mul(sk.public.a, sk.r2, p), q=p.q)
        centred = np.where(r1 > p.q // 2, r1 - p.q, r1)
        assert np.abs(centred).max() <= np.ceil(12 * p.sigma)

    def test_encryption_is_randomized(self, recipient_rlwe):
        key = os.urandom(32)
        assert rlwe.encrypt_key(key, recipient_rlwe.public) != rlwe.encrypt_key(key, recipient_rlwe.public)

    def test_wrong_private_key_gives_wrong_key(self, recipient_rlwe, other_rlwe):
        key = os.urandom(32)
        assert rlwe.decrypt_key(rlwe.encrypt_key(key, recipient_rlwe.public), other_rlwe) != key

    def test_param_mismatch_rejected(self, recipient_rlwe):
        enc = rlwe.encrypt_key(os.urandom(32), recipient_rlwe.public)
        with pytest.raises(rlwe.RLWEError):
            rlwe.decrypt_key(enc, rlwe.generate_keypair("P1"))

    def test_malformed_ciphertext_rejected(self, recipient_rlwe):
        with pytest.raises(rlwe.RLWEError):
            rlwe.decrypt_key(b"{not json", recipient_rlwe)

    def test_key_serialization(self, recipient_rlwe):
        pub = rlwe.public_key_from_bytes(rlwe.public_key_to_bytes(recipient_rlwe.public))
        priv = rlwe.private_key_from_bytes(rlwe.private_key_to_bytes(recipient_rlwe))
        key = os.urandom(32)
        assert rlwe.decrypt_key(rlwe.encrypt_key(key, pub), priv) == key

    def test_passphrase_protected_private_key(self, recipient_rlwe):
        blob = rlwe.private_key_to_bytes(recipient_rlwe, b"correct horse")
        assert rlwe._pack(recipient_rlwe.r2) not in blob.decode()
        assert np.array_equal(rlwe.private_key_from_bytes(blob, b"correct horse").r2, recipient_rlwe.r2)
        with pytest.raises(rlwe.RLWEError):
            rlwe.private_key_from_bytes(blob, b"wrong")
        with pytest.raises(rlwe.RLWEError):
            rlwe.private_key_from_bytes(blob)


# --------------------------------------------------------------------------- RSA
class TestRSASignature:
    def test_key_size(self, owner_rsa):
        assert owner_rsa.key_size == 3072

    def test_sign_verify(self, owner_rsa):
        sig = signature.sign(b"mht", owner_rsa)
        assert signature.verify(b"mht", sig, owner_rsa.public_key())
        assert not signature.verify(b"mhT", sig, owner_rsa.public_key())

    def test_signed_mht_roundtrip(self, owner_rsa):
        signed = signature.create_signed_mht(b"RING-CRYPTER-MHT v1\nroot: x\n", owner_rsa)
        assert signature.verify_signed_mht(signed, owner_rsa.public_key()) == \
            b"RING-CRYPTER-MHT v1\nroot: x\n"

    def test_wrong_public_key(self, owner_rsa, attacker_rsa):
        signed = signature.create_signed_mht(b"data\n", owner_rsa)
        with pytest.raises(signature.SignatureError):
            signature.verify_signed_mht(signed, attacker_rsa.public_key())

    def test_modified_content(self, owner_rsa):
        signed = signature.create_signed_mht(b"data\n", owner_rsa)
        with pytest.raises(signature.SignatureError):
            signature.verify_signed_mht(b"Data" + signed[4:], owner_rsa.public_key())

    def test_missing_signature(self, owner_rsa):
        with pytest.raises(signature.SignatureError):
            signature.verify_signed_mht(b"data\n", owner_rsa.public_key())

    def test_pem_roundtrip_with_passphrase(self, owner_rsa):
        pem = signature.private_key_to_pem(owner_rsa, b"pw")
        assert b"ENCRYPTED" in pem
        key = signature.load_private_key(pem, b"pw")
        sig = signature.sign(b"m", key)
        pub = signature.load_public_key(signature.public_key_to_pem(owner_rsa.public_key()))
        assert signature.verify(b"m", sig, pub)
