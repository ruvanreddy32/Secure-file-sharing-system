"""End-to-end workflow: functional and tampering tests (paper §IV, §V-C)."""

import dataclasses
import os

import pytest

from securecloud import aes_cipher, mht, rlwe, signature, workflow
from securecloud.storage import LocalFolderStorage
from securecloud.workflow import IntegrityError, decrypt_verified, open_bundle, verify_integrity

PLAINTEXT = os.urandom(4096 * 6 + 123)   # 7 blocks after encryption


def _replace(bundle, **kw):
    return dataclasses.replace(bundle, **kw)


def _flip(data: bytes, *offsets: int) -> bytes:
    b = bytearray(data)
    for off in offsets:
        b[off] ^= 0x01
    return bytes(b)


def _assert_rejected(bundle, owner_rsa, recipient_rlwe):
    """Every tampered bundle: verification fails AND decryption is refused."""
    report = verify_integrity(bundle, owner_rsa.public_key())
    assert not report.ok
    assert report.verified_digest == ""
    with pytest.raises(IntegrityError):
        open_bundle(bundle, owner_rsa.public_key(), recipient_rlwe)
    with pytest.raises(IntegrityError):
        decrypt_verified(bundle, report, recipient_rlwe)
    return report


# --------------------------------------------------------------------------- functional
class TestFunctional:
    def test_setup_produces_three_files(self, protect):
        b = protect(PLAINTEXT, "report.pdf")
        assert set(b.files()) == {"report.pdf.aes", "report.pdf.key.rlwe", "report.pdf.mht.signed"}
        assert PLAINTEXT not in b.encrypted_file

    def test_mht_is_over_ciphertext_not_plaintext(self, protect, owner_rsa):
        b = protect(PLAINTEXT)
        stored = mht.parse(signature.verify_signed_mht(b.signed_mht, owner_rsa.public_key()))
        assert stored.root == mht.build_tree(b.encrypted_file, 4096).root.hash
        assert stored.root != mht.build_tree(PLAINTEXT, 4096).root.hash

    def test_setup_timings(self, owner_rsa, recipient_rlwe):
        _b, t = workflow.setup_phase(PLAINTEXT, "x", owner_rsa, recipient_rlwe.public)
        for k in ("aes_encrypt_ms", "rlwe_key_encrypt_ms", "sha256_block_hashing_ms",
                  "mht_construction_ms", "rsa_sign_ms", "total_setup_ms"):
            assert t[k] >= 0

    def test_unmodified_file_verifies_and_decrypts(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert report.ok and report.signature_valid and report.mht_match and report.key_file_match
        assert report.stored_root == report.computed_root
        assert "Verified" in report.summary
        assert out == PLAINTEXT

    def test_upload_download_roundtrip_local_folder(self, protect, owner_rsa, recipient_rlwe, tmp_path):
        store = LocalFolderStorage(tmp_path / "cloud")
        b = protect(PLAINTEXT, "data.txt")
        workflow.upload_bundle(store, b)
        assert workflow.list_bundles(store) == ["data.txt"]
        dl, _ms = workflow.download_bundle(store, "data.txt")
        assert dl == b
        out, report = open_bundle(dl, owner_rsa.public_key(), recipient_rlwe)
        assert report.ok and out == PLAINTEXT

    def test_save_and_load_bundle(self, protect, tmp_path):
        b = protect(PLAINTEXT, "a.bin")
        workflow.save_bundle(b, tmp_path)
        assert workflow.load_bundle(tmp_path, "a.bin") == b

    def test_paper_mode_end_to_end(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT, paper_mode=True)
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert report.block_count == 2 and out == PLAINTEXT

    def test_p1_parameters_end_to_end(self, owner_rsa):
        sk = rlwe.generate_keypair("P1")
        b, _ = workflow.setup_phase(PLAINTEXT, "p1.bin", owner_rsa, sk.public)
        out, report = open_bundle(b, owner_rsa.public_key(), sk)
        assert report.ok and out == PLAINTEXT


# --------------------------------------------------------------------------- tampering
class TestTampering:
    def test_modify_one_block(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        r = _assert_rejected(_replace(b, encrypted_file=_flip(b.encrypted_file, 4096 * 3 + 10)),
                             owner_rsa, recipient_rlwe)
        assert r.signature_valid and not r.mht_match and r.tampered_blocks == [3]

    def test_modify_multiple_blocks(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        bad = _flip(b.encrypted_file, 0, 4096 * 2, 4096 * 6 + 1)
        r = _assert_rejected(_replace(b, encrypted_file=bad), owner_rsa, recipient_rlwe)
        assert r.tampered_blocks == [0, 2, 6]

    def test_single_bit_in_last_partial_block(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        r = _assert_rejected(_replace(b, encrypted_file=_flip(b.encrypted_file, len(b.encrypted_file) - 1)),
                             owner_rsa, recipient_rlwe)
        assert r.tampered_blocks == [r.block_count - 1]

    def test_delete_part_of_file(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        r = _assert_rejected(_replace(b, encrypted_file=b.encrypted_file[:4096 * 4]),
                             owner_rsa, recipient_rlwe)
        assert r.size_changed

    def test_delete_bytes_in_middle(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        e = b.encrypted_file
        _assert_rejected(_replace(b, encrypted_file=e[:5000] + e[5100:]), owner_rsa, recipient_rlwe)

    def test_append_data(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        r = _assert_rejected(_replace(b, encrypted_file=b.encrypted_file + b"\x00"),
                             owner_rsa, recipient_rlwe)
        assert r.size_changed

    def test_empty_downloaded_file(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        _assert_rejected(_replace(b, encrypted_file=b""), owner_rsa, recipient_rlwe)

    def test_replace_with_different_content_same_size(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        _assert_rejected(_replace(b, encrypted_file=os.urandom(len(b.encrypted_file))),
                         owner_rsa, recipient_rlwe)

    def test_replace_with_other_validly_encrypted_file(self, protect, owner_rsa, recipient_rlwe):
        """Attacker swaps in a different file encrypted by the same owner (same name)."""
        a, other = protect(PLAINTEXT, "data.txt"), protect(b"other content", "data.txt")
        _assert_rejected(_replace(a, encrypted_file=other.encrypted_file), owner_rsa, recipient_rlwe)
        _assert_rejected(_replace(a, encrypted_file=other.encrypted_file,
                                  encrypted_key=other.encrypted_key), owner_rsa, recipient_rlwe)

    def test_swap_bundle_between_file_names(self, protect, owner_rsa, recipient_rlwe):
        other = protect(b"payroll", "payroll.xlsx")
        r = _assert_rejected(_replace(other, name="data.txt"), owner_rsa, recipient_rlwe)
        assert not r.file_name_match

    def test_modify_mht_metadata(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        mht_bytes, _sig = signature.split_signed_mht(b.signed_mht)
        idx = b.signed_mht.index(b"\nL0 0 ") + 7
        bad = bytearray(b.signed_mht)
        bad[idx] = ord("0") if bad[idx] != ord("0") else ord("1")
        r = _assert_rejected(_replace(b, signed_mht=bytes(bad)), owner_rsa, recipient_rlwe)
        assert not r.signature_valid

    def test_attacker_rewrites_mht_to_match_tampered_file(self, protect, owner_rsa, recipient_rlwe):
        """Tamper the file AND recompute a matching MHT; the old signature no longer verifies."""
        b = protect(PLAINTEXT)
        bad_file = _flip(b.encrypted_file, 100)
        forged = mht.serialize(mht.generate_mht(bad_file, b.encrypted_name, b.encrypted_key))
        _mht, sig_block = b.signed_mht[: b.signed_mht.index(signature.BEGIN)], \
            b.signed_mht[b.signed_mht.index(signature.BEGIN):]
        r = _assert_rejected(_replace(b, encrypted_file=bad_file, signed_mht=forged + sig_block),
                             owner_rsa, recipient_rlwe)
        assert not r.signature_valid

    def test_replace_signature(self, protect, owner_rsa, attacker_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        mht_bytes, _ = signature.split_signed_mht(b.signed_mht)
        resigned = signature.create_signed_mht(mht_bytes, attacker_rsa)
        r = _assert_rejected(_replace(b, signed_mht=resigned), owner_rsa, recipient_rlwe)
        assert not r.signature_valid

    def test_attacker_signs_forged_mht_with_own_key(self, protect, owner_rsa, attacker_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        bad_file = _flip(b.encrypted_file, 50)
        forged = signature.create_signed_mht(
            mht.serialize(mht.generate_mht(bad_file, b.encrypted_name, b.encrypted_key)), attacker_rsa)
        _assert_rejected(_replace(b, encrypted_file=bad_file, signed_mht=forged), owner_rsa, recipient_rlwe)

    def test_signature_removed(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        mht_bytes, _ = signature.split_signed_mht(b.signed_mht)
        _assert_rejected(_replace(b, signed_mht=mht_bytes), owner_rsa, recipient_rlwe)

    def test_corrupted_signature_bytes(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        pos = b.signed_mht.index(b"signer-key-sha256")
        pos = b.signed_mht.index(b"\n", pos) + 5
        bad = bytearray(b.signed_mht)
        bad[pos] = ord("A") if bad[pos] != ord("A") else ord("B")
        _assert_rejected(_replace(b, signed_mht=bytes(bad)), owner_rsa, recipient_rlwe)

    def test_incorrect_public_key(self, protect, attacker_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        report = verify_integrity(b, attacker_rsa.public_key())
        assert not report.ok and not report.signature_valid
        with pytest.raises(IntegrityError):
            open_bundle(b, attacker_rsa.public_key(), recipient_rlwe)

    def test_modified_encrypted_key_file(self, protect, owner_rsa, recipient_rlwe):
        import json
        import numpy as np
        b = protect(PLAINTEXT)
        doc = json.loads(b.encrypted_key)
        c2 = rlwe._unpack(doc["ciphertexts"][0]["c2"], recipient_rlwe.params)
        c2[0] = (c2[0] + recipient_rlwe.params.q // 2) % recipient_rlwe.params.q
        doc["ciphertexts"][0]["c2"] = rlwe._pack(np.asarray(c2))
        r = _assert_rejected(_replace(b, encrypted_key=json.dumps(doc, indent=1).encode()),
                             owner_rsa, recipient_rlwe)
        assert r.signature_valid and r.mht_match and not r.key_file_match

    def test_decryption_blocked_after_failed_verification(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT)
        bad = _replace(b, encrypted_file=_flip(b.encrypted_file, 20))
        report = verify_integrity(bad, owner_rsa.public_key())
        assert not report.ok
        with pytest.raises(IntegrityError, match="refused"):
            decrypt_verified(bad, report, recipient_rlwe)
        report.ok = True   # even a forged 'ok' flag does not help: digest is bound to bytes
        with pytest.raises(IntegrityError):
            decrypt_verified(bad, report, recipient_rlwe)

    def test_report_of_other_bundle_cannot_unlock(self, protect, owner_rsa, recipient_rlwe):
        good = protect(PLAINTEXT)
        report = verify_integrity(good, owner_rsa.public_key())
        assert report.ok
        bad = _replace(good, encrypted_file=_flip(good.encrypted_file, 20))
        with pytest.raises(IntegrityError, match="not the ones that were verified"):
            decrypt_verified(bad, report, recipient_rlwe)

    def test_decrypt_requires_a_report(self, protect, recipient_rlwe):
        with pytest.raises(IntegrityError):
            decrypt_verified(protect(PLAINTEXT), None, recipient_rlwe)

    def test_wrong_recipient_cannot_decrypt(self, protect, owner_rsa, other_rlwe):
        """Integrity verifies (public check) but only the intended recipient recovers K."""
        b = protect(PLAINTEXT)
        with pytest.raises(aes_cipher.DecryptionError):
            open_bundle(b, owner_rsa.public_key(), other_rlwe)

    def test_paper_mode_detects_tampering(self, protect, owner_rsa, recipient_rlwe):
        b = protect(PLAINTEXT, paper_mode=True)
        r = _assert_rejected(_replace(b, encrypted_file=_flip(b.encrypted_file, len(b.encrypted_file) - 3)),
                             owner_rsa, recipient_rlwe)
        assert r.tampered_blocks == [1]
