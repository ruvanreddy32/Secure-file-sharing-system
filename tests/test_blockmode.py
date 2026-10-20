"""ENHANCEMENT (not part of the IEEE paper): per-block AES-256-GCM files (RCB1) and
block-level dynamic updates.  Repository tests run on mocked Supabase, mocked Dropbox and the
local folder."""

import json
import os

import pytest

from fakes import FakeSupabaseClient
from test_storage import FakeDropboxClient
from test_versioning import FlakyStorage
from securecloud import aes_cipher, blockmode as bm, mht, signature, workflow
from securecloud.storage import CountingStorage, DropboxStorage, LocalFolderStorage, SupabaseStorage
from securecloud.versioning import (ManifestError, PublishError, VersionedRepository, block_key,
                                    manifest_key)
from securecloud.workflow import IntegrityError, decrypt_verified

BS = bm.BLOCK_SIZE
DATA = os.urandom(16 * BS + 1234)          # 17 blocks, partial last block


def _meta(signed):
    return mht.parse(signature.split_signed_mht(signed)[0])


# =========================================================================== pure block layer
class TestBlockCrypto:
    KEY, FID = aes_cipher.generate_file_key(), os.urandom(16)

    def test_roundtrip_and_overhead(self):
        cb = bm.encrypt_block(self.KEY, self.FID, 3, 2, b"x" * 100)
        assert len(cb) == 100 + bm.OVERHEAD
        assert bm.parse_block_header(cb)[:2] == (3, 2)
        assert bm.decrypt_block(self.KEY, self.FID, 3, cb) == b"x" * 100

    def test_block_moved_to_other_index_fails(self):
        cb = bm.encrypt_block(self.KEY, self.FID, 3, 1, b"data")
        with pytest.raises(aes_cipher.DecryptionError):
            bm.decrypt_block(self.KEY, self.FID, 4, cb)

    def test_header_index_rewritten_fails_aad(self):
        cb = bytearray(bm.encrypt_block(self.KEY, self.FID, 3, 1, b"data"))
        cb[4:12] = (4).to_bytes(8, "big")
        with pytest.raises(aes_cipher.DecryptionError):
            bm.decrypt_block(self.KEY, self.FID, 4, bytes(cb))

    def test_version_field_bound_by_aad(self):
        cb = bytearray(bm.encrypt_block(self.KEY, self.FID, 0, 1, b"data"))
        cb[12:16] = (5).to_bytes(4, "big")
        with pytest.raises(aes_cipher.DecryptionError):
            bm.decrypt_block(self.KEY, self.FID, 0, bytes(cb))

    def test_other_file_identity_fails(self):
        cb = bm.encrypt_block(self.KEY, self.FID, 0, 1, b"data")
        with pytest.raises(aes_cipher.DecryptionError):
            bm.decrypt_block(self.KEY, os.urandom(16), 0, cb)

    def test_ciphertext_tamper_fails(self):
        cb = bytearray(bm.encrypt_block(self.KEY, self.FID, 0, 1, b"data"))
        cb[-1] ^= 1
        with pytest.raises(aes_cipher.DecryptionError):
            bm.decrypt_block(self.KEY, self.FID, 0, bytes(cb))

    def test_nonces_are_fresh(self):
        nonces = {bm.parse_block_header(bm.encrypt_block(self.KEY, self.FID, i, 1, b""))[2]
                  for i in range(2000)}
        assert len(nonces) == 2000

    def test_oversized_block_rejected(self):
        with pytest.raises(ValueError):
            bm.encrypt_block(self.KEY, self.FID, 0, 1, b"x" * (BS + 1))


class TestPlanning:
    def _m(self, size):
        n = bm.block_count_for(size)
        return mht.MHTData("f.rcb", size + n * bm.OVERHEAD, BS, [["0" * 64] * n], "0" * 64,
                           encryption_format="RCB1", file_id="0" * 32, plaintext_size=size,
                           owner_key_sha256="0" * 64, key_block_encryptions=n)

    def test_patch_inside_one_block_reads_it(self):
        reads = []
        changes, size = bm.plan_patch(self._m(3 * BS), 10, b"abc", lambda i: reads.append(i) or b"\1" * BS)
        assert list(changes) == [0] and size == 3 * BS and reads == [0]
        assert changes[0][10:13] == b"abc" and changes[0][:10] == b"\1" * 10

    def test_patch_spanning_two_blocks(self):
        changes, _ = bm.plan_patch(self._m(3 * BS), BS - 2, b"WXYZ", lambda i: b"\0" * BS)
        assert sorted(changes) == [0, 1]
        assert changes[0][-2:] == b"WX" and changes[1][:2] == b"YZ"

    def test_full_block_overwrite_needs_no_read(self):
        reads = []
        bm.plan_patch(self._m(3 * BS), BS, b"\7" * BS, lambda i: reads.append(i) or b"")
        assert reads == []

    def test_append_from_partial_last_block(self):
        changes, size = bm.plan_patch(self._m(BS + 100), BS + 100, b"z" * 5000, lambda i: b"\2" * 100)
        assert size == BS + 5100 and sorted(changes) == [1, 2]
        assert len(changes[1]) == BS and len(changes[2]) == (BS + 5100) - 2 * BS
        assert changes[1][:100] == b"\2" * 100 and changes[1][100:] == b"z" * (BS - 100)

    def test_offset_beyond_end_rejected(self):
        with pytest.raises(ValueError):
            bm.plan_patch(self._m(100), 101, b"x", lambda i: b"")

    def test_replace_block_rules(self):
        m = self._m(3 * BS + 10)
        with pytest.raises(ValueError):
            bm.plan_replace_block(m, 1, b"short")
        changes, size = bm.plan_replace_block(m, 3, b"tail!")
        assert size == 3 * BS + 5 and changes == {3: b"tail!"}

    def test_multiple_edits_one_version(self):
        reads = []
        changes, size = bm.plan_patches(self._m(4 * BS), [(10, b"aa"), (20, b"bb"), (3 * BS + 1, b"cc")],
                                        lambda i: reads.append(i) or b"\0" * BS)
        assert sorted(changes) == [0, 3] and reads == [0, 3]          # block 0 read once
        assert changes[0][10:12] == b"aa" and changes[0][20:22] == b"bb" and size == 4 * BS

    def test_multiple_edits_with_growth(self):
        changes, size = bm.plan_patches(self._m(BS), [(BS, b"x" * 10), (BS + 5, b"yy")], lambda i: b"\1" * BS)
        assert size == BS + 10 and changes[1] == b"xxxxxyyxxx"

    def test_sync_diff(self):
        old = os.urandom(5 * BS)
        new = bytearray(old)
        new[2 * BS + 7] ^= 1
        changes, size = bm.plan_sync(self._m(len(old)), old, bytes(new))
        assert list(changes) == [2] and size == len(old)
        changes, size = bm.plan_sync(self._m(len(old)), old, old[:2 * BS + 1])   # shrink
        assert list(changes) == [2] and size == 2 * BS + 1


class TestUpdateBuilder:
    @pytest.fixture
    def v1(self, owner_rsa, recipient_rlwe, owner_rlwe):
        b, _ = bm.block_setup_phase(DATA, "f.bin", owner_rsa, recipient_rlwe.public, owner_rlwe.public)
        return b, bm.recover_file_key(b.owner_key, owner_rlwe)

    def test_uses_merkle_updater_path_only(self, v1, owner_rsa, monkeypatch):
        b, key = v1
        calls = []
        real = bm.merkle_update_block
        monkeypatch.setattr(bm, "merkle_update_block", lambda t, i, d: calls.append(i) or real(t, i, d))
        meta = _meta(b.signed_mht)
        upd = bm.build_block_update(meta, b.signed_mht, key, {3: b"\1" * BS, 9: b"\2" * BS},
                                    meta.plaintext_size, owner_rsa)
        assert calls == [3, 9]
        height = 5                                           # 17 leaves -> ceil(log2 17)
        assert upd.stats["sha256_internal_hashes"] == 2 * height
        assert upd.stats["sha256_leaf_hashes"] == 2 and upd.stats["plaintext_bytes_encrypted"] == 2 * BS
        # the incremental tree equals a full rebuild over the new leaves
        leaves = list(meta.leaf_hashes)
        for i, cb in upd.new_blocks.items():
            leaves[i] = bm._sha(cb)
        from merkle.tree import MerkleTree
        assert upd.meta.levels == MerkleTree.from_leaf_hashes(leaves, BS).level_hashes()
        assert upd.meta.version == 2 and upd.meta.previous_mht_sha256 == bm._sha(b.signed_mht)
        assert upd.meta.key_block_encryptions == 17 + 2

    def test_nonce_budget_enforced(self, v1, owner_rsa):
        b, key = v1
        meta = _meta(b.signed_mht)
        meta.key_block_encryptions = bm.MAX_BLOCK_ENCRYPTIONS
        with pytest.raises(bm.BlockFormatError, match="nonce budget"):
            bm.build_block_update(meta, b.signed_mht, key, {0: b"\0" * BS}, meta.plaintext_size, owner_rsa)

    def test_missing_new_blocks_rejected(self, v1, owner_rsa):
        b, key = v1
        meta = _meta(b.signed_mht)
        with pytest.raises(ValueError):
            bm.build_block_update(meta, b.signed_mht, key, {}, meta.plaintext_size + 10 * BS, owner_rsa)


class TestVerification:
    @pytest.fixture
    def b1(self, owner_rsa, recipient_rlwe, owner_rlwe):
        return bm.block_setup_phase(DATA, "f.bin", owner_rsa, recipient_rlwe.public, owner_rlwe.public)[0]

    def test_ok_and_decrypt(self, b1, owner_rsa, recipient_rlwe):
        r = bm.block_verify_integrity(b1, owner_rsa.public_key())
        assert r.ok and decrypt_verified(b1, r, recipient_rlwe) == DATA

    def test_metadata_is_v3_and_signed(self, b1):
        meta = _meta(b1.signed_mht)
        assert b1.signed_mht.startswith(b"RING-CRYPTER-MHT v3\n")
        assert (meta.encryption_format, meta.plaintext_size, meta.block_count) == ("RCB1", len(DATA), 17)

    @pytest.mark.parametrize("attack", ["swap", "drop_last", "replace_random", "duplicate"])
    def test_block_level_attacks(self, b1, owner_rsa, recipient_rlwe, attack):
        blocks = list(b1.blocks)
        if attack == "swap":
            blocks[2], blocks[5] = blocks[5], blocks[2]
        elif attack == "drop_last":
            blocks = blocks[:-1]
        elif attack == "replace_random":
            blocks[4] = os.urandom(len(blocks[4]))
        else:
            blocks[6] = blocks[3]
        bad = bm.BlockBundle(b1.name, blocks, b1.encrypted_key, b1.owner_key, b1.signed_mht)
        r = bm.block_verify_integrity(bad, owner_rsa.public_key())
        assert not r.ok
        with pytest.raises(IntegrityError):
            decrypt_verified(bad, r, recipient_rlwe)
        if attack == "swap":
            assert r.tampered_blocks == [2, 5]

    def test_duplicate_nonce_rejected_even_if_signed(self, owner_rsa, recipient_rlwe, owner_rlwe, monkeypatch):
        """An owner-side RNG failure (repeated nonce) is caught by the verifier."""
        monkeypatch.setattr(bm.os, "urandom", lambda n: b"\x07" * n)
        b, _ = bm.block_setup_phase(b"a" * (3 * BS), "n.bin",
                                    owner_rsa, recipient_rlwe.public, owner_rlwe.public)
        monkeypatch.undo()
        r = bm.block_verify_integrity(b, owner_rsa.public_key())
        assert not r.ok and any("nonce reused" in m for m in r.messages)

    def test_owner_key_file_bound(self, b1, owner_rsa):
        bad = bm.BlockBundle(b1.name, b1.blocks, b1.encrypted_key, b1.owner_key + b" ", b1.signed_mht)
        r = bm.block_verify_integrity(bad, owner_rsa.public_key())
        assert not r.ok and not r.key_file_match

    def test_whole_file_metadata_still_v2(self, protect):
        """Backward compatibility: the paper's RCF1 path writes exactly the v2 format."""
        b = protect(b"hello")
        assert b.signed_mht.startswith(b"RING-CRYPTER-MHT v2\n") and b"encryption-format" not in b.signed_mht


# =========================================================================== repository (cloud)
@pytest.fixture(params=["supabase", "dropbox", "local"])
def store(request, tmp_path):
    if request.param == "supabase":
        return SupabaseStorage("ringcrypter", client=FakeSupabaseClient())
    if request.param == "dropbox":
        return DropboxStorage("/RingCrypter", client=FakeDropboxClient())
    return LocalFolderStorage(tmp_path / "cloud")


@pytest.fixture
def counter(store):
    return CountingStorage(store)


@pytest.fixture
def repo(counter, owner_rsa, recipient_rlwe, owner_rlwe):
    r = VersionedRepository(counter)
    b, _ = bm.block_setup_phase(DATA, "big.bin", owner_rsa, recipient_rlwe.public, owner_rlwe.public)
    r.publish(b, owner_rsa)
    counter.reset()
    return r


def _open(repo, owner_rsa, recipient_rlwe, version=None, **kw):
    b, r = repo.fetch_verified("big.bin", owner_rsa.public_key(), version, **kw)
    if not r.ok:
        with pytest.raises(IntegrityError):
            decrypt_verified(b, r, recipient_rlwe)
        return None, r
    return decrypt_verified(b, r, recipient_rlwe), r


def _expected_after_patch(data, offset, patch):
    out = bytearray(data)
    out[offset:offset + len(patch)] = patch
    return bytes(out)


class TestRepository:
    def test_layout_is_content_addressed(self, repo, store, owner_rsa):
        keys = store.list("big.bin")
        assert sum(k.startswith("big.bin/blocks/") for k in keys) == 17
        assert sum(k.startswith("big.bin/keys/") for k in keys) == 2
        v = [k for k in keys if "/v000001-" in k]
        assert len(v) == 1 and v[0].endswith(".mht.signed")

    def test_single_block_patch_uploads_one_block(self, repo, counter, owner_rsa, recipient_rlwe, owner_rlwe):
        entry, stats = repo.block_patch("big.bin", 3 * BS + 17, b"PATCH", owner_rsa, owner_rlwe)
        snap = counter.snapshot()
        assert entry.version == 2 and stats["blocks_changed"] == 1 and stats["unchanged_blocks_reused"] == 16
        assert snap["ops_upload"] == 3                                 # block + signed MHT + manifest
        assert snap["bytes_uploaded"] < len(DATA) / 5
        assert stats["merkle_mode"].startswith("incremental")
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out == _expected_after_patch(DATA, 3 * BS + 17, b"PATCH") and r.version == 2
        old, r1 = _open(repo, owner_rsa, recipient_rlwe, 1)
        assert old == DATA and r1.ok                                   # immutable old version

    def test_versions_share_unchanged_blocks(self, repo, owner_rsa, owner_rlwe):
        repo.block_patch("big.bin", 0, b"x", owner_rsa, owner_rlwe)
        b1 = set(repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"])
        b2 = set(repo.keys_for("big.bin", 2, owner_rsa.public_key())["blocks"])
        assert len(b1 & b2) == 16 and len(b2 - b1) == 1

    def test_multiple_updates_chain(self, repo, owner_rsa, recipient_rlwe, owner_rlwe):
        expected = {1: DATA}
        cur = DATA
        repo.block_patch("big.bin", 100, b"one", owner_rsa, owner_rlwe)
        cur = _expected_after_patch(cur, 100, b"one"); expected[2] = cur
        repo.block_replace("big.bin", 7, b"\x55" * BS, owner_rsa, owner_rlwe)
        cur = cur[:7 * BS] + b"\x55" * BS + cur[8 * BS:]; expected[3] = cur
        repo.block_patch("big.bin", len(cur), b"appended" * 1000, owner_rsa, owner_rlwe)
        cur = cur + b"appended" * 1000; expected[4] = cur
        repo.block_replace("big.bin", 18, b"end", owner_rsa, owner_rlwe)     # shrink last block
        cur = cur[:18 * BS] + b"end"; expected[5] = cur
        for v, exp in expected.items():
            out, r = _open(repo, owner_rsa, recipient_rlwe, v)
            assert out == exp and r.ok and r.version == v, v

    def test_patch_many_uploads_only_touched_blocks(self, repo, counter, owner_rsa, recipient_rlwe, owner_rlwe):
        edits = [(i * 2 * BS + 50, b"E%d" % i) for i in range(8)]
        _, stats = repo.block_patch_many("big.bin", edits, owner_rsa, owner_rlwe)
        assert stats["blocks_changed"] == 8 and counter.ops["upload"] == 10      # 8 blocks + MHT + manifest
        assert stats["blocks_read_for_partial_writes"] == 8
        expected = bytearray(DATA)
        for off, d in edits:
            expected[off:off + len(d)] = d
        assert _open(repo, owner_rsa, recipient_rlwe)[0] == bytes(expected)

    def test_sync_uploads_only_differing_blocks(self, repo, counter, owner_rsa, recipient_rlwe, owner_rlwe):
        new = bytearray(DATA)
        new[2 * BS] ^= 1
        new[11 * BS + 5] ^= 1
        counter.reset()
        _, stats = repo.block_sync("big.bin", bytes(new), owner_rsa, owner_rlwe)
        assert stats["new_block_objects_uploaded"] == 2 and counter.ops["upload"] == 4
        assert _open(repo, owner_rsa, recipient_rlwe)[0] == bytes(new)

    def test_sync_shrink_and_grow(self, repo, owner_rsa, recipient_rlwe, owner_rlwe):
        repo.block_sync("big.bin", DATA[:5 * BS + 3], owner_rsa, owner_rlwe)
        assert _open(repo, owner_rsa, recipient_rlwe)[0] == DATA[:5 * BS + 3]
        repo.block_sync("big.bin", DATA + b"more", owner_rsa, owner_rlwe)
        assert _open(repo, owner_rsa, recipient_rlwe)[0] == DATA + b"more"


class TestRepositoryAttacks:
    def _v2(self, repo, owner_rsa, owner_rlwe):
        repo.block_patch("big.bin", 3 * BS, b"new content", owner_rsa, owner_rlwe)
        k1 = repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"]
        k2 = repo.keys_for("big.bin", 2, owner_rsa.public_key())["blocks"]
        return k1, k2

    def test_replay_old_block_into_new_version(self, repo, store, owner_rsa, recipient_rlwe, owner_rlwe):
        k1, k2 = self._v2(repo, owner_rsa, owner_rlwe)
        store.upload(k2[3], store.download(k1[3]))          # genuine old block 3
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out is None and r.tampered_blocks == [3]

    def test_block_substitution_and_reorder(self, repo, store, owner_rsa, recipient_rlwe):
        k = repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"]
        a, b = store.download(k[2]), store.download(k[9])
        store.upload(k[2], b)
        store.upload(k[9], a)
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out is None and r.tampered_blocks == [2, 9]

    def test_missing_block_object(self, repo, store, owner_rsa, recipient_rlwe):
        k = repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"]
        store.delete([k[4]])
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out is None and 4 in r.tampered_blocks and "missing" in r.summary

    def test_tampered_signed_mht(self, repo, store, owner_rsa, recipient_rlwe):
        mk = repo.keys_for("big.bin", 1, owner_rsa.public_key())["signed_mht"]
        signed = store.download(mk)
        store.upload(mk, signed.replace(b"plaintext-size: ", b"plaintext-size: 1"))
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out is None and r.manifest_valid is False

    def test_forged_version_by_attacker(self, repo, store, owner_rsa, attacker_rsa, recipient_rlwe, owner_rlwe):
        """Attacker with write access builds 'v2' signed with its own key and a forged manifest."""
        evil_repo = VersionedRepository(store)
        evil, _ = bm.block_setup_phase(b"evil", "big.bin", attacker_rsa, recipient_rlwe.public, owner_rlwe.public)
        m = json.loads(signature.split_signed_mht(store.download(manifest_key("big.bin")))[0])
        m["current_version"] = 2
        store.upload(manifest_key("big.bin"), signature.create_signed_mht(
            (json.dumps(m) + "\n").encode(), attacker_rsa))
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out is None and r.manifest_valid is False
        with pytest.raises(ManifestError):
            evil_repo.block_patch("big.bin", 0, b"x", attacker_rsa, owner_rlwe)

    def test_unauthorized_block_patch_refused(self, repo, attacker_rsa, owner_rlwe):
        with pytest.raises(ManifestError):
            repo.block_patch("big.bin", 0, b"x", attacker_rsa, owner_rlwe)

    def test_update_refused_if_partial_block_corrupted(self, repo, store, owner_rsa, owner_rlwe):
        k = repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"]
        data = bytearray(store.download(k[0]))
        data[-1] ^= 1
        store.upload(k[0], bytes(data))
        with pytest.raises(IntegrityError, match="block 0 is corrupted"):
            repo.block_patch("big.bin", 5, b"x", owner_rsa, owner_rlwe)

    def test_wrong_owner_ring_lwe_key_cannot_update(self, repo, owner_rsa, other_rlwe):
        with pytest.raises(Exception):
            repo.block_patch("big.bin", 5, b"x", owner_rsa, other_rlwe)   # recovers a wrong K

    def test_rollback_detected_with_min_version(self, repo, store, owner_rsa, recipient_rlwe, owner_rlwe):
        old_manifest = store.download(manifest_key("big.bin"))
        repo.block_patch("big.bin", 0, b"v2", owner_rsa, owner_rlwe)
        store.upload(manifest_key("big.bin"), old_manifest)
        out, r = _open(repo, owner_rsa, recipient_rlwe, min_version=2)
        assert out is None and "Rollback" in r.summary


class TestInterruptedUpdates:
    @pytest.mark.parametrize("fail_on", ["/blocks/", ".mht.signed", "manifest.signed"])
    def test_interrupted_update_not_activated(self, repo, counter, owner_rsa, recipient_rlwe, owner_rlwe, fail_on):
        before = set(counter.inner.list("big.bin"))
        flaky = VersionedRepository(FlakyStorage(counter.inner, lambda k: fail_on in k and "/v000001-" not in k
                                                 and not k.startswith("big.bin/blocks/x")))
        with pytest.raises(PublishError, match="NOT activ"):
            flaky.block_patch("big.bin", 0, b"half", owner_rsa, owner_rlwe)
        out, r = _open(repo, owner_rsa, recipient_rlwe)
        assert out == DATA and r.version == 1                       # old version stays active
        repo.cleanup_incomplete("big.bin", owner_rsa.public_key())
        assert set(counter.inner.list("big.bin")) == before          # only orphans removed
        repo.block_patch("big.bin", 0, b"half", owner_rsa, owner_rlwe)   # retry works
        assert _open(repo, owner_rsa, recipient_rlwe)[0][:4] == b"half"

    def test_missing_referenced_block_blocks_activation(self, repo, store, owner_rsa, recipient_rlwe, owner_rlwe):
        k = repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"]
        store.delete([k[10]])                                        # lost shared block
        with pytest.raises(PublishError, match="missing"):
            repo.block_patch("big.bin", 0, b"x", owner_rsa, owner_rlwe)
        _, r = repo.fetch_verified("big.bin", owner_rsa.public_key())
        assert r.version == 1                                        # nothing activated


class TestDeleteAndCompatibility:
    def test_delete_old_version_keeps_shared_blocks(self, repo, store, owner_rsa, recipient_rlwe, owner_rlwe):
        repo.block_patch("big.bin", 0, b"v2", owner_rsa, owner_rlwe)
        k1 = set(repo.keys_for("big.bin", 1, owner_rsa.public_key())["blocks"])
        k2 = set(repo.keys_for("big.bin", 2, owner_rsa.public_key())["blocks"])
        removed = repo.delete("big.bin", owner_rsa, version=1)
        assert set(k for k in removed if "/blocks/" in k) == k1 - k2        # only v1's unique block
        assert _open(repo, owner_rsa, recipient_rlwe)[0][:2] == b"v2"
        repo.delete("big.bin", owner_rsa)
        assert store.list("big.bin") == []

    def test_mixed_formats_in_one_repository(self, repo, protect, owner_rsa, recipient_rlwe, owner_rlwe):
        repo.publish(protect(b"paper workflow", "paper.txt"), owner_rsa)
        assert repo.list_files() == ["big.bin", "paper.txt"]
        b, r = repo.fetch_verified("paper.txt", owner_rsa.public_key())
        assert r.ok and decrypt_verified(b, r, recipient_rlwe) == b"paper workflow"
        repo.update("paper.txt", b"paper v2", owner_rsa, recipient_rlwe.public)   # whole-file path
        with pytest.raises(PublishError):
            repo.update("big.bin", b"x", owner_rsa, recipient_rlwe.public)      # wrong path for RCB1
        with pytest.raises(PublishError):
            repo.block_patch("paper.txt", 0, b"x", owner_rsa, owner_rlwe)       # wrong path for RCF1
        m, versions = repo.versions("paper.txt", owner_rsa.public_key())
        assert [v.format for v in versions] == ["RCF1", "RCF1"]
        _, bv = repo.versions("big.bin", owner_rsa.public_key())
        assert bv[0].format == "RCB1"

    def test_old_manifest_without_format_field(self, repo, protect, store, owner_rsa, recipient_rlwe):
        repo.publish(protect(b"legacy", "legacy.txt"), owner_rsa)
        body = json.loads(signature.split_signed_mht(store.download(manifest_key("legacy.txt")))[0])
        for v in body["versions"]:
            v.pop("format")                      # what manifests looked like before RCB1 existed
        store.upload(manifest_key("legacy.txt"),
                     signature.create_signed_mht((json.dumps(body) + "\n").encode(), owner_rsa))
        b, r = repo.fetch_verified("legacy.txt", owner_rsa.public_key())
        assert r.ok and decrypt_verified(b, r, recipient_rlwe) == b"legacy"
