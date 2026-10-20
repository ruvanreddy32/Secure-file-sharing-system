"""Merkle Hash Tree of the encrypted file and the MHT text file (paper §III-A, §V-C(1)-(2))."""

import hashlib
import os

import pytest

from merkle.chunker import chunk_bytes
from merkle.tree import MerkleTree
from securecloud import mht

KEY = b"encrypted-key-file"


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class TestGeneration:
    def test_matches_repository_merkle_tree(self):
        data = os.urandom(50_000)
        m = mht.generate_mht(data, "f.aes", KEY, block_size=4096)
        tree = MerkleTree(chunk_bytes(data, 4096), 4096)
        assert m.root == tree.root.hash
        assert m.leaf_hashes == [leaf.hash for leaf in tree.leaves]
        assert m.levels == tree.level_hashes()

    def test_paper_figure1_rule_8_leaves(self):
        """H(1,2) = H(H(1) || H(2)) ... up to H(1,8) (Fig. 1) with hex concatenation."""
        blocks = [bytes([i]) * 10 for i in range(8)]
        m = mht.generate_mht(b"".join(blocks), "f.aes", KEY, block_size=10)
        h = [_h(b) for b in blocks]
        h12, h34, h56, h78 = (_h((h[i] + h[i + 1]).encode()) for i in (0, 2, 4, 6))
        h14, h58 = _h((h12 + h34).encode()), _h((h56 + h78).encode())
        assert m.root == _h((h14 + h58).encode())
        assert [len(level) for level in m.levels] == [8, 4, 2, 1]

    def test_paper_mode_gives_3_node_tree(self):
        """§V-C(2): 'a merkle hash tree of height 2 containing 3 nodes'."""
        for size in (33, 1000, 100_001):
            m = mht.generate_mht(os.urandom(size), "f.aes", KEY, paper_mode=True)
            assert [len(level) for level in m.levels] == [2, 1]
            assert sum(len(level) for level in m.levels) == 3

    def test_hex_encoding(self):
        m = mht.generate_mht(os.urandom(9000), "f.aes", KEY)
        for level in m.levels:
            for node in level:
                assert len(node) == 64 and int(node, 16) >= 0

    def test_timings_recorded(self):
        t = {}
        mht.generate_mht(os.urandom(9000), "f.aes", KEY, timings=t)
        assert set(t) == {"sha256_block_hashing_ms", "mht_construction_ms"}


class TestFile:
    def test_roundtrip(self):
        m = mht.generate_mht(os.urandom(30_000), "data.txt.aes", KEY)
        text = mht.serialize(m)
        assert text.startswith(b"RING-CRYPTER-MHT v1\n")
        assert f"root: {m.root}\n".encode() in text
        back = mht.parse(text)
        assert back == m

    def test_deterministic(self):
        data = os.urandom(10_000)
        assert mht.serialize(mht.generate_mht(data, "a", KEY)) == \
            mht.serialize(mht.generate_mht(data, "a", KEY))

    @pytest.mark.parametrize("mutate", [
        lambda t: t.replace(b"RING-CRYPTER-MHT v1", b"OTHER"),
        lambda t: t[:-1],                                          # no trailing newline
        lambda t: t.replace(b"block-count: 8", b"block-count: 9"),
        lambda t: t.replace(b"\nL0 3 ", b"\nL0 4 "),               # node out of order
        lambda t: t.replace(b"SHA-256\n", b"MD5\n", 1),
    ])
    def test_malformed_rejected(self, mutate):
        text = mht.serialize(mht.generate_mht(os.urandom(4096 * 8), "a", KEY))
        with pytest.raises(mht.MHTFormatError):
            mht.parse(mutate(text))

    def test_inconsistent_internal_node_rejected(self):
        m = mht.generate_mht(os.urandom(4096 * 4), "a", KEY)
        m.levels[1][0] = "0" * 64
        with pytest.raises(mht.MHTFormatError):
            mht.parse(mht.serialize(m))


class TestCompare:
    def test_identical(self):
        data = os.urandom(20_000)
        a = mht.generate_mht(data, "f", KEY)
        c = mht.compare(a, mht.generate_mht(data, "f", KEY))
        assert c.match and c.mismatched_nodes == 0 and c.tampered_blocks == []

    def test_localizes_modified_blocks(self):
        data = bytearray(os.urandom(4096 * 10))
        a = mht.generate_mht(bytes(data), "f", KEY)
        data[4096 * 2 + 5] ^= 1
        data[4096 * 7] ^= 1
        c = mht.compare(a, mht.generate_mht(bytes(data), "f", KEY, block_size=a.block_size))
        assert not c.match and c.tampered_blocks == [2, 7]

    def test_truncation(self):
        data = os.urandom(4096 * 5)
        a = mht.generate_mht(data, "f", KEY)
        c = mht.compare(a, mht.generate_mht(data[:4096 * 3], "f", KEY, block_size=4096))
        assert not c.match and c.size_changed and c.tampered_blocks == [3, 4]
