"""tests/test_tamper.py — Gherkin Sprint 2: tamper localization scenarios."""

import pytest
from merkle.tree import MerkleTree
from merkle.tamper import find_tampered_blocks


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_blocks(n: int, block_size: int = 4) -> list:
    return [
        {"index": i, "offset": i * block_size, "length": block_size,
         "data": bytes([i % 256] * block_size)}
        for i in range(n)
    ]


def copy_blocks(blocks: list) -> list:
    return [dict(b) for b in blocks]


# ---------------------------------------------------------------------------
# Scenario: No tampering — empty result
# ---------------------------------------------------------------------------

class TestNoTampering:
    def test_identical_trees_return_empty(self):
        blocks = make_blocks(8)
        t1 = MerkleTree(copy_blocks(blocks))
        t2 = MerkleTree(copy_blocks(blocks))
        assert find_tampered_blocks(t1, t2) == []

    def test_identical_single_block(self):
        blocks = make_blocks(1)
        t1 = MerkleTree(copy_blocks(blocks))
        t2 = MerkleTree(copy_blocks(blocks))
        assert find_tampered_blocks(t1, t2) == []


# ---------------------------------------------------------------------------
# Scenario: Localizing a single tampered block
# ---------------------------------------------------------------------------

class TestSingleTamper:
    @pytest.mark.parametrize("tamper_idx", [0, 1, 3, 7])
    def test_localize_block(self, tamper_idx):
        blocks = make_blocks(8)
        old_tree = MerkleTree(copy_blocks(blocks))

        new_blocks = copy_blocks(blocks)
        new_blocks[tamper_idx]["data"] = b"\xff\xff\xff\xff"
        new_tree = MerkleTree(new_blocks)

        result = find_tampered_blocks(old_tree, new_tree)
        assert result == [tamper_idx]

    def test_localize_first_block(self):
        blocks = make_blocks(4)
        old_tree = MerkleTree(copy_blocks(blocks))
        new_blocks = copy_blocks(blocks)
        new_blocks[0]["data"] = b"\xde\xad"[:4]
        new_tree = MerkleTree(new_blocks)
        assert find_tampered_blocks(old_tree, new_tree) == [0]

    def test_localize_last_block_odd_tree(self):
        """Tamper the last block in a 5-leaf tree (exercises odd-dup path)."""
        blocks = make_blocks(5)
        old_tree = MerkleTree(copy_blocks(blocks))
        new_blocks = copy_blocks(blocks)
        new_blocks[4]["data"] = b"xxxx"
        new_tree = MerkleTree(new_blocks)
        result = find_tampered_blocks(old_tree, new_tree)
        assert result == [4]


# ---------------------------------------------------------------------------
# Scenario: Multiple tampered blocks
# ---------------------------------------------------------------------------

class TestMultiTamper:
    def test_two_blocks_tampered(self):
        blocks = make_blocks(8)
        old_tree = MerkleTree(copy_blocks(blocks))

        new_blocks = copy_blocks(blocks)
        new_blocks[1]["data"] = b"aaaa"
        new_blocks[5]["data"] = b"bbbb"
        new_tree = MerkleTree(new_blocks)

        result = find_tampered_blocks(old_tree, new_tree)
        assert result == [1, 5]

    def test_result_is_sorted(self):
        blocks = make_blocks(8)
        old_tree = MerkleTree(copy_blocks(blocks))

        new_blocks = copy_blocks(blocks)
        new_blocks[6]["data"] = b"zzzz"
        new_blocks[2]["data"] = b"wwww"
        new_tree = MerkleTree(new_blocks)

        result = find_tampered_blocks(old_tree, new_tree)
        assert result == sorted(result)
        assert set(result) == {2, 6}
