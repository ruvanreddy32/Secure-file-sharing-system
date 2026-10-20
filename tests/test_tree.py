"""tests/test_tree.py — Gherkin Sprint 1: tree construction scenarios."""

import hashlib
import math
import pytest
from merkle.chunker import chunk_bytes
from merkle.tree import MerkleTree


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_blocks(n: int, block_size: int = 4) -> list:
    """Create *n* distinct blocks of *block_size* bytes each."""
    return [
        {"index": i, "offset": i * block_size, "length": block_size,
         "data": bytes([i % 256] * block_size)}
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Scenario: Building a tree from an even number of blocks
# ---------------------------------------------------------------------------

class TestEvenLeaves:
    def test_leaf_count_8(self):
        tree = MerkleTree(make_blocks(8))
        assert len(tree.leaves) == 8

    def test_height_8_leaves(self):
        """8 leaves → height = log2(8) = 3."""
        tree = MerkleTree(make_blocks(8))
        assert tree.height == 3

    def test_single_root_exists(self):
        tree = MerkleTree(make_blocks(8))
        assert tree.root is not None

    def test_root_has_no_parent(self):
        tree = MerkleTree(make_blocks(8))
        assert tree.root.parent is None

    def test_all_leaves_flagged(self):
        tree = MerkleTree(make_blocks(8))
        assert all(leaf.is_leaf for leaf in tree.leaves)

    def test_leaf_block_indices(self):
        tree = MerkleTree(make_blocks(8))
        for i, leaf in enumerate(tree.leaves):
            assert leaf.block_index == i

    def test_leaf_hashes_match_sha256(self):
        blocks = make_blocks(8)
        tree = MerkleTree(blocks)
        for i, leaf in enumerate(tree.leaves):
            expected = hashlib.sha256(blocks[i]["data"]).hexdigest()
            assert leaf.hash == expected

    def test_root_is_not_leaf(self):
        tree = MerkleTree(make_blocks(8))
        assert not tree.root.is_leaf


# ---------------------------------------------------------------------------
# Scenario: Building a tree from an odd number of blocks
# ---------------------------------------------------------------------------

class TestOddLeaves:
    def test_single_root_5_leaves(self):
        tree = MerkleTree(make_blocks(5))
        assert tree.root is not None
        assert tree.root.parent is None

    def test_single_root_3_leaves(self):
        tree = MerkleTree(make_blocks(3))
        assert tree.root is not None

    def test_single_root_7_leaves(self):
        tree = MerkleTree(make_blocks(7))
        assert tree.root is not None

    def test_leaf_count_preserved(self):
        """Duplication must not inflate the leaf list."""
        for n in (1, 3, 5, 7, 9):
            tree = MerkleTree(make_blocks(n))
            assert len(tree.leaves) == n, f"Expected {n} leaves, got {len(tree.leaves)}"

    def test_height_5_leaves(self):
        """5 leaves → ceil(log2(5)) = 3."""
        tree = MerkleTree(make_blocks(5))
        assert tree.height == 3

    def test_height_3_leaves(self):
        """3 leaves → ceil(log2(3)) = 2."""
        tree = MerkleTree(make_blocks(3))
        assert tree.height == 2


# ---------------------------------------------------------------------------
# Scenario: Root hash changes when any block changes
# ---------------------------------------------------------------------------

class TestRootSensitivity:
    def test_root_changes_on_first_block_mutation(self):
        blocks = make_blocks(8)
        tree1 = MerkleTree([dict(b) for b in blocks])
        original_root = tree1.root.hash

        blocks[0]["data"] = b"\xff\xff\xff\xff"
        tree2 = MerkleTree(blocks)
        assert tree2.root.hash != original_root

    def test_root_changes_on_last_block_mutation(self):
        blocks = make_blocks(8)
        tree1 = MerkleTree([dict(b) for b in blocks])
        original_root = tree1.root.hash

        blocks[-1]["data"] = b"\xde\xad\xbe\xef"
        tree2 = MerkleTree(blocks)
        assert tree2.root.hash != original_root

    def test_root_changes_on_middle_block_mutation(self):
        blocks = make_blocks(8)
        tree1 = MerkleTree([dict(b) for b in blocks])
        original_root = tree1.root.hash

        blocks[3]["data"] = b"\x01\x02\x03\x04"
        tree2 = MerkleTree(blocks)
        assert tree2.root.hash != original_root

    def test_identical_data_same_root(self):
        blocks = make_blocks(8)
        t1 = MerkleTree([dict(b) for b in blocks])
        t2 = MerkleTree([dict(b) for b in blocks])
        assert t1.root.hash == t2.root.hash


# ---------------------------------------------------------------------------
# Scenario: Single-block edge cases
# ---------------------------------------------------------------------------

class TestSingleBlock:
    def test_height_is_zero(self):
        tree = MerkleTree(make_blocks(1))
        assert tree.height == 0

    def test_root_is_leaf(self):
        tree = MerkleTree(make_blocks(1))
        assert tree.root.is_leaf

    def test_root_hash_matches_leaf_hash(self):
        blocks = make_blocks(1)
        tree = MerkleTree(blocks)
        expected = hashlib.sha256(blocks[0]["data"]).hexdigest()
        assert tree.root.hash == expected


# ---------------------------------------------------------------------------
# Scenario: op_count is non-zero
# ---------------------------------------------------------------------------

class TestOpCount:
    def test_op_count_positive_after_build(self):
        tree = MerkleTree(make_blocks(4))
        assert tree.op_count > 0


# ---------------------------------------------------------------------------
# from_leaf_hashes / level_hashes (added for the signed MHT-file workflow)
# ---------------------------------------------------------------------------

class TestFromLeafHashes:
    @pytest.mark.parametrize("n_blocks", [1, 2, 3, 5, 8, 13])
    def test_rebuild_matches_original(self, n_blocks):
        blocks = chunk_bytes(bytes(range(256)) * n_blocks, 256)
        original = MerkleTree(blocks, 256)
        rebuilt = MerkleTree.from_leaf_hashes([leaf.hash for leaf in original.leaves], 256)
        assert rebuilt.root.hash == original.root.hash
        assert rebuilt.level_hashes() == original.level_hashes()

    def test_level_hashes_shape(self):
        tree = MerkleTree(chunk_bytes(b"x" * 5 * 16, 16), 16)
        assert [len(level) for level in tree.level_hashes()] == [5, 3, 2, 1]
        assert tree.level_hashes()[-1] == [tree.root.hash]
