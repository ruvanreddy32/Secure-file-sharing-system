"""tests/test_updater.py — Gherkin Sprint 3: dynamic block update scenarios."""

import hashlib
import pytest
from merkle.tree import MerkleTree
from merkle.updater import update_block
from merkle.proof import get_proof, verify_proof


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_tree(n: int, block_size: int = 4) -> MerkleTree:
    blocks = [
        {"index": i, "offset": i * block_size, "length": block_size,
         "data": bytes([i % 256] * block_size)}
        for i in range(n)
    ]
    return MerkleTree(blocks)


# ---------------------------------------------------------------------------
# Scenario: Updating one block only rehashes its path
# ---------------------------------------------------------------------------

class TestUpdateBlock:
    def test_op_count_equals_tree_height_16(self):
        """For 16 blocks, tree height = 4 and update_block must return 4."""
        tree = make_tree(16)
        op_count = update_block(tree, 5, b"new_data_here!!!")
        assert op_count == tree.height  # 4

    def test_op_count_equals_tree_height_8(self):
        tree = make_tree(8)
        op_count = update_block(tree, 3, b"newdata!")
        assert op_count == tree.height  # 3

    def test_non_updated_leaf_hashes_unchanged(self):
        """Leaves other than the updated one must keep their original hashes."""
        tree = make_tree(16)
        original_hashes = {i: tree.leaves[i].hash for i in range(16)}

        update_block(tree, 5, b"new_data_here!!!")

        for i in range(16):
            if i != 5:
                assert tree.leaves[i].hash == original_hashes[i], (
                    f"Leaf {i} hash changed unexpectedly"
                )

    def test_updated_leaf_hash_changes(self):
        tree = make_tree(8)
        old_hash = tree.leaves[3].hash
        update_block(tree, 3, b"different")
        assert tree.leaves[3].hash != old_hash

    def test_root_hash_changes_after_update(self):
        tree = make_tree(8)
        old_root = tree.root.hash
        update_block(tree, 2, b"changed!")
        assert tree.root.hash != old_root

    def test_updated_leaf_hash_correct(self):
        tree = make_tree(8)
        new_data = b"brand_new"
        update_block(tree, 4, new_data)
        expected = hashlib.sha256(new_data).hexdigest()
        assert tree.leaves[4].hash == expected

    def test_root_hash_correct_after_update(self):
        """Root hash must equal what a full rebuild produces."""
        tree = make_tree(8)
        new_data = b"correct!"
        update_block(tree, 6, new_data)
        updated_root = tree.root.hash

        # Rebuild from scratch to get expected root
        blocks = [
            {"index": i, "offset": i * 4, "length": 4,
             "data": bytes([i % 256] * 4) if i != 6 else new_data}
            for i in range(8)
        ]
        expected_tree = MerkleTree(blocks)
        assert updated_root == expected_tree.root.hash

    def test_proof_valid_after_update(self):
        """A proof generated AFTER update must verify successfully."""
        tree = make_tree(8)
        new_data = b"updated!"
        update_block(tree, 1, new_data)

        proof = get_proof(tree, 1)
        result, _ = verify_proof(new_data, proof, tree.root.hash)
        assert result is True

    def test_old_proof_invalid_after_update(self):
        """A proof for block 1 generated BEFORE update must fail after."""
        tree = make_tree(8)
        proof_before = get_proof(tree, 1)
        old_root = tree.root.hash
        old_data = tree.blocks[1]["data"]

        update_block(tree, 1, b"mutated!")

        # Old proof against old root with old data should still pass
        result, _ = verify_proof(old_data, proof_before, old_root)
        assert result is True

        # But old proof against NEW root with old data should fail
        result2, _ = verify_proof(old_data, proof_before, tree.root.hash)
        assert result2 is False

    def test_update_first_block(self):
        tree = make_tree(8)
        op_count = update_block(tree, 0, b"firstblk")
        assert op_count == tree.height

    def test_update_last_block(self):
        tree = make_tree(8)
        op_count = update_block(tree, 7, b"lastblck")
        assert op_count == tree.height

    def test_update_odd_tree_last_block(self):
        """Updating the duplicated last leaf of an odd tree must work."""
        tree = make_tree(5)
        op_count = update_block(tree, 4, b"last5")
        assert op_count == tree.height
        proof = get_proof(tree, 4)
        result, _ = verify_proof(b"last5", proof, tree.root.hash)
        assert result is True
