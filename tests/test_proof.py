"""tests/test_proof.py — Gherkin Sprint 2: proof generation & verification."""

import hashlib
import math
import pytest
from merkle.chunker import chunk_bytes
from merkle.tree import MerkleTree
from merkle.proof import get_proof, verify_proof


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_tree(n: int = 8, block_size: int = 4) -> tuple:
    blocks = [
        {"index": i, "offset": i * block_size, "length": block_size,
         "data": bytes([i % 256] * block_size)}
        for i in range(n)
    ]
    return MerkleTree(blocks), blocks


# ---------------------------------------------------------------------------
# Scenario: Verifying an unmodified block
# ---------------------------------------------------------------------------

class TestValidProof:
    def test_block_0_verifies(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 0)
        result, ops = verify_proof(blocks[0]["data"], proof, tree.root.hash)
        assert result is True

    def test_block_2_verifies(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 2)
        result, ops = verify_proof(blocks[2]["data"], proof, tree.root.hash)
        assert result is True

    def test_last_block_verifies(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 7)
        result, ops = verify_proof(blocks[7]["data"], proof, tree.root.hash)
        assert result is True

    def test_op_count_equals_proof_len_plus_one(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 3)
        _, ops = verify_proof(blocks[3]["data"], proof, tree.root.hash)
        assert ops == len(proof) + 1  # 1 for leaf hash + 1 per step


# ---------------------------------------------------------------------------
# Scenario: Verifying a tampered block
# ---------------------------------------------------------------------------

class TestTamperedProof:
    def test_tampered_block_detected(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 2)
        # Use a different data value while keeping the original tree's proof
        result, _ = verify_proof(b"tampered_data", proof, tree.root.hash)
        assert result is False

    def test_wrong_root_fails(self):
        tree, blocks = make_tree(8)
        proof = get_proof(tree, 0)
        wrong_root = "a" * 64
        result, _ = verify_proof(blocks[0]["data"], proof, wrong_root)
        assert result is False

    def test_correct_data_wrong_proof_fails(self):
        tree, blocks = make_tree(8)
        # Proof for block 0 used against block 1's data
        proof_for_0 = get_proof(tree, 0)
        result, _ = verify_proof(blocks[1]["data"], proof_for_0, tree.root.hash)
        assert result is False


# ---------------------------------------------------------------------------
# Scenario: Proof size is logarithmic
# ---------------------------------------------------------------------------

class TestProofLength:
    def test_proof_length_equals_tree_height_8(self):
        tree, _ = make_tree(8)
        proof = get_proof(tree, 0)
        assert len(proof) == tree.height  # 3

    def test_proof_length_equals_tree_height_1024(self):
        blocks = [
            {"index": i, "offset": i * 4, "length": 4, "data": bytes([i % 256] * 4)}
            for i in range(1024)
        ]
        tree = MerkleTree(blocks)
        proof = get_proof(tree, 0)
        assert len(proof) == tree.height  # 10

    def test_proof_length_logarithmic_various_sizes(self):
        for n in [2, 4, 8, 16, 32, 64]:
            blocks = [
                {"index": i, "offset": i, "length": 1, "data": bytes([i % 256])}
                for i in range(n)
            ]
            tree = MerkleTree(blocks)
            proof = get_proof(tree, 0)
            assert len(proof) == tree.height, (
                f"n={n}: expected proof len {tree.height}, got {len(proof)}"
            )

    def test_single_leaf_proof_is_empty(self):
        blocks = [{"index": 0, "offset": 0, "length": 4, "data": b"test"}]
        tree = MerkleTree(blocks)
        proof = get_proof(tree, 0)
        assert proof == []


# ---------------------------------------------------------------------------
# Scenario: Proof steps have correct structure
# ---------------------------------------------------------------------------

class TestProofStructure:
    def test_proof_steps_have_hash_and_side(self):
        tree, _ = make_tree(8)
        proof = get_proof(tree, 3)
        for step in proof:
            assert "hash" in step
            assert "side" in step
            assert step["side"] in ("left", "right")
            assert len(step["hash"]) == 64  # SHA-256 hex = 64 chars
