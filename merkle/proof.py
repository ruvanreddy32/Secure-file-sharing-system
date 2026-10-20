"""
merkle/proof.py — Merkle proof generation and O(log n) block verification.

Proof format
------------
A proof is a list of dicts, ordered from the leaf's level up to (but not
including) the root.  Each dict has two keys:

    hash  (str):  Hex SHA-256 of the *sibling* node at this level.
    side  (str):  "left"  — the sibling is to the LEFT  of the candidate
                             (i.e. the candidate is the RIGHT child).
                  "right" — the sibling is to the RIGHT of the candidate
                             (i.e. the candidate is the LEFT child).

Verification
------------
``verify_proof`` re-derives the root hash from a block's raw bytes and its
proof without reading any other block.  It makes exactly ``1 + len(proof)``
SHA-256 calls.

Operation counting
------------------
``verify_proof`` returns ``(result: bool, ops: int)`` where *ops* is the
exact number of SHA-256 calls performed.
"""

from __future__ import annotations

import hashlib
from typing import List, Dict, Tuple

from .tree import MerkleTree
from .node import MerkleNode


def get_proof(tree: MerkleTree, block_index: int) -> List[Dict]:
    """Generate the Merkle proof for a single block.

    Walks from the target leaf to the root, collecting the sibling hash and
    its relative position at each level.

    Args:
        tree:        A fully constructed :class:`~merkle.tree.MerkleTree`.
        block_index: Zero-based index of the block to prove.

    Returns:
        Ordered list of proof steps (leaf-level first, root-level last).
        An empty list is returned for a single-leaf tree (the leaf IS the root).

    Raises:
        IndexError: If *block_index* is out of range.
    """
    proof: List[Dict] = []
    node: MerkleNode = tree.get_leaf(block_index)

    while node.parent is not None:
        parent = node.parent
        if parent.left is node:
            # node is left child → sibling is right child
            sibling = parent.right
            proof.append({"hash": sibling.hash, "side": "right"})
        else:
            # node is right child → sibling is left child
            sibling = parent.left
            proof.append({"hash": sibling.hash, "side": "left"})
        node = parent

    return proof


def verify_proof(
    block_data: bytes,
    proof: List[Dict],
    root_hash: str,
) -> Tuple[bool, int]:
    """Verify a block against a trusted root hash using its Merkle proof.

    Recomputes the candidate root hash from *block_data* and *proof*
    without reading any other block.

    SHA-256 calls:
        1 for the initial leaf hash + 1 per proof step = ``1 + len(proof)``.

    Args:
        block_data: Raw bytes of the block being verified.
        proof:      Proof list returned by :func:`get_proof`.
        root_hash:  Trusted (previously stored) root hash hex string.

    Returns:
        ``(is_valid, ops)`` where *is_valid* is True iff the recomputed root
        matches *root_hash*, and *ops* is the number of SHA-256 calls made.
    """
    ops = 0

    # Step 1 — hash the block itself
    candidate = hashlib.sha256(block_data).hexdigest()
    ops += 1

    # Step 2 — combine with siblings up to the root
    for step in proof:
        if step["side"] == "right":
            # candidate is left child, sibling is right child
            combined = (candidate + step["hash"]).encode()
        else:
            # candidate is right child, sibling is left child
            combined = (step["hash"] + candidate).encode()
        candidate = hashlib.sha256(combined).hexdigest()
        ops += 1

    return candidate == root_hash, ops


def get_proof_path_ids(tree: MerkleTree, block_index: int) -> Tuple[List[int], List[int]]:
    """Return Python ``id()`` values for the proof path nodes.

    Used by the Streamlit visualizer to highlight nodes without coupling
    the display logic to MerkleNode internals.

    Returns:
        ``(main_path_ids, sibling_ids)``
        - *main_path_ids*: from target leaf up to (and including) root.
        - *sibling_ids*:   sibling nodes included in the proof.
    """
    main_path: List[int] = []
    sibling_ids: List[int] = []
    node = tree.get_leaf(block_index)

    while node is not None:
        main_path.append(id(node))
        if node.parent is not None:
            parent = node.parent
            sibling = parent.right if parent.left is node else parent.left
            if sibling is not node:
                sibling_ids.append(id(sibling))
        node = node.parent

    return main_path, sibling_ids
