"""
merkle/tamper.py — Tampered block localization.

Compares two Merkle trees built from the same file (one original, one
potentially modified) by recursively descending into the child whose hash
differs, and collecting the block indices of all tampered leaves.

Assumptions:
    - Both trees have the same number of leaves (file size unchanged).
    - Tampering modifies bytes in place; no blocks are inserted or removed.

Algorithm:
    Starting from the root pair, if the hashes differ, recurse into any
    child pair whose hashes disagree.  When a leaf pair is reached, its
    block_index is recorded.  This gives an O(k · log n) traversal where
    k is the number of tampered blocks.
"""

from __future__ import annotations

from typing import List

from .node import MerkleNode
from .tree import MerkleTree


def find_tampered_blocks(old_tree: MerkleTree, new_tree: MerkleTree) -> List[int]:
    """Return the block indices of all blocks that differ between the two trees.

    Args:
        old_tree: The original (trusted) Merkle tree.
        new_tree: A tree rebuilt after potential tampering.

    Returns:
        Sorted list of zero-based block indices that have changed.
        An empty list means the trees are identical (no tampering detected).
    """
    result: List[int] = []
    _descend(old_tree.root, new_tree.root, result)
    result.sort()
    return result


def _descend(old: MerkleNode, new: MerkleNode, result: List[int]) -> None:
    """Recursive descent into differing subtrees."""
    if old.hash == new.hash:
        return  # subtree is intact — prune

    if old.is_leaf:
        # Reached a differing leaf — record it
        result.append(old.block_index)  # type: ignore[arg-type]
        return

    # Recurse into left subtree if it differs
    if old.left is not None and new.left is not None:
        _descend(old.left, new.left, result)

    # Recurse into right subtree if it differs AND it is not the same object
    # as left (which happens with the odd-leaf duplication strategy).
    if (
        old.right is not None
        and new.right is not None
        and old.right is not old.left  # avoid double-visiting duplicated leaf
    ):
        _descend(old.right, new.right, result)


def get_ancestor_ids(tree: MerkleTree, block_index: int) -> List[int]:
    """Return Python ``id()`` values from leaf *block_index* to the root.

    Used by the Streamlit visualizer to highlight the tampered or updated
    path without coupling display logic to MerkleNode internals.
    """
    path: List[int] = []
    node: MerkleNode = tree.get_leaf(block_index)
    while node is not None:
        path.append(id(node))
        node = node.parent  # type: ignore[assignment]
    return path
