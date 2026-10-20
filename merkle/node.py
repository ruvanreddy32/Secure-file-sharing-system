"""
merkle/node.py — MerkleNode data structure.

Each node in the Merkle tree carries its SHA-256 hash, structural links
(left, right, parent), and leaf-specific metadata (block_index, is_leaf).
"""

from __future__ import annotations
from typing import Optional


class MerkleNode:
    """A single node in a binary Merkle hash tree.

    Attributes:
        hash        (str):  Hex-encoded SHA-256 digest of this node's content.
                            For leaf nodes this is sha256(block_data).
                            For internal nodes this is sha256(left.hash + right.hash).
        left        (MerkleNode | None): Left child; None for leaf nodes.
        right       (MerkleNode | None): Right child; None for leaf nodes.
                                         May equal ``left`` when the odd-leaf duplication
                                         strategy is applied (last node at an odd level
                                         is paired with itself).
        parent      (MerkleNode | None): Parent node; None for the root.
        block_index (int | None):        Index of the original file block (leaf only).
        is_leaf     (bool):              True iff this node is a leaf (represents a block).
    """

    __slots__ = ("hash", "left", "right", "parent", "block_index", "is_leaf")

    def __init__(
        self,
        hash_val: str,
        left: Optional["MerkleNode"] = None,
        right: Optional["MerkleNode"] = None,
        parent: Optional["MerkleNode"] = None,
        block_index: Optional[int] = None,
        is_leaf: bool = False,
    ) -> None:
        self.hash: str = hash_val
        self.left: Optional[MerkleNode] = left
        self.right: Optional[MerkleNode] = right
        self.parent: Optional[MerkleNode] = parent
        self.block_index: Optional[int] = block_index
        self.is_leaf: bool = is_leaf

    def __repr__(self) -> str:
        tag = f"leaf[{self.block_index}]" if self.is_leaf else "internal"
        return f"MerkleNode({tag}, hash={self.hash[:8]}...)"
