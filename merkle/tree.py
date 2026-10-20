"""
merkle/tree.py — Merkle tree builder.

Constructs a binary Merkle hash tree bottom-up from a list of file block
descriptors produced by :mod:`merkle.chunker`.

Odd-leaf duplication strategy
------------------------------
At every level of the tree, if the number of nodes at that level is odd,
the **last node is appended to itself** (same object reference, not a copy)
before pairing begins.  This means the duplicated node's parent will have
``parent.left is parent.right`` — the same Python object appears on both
sides.  The same rule is applied recursively at every level until a single
root node remains.  This strategy is documented and applied consistently
throughout the build process.

SHA-256 hashing
---------------
All hashes are computed with ``hashlib.sha256``.
- Leaf hash:     sha256(block_data)
- Internal hash: sha256(left.hash + right.hash)   (concatenation of hex strings)
"""

from __future__ import annotations

import hashlib
import math
from typing import List, Optional

from .node import MerkleNode


def _sha256(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    """Binary Merkle hash tree built bottom-up from file blocks.

    Attributes:
        blocks      (list[dict]):       The block descriptors used to build this tree.
        block_size  (int):              Nominal block size (informational only).
        leaves      (list[MerkleNode]): Leaf nodes in block-index order.
        root        (MerkleNode):       The single root node.
        op_count    (int):              Total SHA-256 calls made during :meth:`_build`.
        height      (int):              Number of edges from root to any leaf
                                        (= ceil(log2(n_leaves)) for n_leaves > 1, 0 otherwise).
    """

    def __init__(self, blocks: List[dict], block_size: int = 4096) -> None:
        """Build the tree immediately from *blocks*.

        Args:
            blocks:     Ordered list of block descriptors (each must have 'data').
            block_size: Nominal block size in bytes (stored for reference).

        Raises:
            ValueError: If *blocks* is empty.
        """
        if not blocks:
            raise ValueError("Cannot build a Merkle tree from an empty block list")

        self.block_size: int = block_size
        # Store a copy of block metadata (not the raw data bytes) for the UI
        self.blocks: List[dict] = list(blocks)
        self.leaves: List[MerkleNode] = []
        self.op_count: int = 0
        self.root: MerkleNode = self._build()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_leaf(self, data: bytes) -> str:
        """SHA-256 hash a raw block, incrementing the operation counter."""
        self.op_count += 1
        return _sha256(data)

    def _hash_pair(self, left_hash: str, right_hash: str) -> str:
        """SHA-256 hash the concatenation of two hex hashes, incrementing counter."""
        self.op_count += 1
        return _sha256((left_hash + right_hash).encode())

    def _build(self) -> MerkleNode:
        """Construct the tree bottom-up and return the root node.

        Step 1: Create one leaf node per block, hashing the block's raw data.
        Step 2: Pair adjacent nodes level by level.
                If a level has an odd number of nodes, duplicate the last node
                (same object reference) before pairing — see module docstring.
        Step 3: Repeat until one node (the root) remains.
        """
        # --- Step 1: leaf nodes ---
        # A block descriptor normally carries raw 'data'.  Descriptors built by
        # from_leaf_hashes() carry a precomputed 'hash' instead (no data).
        current_level: List[MerkleNode] = []
        for block in self.blocks:
            if "data" in block:
                h = self._hash_leaf(block["data"])
            else:
                h = block["hash"]
            leaf = MerkleNode(h, block_index=block["index"], is_leaf=True)
            self.leaves.append(leaf)
            current_level.append(leaf)
        self._levels: List[List[MerkleNode]] = [list(current_level)]

        # --- Steps 2 & 3: build internal levels ---
        while len(current_level) > 1:
            # Odd-leaf duplication: append the last node (same object) so the
            # level always has an even count before pairing.
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            next_level: List[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]

                parent_hash = self._hash_pair(left.hash, right.hash)
                parent = MerkleNode(parent_hash, left=left, right=right)

                # Assign parent reference.
                # When left is right (duplicated), only one assignment is needed.
                left.parent = parent
                if right is not left:
                    right.parent = parent

                next_level.append(parent)

            current_level = next_level
            self._levels.append(list(current_level))

        return current_level[0]

    # ------------------------------------------------------------------
    # Alternate constructor
    # ------------------------------------------------------------------

    @classmethod
    def from_leaf_hashes(cls, leaf_hashes: List[str], block_size: int = 4096) -> "MerkleTree":
        """Rebuild a tree from stored hex leaf hashes (e.g. a parsed MHT file).

        The internal nodes are recomputed with exactly the same rules as a
        tree built from raw blocks, so the two can be compared node by node
        (and passed to :func:`merkle.tamper.find_tampered_blocks`).
        """
        blocks = [{"index": i, "hash": h} for i, h in enumerate(leaf_hashes)]
        return cls(blocks, block_size)

    def level_hashes(self) -> List[List[str]]:
        """Hex hashes of every distinct node, level by level.

        Level 0 holds the leaves (block order); the last level holds only the
        root.  Duplicated odd nodes are not repeated.
        """
        return [[node.hash for node in level] for level in self._levels]

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def height(self) -> int:
        """Number of edges from root to any leaf.

        Equals ``ceil(log2(n_leaves))`` for n_leaves > 1, and 0 for a
        single-block (single-leaf) tree.
        """
        n = len(self.leaves)
        if n <= 1:
            return 0
        return math.ceil(math.log2(n))

    def get_leaf(self, block_index: int) -> MerkleNode:
        """Return the leaf node for the given block index.

        Args:
            block_index: Zero-based index into :attr:`leaves`.

        Raises:
            IndexError: If *block_index* is out of range.
        """
        return self.leaves[block_index]

    def __repr__(self) -> str:
        return (
            f"MerkleTree(leaves={len(self.leaves)}, height={self.height}, "
            f"root={self.root.hash[:12]}...)"
        )
