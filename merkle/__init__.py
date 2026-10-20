"""
Merkle Tree File Integrity Verification Package.

Modules:
    node     – MerkleNode data structure
    chunker  – Fixed-size file block splitter
    tree     – MerkleTree builder (bottom-up, SHA-256)
    proof    – Proof generation and O(log n) block verification
    tamper   – Tampered-block localization
    updater  – O(log n) dynamic block update
"""

from .node import MerkleNode
from .chunker import chunk_file, chunk_bytes
from .tree import MerkleTree
from .proof import get_proof, verify_proof
from .tamper import find_tampered_blocks
from .updater import update_block

__all__ = [
    "MerkleNode",
    "chunk_file",
    "chunk_bytes",
    "MerkleTree",
    "get_proof",
    "verify_proof",
    "find_tampered_blocks",
    "update_block",
]
