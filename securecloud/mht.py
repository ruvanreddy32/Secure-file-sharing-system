"""
securecloud/mht.py — Merkle Hash Tree of the encrypted file and the "MHT file" (paper §III-A, §V-C).

Setup phase, steps (1) and (2):

(1) Node generation: the *encrypted* file is divided into blocks and each
    block is hashed with SHA-256 and converted to hex (``merkle.chunker`` +
    ``merkle.tree``, reused from the original repository).
(2) MHT generation: parents are SHA-256(hex(left) || hex(right)) up to a
    single root.  "Each of the hashed node formed is converted and stored in
    hex format in a text file.  This file is called the MHT file."

Blocking
--------
* Default: fixed 4096-byte blocks (the repository's block size), which
  gives block-level tamper localization (the paper's future work, §VII).
* ``paper_mode=True``: the encrypted file is split into exactly two halves,
  giving the 2-leaf, 3-node tree described in §V-C(2).

MHT file format (UTF-8 text, LF line endings, deterministic)::

    RING-CRYPTER-MHT v2
    hash-algorithm: SHA-256
    node-rule: SHA-256(hex(left) || hex(right)); odd node paired with itself
    file-name: <name of the encrypted file>
    encrypted-file-size: <bytes>
    block-size: <bytes>
    block-count: <leaves>
    encrypted-key-sha256: <hex>          # extension, see below
    version: <1, 2, ...>                 # extension: dynamic updates
    previous-mht-sha256: <hex | none>    # SHA-256 of the previous version's signed MHT file
    levels: <number of levels>
    L0 0 <hex>                            # one line per node, leaves first
    ...
    root: <hex>

``encrypted-key-sha256`` binds the uploaded encrypted-key file to the signed
metadata.  The paper signs only the MHT; this line is a documented extension
so that a swapped key file is rejected before decryption is attempted.

``version`` / ``previous-mht-sha256`` (format v2) support authorized dynamic
updates: version N+1 is signed by the owner and names the exact signed MHT
file of version N, forming a signed hash chain.  v1 files (no such lines) are
still accepted and read as version 1.  The hashing and tree rules are identical
in both formats.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from merkle.chunker import chunk_bytes
from merkle.tamper import find_tampered_blocks
from merkle.tree import MerkleTree

DEFAULT_BLOCK_SIZE = 4096
HEADER = "RING-CRYPTER-MHT v2"
HEADER_V1 = "RING-CRYPTER-MHT v1"
HEADER_V3 = "RING-CRYPTER-MHT v3"     # enhancement: per-block AES-256-GCM files (RCB1)
FORMAT_WHOLE = "RCF1"                 # whole-file AES-256-GCM (the paper's workflow)
FORMAT_BLOCK = "RCB1"                 # per-block AES-256-GCM (enhancement, NOT in the paper)
RCB1_BLOCK_OVERHEAD = 44              # 28-byte block header + 16-byte GCM tag (see blockmode.py)
NODE_RULE = "SHA-256(hex(left) || hex(right)); odd node paired with itself"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class MHTFormatError(Exception):
    """Raised when an MHT file cannot be parsed or is internally inconsistent."""


@dataclass
class MHTData:
    file_name: str
    encrypted_file_size: int
    block_size: int
    levels: List[List[str]]
    encrypted_key_sha256: str
    version: int = 1
    previous_mht_sha256: str = ""   # "" for the first version
    # --- v3 / RCB1 only (per-block encryption enhancement) ---
    encryption_format: str = FORMAT_WHOLE
    file_id: str = ""               # 128-bit random file identity (hex), fixed across versions
    plaintext_size: Optional[int] = None
    owner_key_sha256: str = ""      # SHA-256 of the owner's Ring-LWE copy of the file key
    key_block_encryptions: int = 0  # AES-GCM block encryptions under this key so far (nonce budget)

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    @property
    def leaf_hashes(self) -> List[str]:
        return self.levels[0]

    @property
    def block_count(self) -> int:
        return len(self.levels[0])


def choose_block_size(size: int, block_size: Optional[int] = None, paper_mode: bool = False) -> int:
    if paper_mode:
        return max(1, math.ceil(size / 2))   # two leaves -> 3-node tree
    return block_size or DEFAULT_BLOCK_SIZE


def build_tree(encrypted: bytes, block_size: int) -> MerkleTree:
    """Steps (1)+(2): split the encrypted file into blocks and build the MHT."""
    return MerkleTree(chunk_bytes(encrypted, block_size), block_size)


def hash_blocks(encrypted: bytes, block_size: int) -> List[str]:
    """Step (1) only: SHA-256 hex digest of every block (same as MerkleTree leaves)."""
    return [hashlib.sha256(b["data"]).hexdigest() for b in chunk_bytes(encrypted, block_size)]


def generate_mht(encrypted: bytes, file_name: str, encrypted_key: bytes,
                 block_size: Optional[int] = None, paper_mode: bool = False,
                 timings: Optional[Dict[str, float]] = None,
                 version: int = 1, previous_mht_sha256: str = "") -> MHTData:
    """Run Setup steps (1) and (2) on the encrypted file.

    Equivalent to ``build_tree(encrypted, bs)``; the two steps are split so
    that block hashing and tree construction can be timed separately
    (keys ``sha256_block_hashing_ms`` and ``mht_construction_ms``).
    """
    bs = choose_block_size(len(encrypted), block_size, paper_mode)
    t0 = time.perf_counter()
    leaves = hash_blocks(encrypted, bs)
    t1 = time.perf_counter()
    levels = MerkleTree.from_leaf_hashes(leaves, bs).level_hashes()
    t2 = time.perf_counter()
    if timings is not None:
        timings["sha256_block_hashing_ms"] = (t1 - t0) * 1000
        timings["mht_construction_ms"] = (t2 - t1) * 1000
    return MHTData(file_name, len(encrypted), bs, levels,
                   hashlib.sha256(encrypted_key).hexdigest(), version, previous_mht_sha256)


def serialize(mht: MHTData) -> bytes:
    """RCF1 (whole-file) metadata is written as format v2 exactly as before; RCB1 as v3."""
    is_v3 = mht.encryption_format != FORMAT_WHOLE
    lines = [
        HEADER_V3 if is_v3 else HEADER,
        "hash-algorithm: SHA-256",
        f"node-rule: {NODE_RULE}",
        f"file-name: {mht.file_name}",
        f"encrypted-file-size: {mht.encrypted_file_size}",
        f"block-size: {mht.block_size}",
        f"block-count: {mht.block_count}",
        f"encrypted-key-sha256: {mht.encrypted_key_sha256}",
        f"version: {mht.version}",
        f"previous-mht-sha256: {mht.previous_mht_sha256 or 'none'}",
    ]
    if is_v3:
        lines += [
            f"encryption-format: {mht.encryption_format}",
            f"file-id: {mht.file_id}",
            f"plaintext-size: {mht.plaintext_size}",
            f"owner-key-sha256: {mht.owner_key_sha256}",
            f"key-block-encryptions: {mht.key_block_encryptions}",
        ]
    lines += [
        f"levels: {len(mht.levels)}",
    ]
    for lvl, hashes in enumerate(mht.levels):
        lines.extend(f"L{lvl} {i} {h}" for i, h in enumerate(hashes))
    lines.append(f"root: {mht.root}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse(data: bytes, verify_tree: bool = True) -> MHTData:
    """Parse an MHT file and check that it is a well-formed, self-consistent tree.

    ``verify_tree=False`` skips re-deriving every internal node from the leaves (O(n) SHA-256
    calls).  Only use it for metadata whose RSA signature was just verified with the OWNER'S own
    key on the owner's update path; receivers always verify (and regenerate the tree anyway).
    """
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise MHTFormatError("MHT file is not UTF-8 text") from exc
    if not lines or lines[0] not in (HEADER, HEADER_V1, HEADER_V3) or lines[-1] != "":
        raise MHTFormatError("Missing MHT header or trailing newline")
    is_v3 = lines[0] == HEADER_V3
    is_v2 = lines[0] == HEADER or is_v3
    lines = lines[1:-1]

    def header(idx: int, key: str) -> str:
        if idx >= len(lines) or not lines[idx].startswith(key + ": "):
            raise MHTFormatError(f"Expected '{key}' on line {idx + 2}")
        return lines[idx][len(key) + 2:]

    try:
        if header(0, "hash-algorithm") != "SHA-256" or header(1, "node-rule") != NODE_RULE:
            raise MHTFormatError("Unsupported hash algorithm or node rule")
        file_name = header(2, "file-name")
        size = int(header(3, "encrypted-file-size"))
        block_size = int(header(4, "block-size"))
        block_count = int(header(5, "block-count"))
        key_hash = header(6, "encrypted-key-sha256")
        version, previous, nxt = 1, "", 7
        if is_v2:
            version = int(header(7, "version"))
            previous = header(8, "previous-mht-sha256")
            previous = "" if previous == "none" else previous
            nxt = 9
        fmt, file_id, pt_size, owner_key, key_enc = FORMAT_WHOLE, "", None, "", 0
        if is_v3:
            fmt = header(9, "encryption-format")
            file_id = header(10, "file-id")
            pt_size = int(header(11, "plaintext-size"))
            owner_key = header(12, "owner-key-sha256")
            key_enc = int(header(13, "key-block-encryptions"))
            nxt = 14
        n_levels = int(header(nxt, "levels"))
    except ValueError as exc:
        raise MHTFormatError(f"Bad numeric header: {exc}") from exc
    if block_size < 1 or block_count < 1 or not _HEX64.match(key_hash):
        raise MHTFormatError("Invalid block parameters or key hash")
    if version < 1 or (previous and not _HEX64.match(previous)) or (version == 1) != (previous == ""):
        raise MHTFormatError("Invalid version / previous-mht-sha256 (version 1 has no predecessor)")
    if is_v3:
        if fmt != FORMAT_BLOCK or not re.fullmatch(r"[0-9a-f]{32}", file_id)                 or not _HEX64.match(owner_key) or pt_size < 0:
            raise MHTFormatError("Invalid v3 (RCB1) metadata")
        if block_count != max(1, math.ceil(pt_size / block_size))                 or size != pt_size + block_count * RCB1_BLOCK_OVERHEAD or key_enc < block_count:
            raise MHTFormatError("RCB1 block-count / sizes / key-block-encryptions are inconsistent")
    elif block_count != max(1, math.ceil(size / block_size)):
        raise MHTFormatError("block-count does not match encrypted-file-size / block-size")

    levels: List[List[str]] = [[] for _ in range(n_levels)]
    for line in lines[nxt + 1:-1]:
        m = re.fullmatch(r"L(\d+) (\d+) ([0-9a-f]{64})", line)
        if not m:
            raise MHTFormatError(f"Malformed node line: {line[:80]!r}")
        lvl, idx, h = int(m.group(1)), int(m.group(2)), m.group(3)
        if lvl >= n_levels or idx != len(levels[lvl]):
            raise MHTFormatError("Node lines out of order")
        levels[lvl].append(h)
    root_line = lines[-1] if lines else ""
    if not root_line.startswith("root: ") or not levels or levels[-1] != [root_line[6:]]:
        raise MHTFormatError("Root line missing or inconsistent with last level")
    if len(levels[0]) != block_count:
        raise MHTFormatError("Leaf count does not match block-count")

    # Internal nodes must follow from the leaves (the file is self-consistent).
    if verify_tree and MerkleTree.from_leaf_hashes(levels[0], block_size).level_hashes() != levels:
        raise MHTFormatError("Internal node hashes are inconsistent with the leaf hashes")
    return MHTData(file_name, size, block_size, levels, key_hash, version, previous,
                   fmt, file_id, pt_size, owner_key, key_enc)


@dataclass
class MHTComparison:
    match: bool
    stored_root: str
    computed_root: str
    size_changed: bool
    mismatched_nodes: int
    tampered_blocks: List[int] = field(default_factory=list)


def compare(stored: MHTData, computed: MHTData) -> MHTComparison:
    """Compare the authenticated (uploaded) MHT with the recomputed one, node by node."""
    size_changed = (stored.encrypted_file_size != computed.encrypted_file_size
                    or stored.block_count != computed.block_count)
    if size_changed:
        mismatched = sum(len(level) for level in computed.levels)
        tampered: List[int] = []
        # Blocks that still exist and changed, then everything past the old end.
        common = min(stored.block_count, computed.block_count)
        tampered = [i for i in range(common) if stored.leaf_hashes[i] != computed.leaf_hashes[i]]
        tampered += list(range(common, max(stored.block_count, computed.block_count)))
    else:
        mismatched = sum(a != b for ls, lc in zip(stored.levels, computed.levels)
                         for a, b in zip(ls, lc))
        tampered = find_tampered_blocks(
            MerkleTree.from_leaf_hashes(stored.leaf_hashes, stored.block_size),
            MerkleTree.from_leaf_hashes(computed.leaf_hashes, computed.block_size),
        )
    match = (not size_changed and mismatched == 0 and stored.levels == computed.levels)
    return MHTComparison(match, stored.root, computed.root, size_changed, mismatched, tampered)
