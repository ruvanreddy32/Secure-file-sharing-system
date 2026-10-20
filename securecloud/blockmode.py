"""
securecloud/blockmode.py — ENHANCEMENT (not part of the IEEE paper): per-block AES-256-GCM files
with efficient block-level dynamic updates.

The paper encrypts the whole file with AES-256 and builds the MHT over the ciphertext
(implemented unchanged as format "RCF1" in aes_cipher.py / workflow.py).  With whole-file
encryption any edit re-randomises the entire ciphertext, so an update must re-encrypt, re-hash
and re-upload everything.  Format "RCB1" keeps the paper's primitives (AES-256-GCM, Ring-LWE key
encryption, SHA-256 MHT, RSA-PSS signature) but applies AES-256-GCM to each 4096-byte plaintext
block independently, so an edit touches only the affected blocks.

Ciphertext block (one Merkle leaf; leaf hash = SHA-256(ciphertext block))::

    magic "RCB1" (4) | block index u64 (8) | written-in-version u32 (4) | nonce (12) | ct || tag (16)

    AAD = "RCB1" || file-id (16) || block index u64 || written-in-version u32 || block size u32

* nonce: 96 random bits from the OS CSPRNG for every block encryption (never derived from
  state that two concurrent writers could share).  The number of block encryptions under one
  key is counted in the signed metadata (``key-block-encryptions``) and capped at 2**32, the
  NIST SP 800-38D limit for random 96-bit IVs; the verifier also rejects duplicate nonces.
* AAD binds each block to its file identity, its position and the version that wrote it, so a
  block moved to another index or another file fails AES-GCM authentication even if the MHT
  check were bypassed (defence in depth).
* The RSA-signed MHT file (format v3, :mod:`securecloud.mht`) binds file name, format, file id,
  plaintext length, block count, block size, version, previous-version link, both key-file
  hashes, the nonce budget and every leaf/node hash.  Block substitution, reordering, replay of
  older blocks, truncation and extension therefore change a leaf hash or the signed counts and
  are detected *before* decryption.
* The same file key K is used for all versions of a file (otherwise every block would change).
  K is Ring-LWE-encrypted twice: for the recipient (``encrypted_key``) and for the owner
  (``owner_key``), so the owner can re-encrypt changed blocks without re-keying.

Block-level update (owner): the current signed MHT is authenticated with the owner's key; only
the affected plaintext blocks are (re-)encrypted; ``merkle.updater.update_block`` rehashes only
the changed leaves' root paths; a new version is signed.  Unchanged ciphertext blocks are
reused as-is (and, in storage, not uploaded again).
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from merkle.tree import MerkleTree
from merkle.updater import update_block as merkle_update_block

from . import aes_cipher, mht, rlwe, signature
from .workflow import IntegrityError, VerificationReport

FORMAT = mht.FORMAT_BLOCK
MAGIC = FORMAT.encode()
BLOCK_SIZE = 4096
_HDR = struct.Struct(">4sQI12s")             # magic, index, written-in-version, nonce
TAG_SIZE = 16
OVERHEAD = _HDR.size + TAG_SIZE               # 44
assert OVERHEAD == mht.RCB1_BLOCK_OVERHEAD
MAX_BLOCK_ENCRYPTIONS = 2 ** 32               # NIST SP 800-38D, random 96-bit IVs per key
BLOCK_SUFFIX = ".rcb"
OWNER_KEY_SUFFIX = ".owner.key.rlwe"


class BlockFormatError(Exception):
    """Malformed RCB1 block or metadata."""


# ---------------------------------------------------------------------------
# Per-block AES-256-GCM
# ---------------------------------------------------------------------------

def block_aad(file_id: bytes, index: int, written_version: int) -> bytes:
    return MAGIC + file_id + struct.pack(">QII", index, written_version, BLOCK_SIZE)


def encrypt_block(key: bytes, file_id: bytes, index: int, written_version: int,
                  plaintext: bytes) -> bytes:
    if len(plaintext) > BLOCK_SIZE:
        raise ValueError("plaintext block larger than BLOCK_SIZE")
    if len(file_id) != 16:
        raise ValueError("file id must be 16 bytes")
    nonce = os.urandom(12)
    header = _HDR.pack(MAGIC, index, written_version, nonce)
    return header + AESGCM(key).encrypt(nonce, plaintext, block_aad(file_id, index, written_version))


def parse_block_header(cblock: bytes) -> Tuple[int, int, bytes]:
    """(index, written_version, nonce) — no key needed."""
    if len(cblock) < OVERHEAD or len(cblock) > OVERHEAD + BLOCK_SIZE:
        raise BlockFormatError("ciphertext block has an invalid length")
    magic, index, version, nonce = _HDR.unpack_from(cblock)
    if magic != MAGIC:
        raise BlockFormatError("not an RCB1 block")
    return index, version, nonce


def decrypt_block(key: bytes, file_id: bytes, expected_index: int, cblock: bytes) -> bytes:
    index, version, nonce = parse_block_header(cblock)
    if index != expected_index:
        raise aes_cipher.DecryptionError(f"block {expected_index} carries index {index}")
    try:
        return AESGCM(key).decrypt(nonce, cblock[_HDR.size:], block_aad(file_id, index, version))
    except InvalidTag as exc:
        raise aes_cipher.DecryptionError(f"AES-GCM authentication failed for block {index}") from exc


def split_plaintext(data: bytes) -> List[bytes]:
    if not data:
        return [b""]
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def block_count_for(size: int) -> int:
    return max(1, math.ceil(size / BLOCK_SIZE))


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

@dataclass
class BlockBundle:
    """One version of an RCB1 file: ciphertext blocks + key files + signed MHT (v3)."""
    name: str
    blocks: List[bytes]
    encrypted_key: bytes      # K under the recipient's Ring-LWE public key
    owner_key: bytes          # K under the owner's Ring-LWE public key
    signed_mht: bytes

    @property
    def encrypted_name(self) -> str:
        return self.name + BLOCK_SUFFIX

    @property
    def leaf_hashes(self) -> List[str]:
        return [_sha(b) for b in self.blocks]


def bundle_digest(b: BlockBundle) -> str:
    h = hashlib.sha256(b"RCB1-bundle")
    for part in (b.name.encode(), b.encrypted_key, b.owner_key, b.signed_mht, *b.blocks):
        h.update(hashlib.sha256(part).digest())
    return h.hexdigest()


def _metadata(name: str, blocks: List[bytes], plaintext_size: int, levels, encrypted_key: bytes,
              owner_key: bytes, file_id: bytes, version: int, previous: str,
              key_block_encryptions: int) -> mht.MHTData:
    return mht.MHTData(name + BLOCK_SUFFIX, sum(map(len, blocks)), BLOCK_SIZE, levels,
                       _sha(encrypted_key), version, previous, FORMAT, file_id.hex(),
                       plaintext_size, _sha(owner_key), key_block_encryptions)


# ---------------------------------------------------------------------------
# Owner: initial setup (version 1)
# ---------------------------------------------------------------------------

def block_setup_phase(plaintext: bytes, name: str, signing_key, recipient_rlwe_public,
                      owner_rlwe_public) -> Tuple[BlockBundle, Dict[str, float]]:
    """Setup phase for an RCB1 file (version 1).  Returns (bundle, timings in ms)."""
    if not name or "/" in name or "\\" in name:
        raise ValueError(f"Invalid file name {name!r}")
    t: Dict[str, float] = {}
    t_all = t0 = time.perf_counter()
    key, file_id = aes_cipher.generate_file_key(), os.urandom(16)
    blocks = [encrypt_block(key, file_id, i, 1, pt) for i, pt in enumerate(split_plaintext(plaintext))]
    t["aes_encrypt_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    ek, ok = rlwe.encrypt_key(key, recipient_rlwe_public), rlwe.encrypt_key(key, owner_rlwe_public)
    t["rlwe_key_encrypt_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    leaves = [_sha(b) for b in blocks]
    t["sha256_block_hashing_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    levels = MerkleTree.from_leaf_hashes(leaves, BLOCK_SIZE).level_hashes()
    t["mht_construction_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    meta = _metadata(name, blocks, len(plaintext), levels, ek, ok, file_id, 1, "", len(blocks))
    signed = signature.create_signed_mht(mht.serialize(meta), signing_key)
    t["rsa_sign_ms"] = (time.perf_counter() - t0) * 1000
    t["total_setup_ms"] = (time.perf_counter() - t_all) * 1000
    return BlockBundle(name, blocks, ek, ok, signed), t


# ---------------------------------------------------------------------------
# Receiver: integrity verification (paper steps, applied to the block list)
# ---------------------------------------------------------------------------

def block_verify_integrity(bundle: BlockBundle, signer_public_key, *,
                           expected_version: Optional[int] = None,
                           expected_previous_mht_sha256: Optional[str] = None) -> VerificationReport:
    """Signature check -> regenerate the MHT from the downloaded ciphertext blocks -> compare.

    Also checks the block headers (index, version, nonce uniqueness) and both key-file hashes.
    Never raises on tampering.
    """
    r = VerificationReport()
    t = r.timings_ms
    t_all = t0 = time.perf_counter()
    try:
        mht_bytes = signature.verify_signed_mht(bundle.signed_mht, signer_public_key)
        r.signature_valid = True
    except signature.SignatureError as exc:
        r.messages.append(str(exc))
    t["rsa_verify_ms"] = (time.perf_counter() - t0) * 1000
    if not r.signature_valid:
        t["total_verify_ms"] = (time.perf_counter() - t_all) * 1000
        return r
    try:
        stored = mht.parse(mht_bytes)
        if stored.encryption_format != FORMAT:
            raise mht.MHTFormatError(f"expected {FORMAT} metadata, got {stored.encryption_format}")
        r.mht_well_formed = True
    except mht.MHTFormatError as exc:
        r.messages.append(f"Signed MHT file is malformed: {exc}")
        t["total_verify_ms"] = (time.perf_counter() - t_all) * 1000
        return r
    r.stored_root, r.block_count, r.block_size = stored.root, stored.block_count, stored.block_size
    r.version, r.previous_mht_sha256 = stored.version, stored.previous_mht_sha256
    if expected_version is not None and stored.version != expected_version:
        r.version_ok = False
        r.messages.append(f"Signed MHT is version {stored.version}, expected version {expected_version}")
    if expected_previous_mht_sha256 is not None and stored.previous_mht_sha256 != expected_previous_mht_sha256:
        r.version_ok = False
        r.messages.append("Version chain broken: previous-mht-sha256 does not match the preceding version")
    r.file_name_match = stored.file_name == bundle.encrypted_name
    if not r.file_name_match:
        r.messages.append(f"MHT was signed for '{stored.file_name}', not '{bundle.encrypted_name}'")

    # (1) re-run node generation + MHT generation on the downloaded ciphertext blocks
    t0 = time.perf_counter()
    leaves = [_sha(b) for b in bundle.blocks] or [_sha(b"")]
    t["sha256_block_hashing_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    levels = MerkleTree.from_leaf_hashes(leaves, BLOCK_SIZE).level_hashes()
    t["mht_construction_ms"] = (time.perf_counter() - t0) * 1000
    computed = mht.MHTData(stored.file_name, sum(map(len, bundle.blocks)), BLOCK_SIZE, levels,
                           _sha(bundle.encrypted_key))
    # (2b) compare
    t0 = time.perf_counter()
    cmp = mht.compare(stored, computed)
    t["mht_compare_ms"] = (time.perf_counter() - t0) * 1000
    r.mht_match, r.computed_root = cmp.match, cmp.computed_root
    r.size_changed, r.mismatched_nodes, r.tampered_blocks = cmp.size_changed, cmp.mismatched_nodes, cmp.tampered_blocks
    if not r.mht_match:
        r.messages.append(f"Merkle root mismatch: {r.mismatched_nodes} MHT node(s) differ; "
                          f"modified block(s): {r.tampered_blocks[:20]}")
    r.key_file_match = (_sha(bundle.encrypted_key) == stored.encrypted_key_sha256
                        and _sha(bundle.owner_key) == stored.owner_key_sha256)
    if not r.key_file_match:
        r.messages.append("Encrypted key file(s) do not match the signed MHT metadata")

    # structural checks on block headers (no key needed)
    header_ok, nonces = True, set()
    for i, b in enumerate(bundle.blocks):
        try:
            idx, wv, nonce = parse_block_header(b)
        except BlockFormatError as exc:
            header_ok = False
            r.messages.append(f"block {i}: {exc}")
            continue
        if idx != i or wv > stored.version or wv < 1:
            header_ok = False
            r.messages.append(f"block {i}: header says index {idx}, version {wv}")
        if nonce in nonces:
            header_ok = False
            r.messages.append(f"block {i}: nonce reused within the file")
        nonces.add(nonce)
    if bundle.blocks and sum(len(b) - OVERHEAD for b in bundle.blocks) != stored.plaintext_size:
        header_ok = False
        r.messages.append("plaintext length implied by the blocks differs from the signed length")

    r.ok = (r.signature_valid and r.mht_well_formed and r.file_name_match and r.mht_match
            and r.key_file_match and r.version_ok and header_ok)
    if r.ok:
        r.verified_digest = bundle_digest(bundle)
    t["total_verify_ms"] = (time.perf_counter() - t_all) * 1000
    return r


def block_decrypt_verified(bundle: BlockBundle, report: VerificationReport, rlwe_private_key,
                           timings: Optional[Dict[str, float]] = None) -> bytes:
    """Decrypt an RCB1 bundle — refused unless *report* verified exactly these bytes."""
    if not isinstance(report, VerificationReport) or not report.ok:
        raise IntegrityError("Decryption refused: integrity verification did not succeed. "
                             + (report.summary if isinstance(report, VerificationReport) else ""),
                             report if isinstance(report, VerificationReport) else None)
    if report.verified_digest != bundle_digest(bundle):
        raise IntegrityError("Decryption refused: these bytes are not the ones that were verified", report)
    meta = mht.parse(signature.split_signed_mht(bundle.signed_mht)[0])
    t = timings if timings is not None else {}
    t0 = time.perf_counter()
    key = rlwe.decrypt_key(bundle.encrypted_key, rlwe_private_key)
    t["rlwe_key_decrypt_ms"] = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    file_id = bytes.fromhex(meta.file_id)
    out = b"".join(decrypt_block(key, file_id, i, b) for i, b in enumerate(bundle.blocks))
    t["aes_decrypt_ms"] = (time.perf_counter() - t0) * 1000
    if len(out) != meta.plaintext_size:
        raise IntegrityError("Decrypted length differs from the signed plaintext length", report)
    return out


# ---------------------------------------------------------------------------
# Owner: block-level update planning (pure; storage handled by versioning.py)
# ---------------------------------------------------------------------------

@dataclass
class BlockUpdate:
    signed_mht: bytes
    meta: mht.MHTData
    new_blocks: Dict[int, bytes]            # index -> new ciphertext block
    leaves: List[str]                       # leaf hashes of the new version (= block object ids)
    stats: Dict[str, float] = field(default_factory=dict)


def recover_file_key(owner_key: bytes, owner_rlwe_private) -> bytes:
    return rlwe.decrypt_key(owner_key, owner_rlwe_private)


def build_block_update(current_meta: mht.MHTData, current_signed_mht: bytes, file_key: bytes,
                       changes: Dict[int, bytes], new_plaintext_size: int,
                       signing_key) -> BlockUpdate:
    """Create version N+1 from the authenticated metadata of version N and the changed blocks.

    *changes* maps block index -> complete new plaintext of that block.  Every block of the new
    file must either be unchanged (index < old count and not in *changes*) or be in *changes*.
    Only the changed blocks are encrypted and hashed; when the block count is unchanged,
    ``merkle.updater.update_block`` rehashes only each changed leaf's path to the root.
    """
    if current_meta.encryption_format != FORMAT:
        raise BlockFormatError("block-level updates require an RCB1 file")
    old_n, new_n = current_meta.block_count, block_count_for(new_plaintext_size)
    old_size = current_meta.plaintext_size
    if not changes and new_plaintext_size == old_size:
        raise ValueError("no changes")
    for i, pt in changes.items():
        if not 0 <= i < new_n:
            raise ValueError(f"block index {i} outside the new file (0..{new_n - 1})")
        expected = min(BLOCK_SIZE, new_plaintext_size - i * BLOCK_SIZE) if new_plaintext_size else 0
        if len(pt) != expected:
            raise ValueError(f"block {i} must be exactly {expected} bytes, got {len(pt)}")
    missing = [i for i in range(old_n, new_n) if i not in changes]
    if missing:
        raise ValueError(f"new blocks {missing} are not provided")
    last = new_n - 1
    if new_plaintext_size != old_size and last < old_n and last not in changes:
        raise ValueError("the last block must be rewritten when the file length changes")
    budget = current_meta.key_block_encryptions + len(changes)
    if budget > MAX_BLOCK_ENCRYPTIONS:
        raise BlockFormatError("AES-GCM nonce budget for this key exhausted; re-key by publishing a new file")

    version = current_meta.version + 1
    file_id = bytes.fromhex(current_meta.file_id)
    stats: Dict[str, float] = {"blocks_total": new_n, "blocks_changed": len(changes)}
    t0 = time.perf_counter()
    new_blocks = {i: encrypt_block(file_key, file_id, i, version, changes[i]) for i in sorted(changes)}
    stats["aes_encrypt_ms"] = (time.perf_counter() - t0) * 1000
    stats["plaintext_bytes_encrypted"] = sum(len(p) for p in changes.values())
    stats["ciphertext_bytes_hashed"] = sum(len(b) for b in new_blocks.values())

    t0 = time.perf_counter()
    old_leaves = current_meta.leaf_hashes
    if new_n == old_n:
        tree = MerkleTree.from_leaf_hashes(list(old_leaves), BLOCK_SIZE)   # no data re-hashed
        internal = 0
        for i, cb in new_blocks.items():
            internal += merkle_update_block(tree, i, cb)                  # O(log n) per block
        levels = tree.level_hashes()
        stats["merkle_mode"] = "incremental (merkle/updater.py)"
    else:
        leaves = [old_leaves[i] if i < old_n else "" for i in range(new_n)]
        for i, cb in new_blocks.items():
            leaves[i] = _sha(cb)
        tree = MerkleTree.from_leaf_hashes(leaves, BLOCK_SIZE)
        internal = tree.op_count                                           # internal nodes only
        levels = tree.level_hashes()
        stats["merkle_mode"] = "rebuild from leaf hashes (block count changed)"
    stats["sha256_leaf_hashes"] = len(new_blocks)
    stats["sha256_internal_hashes"] = internal
    stats["merkle_update_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    meta = mht.MHTData(current_meta.file_name, new_plaintext_size + new_n * OVERHEAD, BLOCK_SIZE,
                       levels, current_meta.encrypted_key_sha256, version,
                       _sha(current_signed_mht), FORMAT, current_meta.file_id, new_plaintext_size,
                       current_meta.owner_key_sha256, budget)
    signed = signature.create_signed_mht(mht.serialize(meta), signing_key)
    stats["rsa_sign_ms"] = (time.perf_counter() - t0) * 1000
    return BlockUpdate(signed, meta, new_blocks, levels[0], stats)


def plan_patches(meta: mht.MHTData, edits: List[Tuple[int, bytes]],
                 read_plaintext_block: Callable[[int], bytes]) -> Tuple[Dict[int, bytes], int]:
    """Apply several (offset, data) writes in order as ONE new version.

    Each block is read at most once and encrypted once, however many edits touch it.
    """
    if not edits:
        raise ValueError("no edits")
    changes: Dict[int, bytes] = {}
    view = mht.MHTData(**{**meta.__dict__})          # tracks the growing plaintext size
    for offset, data in edits:
        step, new_size = plan_patch(view, offset, data,
                                    lambda i: changes[i] if i in changes else read_plaintext_block(i))
        changes.update(step)
        view.plaintext_size = new_size
        view.levels = [[""] * block_count_for(new_size)]
    return changes, view.plaintext_size


def plan_patch(meta: mht.MHTData, offset: int, data: bytes,
               read_plaintext_block: Callable[[int], bytes]) -> Tuple[Dict[int, bytes], int]:
    """Write *data* at byte *offset* (may extend the file).  Returns (changes, new_size).

    Only the blocks that are partially overwritten are read (and decrypted) via
    *read_plaintext_block*.
    """
    old_size = meta.plaintext_size
    if offset < 0 or offset > old_size:
        raise ValueError(f"offset must be between 0 and the file size ({old_size})")
    if not data:
        raise ValueError("no data to write")
    end = offset + len(data)
    new_size = max(old_size, end)
    changes: Dict[int, bytes] = {}
    first, last = offset // BLOCK_SIZE, (end - 1) // BLOCK_SIZE
    if new_size > old_size and old_size % BLOCK_SIZE and (old_size - 1) // BLOCK_SIZE < first:
        first = (old_size - 1) // BLOCK_SIZE     # old partial last block must be re-padded
    old_n = meta.block_count
    for i in range(first, last + 1):
        start = i * BLOCK_SIZE
        length = min(BLOCK_SIZE, new_size - start)
        covered_from, covered_to = max(offset, start), min(end, start + length)
        if i < old_n and old_size > start and not (covered_from == start and covered_to == start + length):
            base = bytearray(read_plaintext_block(i))
        else:
            base = bytearray()
        base.extend(b"\0" * (length - len(base)))
        del base[length:]
        if covered_to > covered_from:
            base[covered_from - start:covered_to - start] = data[covered_from - offset:covered_to - offset]
        changes[i] = bytes(base)
    return changes, new_size


def plan_replace_block(meta: mht.MHTData, index: int, data: bytes) -> Tuple[Dict[int, bytes], int]:
    """Replace block *index* entirely.  Non-last blocks must stay exactly BLOCK_SIZE bytes; the
    last block may change length (which changes the file length)."""
    n = meta.block_count
    if not 0 <= index < n:
        raise ValueError(f"block index must be 0..{n - 1}")
    if index < n - 1:
        if len(data) != BLOCK_SIZE:
            raise ValueError(f"block {index} is not the last block: new data must be {BLOCK_SIZE} bytes")
        return {index: data}, meta.plaintext_size
    if len(data) > BLOCK_SIZE:
        raise ValueError(f"block data larger than {BLOCK_SIZE} bytes")
    return {index: data}, index * BLOCK_SIZE + len(data)


def plan_sync(meta: mht.MHTData, old_plaintext: bytes, new_plaintext: bytes) -> Tuple[Dict[int, bytes], int]:
    """Diff two plaintexts block by block; only differing (or new) blocks are returned."""
    old_b, new_b = split_plaintext(old_plaintext), split_plaintext(new_plaintext)
    changes = {i: b for i, b in enumerate(new_b) if i >= len(old_b) or old_b[i] != b}
    if len(new_plaintext) != len(old_plaintext):
        last = len(new_b) - 1
        changes.setdefault(last, new_b[last])
    return changes, len(new_plaintext)
