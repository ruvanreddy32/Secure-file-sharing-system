"""
securecloud/aes_cipher.py — AES-256 file encryption (paper §IV, §V-C "Initialization").

The paper encrypts the plaintext file with AES-256 under a symmetric file key K
but does not name a mode of operation.  We use AES-256-GCM (authenticated
encryption, NIST SP 800-38D) from the ``cryptography`` package:

* K       : 32 bytes from the OS CSPRNG (never hard-coded, never reused across files).
* nonce   : 12 random bytes per encryption.
* AAD     : the 4-byte format magic, so the header cannot be swapped.

Encrypted file layout (all integers big-endian)::

    magic  b"RCF1"   (4 bytes)
    nonce            (12 bytes)
    ciphertext||tag  (len(plaintext) + 16 bytes)

The ciphertext is never empty (it always carries the 16-byte tag), so the
Merkle tree of an encrypted *empty* file is well defined.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32          # AES-256
NONCE_SIZE = 12
TAG_SIZE = 16
MAGIC = b"RCF1"
HEADER_SIZE = len(MAGIC) + NONCE_SIZE


class DecryptionError(Exception):
    """Raised when AES-GCM authentication fails (wrong key or altered ciphertext)."""


def generate_file_key() -> bytes:
    """Return a fresh 256-bit AES key from the operating-system CSPRNG."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt *plaintext* and return the encrypted-file bytes."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC)


def decrypt_bytes(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt bytes produced by :func:`encrypt_bytes`.

    Raises:
        DecryptionError: malformed input, wrong key, or modified ciphertext.
    """
    _check_key(key)
    if len(encrypted) < HEADER_SIZE + TAG_SIZE or encrypted[:4] != MAGIC:
        raise DecryptionError("Not a Ring Crypter encrypted file (bad header)")
    nonce = encrypted[4:HEADER_SIZE]
    try:
        return AESGCM(key).decrypt(nonce, encrypted[HEADER_SIZE:], MAGIC)
    except InvalidTag as exc:
        raise DecryptionError("AES-GCM authentication failed") from exc


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")
