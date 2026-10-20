"""
securecloud/workflow.py — The paper's end-to-end workflow (§IV, §V-C, Figs. 2–3).

File owner (Initialization + Setup phase)::

    plaintext --AES-256--> encrypted file
    file key K --Ring-LWE(recipient public key)--> encrypted key file
    encrypted file --blocks--> SHA-256 --> Merkle Hash Tree --> MHT file
    MHT file --RSA sign(Kpri)--> signed MHT file
    upload: <name>.aes, <name>.key.rlwe, <name>.mht.signed

Receiver (Integrity Verification, then decryption)::

    download the three files
    (2a) verify the RSA signature of the signed MHT file with Kpub   -> stop on failure
    (1)  re-run Setup steps (1)-(2) on the downloaded encrypted file
    (2b) compare the recomputed MHT with the authenticated MHT       -> stop on mismatch
         (+ encrypted-key-file hash and file-name binding, extensions)
    only if everything matches: Ring-LWE-decrypt K, AES-decrypt the file

Authorized dynamic update (:func:`update_phase`)::

    the owner verifies the current version N with its own public key, then runs
    the Setup phase on the new content with version = N+1 and
    previous-mht-sha256 = SHA-256(signed MHT file of version N), signed with the
    same owner key.  Receivers check the version number and the chain link, so
    versions that are forged, re-ordered or signed by anyone else fail.

Decryption is reachable only through :func:`decrypt_verified` /
:func:`open_bundle`, which refuse to run unless a successful
:class:`VerificationReport` for *exactly these bytes* is supplied.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from . import aes_cipher, mht, rlwe, signature
from .storage import Storage

ENC_SUFFIX = ".aes"
KEY_SUFFIX = ".key.rlwe"
MHT_SUFFIX = ".mht.signed"


class IntegrityError(Exception):
    """Raised when decryption is attempted without successful integrity verification."""

    def __init__(self, message: str, report: Optional["VerificationReport"] = None) -> None:
        super().__init__(message)
        self.report = report


@dataclass
class ProtectedBundle:
    """The three objects the owner uploads (paper Fig. 2)."""
    name: str               # original file name, e.g. "data.txt"
    encrypted_file: bytes   # <name>.aes
    encrypted_key: bytes    # <name>.key.rlwe
    signed_mht: bytes       # <name>.mht.signed

    @property
    def encrypted_name(self) -> str:
        return self.name + ENC_SUFFIX

    def files(self) -> Dict[str, bytes]:
        return {self.name + ENC_SUFFIX: self.encrypted_file,
                self.name + KEY_SUFFIX: self.encrypted_key,
                self.name + MHT_SUFFIX: self.signed_mht}


@dataclass
class VerificationReport:
    ok: bool = False
    signature_valid: bool = False
    mht_well_formed: bool = False
    file_name_match: bool = False
    mht_match: bool = False
    key_file_match: bool = False
    size_changed: bool = False
    version: int = 0
    previous_mht_sha256: str = ""
    version_ok: bool = True
    manifest_valid: Optional[bool] = None   # set by versioning.VersionedRepository
    stored_root: str = ""
    computed_root: str = ""
    block_count: int = 0
    block_size: int = 0
    mismatched_nodes: int = 0
    tampered_blocks: List[int] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    timings_ms: Dict[str, float] = field(default_factory=dict)
    verified_digest: str = ""

    @property
    def summary(self) -> str:
        if self.ok:
            return "Downloaded Data Verified!!! Integrity check PASSED."
        return "INTEGRITY CHECK FAILED: " + "; ".join(self.messages)


def _digest(bundle: ProtectedBundle) -> str:
    h = hashlib.sha256()
    for part in (bundle.name.encode(), bundle.encrypted_file, bundle.encrypted_key, bundle.signed_mht):
        h.update(hashlib.sha256(part).digest())
    return h.hexdigest()


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


# ---------------------------------------------------------------------------
# Owner side: Initialization + Setup phase
# ---------------------------------------------------------------------------

def setup_phase(plaintext: bytes, name: str, signing_key, recipient_rlwe_public: rlwe.RLWEPublicKey,
                *, block_size: Optional[int] = None, paper_mode: bool = False,
                version: int = 1, previous_mht_sha256: str = ""
                ) -> Tuple[ProtectedBundle, Dict[str, float]]:
    """Encrypt, encrypt the key, build and sign the MHT.  Returns (bundle, timings in ms)."""
    if not name or "/" in name or "\\" in name:
        raise ValueError(f"Invalid file name {name!r}")
    t: Dict[str, float] = {}
    t_all = time.perf_counter()

    t0 = time.perf_counter()
    file_key = aes_cipher.generate_file_key()
    encrypted = aes_cipher.encrypt_bytes(plaintext, file_key)
    t["aes_encrypt_ms"] = _ms(t0)

    t0 = time.perf_counter()
    encrypted_key = rlwe.encrypt_key(file_key, recipient_rlwe_public)
    t["rlwe_key_encrypt_ms"] = _ms(t0)

    data = mht.generate_mht(encrypted, name + ENC_SUFFIX, encrypted_key,
                            block_size=block_size, paper_mode=paper_mode, timings=t,
                            version=version, previous_mht_sha256=previous_mht_sha256)
    t0 = time.perf_counter()
    mht_bytes = mht.serialize(data)
    t["mht_file_write_ms"] = _ms(t0)

    t0 = time.perf_counter()
    signed = signature.create_signed_mht(mht_bytes, signing_key)
    t["rsa_sign_ms"] = _ms(t0)

    t["total_setup_ms"] = _ms(t_all)
    return ProtectedBundle(name, encrypted, encrypted_key, signed), t


def signed_mht_sha256(bundle: ProtectedBundle) -> str:
    return hashlib.sha256(bundle.signed_mht).hexdigest()


def update_phase(new_plaintext: bytes, previous: ProtectedBundle, signing_key,
                 recipient_rlwe_public: rlwe.RLWEPublicKey, *, block_size: Optional[int] = None,
                 paper_mode: bool = False) -> Tuple[ProtectedBundle, Dict[str, float]]:
    """Authorized dynamic update: create version N+1 of *previous* (paper §VII future work).

    The owner first verifies the current version under its own public key (so it
    never extends a tampered or foreign chain), then re-runs the paper's Setup
    phase on the new content.  The cryptographic algorithms are unchanged; the
    new signed MHT carries version = N+1 and SHA-256 of version N's signed MHT.

    Raises:
        IntegrityError: the previous version does not verify under the owner's key.
    """
    report = verify_integrity(previous, signing_key.public_key())
    if not report.ok:
        raise IntegrityError("Update refused: the current version does not verify under the "
                             "owner's key. " + report.summary, report)
    return setup_phase(new_plaintext, previous.name, signing_key, recipient_rlwe_public,
                       block_size=block_size, paper_mode=paper_mode,
                       version=report.version + 1, previous_mht_sha256=signed_mht_sha256(previous))


# ---------------------------------------------------------------------------
# Receiver side: Integrity verification
# ---------------------------------------------------------------------------

def verify_integrity(bundle: ProtectedBundle, signer_public_key, *,
                     expected_version: Optional[int] = None,
                     expected_previous_mht_sha256: Optional[str] = None) -> VerificationReport:
    """Paper §V-C Integrity Verification steps (1) and (2).  Never raises on tampering."""
    r = VerificationReport()
    t = r.timings_ms
    t_all = time.perf_counter()

    # (2a) signature of the signed MHT file
    t0 = time.perf_counter()
    try:
        mht_bytes = signature.verify_signed_mht(bundle.signed_mht, signer_public_key)
        r.signature_valid = True
    except signature.SignatureError as exc:
        r.messages.append(str(exc))
    t["rsa_verify_ms"] = _ms(t0)
    if not r.signature_valid:
        t["total_verify_ms"] = _ms(t_all)
        return r  # the paper stops here: the reference MHT cannot be trusted

    t0 = time.perf_counter()
    try:
        stored = mht.parse(mht_bytes)
        r.mht_well_formed = True
    except mht.MHTFormatError as exc:
        r.messages.append(f"Signed MHT file is malformed: {exc}")
        t["total_verify_ms"] = _ms(t_all)
        return r
    t["mht_parse_ms"] = _ms(t0)
    r.stored_root, r.block_count, r.block_size = stored.root, stored.block_count, stored.block_size
    r.version, r.previous_mht_sha256 = stored.version, stored.previous_mht_sha256
    if expected_version is not None and stored.version != expected_version:
        r.version_ok = False
        r.messages.append(f"Signed MHT is version {stored.version}, expected version {expected_version}")
    if (expected_previous_mht_sha256 is not None
            and stored.previous_mht_sha256 != expected_previous_mht_sha256):
        r.version_ok = False
        r.messages.append("Version chain broken: previous-mht-sha256 does not match the "
                          "preceding version")

    r.file_name_match = stored.file_name == bundle.encrypted_name
    if not r.file_name_match:
        r.messages.append(f"MHT was signed for '{stored.file_name}', not '{bundle.encrypted_name}'")

    # (1) re-run the Setup phase on the downloaded encrypted file (same block size)
    if bundle.encrypted_file:
        computed = mht.generate_mht(bundle.encrypted_file, bundle.encrypted_name,
                                    bundle.encrypted_key, block_size=stored.block_size, timings=t)
        # (2b) compare uploaded MHT with the recomputed MHT
        t0 = time.perf_counter()
        cmp = mht.compare(stored, computed)
        t["mht_compare_ms"] = _ms(t0)
        r.mht_match, r.computed_root = cmp.match, cmp.computed_root
        r.size_changed, r.mismatched_nodes = cmp.size_changed, cmp.mismatched_nodes
        r.tampered_blocks = cmp.tampered_blocks
        r.key_file_match = computed.encrypted_key_sha256 == stored.encrypted_key_sha256
    else:
        r.size_changed, r.tampered_blocks = True, list(range(stored.block_count))
        r.key_file_match = (hashlib.sha256(bundle.encrypted_key).hexdigest()
                            == stored.encrypted_key_sha256)

    if not r.mht_match:
        detail = (f"encrypted file size changed ({stored.encrypted_file_size} -> "
                  f"{len(bundle.encrypted_file)} bytes)" if r.size_changed
                  else f"{r.mismatched_nodes} MHT node(s) differ")
        r.messages.append(f"Merkle root mismatch: {detail}; modified block(s): "
                          f"{_fmt_blocks(r.tampered_blocks)}")
    if not r.key_file_match:
        r.messages.append("Encrypted key file does not match the signed MHT metadata")

    r.ok = r.signature_valid and r.mht_well_formed and r.file_name_match \
        and r.mht_match and r.key_file_match and r.version_ok
    if r.ok:
        r.verified_digest = _digest(bundle)
    t["total_verify_ms"] = _ms(t_all)
    return r


def _fmt_blocks(blocks: List[int], limit: int = 20) -> str:
    if not blocks:
        return "none"
    shown = ", ".join(map(str, blocks[:limit]))
    return shown + (f", ... ({len(blocks)} total)" if len(blocks) > limit else "")


# ---------------------------------------------------------------------------
# Receiver side: decryption (only after successful verification)
# ---------------------------------------------------------------------------

def decrypt_verified(bundle: ProtectedBundle, report: VerificationReport,
                     rlwe_private_key: rlwe.RLWEPrivateKey,
                     timings: Optional[Dict[str, float]] = None) -> bytes:
    """Recover K with Ring-LWE and AES-decrypt — refused unless *report* verified these bytes."""
    from . import blockmode   # lazy: blockmode imports this module
    if isinstance(bundle, blockmode.BlockBundle):
        return blockmode.block_decrypt_verified(bundle, report, rlwe_private_key, timings)
    if not isinstance(report, VerificationReport) or not report.ok:
        raise IntegrityError("Decryption refused: integrity verification did not succeed. "
                             + (report.summary if isinstance(report, VerificationReport) else ""),
                             report if isinstance(report, VerificationReport) else None)
    if report.verified_digest != _digest(bundle):
        raise IntegrityError("Decryption refused: these bytes are not the ones that were verified",
                             report)
    t = timings if timings is not None else {}
    t0 = time.perf_counter()
    file_key = rlwe.decrypt_key(bundle.encrypted_key, rlwe_private_key)
    t["rlwe_key_decrypt_ms"] = _ms(t0)
    t0 = time.perf_counter()
    plaintext = aes_cipher.decrypt_bytes(bundle.encrypted_file, file_key)
    t["aes_decrypt_ms"] = _ms(t0)
    return plaintext


def open_bundle(bundle: ProtectedBundle, signer_public_key,
                rlwe_private_key: rlwe.RLWEPrivateKey) -> Tuple[bytes, VerificationReport]:
    """Verify, then decrypt.  Raises :class:`IntegrityError` if verification fails."""
    report = verify_integrity(bundle, signer_public_key)
    if not report.ok:
        raise IntegrityError(report.summary, report)
    return decrypt_verified(bundle, report, rlwe_private_key, report.timings_ms), report


# ---------------------------------------------------------------------------
# Persistence: local files and cloud storage
# ---------------------------------------------------------------------------

def save_bundle(bundle: ProtectedBundle, directory: Union[str, Path]) -> List[Path]:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for fname, data in bundle.files().items():
        (d / fname).write_bytes(data)
        out.append(d / fname)
    return out


def load_bundle(directory: Union[str, Path], name: str) -> ProtectedBundle:
    d = Path(directory)
    return ProtectedBundle(name, (d / (name + ENC_SUFFIX)).read_bytes(),
                           (d / (name + KEY_SUFFIX)).read_bytes(),
                           (d / (name + MHT_SUFFIX)).read_bytes())


def upload_bundle(storage: Storage, bundle: ProtectedBundle) -> Dict[str, float]:
    """Upload the three files; each upload is confirmed by the backend or raises."""
    timings: Dict[str, float] = {}
    for fname, data in bundle.files().items():
        t0 = time.perf_counter()
        storage.upload(fname, data)
        timings[f"upload {fname}"] = _ms(t0)
    return timings


def download_bundle(storage: Storage, name: str) -> Tuple[ProtectedBundle, float]:
    t0 = time.perf_counter()
    bundle = ProtectedBundle(name, storage.download(name + ENC_SUFFIX),
                             storage.download(name + KEY_SUFFIX),
                             storage.download(name + MHT_SUFFIX))
    return bundle, _ms(t0)


def list_bundles(storage: Storage) -> List[str]:
    """Names for which all three files are present in storage."""
    files = set(storage.list())
    return sorted(f[:-len(ENC_SUFFIX)] for f in files if f.endswith(ENC_SUFFIX)
                  and f[:-len(ENC_SUFFIX)] + KEY_SUFFIX in files
                  and f[:-len(ENC_SUFFIX)] + MHT_SUFFIX in files)
