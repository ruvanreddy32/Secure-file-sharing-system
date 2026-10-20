"""
securecloud/versioning.py — Versioned cloud storage with atomic activation and authorized updates.

Remote layout (identical on Supabase, Dropbox and the local folder)::

    <name>/manifest.signed                     active-version pointer (RSA-signed by the owner)
    <name>/v000001-<id>/<name>.aes             encrypted file            } the paper's three
    <name>/v000001-<id>/<name>.key.rlwe        Ring-LWE-encrypted key    } objects (§IV, Fig. 2)
    <name>/v000001-<id>/<name>.mht.signed      RSA-signed MHT file       }
    <name>/v000002-<id>/...                    later versions (dynamic updates)

<id> = first 16 hex digits of SHA-256(signed MHT file).  Every publish attempt therefore has its
own folder: two concurrent writers of "version 2" never overwrite (or clean up) each other's
objects, and the manifest entry (which stores the full hash) identifies the folder.

Consistency — a version becomes visible only through the manifest:

    1. upload the three objects of version N+1 (each upload is confirmed by the backend)
    2. if any upload fails  -> delete what was uploaded, raise; manifest still names version N
    3. re-read the manifest (detects a concurrent publisher), then write the new signed
       manifest naming N+1.  A single-object write is atomic on Supabase / Dropbox, so readers
       see either the old or the new version, never a partial one.
    Objects of versions not referenced by the manifest are "incomplete" and are never served;
    :meth:`VersionedRepository.cleanup_incomplete` removes them.

The manifest is a JSON document signed with the owner's RSA key using the *same* signed-file
format as the MHT (RSASSA-PSS-SHA256, :mod:`securecloud.signature`).  For every version it
records SHA-256 of that version's signed MHT file, so the receiver checks:

    manifest signature (owner key)  ->  version listed  ->  SHA-256(signed MHT) matches entry
    ->  paper verification (MHT signature, MHT regeneration and comparison)
    ->  version number and chain link to the previous version's signed MHT.

Block-mode files (format RCB1, ENHANCEMENT - not part of the paper; see blockmode.py)::

    <name>/manifest.signed
    <name>/blocks/<sha256 of ciphertext block>      immutable, content-addressed, SHARED by versions
    <name>/keys/<sha256>.key.rlwe                   file key for the recipient   (content-addressed)
    <name>/keys/<sha256>.owner.key.rlwe             file key for the owner       (content-addressed)
    <name>/v000002-<id>/<name>.mht.signed           signed MHT v3 = the version's block list

The Merkle leaf hash of a ciphertext block *is* its object id, so a new version uploads only the
blocks that changed plus its signed MHT; unchanged blocks are referenced, never re-uploaded.
Activation is the same: new objects first, then a check that every referenced block exists,
then the manifest.  Objects are never overwritten with different content.

Limitation (documented): the manifest has no trusted timestamp, so a storage provider that
replays an *older genuine* manifest can roll a reader back to an older genuine version unless
the reader remembers the highest version it has seen (``min_version``).
"""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from . import blockmode, mht, signature, workflow
from .blockmode import BlockBundle
from .storage import ObjectNotFound, Storage, StorageError, UploadError
from .workflow import ENC_SUFFIX, KEY_SUFFIX, MHT_SUFFIX, ProtectedBundle, VerificationReport

MANIFEST_FILE = "manifest.signed"
MANIFEST_FORMAT = "RING-CRYPTER-MANIFEST v1"


class ManifestError(StorageError):
    """The manifest is missing, malformed, or not signed by the expected owner."""


class PublishError(UploadError):
    """A version could not be published; the previously active version is unchanged."""


@dataclass
class VersionEntry:
    version: int
    mht_sha256: str          # SHA-256 of the version's signed MHT file
    encrypted_size: int
    created_utc: str
    deleted: bool = False    # files removed; entry kept so the hash chain stays checkable
    format: str = mht.FORMAT_WHOLE   # "RCF1" whole-file (paper) | "RCB1" per-block (enhancement)


@dataclass
class Manifest:
    name: str
    current_version: int
    owner_key_sha256: str
    versions: List[VersionEntry] = field(default_factory=list)

    def entry(self, version: int) -> Optional[VersionEntry]:
        return next((e for e in self.versions if e.version == version), None)

    def to_bytes(self) -> bytes:
        doc = {"format": MANIFEST_FORMAT, "name": self.name, "current_version": self.current_version,
               "owner_key_sha256": self.owner_key_sha256,
               "versions": [asdict(v) for v in self.versions]}
        return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Manifest":
        try:
            doc = json.loads(data)
            if doc["format"] != MANIFEST_FORMAT:
                raise ManifestError("Unknown manifest format")
            versions = [VersionEntry(**v) for v in doc["versions"]]
            m = cls(doc["name"], int(doc["current_version"]), doc["owner_key_sha256"], versions)
        except (ValueError, KeyError, TypeError) as exc:
            raise ManifestError(f"Malformed manifest: {exc}") from exc
        if m.entry(m.current_version) is None or m.entry(m.current_version).deleted:
            raise ManifestError("Manifest's current version is not available")
        return m


def version_dir(name: str, version: int, mht_sha256: str) -> str:
    return f"{name}/v{version:06d}-{mht_sha256[:16]}"


def version_keys(name: str, version: int, mht_sha256: str) -> Dict[str, str]:
    d = version_dir(name, version, mht_sha256)
    return {"encrypted_file": f"{d}/{name}{ENC_SUFFIX}",
            "encrypted_key": f"{d}/{name}{KEY_SUFFIX}",
            "signed_mht": f"{d}/{name}{MHT_SUFFIX}"}


def manifest_key(name: str) -> str:
    return f"{name}/{MANIFEST_FILE}"


def block_key(name: str, leaf_hash: str) -> str:
    return f"{name}/blocks/{leaf_hash}"


def block_mht_key(name: str, version: int, mht_sha256: str) -> str:
    return f"{version_dir(name, version, mht_sha256)}/{name}{MHT_SUFFIX}"


def block_key_file_keys(name: str, meta: mht.MHTData) -> Dict[str, str]:
    return {"encrypted_key": f"{name}/keys/{meta.encrypted_key_sha256}{KEY_SUFFIX}",
            "owner_key": f"{name}/keys/{meta.owner_key_sha256}{blockmode.OWNER_KEY_SUFFIX}"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class VersionTrustStore:
    """Persistent local reference for highest known/verified versions of files.

    Protects against manifest rollback attacks where an attacker replaces manifest.signed
    with an older, genuinely signed manifest.

    Limitation / Trust On First Use (TOFU):
    If no record exists for a file, the first verified manifest is accepted (trust-on-first-use)
    and recorded as the baseline. Rollback protection cannot protect against rollbacks on first use
    if the reader has never observed any version before and has no out-of-band version reference.
    Furthermore, this local store assumes the attacker cannot modify the client's local trust store.
    """

    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        if path is not None:
            self.path = Path(path)
        elif os.environ.get("RINGCRYPTER_TRUST_STORE"):
            self.path = Path(os.environ["RINGCRYPTER_TRUST_STORE"])
        else:
            self.path = Path("keys") / ".trusted_versions.json"

    def get_trusted_version(self, name: str) -> Optional[int]:
        data = self._load()
        return data.get(name)

    def record_version(self, name: str, version: int) -> None:
        data = self._load()
        current = data.get(name, 0)
        if version > current:
            data[name] = version
            self._save(data)

    def clear(self, name: Optional[str] = None) -> None:
        if not self.path.exists():
            return
        if name is None:
            try:
                self.path.unlink()
            except OSError:
                pass
        else:
            data = self._load()
            if name in data:
                del data[name]
                self._save(data)

    def _load(self) -> Dict[str, int]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, data: Dict[str, int]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


class VersionedRepository:
    """Owner and receiver operations on versioned, integrity-protected files in a storage backend."""

    def __init__(self, storage: Storage, max_workers: int = 8,
                 trust_store: Optional[VersionTrustStore] = None) -> None:
        self.storage = storage
        self.max_workers = max_workers   # parallel object transfers (block mode)
        self._pool: Optional[ThreadPoolExecutor] = None   # long-lived: keeps per-thread HTTP
                                                          # clients / TLS connections warm
        if trust_store is not None:
            self.trust_store: Optional[VersionTrustStore] = trust_store
        elif os.environ.get("RINGCRYPTER_TRUST_STORE"):
            self.trust_store = VersionTrustStore(os.environ["RINGCRYPTER_TRUST_STORE"])
        elif hasattr(storage, "root"):
            keys_dir = Path(storage.root).parent / "keys"
            self.trust_store = VersionTrustStore(keys_dir / ".trusted_versions.json")
        else:
            self.trust_store = VersionTrustStore()

    # ------------------------------------------------------------------ manifest
    def read_manifest(self, name: str, owner_public_key) -> Optional[Manifest]:
        """Return the verified manifest, None if the file does not exist.

        Raises:
            ManifestError: present but malformed or not signed by *owner_public_key*.
        """
        try:
            signed = self.storage.download(manifest_key(name))
        except ObjectNotFound:
            return None
        try:
            body = signature.verify_signed_mht(signed, owner_public_key)  # same signed-file format
        except signature.SignatureError as exc:
            raise ManifestError(f"Manifest signature invalid for '{name}': {exc}") from exc
        m = Manifest.from_bytes(body)
        if m.name != name:
            raise ManifestError(f"Manifest is for '{m.name}', not '{name}'")
        return m

    def _write_manifest(self, m: Manifest, signing_key) -> None:
        self.storage.upload(manifest_key(m.name), signature.create_signed_mht(m.to_bytes(), signing_key))

    # ------------------------------------------------------------------ owner
    def publish(self, bundle: Union[ProtectedBundle, BlockBundle], signing_key) -> VersionEntry:
        """Upload *bundle* as a new version and activate it atomically (see module docstring)."""
        if isinstance(bundle, BlockBundle):
            return self.publish_blocks(bundle, signing_key)
        pub = signing_key.public_key()
        report = workflow.verify_integrity(bundle, pub)
        if not report.ok:
            raise PublishError("Refusing to publish a bundle that does not verify under the "
                               "signing key: " + report.summary)
        current = self.read_manifest(bundle.name, pub)   # ManifestError -> not our file
        if current is None:
            if report.version != 1:
                raise PublishError(f"'{bundle.name}' does not exist yet; first version must be 1, "
                                   f"got {report.version}")
        else:
            prev = current.entry(current.current_version)
            if prev.format != mht.FORMAT_WHOLE:
                raise PublishError(f"'{bundle.name}' is a per-block (RCB1) file; use block updates")
            if report.version != current.current_version + 1 \
                    or report.previous_mht_sha256 != prev.mht_sha256:
                raise PublishError(f"Bundle is version {report.version} but '{bundle.name}' is at "
                                   f"version {current.current_version}; build it with update_phase "
                                   "from the current version")

        keys = version_keys(bundle.name, report.version, workflow.signed_mht_sha256(bundle))
        uploaded: List[str] = []
        try:
            for attr, key in keys.items():
                self.storage.upload(key, getattr(bundle, attr))
                uploaded.append(key)
        except Exception as exc:
            self._discard(uploaded)
            raise PublishError(f"Upload of version {report.version} failed ({exc}); "
                               "the version was NOT activated") from exc

        latest = self.read_manifest(bundle.name, pub)
        if (latest.current_version if latest else 0) != (current.current_version if current else 0):
            self._discard(uploaded)
            raise PublishError("Another update was published concurrently; nothing was activated")

        entry = VersionEntry(report.version, workflow.signed_mht_sha256(bundle),
                             len(bundle.encrypted_file),
                             datetime.now(timezone.utc).isoformat(timespec="seconds"))
        new = Manifest(bundle.name, report.version, signature.fingerprint(pub),
                       (current.versions if current else []) + [entry])
        try:
            self._write_manifest(new, signing_key)       # <- activation point
        except Exception as exc:
            raise PublishError(f"Version {report.version} uploaded but the manifest could not be "
                               f"written ({exc}); it is NOT active (run cleanup)") from exc
        if self.trust_store is not None:
            self.trust_store.record_version(bundle.name, entry.version)
        return entry

    def update(self, name: str, new_plaintext: bytes, signing_key, recipient_rlwe_public,
               *, block_size: Optional[int] = None, paper_mode: bool = False
               ) -> Tuple[VersionEntry, Dict[str, float]]:
        """Authorized dynamic update: fetch + verify the current version, build N+1, publish."""
        m = self.read_manifest(name, signing_key.public_key())
        if m is not None and m.entry(m.current_version).format == mht.FORMAT_BLOCK:
            raise PublishError(f"'{name}' is a per-block (RCB1) file: use block_patch / block_sync")
        current, report = self.fetch_verified(name, signing_key.public_key())
        if current is None or not report.ok:
            raise workflow.IntegrityError("Update refused: current version of "
                                          f"'{name}' does not verify. " + report.summary, report)
        bundle, t = workflow.update_phase(new_plaintext, current, signing_key, recipient_rlwe_public,
                                          block_size=block_size, paper_mode=paper_mode)
        return self.publish(bundle, signing_key), t

    def delete(self, name: str, signing_key, version: Optional[int] = None) -> List[str]:
        """Delete a whole file (version=None) or one non-active version.  Returns removed keys."""
        pub = signing_key.public_key()
        m = self.read_manifest(name, pub)
        if m is None:
            raise ObjectNotFound(f"'{name}' not found")
        if version is None:
            self.storage.delete([manifest_key(name)])     # deactivate first
            keys = self.storage.list(name)
            self.storage.delete(keys)
            if self.trust_store is not None:
                self.trust_store.clear(name)
            return [manifest_key(name)] + keys
        e = m.entry(version)
        if e is None or e.deleted:
            raise ObjectNotFound(f"'{name}' has no version {version}")
        if version == m.current_version:
            raise StorageError("Cannot delete the active version; publish an update or delete the "
                               "whole file")
        doomed = self._version_objects(name, e, pub)
        e.deleted = True
        self._write_manifest(m, signing_key)
        keep: Set[str] = set()
        for other in m.versions:
            if not other.deleted:
                keep |= self._version_objects(name, other, pub)
        keys = sorted(doomed - keep)          # blocks / key files shared with live versions stay
        self.storage.delete(keys)
        return keys

    def cleanup_incomplete(self, name: str, owner_public_key) -> List[str]:
        """Remove objects under *name*/ that the manifest does not reference (failed publishes)."""
        m = self.read_manifest(name, owner_public_key)
        live = {manifest_key(name)}
        if m is not None:
            for e in m.versions:
                if not e.deleted:
                    live |= self._version_objects(name, e, owner_public_key)
        stale = [k for k in self.storage.list(name) if k not in live]
        self.storage.delete(stale)
        return stale

    def _discard(self, keys: List[str]) -> None:
        try:
            self.storage.delete(keys)
        except Exception:
            pass  # best effort; unreferenced objects are never served and can be cleaned up

    # ------------------------------------------------------------------ receiver
    def list_files(self) -> List[str]:
        """Names that have a manifest (i.e. at least one activated version)."""
        return sorted(k[: -len(MANIFEST_FILE) - 1] for k in self.storage.list()
                      if k.endswith("/" + MANIFEST_FILE) and k.count("/") == 1)

    def versions(self, name: str, owner_public_key) -> Tuple[Manifest, List[VersionEntry]]:
        m = self.read_manifest(name, owner_public_key)
        if m is None:
            raise ObjectNotFound(f"'{name}' not found")
        return m, [e for e in m.versions if not e.deleted]

    def keys_for(self, name: str, version: int, owner_public_key) -> Dict[str, str]:
        """Storage keys of *version* as recorded in the verified manifest."""
        m = self.read_manifest(name, owner_public_key)
        e = m.entry(version) if m else None
        if e is None:
            raise ObjectNotFound(f"'{name}' has no version {version}")
        if e.format == mht.FORMAT_BLOCK:
            meta, _ = self._block_meta(name, e, owner_public_key)
            return {"signed_mht": block_mht_key(name, e.version, e.mht_sha256),
                    "blocks": [block_key(name, h) for h in meta.leaf_hashes],
                    **block_key_file_keys(name, meta)}
        return version_keys(name, version, e.mht_sha256)

    def download(self, name: str, entry: VersionEntry) -> ProtectedBundle:
        keys = version_keys(name, entry.version, entry.mht_sha256)
        return ProtectedBundle(name, *(self.storage.download(keys[a])
                                       for a in ("encrypted_file", "encrypted_key", "signed_mht")))

    def fetch_verified(self, name: str, owner_public_key, version: Optional[int] = None,
                       min_version: Optional[int] = None
                       ) -> Tuple[Optional[ProtectedBundle], VerificationReport]:
        """Receiver: manifest check + download + the paper's integrity verification.

        Never raises on tampering; returns (bundle or None, report).  Decrypt only via
        :func:`securecloud.workflow.decrypt_verified` with the returned report.
        """
        fail = VerificationReport()
        try:
            m = self.read_manifest(name, owner_public_key)
        except ManifestError as exc:
            fail.manifest_valid = False
            fail.messages.append(str(exc))
            return None, fail
        if m is None:
            fail.messages.append(f"'{name}' not found in {self.storage.name} storage")
            return None, fail

        trusted_v = self.trust_store.get_trusted_version(name) if self.trust_store else None
        effective_min = min_version
        if trusted_v is not None:
            effective_min = max(effective_min or 0, trusted_v)

        if effective_min is not None and m.current_version < effective_min:
            fail.manifest_valid = False
            fail.messages.append(f"Rollback detected: storage offers version {m.current_version}, "
                                 f"but version {effective_min} was seen before")
            return None, fail

        v = version or m.current_version
        entry = m.entry(v)
        if entry is None or entry.deleted:
            fail.manifest_valid = True
            fail.messages.append(f"Version {v} of '{name}' is not listed in the signed manifest")
            return None, fail
        if entry.format == mht.FORMAT_BLOCK:
            return self._fetch_block_version(name, m, entry, owner_public_key)
        try:
            bundle = self.download(name, entry)
        except StorageError as exc:
            fail.manifest_valid = True
            fail.messages.append(f"Version {v} files missing or unreadable: {exc}")
            return None, fail

        prev = m.entry(v - 1) if v > 1 else None
        report = workflow.verify_integrity(bundle, owner_public_key, expected_version=v,
                                           expected_previous_mht_sha256=prev.mht_sha256 if prev else "")
        report.manifest_valid = True
        if workflow.signed_mht_sha256(bundle) != entry.mht_sha256:
            report.messages.append("Signed MHT file differs from the one recorded in the signed "
                                   "manifest for this version")
            report.manifest_valid = False
        if v > 1 and prev is None:
            report.messages.append(f"Manifest has no entry for version {v - 1}; chain unverifiable")
            report.version_ok = False
        if not (report.manifest_valid and report.version_ok):
            report.ok = False
        if not report.ok:
            report.verified_digest = ""   # decrypt_verified will refuse
        elif self.trust_store is not None:
            self.trust_store.record_version(name, m.current_version)
        return bundle, report

    # ------------------------------------------------------------------ helpers (all formats)
    def _parallel(self, fn: Callable, items: Iterable) -> List:
        items = list(items)
        if len(items) <= 1 or self.max_workers <= 1:
            return [fn(x) for x in items]
        if self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=self.max_workers,
                                            thread_name_prefix="ringcrypter-io")
        return list(self._pool.map(fn, items))

    def _block_meta(self, name: str, entry: VersionEntry, owner_public_key,
                    verify_tree: bool = True) -> Tuple[mht.MHTData, bytes]:
        """Download, authenticate (owner signature + manifest hash) and parse a version's MHT v3."""
        signed = self.storage.download(block_mht_key(name, entry.version, entry.mht_sha256))
        if _sha256(signed) != entry.mht_sha256:
            raise ManifestError(f"signed MHT of version {entry.version} differs from the manifest entry")
        try:
            meta = mht.parse(signature.verify_signed_mht(signed, owner_public_key), verify_tree)
        except (signature.SignatureError, mht.MHTFormatError) as exc:
            raise ManifestError(f"signed MHT of version {entry.version} is invalid: {exc}") from exc
        return meta, signed

    def _version_objects(self, name: str, entry: VersionEntry, owner_public_key) -> Set[str]:
        """All storage keys a version needs (RCB1: its MHT, its blocks and its key files)."""
        if entry.format != mht.FORMAT_BLOCK:
            return set(version_keys(name, entry.version, entry.mht_sha256).values())
        try:
            meta, _ = self._block_meta(name, entry, owner_public_key)
        except StorageError:
            return {block_mht_key(name, entry.version, entry.mht_sha256)}
        return ({block_mht_key(name, entry.version, entry.mht_sha256)}
                | {block_key(name, h) for h in meta.leaf_hashes}
                | set(block_key_file_keys(name, meta).values()))

    def _upload_all(self, objects: Dict[str, bytes], what: str) -> List[str]:
        """Upload in parallel; on any failure delete what was uploaded and raise PublishError."""
        uploaded: List[str] = []

        def put(item):
            key, data = item
            self.storage.upload(key, data)
            uploaded.append(key)

        try:
            self._parallel(put, objects.items())
        except Exception as exc:
            self._discard(uploaded)
            raise PublishError(f"Upload of {what} failed ({exc}); the version was NOT activated") from exc
        return uploaded

    def _activate(self, name: str, entry: VersionEntry, current: Optional[Manifest], signing_key,
                  uploaded: List[str]) -> VersionEntry:
        pub = signing_key.public_key()
        latest = self.read_manifest(name, pub)
        if (latest.current_version if latest else 0) != (current.current_version if current else 0):
            self._discard(uploaded)
            raise PublishError("Another update was published concurrently; nothing was activated")
        new = Manifest(name, entry.version, signature.fingerprint(pub),
                       (current.versions if current else []) + [entry])
        try:
            self._write_manifest(new, signing_key)       # <- activation point
        except Exception as exc:
            raise PublishError(f"Version {entry.version} uploaded but the manifest could not be "
                               f"written ({exc}); it is NOT active (run cleanup)") from exc
        if self.trust_store is not None:
            self.trust_store.record_version(name, entry.version)
        return entry

    # ------------------------------------------------------------------ block mode (RCB1)
    def publish_blocks(self, bundle: BlockBundle, signing_key) -> VersionEntry:
        """Publish version 1 of a per-block (RCB1) file (enhancement, not part of the paper)."""
        pub = signing_key.public_key()
        report = blockmode.block_verify_integrity(bundle, pub)
        if not report.ok:
            raise PublishError("Refusing to publish a bundle that does not verify: " + report.summary)
        if report.version != 1:
            raise PublishError("publish_blocks publishes version 1; use block_patch / block_sync")
        if self.read_manifest(bundle.name, pub) is not None:
            raise PublishError(f"'{bundle.name}' already exists; use block_patch / block_sync")
        meta = mht.parse(signature.split_signed_mht(bundle.signed_mht)[0])
        mht_sha = _sha256(bundle.signed_mht)
        keyfiles = block_key_file_keys(bundle.name, meta)
        objects = {block_key(bundle.name, h): b for h, b in zip(bundle.leaf_hashes, bundle.blocks)}
        objects[keyfiles["encrypted_key"]] = bundle.encrypted_key
        objects[keyfiles["owner_key"]] = bundle.owner_key
        objects[block_mht_key(bundle.name, 1, mht_sha)] = bundle.signed_mht
        uploaded = self._upload_all(objects, "version 1")
        entry = VersionEntry(1, mht_sha, meta.encrypted_file_size,
                             datetime.now(timezone.utc).isoformat(timespec="seconds"),
                             format=mht.FORMAT_BLOCK)
        return self._activate(bundle.name, entry, None, signing_key, uploaded)

    def _block_update(self, name: str, signing_key, owner_rlwe_private,
                      planner: Callable[[mht.MHTData, Callable[[int], bytes]], Tuple[Dict[int, bytes], int]]
                      ) -> Tuple[VersionEntry, Dict[str, float]]:
        pub = signing_key.public_key()
        current = self.read_manifest(name, pub)            # ManifestError if not the owner
        if current is None:
            raise ObjectNotFound(f"'{name}' not found")
        entry = current.entry(current.current_version)
        if entry.format != mht.FORMAT_BLOCK:
            raise PublishError(f"'{name}' is a whole-file (RCF1) file; block updates need RCB1")
        # owner authenticates its OWN signed metadata; the O(n) tree re-derivation is skipped here
        meta, signed = self._block_meta(name, entry, pub, verify_tree=False)
        owner_key = self.storage.download(block_key_file_keys(name, meta)["owner_key"])
        if _sha256(owner_key) != meta.owner_key_sha256:
            raise workflow.IntegrityError("Owner key file in storage does not match the signed metadata")
        key = blockmode.recover_file_key(owner_key, owner_rlwe_private)
        file_id = bytes.fromhex(meta.file_id)
        read_blocks: List[int] = []

        def read_plaintext(i: int) -> bytes:
            cb = self.storage.download(block_key(name, meta.leaf_hashes[i]))
            if _sha256(cb) != meta.leaf_hashes[i]:
                raise workflow.IntegrityError(f"Update refused: block {i} is corrupted in storage")
            read_blocks.append(i)
            return blockmode.decrypt_block(key, file_id, i, cb)

        changes, new_size = planner(meta, read_plaintext)
        upd = blockmode.build_block_update(meta, signed, key, changes, new_size, signing_key)
        new_sha = _sha256(upd.signed_mht)
        objects = {block_key(name, _sha256(cb)): cb for cb in upd.new_blocks.values()}
        objects[block_mht_key(name, upd.meta.version, new_sha)] = upd.signed_mht
        uploaded = self._upload_all(objects, f"version {upd.meta.version}")

        referenced = {block_key(name, h) for h in upd.leaves}
        missing = referenced - set(self.storage.list(f"{name}/blocks"))
        if missing:
            self._discard(uploaded)
            raise PublishError(f"{len(missing)} referenced block(s) are missing in storage; "
                               "version NOT activated")
        new_entry = VersionEntry(upd.meta.version, new_sha, upd.meta.encrypted_file_size,
                                 datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 format=mht.FORMAT_BLOCK)
        self._activate(name, new_entry, current, signing_key, uploaded)
        stats = dict(upd.stats)
        stats.update(metadata_nodes=sum(len(level) for level in upd.meta.levels),
                     blocks_read_for_partial_writes=len(read_blocks),
                     new_block_objects_uploaded=len(upd.new_blocks),
                     unchanged_blocks_reused=len(upd.leaves) - len(upd.new_blocks),
                     signed_mht_bytes=len(upd.signed_mht))
        return new_entry, stats

    def block_patch(self, name: str, offset: int, data: bytes, signing_key, owner_rlwe_private):
        """Write *data* at byte *offset* of an RCB1 file (may extend it).  Re-encrypts and uploads
        only the affected blocks."""
        return self._block_update(name, signing_key, owner_rlwe_private,
                                  lambda meta, read: blockmode.plan_patch(meta, offset, data, read))

    def block_patch_many(self, name: str, edits: List[Tuple[int, bytes]], signing_key, owner_rlwe_private):
        """Apply several (offset, data) writes as ONE new version; touched blocks only."""
        return self._block_update(name, signing_key, owner_rlwe_private,
                                  lambda meta, read: blockmode.plan_patches(meta, edits, read))

    def block_replace(self, name: str, index: int, data: bytes, signing_key, owner_rlwe_private):
        """Replace one whole 4096-byte block (the last block may change length)."""
        return self._block_update(name, signing_key, owner_rlwe_private,
                                  lambda meta, read: blockmode.plan_replace_block(meta, index, data))

    def block_sync(self, name: str, new_plaintext: bytes, signing_key, owner_rlwe_private):
        """Make the RCB1 file equal to *new_plaintext*: the current version is downloaded and fully
        verified, then only differing blocks are re-encrypted and uploaded."""
        pub = signing_key.public_key()
        bundle, report = self.fetch_verified(name, pub)
        if bundle is None or not report.ok:
            raise workflow.IntegrityError("Update refused: current version does not verify. "
                                          + report.summary, report)
        if not isinstance(bundle, BlockBundle):
            raise PublishError(f"'{name}' is a whole-file (RCF1) file; block updates need RCB1")
        key = blockmode.recover_file_key(bundle.owner_key, owner_rlwe_private)
        meta = mht.parse(signature.split_signed_mht(bundle.signed_mht)[0])
        fid = bytes.fromhex(meta.file_id)
        old = b"".join(blockmode.decrypt_block(key, fid, i, b) for i, b in enumerate(bundle.blocks))
        return self._block_update(name, signing_key, owner_rlwe_private,
                                  lambda m, read: blockmode.plan_sync(m, old, new_plaintext))

    def _fetch_block_version(self, name: str, m: Manifest, entry: VersionEntry, owner_public_key
                             ) -> Tuple[Optional[BlockBundle], VerificationReport]:
        fail = VerificationReport(manifest_valid=True)
        v = entry.version
        try:
            signed = self.storage.download(block_mht_key(name, v, entry.mht_sha256))
        except StorageError as exc:
            fail.messages.append(f"Version {v} metadata missing or unreadable: {exc}")
            return None, fail
        if _sha256(signed) != entry.mht_sha256:
            fail.manifest_valid = False
            fail.messages.append("Signed MHT file differs from the one recorded in the signed manifest")
            return None, fail
        try:   # step (2a) first: the signed MHT says which block objects belong to this version
            meta = mht.parse(signature.verify_signed_mht(signed, owner_public_key))
        except (signature.SignatureError, mht.MHTFormatError):
            report = blockmode.block_verify_integrity(BlockBundle(name, [], b"", b"", signed),
                                                      owner_public_key)
            report.manifest_valid = True
            return None, report
        missing: List[int] = []

        def get_block(i_h):
            i, h = i_h
            try:
                return self.storage.download(block_key(name, h))
            except ObjectNotFound:
                missing.append(i)
                return b""
        blocks = self._parallel(get_block, enumerate(meta.leaf_hashes))
        try:
            kf = block_key_file_keys(name, meta)
            ek, ok = self.storage.download(kf["encrypted_key"]), self.storage.download(kf["owner_key"])
        except StorageError as exc:
            fail.messages.append(f"Version {v} key files missing or unreadable: {exc}")
            return None, fail
        bundle = BlockBundle(name, blocks, ek, ok, signed)
        prev = m.entry(v - 1) if v > 1 else None
        report = blockmode.block_verify_integrity(
            bundle, owner_public_key, expected_version=v,
            expected_previous_mht_sha256=prev.mht_sha256 if prev else "")
        report.manifest_valid = True
        if missing:
            report.messages.append(f"block object(s) missing from storage: {sorted(missing)[:20]}")
            report.ok = False
        if v > 1 and prev is None:
            report.messages.append(f"Manifest has no entry for version {v - 1}; chain unverifiable")
            report.version_ok = report.ok = False
        if not report.ok:
            report.verified_digest = ""
        elif self.trust_store is not None:
            self.trust_store.record_version(name, m.current_version)
        return bundle, report
