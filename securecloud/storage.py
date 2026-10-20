"""
securecloud/storage.py — Cloud storage backends (paper §IV, Fig. 2, Fig. 3).

The paper stores the three protected objects (encrypted file, encrypted key file,
signed MHT file) at a cloud storage provider (Dropbox in the paper).  This module
provides interchangeable backends with one small interface:

    upload(key, data)   download(key) -> bytes   list(prefix="") -> [keys]   delete([keys])

Keys are "/"-separated relative paths (e.g. ``report.pdf/v000002/report.pdf.aes``);
``..``, empty segments, backslashes and leading "/" are rejected.

Backends
--------
``SupabaseStorage`` (default) — official Supabase Python SDK (``supabase`` >= 2),
    **private** bucket.  Credentials from environment variables only:

        SUPABASE_URL                     project URL, https://<ref>.supabase.co
        SUPABASE_SERVICE_ROLE_KEY        server-side key (CLI / Streamlit server)
          or SUPABASE_KEY                a restricted key + Storage RLS policies
        SUPABASE_BUCKET                  bucket id (default "ringcrypter")

    The service-role key bypasses Row Level Security.  It is read only by this
    server-side process and is never sent to a browser (Streamlit renders on
    the server; the key is never displayed).  Every upload is confirmed by
    reading the object back and comparing SHA-256 digests.

``DropboxStorage`` (optional alternative) — official Dropbox SDK; each upload
    is confirmed with Dropbox's ``content_hash``.

``LocalFolderStorage`` — a local directory, for offline use and tests.  It is
    **not** a cloud backend.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Union

DROPBOX_BLOCK = 4 * 1024 * 1024        # content_hash block size (Dropbox spec)
SIMPLE_UPLOAD_LIMIT = 150 * 1024 * 1024  # files_upload limit; larger -> upload session
SESSION_CHUNK = 8 * 1024 * 1024
SUPABASE_DEFAULT_BUCKET = "ringcrypter"
SUPABASE_LIST_PAGE = 1000
SUPABASE_REMOVE_BATCH = 100
SUPABASE_RETRIES = 4            # attempts for transient network errors / HTTP 5xx (idempotent ops)
SUPABASE_RETRY_BACKOFF = 0.5    # seconds, doubled per attempt


class StorageError(Exception):
    """Base class for storage failures."""


class UploadError(StorageError):
    """Raised when an upload cannot be confirmed by the storage provider."""


class ObjectNotFound(StorageError):
    """Raised when a requested object does not exist."""


class Storage(Protocol):
    name: str

    def upload(self, key: str, data: bytes) -> None: ...
    def download(self, key: str) -> bytes: ...
    def list(self, prefix: str = "") -> List[str]: ...
    def delete(self, keys: List[str]) -> None: ...


def _safe_key(key: str) -> str:
    if not key or key.startswith("/") or "\\" in key:
        raise StorageError(f"Invalid storage key: {key!r}")
    if any(part in ("", ".", "..") for part in key.split("/")):
        raise StorageError(f"Invalid storage key: {key!r}")
    return key


def _norm_prefix(prefix: str) -> str:
    prefix = prefix.strip("/")
    if prefix:
        _safe_key(prefix)
    return prefix


def dropbox_content_hash(data: bytes) -> str:
    """Dropbox content hash: SHA-256 over the concatenated SHA-256 of each 4 MiB block."""
    blocks = b"".join(hashlib.sha256(data[i:i + DROPBOX_BLOCK]).digest()
                      for i in range(0, len(data), DROPBOX_BLOCK))
    return hashlib.sha256(blocks).hexdigest()


# ---------------------------------------------------------------------------
# Local folder (offline, NOT a cloud)
# ---------------------------------------------------------------------------

class LocalFolderStorage:
    """Stores objects in a local directory (offline stand-in, NOT a cloud backend)."""

    name = "local-folder"

    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def upload(self, key: str, data: bytes) -> None:
        path = self.root / _safe_key(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if path.read_bytes() != data:
            raise UploadError(f"Read-back mismatch for {path}")

    def download(self, key: str) -> bytes:
        path = self.root / _safe_key(key)
        if not path.is_file():
            raise ObjectNotFound(f"{key} not found in {self.root}")
        return path.read_bytes()

    def list(self, prefix: str = "") -> List[str]:
        prefix = _norm_prefix(prefix)
        base = self.root / prefix if prefix else self.root
        if not base.is_dir():
            return []
        return sorted(p.relative_to(self.root).as_posix() for p in base.rglob("*") if p.is_file())

    def delete(self, keys: List[str]) -> None:
        for key in keys:
            path = self.root / _safe_key(key)
            if path.is_file():
                path.unlink()
            # prune now-empty folders (cloud stores have no empty folders either)
            parent = path.parent
            while parent != self.root and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent


# ---------------------------------------------------------------------------
# Supabase Storage (default cloud backend)
# ---------------------------------------------------------------------------

SUPABASE_KEY_VARS = ("SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY")


def supabase_key_from_env() -> Optional[str]:
    """First set of: SUPABASE_SECRET_KEY (new secret key), SUPABASE_SERVICE_ROLE_KEY (legacy), SUPABASE_KEY."""
    return next((os.environ[v] for v in SUPABASE_KEY_VARS if os.environ.get(v)), None)


def check_supabase_url(url: str) -> None:
    """Reject dashboard links; the SDK needs the project API URL https://<ref>.supabase.co."""
    import re
    m = re.match(r"https?://(?:app\.)?supabase\.com/dashboard/project/([a-z0-9]+)", url.strip())
    if m:
        raise StorageError(f"SUPABASE_URL is a dashboard link. Use the project API URL instead: "
                           f"SUPABASE_URL=https://{m.group(1)}.supabase.co")


def _is_not_found(exc: Exception) -> bool:
    status = str(getattr(exc, "status", ""))
    text = f"{getattr(exc, 'code', '')} {getattr(exc, 'message', '')} {exc}".lower()
    return status in ("400", "404") and ("not found" in text or "not_found" in text
                                         or "notfound" in text) or status == "404"


class SupabaseStorage:
    """Supabase Storage backend built on the official ``supabase`` Python SDK."""

    name = "supabase"

    def __init__(self, bucket: Optional[str] = None, client=None, verify_uploads: bool = True) -> None:
        self.bucket = bucket or os.environ.get("SUPABASE_BUCKET", SUPABASE_DEFAULT_BUCKET)
        # With env credentials every worker thread gets its OWN SDK client: sharing one HTTP
        # connection pool across threads produced persistent "WinError 10035" socket errors on
        # Windows during parallel block transfers (observed against real Supabase).
        self._factory = None if client is not None else self._client_factory_from_env()
        self.client = client if client is not None else self._factory()
        self._local = threading.local()
        self.verify_uploads = verify_uploads
        self.http: Counter = Counter()      # real HTTP requests / bytes (incl. upload read-backs)
        self._http_lock = threading.Lock()

    def _count(self, **kw) -> None:
        with self._http_lock:
            self.http.update(kw)

    @staticmethod
    def _transient(exc: Exception) -> bool:
        try:
            import httpx
            if isinstance(exc, httpx.TransportError):     # connection reset, socket errors, timeouts
                return True
        except ImportError:  # pragma: no cover
            pass
        return str(getattr(exc, "status", "")).startswith("5")

    def _call(self, fn, *args):
        """Run an idempotent SDK call, retrying transient failures with exponential backoff."""
        for attempt in range(SUPABASE_RETRIES):
            try:
                return fn(*args)
            except Exception as exc:
                if attempt == SUPABASE_RETRIES - 1 or not self._transient(exc):
                    raise
                self._count(retries=1)
                time.sleep(SUPABASE_RETRY_BACKOFF * 2 ** attempt)

    @staticmethod
    def _client_factory_from_env():
        url = os.environ.get("SUPABASE_URL")
        key = supabase_key_from_env()
        if not url or not key:
            raise StorageError(
                "Supabase credentials missing: set SUPABASE_URL and SUPABASE_SECRET_KEY "
                "(or SUPABASE_SERVICE_ROLE_KEY / SUPABASE_KEY) as environment variables or in a "
                "git-ignored .env file. See README.md.")
        check_supabase_url(url)
        from supabase import create_client  # imported lazily so offline use does not need it
        return lambda: create_client(url, key)

    def _thread_client(self):
        if self._factory is None or threading.current_thread() is threading.main_thread():
            return self.client
        c = getattr(self._local, "client", None)
        if c is None:
            c = self._local.client = self._factory()
        return c

    @property
    def _files(self):
        return self._thread_client().storage.from_(self.bucket)

    def ensure_bucket(self, create: bool = True) -> str:
        """Check that the bucket exists and is PRIVATE; optionally create it.  Returns a status string."""
        try:
            info = self.client.storage.get_bucket(self.bucket)
        except Exception as exc:
            if not create:
                raise StorageError(f"Supabase bucket {self.bucket!r} not accessible: {exc}") from exc
            try:
                self.client.storage.create_bucket(self.bucket, options={"public": False})
            except Exception as exc2:
                raise StorageError(f"Cannot create Supabase bucket {self.bucket!r}: {exc2}") from exc2
            return f"created private bucket {self.bucket!r}"
        if getattr(info, "public", False):
            raise StorageError(f"Supabase bucket {self.bucket!r} is PUBLIC; make it private "
                               "(Dashboard → Storage → bucket → Edit → Public off).")
        return f"bucket {self.bucket!r} exists and is private"

    def upload(self, key: str, data: bytes) -> None:
        key = _safe_key(key)
        try:
            self._call(self._files.upload, key, data, {"content-type": "application/octet-stream",
                                                       "upsert": "true", "cache-control": "no-cache"})
            self._count(put_requests=1, put_bytes=len(data))
        except Exception as exc:  # storage3.exceptions.StorageApiError, httpx errors
            raise UploadError(f"Supabase upload of {key} failed: {exc}") from exc
        if self.verify_uploads:
            try:
                stored = self._call(self._files.download, key)
                self._count(get_requests=1, get_bytes=len(stored), readback_requests=1)
            except Exception as exc:
                raise UploadError(f"Supabase upload of {key} could not be read back: {exc}") from exc
            if hashlib.sha256(stored).digest() != hashlib.sha256(data).digest():
                raise UploadError(f"Supabase did not confirm {key}: stored bytes differ "
                                  f"({len(stored)} vs {len(data)} bytes)")

    def download(self, key: str) -> bytes:
        key = _safe_key(key)
        try:
            data = self._call(self._files.download, key)
            self._count(get_requests=1, get_bytes=len(data))
            return data
        except Exception as exc:
            if _is_not_found(exc):
                raise ObjectNotFound(f"{key} not found in Supabase bucket {self.bucket!r}") from exc
            raise StorageError(f"Supabase download of {key} failed: {exc}") from exc

    def _list_dir(self, prefix: str) -> List[dict]:
        entries: List[dict] = []
        offset = 0
        while True:
            page = self._call(self._files.list, prefix, {"limit": SUPABASE_LIST_PAGE, "offset": offset,
                                                         "sortBy": {"column": "name", "order": "asc"}})
            self._count(list_requests=1)
            entries.extend(page)
            if len(page) < SUPABASE_LIST_PAGE:
                return entries
            offset += SUPABASE_LIST_PAGE

    def list(self, prefix: str = "") -> List[str]:
        """All object keys under *prefix* (Supabase lists one folder level at a time)."""
        prefix = _norm_prefix(prefix)
        out: List[str] = []
        pending = [prefix]
        try:
            while pending:
                folder = pending.pop()
                for e in self._list_dir(folder):
                    name = e.get("name")
                    if not name or name == ".emptyFolderPlaceholder":
                        continue
                    full = f"{folder}/{name}" if folder else name
                    if e.get("id") is None:      # folders have no object id
                        pending.append(full)
                    else:
                        out.append(full)
        except Exception as exc:
            raise StorageError(f"Supabase listing of {prefix or '/'} failed: {exc}") from exc
        return sorted(out)

    def delete(self, keys: List[str]) -> None:
        keys = [_safe_key(k) for k in keys]
        try:
            for i in range(0, len(keys), SUPABASE_REMOVE_BATCH):
                self._call(self._files.remove, keys[i:i + SUPABASE_REMOVE_BATCH])
                self._count(delete_requests=1)
        except Exception as exc:
            raise StorageError(f"Supabase delete failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Dropbox (optional alternative)
# ---------------------------------------------------------------------------

class DropboxStorage:
    """Dropbox backend built on the official SDK (optional alternative to Supabase)."""

    name = "dropbox"

    def __init__(self, folder: str = "/RingCrypter", client=None) -> None:
        if not folder.startswith("/"):
            folder = "/" + folder
        self.folder = folder.rstrip("/")
        self.client = client if client is not None else self._client_from_env()

    @staticmethod
    def _client_from_env():
        refresh = os.environ.get("DROPBOX_REFRESH_TOKEN")
        app_key = os.environ.get("DROPBOX_APP_KEY")
        access = os.environ.get("DROPBOX_ACCESS_TOKEN")
        if not ((refresh and app_key) or access):
            raise StorageError(
                "Dropbox credentials missing: set DROPBOX_REFRESH_TOKEN and DROPBOX_APP_KEY "
                "(and DROPBOX_APP_SECRET), or DROPBOX_ACCESS_TOKEN. See README.md.")
        import dropbox  # imported lazily so offline use does not need it
        if refresh and app_key:
            return dropbox.Dropbox(oauth2_refresh_token=refresh, app_key=app_key,
                                   app_secret=os.environ.get("DROPBOX_APP_SECRET"))
        return dropbox.Dropbox(oauth2_access_token=access)

    def _path(self, key: str) -> str:
        return f"{self.folder}/{_safe_key(key)}"

    def check_account(self) -> str:
        """Return the account display name (raises if the credentials are invalid)."""
        return self.client.users_get_current_account().name.display_name

    def upload(self, key: str, data: bytes) -> None:
        from dropbox.files import CommitInfo, UploadSessionCursor, WriteMode

        path = self._path(key)
        try:
            if len(data) <= SIMPLE_UPLOAD_LIMIT:
                md = self.client.files_upload(data, path, mode=WriteMode.overwrite)
            else:
                start = self.client.files_upload_session_start(data[:SESSION_CHUNK])
                cursor = UploadSessionCursor(session_id=start.session_id, offset=SESSION_CHUNK)
                while len(data) - cursor.offset > SESSION_CHUNK:
                    self.client.files_upload_session_append_v2(
                        data[cursor.offset:cursor.offset + SESSION_CHUNK], cursor)
                    cursor.offset += SESSION_CHUNK
                md = self.client.files_upload_session_finish(
                    data[cursor.offset:], cursor, CommitInfo(path=path, mode=WriteMode.overwrite))
        except Exception as exc:  # dropbox.exceptions.ApiError / HttpError / AuthError
            raise UploadError(f"Dropbox upload of {path} failed: {exc}") from exc
        expected = dropbox_content_hash(data)
        if md.size != len(data) or md.content_hash != expected:
            raise UploadError(f"Dropbox did not confirm {path}: size {md.size} vs {len(data)}, "
                              f"content_hash {md.content_hash} vs {expected}")

    def download(self, key: str) -> bytes:
        path = self._path(key)
        try:
            _md, resp = self.client.files_download(path)
            return resp.content
        except Exception as exc:
            if "not_found" in str(exc).lower() or "not found" in str(exc).lower():
                raise ObjectNotFound(f"{path} not found in Dropbox") from exc
            raise StorageError(f"Dropbox download of {path} failed: {exc}") from exc

    def list(self, prefix: str = "") -> List[str]:
        prefix = _norm_prefix(prefix)
        root = f"{self.folder}/{prefix}" if prefix else self.folder
        try:
            res = self.client.files_list_folder(root, recursive=True)
            entries = list(res.entries)
            while res.has_more:
                res = self.client.files_list_folder_continue(res.cursor)
                entries += res.entries
        except Exception as exc:
            err = getattr(exc, "error", None)
            if (err is not None and getattr(err, "is_path", lambda: False)()
                    and err.get_path().is_not_found()):
                return []  # folder is created by the first upload
            raise StorageError(f"Dropbox listing of {root} failed: {exc}") from exc
        start = len(self.folder) + 1
        # FileMetadata has a size; FolderMetadata / DeletedMetadata do not.
        return sorted(e.path_display[start:] for e in entries if hasattr(e, "size"))

    def delete(self, keys: List[str]) -> None:
        for key in keys:
            try:
                self.client.files_delete_v2(self._path(key))
            except Exception as exc:
                if "not_found" not in str(exc).lower():
                    raise StorageError(f"Dropbox delete of {key} failed: {exc}") from exc


class CountingStorage:
    """Wraps any backend and counts logical cloud operations and bytes transferred (thread-safe).

    For Supabase, :attr:`SupabaseStorage.http` additionally counts the real HTTP requests,
    including the read-back GET used to confirm every upload.
    """

    def __init__(self, inner: Storage) -> None:
        self.inner, self.name = inner, inner.name
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        """Zero the logical counters and the backend's real-HTTP counters (if it has them)."""
        with self._lock:
            self.ops: Counter = Counter()
            self.bytes_up = self.bytes_down = 0
        http = getattr(self.inner, "http", None)
        if http is not None:
            http.clear()

    def upload(self, key: str, data: bytes) -> None:
        self.inner.upload(key, data)
        with self._lock:
            self.ops["upload"] += 1
            self.bytes_up += len(data)

    def download(self, key: str) -> bytes:
        data = self.inner.download(key)
        with self._lock:
            self.ops["download"] += 1
            self.bytes_down += len(data)
        return data

    def list(self, prefix: str = "") -> List[str]:
        with self._lock:
            self.ops["list"] += 1
        return self.inner.list(prefix)

    def delete(self, keys: List[str]) -> None:
        self.inner.delete(keys)
        with self._lock:
            self.ops["delete_calls"] += 1
            self.ops["objects_deleted"] += len(keys)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            snap = {f"ops_{k}": v for k, v in self.ops.items()}
            snap.update(bytes_uploaded=self.bytes_up, bytes_downloaded=self.bytes_down)
        http = getattr(self.inner, "http", None)
        if http is not None:
            snap.update({f"http_{k}": v for k, v in http.items()})
        return snap


def open_storage(backend: str, location: Optional[str] = None) -> Storage:
    """backend: 'supabase' (location = bucket), 'dropbox' (folder) or 'local' (directory)."""
    if backend == "supabase":
        return SupabaseStorage(location or None)
    if backend == "dropbox":
        return DropboxStorage(location or os.environ.get("DROPBOX_FOLDER", "/RingCrypter"))
    if backend == "local":
        return LocalFolderStorage(location or "cloud_local")
    raise StorageError(f"Unknown storage backend {backend!r} (use 'supabase', 'dropbox' or 'local')")


BACKENDS = ("supabase", "dropbox", "local")
