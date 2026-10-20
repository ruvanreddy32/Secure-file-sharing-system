"""
securecloud/storage.py — Cloud storage backends (paper §IV, Fig. 2, Fig. 3).

``DropboxStorage`` uses the official Dropbox Python SDK (``dropbox`` >= 12).
Credentials come only from environment variables:

    DROPBOX_REFRESH_TOKEN + DROPBOX_APP_KEY (+ DROPBOX_APP_SECRET)   recommended
    DROPBOX_ACCESS_TOKEN                                              short-lived token

Every upload is checked: the metadata Dropbox returns must report the same
size and the same Dropbox ``content_hash`` as computed locally from the
bytes we sent; otherwise :class:`UploadError` is raised.

``LocalFolderStorage`` stores the same three files in a local directory.  It
exists for offline use and automated tests and is **not** a cloud backend.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import List, Optional, Protocol, Union

DROPBOX_BLOCK = 4 * 1024 * 1024        # content_hash block size (Dropbox spec)
SIMPLE_UPLOAD_LIMIT = 150 * 1024 * 1024  # files_upload limit; larger -> upload session
SESSION_CHUNK = 8 * 1024 * 1024


class StorageError(Exception):
    """Base class for storage failures."""


class UploadError(StorageError):
    """Raised when an upload cannot be confirmed by the storage provider."""


class Storage(Protocol):
    name: str

    def upload(self, remote_name: str, data: bytes) -> None: ...
    def download(self, remote_name: str) -> bytes: ...
    def list(self) -> List[str]: ...


def dropbox_content_hash(data: bytes) -> str:
    """Dropbox content hash: SHA-256 over the concatenated SHA-256 of each 4 MiB block."""
    blocks = b"".join(hashlib.sha256(data[i:i + DROPBOX_BLOCK]).digest()
                      for i in range(0, len(data), DROPBOX_BLOCK))
    return hashlib.sha256(blocks).hexdigest()


def _safe_name(remote_name: str) -> str:
    if not remote_name or "/" in remote_name or "\\" in remote_name or remote_name in (".", ".."):
        raise StorageError(f"Invalid remote file name: {remote_name!r}")
    return remote_name


class LocalFolderStorage:
    """Stores files in a local directory (offline stand-in, NOT Dropbox)."""

    name = "local-folder"

    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def upload(self, remote_name: str, data: bytes) -> None:
        path = self.root / _safe_name(remote_name)
        path.write_bytes(data)
        if path.read_bytes() != data:
            raise UploadError(f"Read-back mismatch for {path}")

    def download(self, remote_name: str) -> bytes:
        path = self.root / _safe_name(remote_name)
        if not path.exists():
            raise StorageError(f"{remote_name} not found in {self.root}")
        return path.read_bytes()

    def list(self) -> List[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_file())


class DropboxStorage:
    """Dropbox backend built on the official SDK."""

    name = "dropbox"

    def __init__(self, folder: str = "/RingCrypter", client=None) -> None:
        if not folder.startswith("/"):
            folder = "/" + folder
        self.folder = folder.rstrip("/")
        self.client = client if client is not None else self._client_from_env()

    @staticmethod
    def _client_from_env():
        import dropbox  # imported lazily so offline use does not need it

        refresh = os.environ.get("DROPBOX_REFRESH_TOKEN")
        app_key = os.environ.get("DROPBOX_APP_KEY")
        access = os.environ.get("DROPBOX_ACCESS_TOKEN")
        if refresh and app_key:
            return dropbox.Dropbox(oauth2_refresh_token=refresh, app_key=app_key,
                                   app_secret=os.environ.get("DROPBOX_APP_SECRET"))
        if access:
            return dropbox.Dropbox(oauth2_access_token=access)
        raise StorageError(
            "Dropbox credentials missing: set DROPBOX_REFRESH_TOKEN and DROPBOX_APP_KEY "
            "(and DROPBOX_APP_SECRET), or DROPBOX_ACCESS_TOKEN. See README.md.")

    def _path(self, remote_name: str) -> str:
        return f"{self.folder}/{_safe_name(remote_name)}"

    def check_account(self) -> str:
        """Return the account display name (raises if the credentials are invalid)."""
        return self.client.users_get_current_account().name.display_name

    def upload(self, remote_name: str, data: bytes) -> None:
        from dropbox.files import CommitInfo, UploadSessionCursor, WriteMode

        path = self._path(remote_name)
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

    def download(self, remote_name: str) -> bytes:
        path = self._path(remote_name)
        try:
            _md, resp = self.client.files_download(path)
            return resp.content
        except Exception as exc:
            raise StorageError(f"Dropbox download of {path} failed: {exc}") from exc

    def list(self) -> List[str]:
        try:
            res = self.client.files_list_folder(self.folder)
            names = [e.name for e in res.entries]
            while res.has_more:
                res = self.client.files_list_folder_continue(res.cursor)
                names += [e.name for e in res.entries]
        except Exception as exc:
            err = getattr(exc, "error", None)
            if (err is not None and getattr(err, "is_path", lambda: False)()
                    and err.get_path().is_not_found()):
                return []  # folder is created by the first upload
            raise StorageError(f"Dropbox listing of {self.folder} failed: {exc}") from exc
        return sorted(names)


def open_storage(backend: str, location: Optional[str] = None) -> Storage:
    if backend == "dropbox":
        return DropboxStorage(location or os.environ.get("DROPBOX_FOLDER", "/RingCrypter"))
    if backend == "local":
        return LocalFolderStorage(location or "cloud_local")
    raise StorageError(f"Unknown storage backend {backend!r} (use 'dropbox' or 'local')")
