"""Storage backends.  The Dropbox tests here use a FAKE in-memory client that mimics the
SDK's method signatures; they test our code path, NOT the real Dropbox service
(see test_dropbox_live.py for that)."""

import hashlib
import os
from types import SimpleNamespace

import pytest

from securecloud import storage, workflow
from securecloud.storage import (DropboxStorage, LocalFolderStorage, StorageError, UploadError,
                                 dropbox_content_hash)


class FakeDropboxClient:
    """In-memory stand-in exposing the subset of dropbox.Dropbox used by DropboxStorage."""

    def __init__(self, corrupt_hash=False):
        self.files = {}
        self.sessions = {}
        self.corrupt_hash = corrupt_hash

    def _md(self, path, data):
        h = dropbox_content_hash(data)
        return SimpleNamespace(name=path.rsplit("/", 1)[1], size=len(data),
                               content_hash=("0" * 64 if self.corrupt_hash else h))

    def files_upload(self, data, path, mode=None):
        self.files[path] = bytes(data)
        return self._md(path, data)

    def files_upload_session_start(self, chunk):
        sid = f"s{len(self.sessions)}"
        self.sessions[sid] = bytearray(chunk)
        return SimpleNamespace(session_id=sid)

    def files_upload_session_append_v2(self, chunk, cursor):
        assert len(self.sessions[cursor.session_id]) == cursor.offset
        self.sessions[cursor.session_id] += chunk

    def files_upload_session_finish(self, chunk, cursor, commit):
        data = bytes(self.sessions.pop(cursor.session_id) + chunk)
        self.files[commit.path] = data
        return self._md(commit.path, data)

    def files_download(self, path):
        if path not in self.files:
            raise RuntimeError("path/not_found")
        return self._md(path, self.files[path]), SimpleNamespace(content=self.files[path])

    def files_list_folder(self, folder):
        names = [p.rsplit("/", 1)[1] for p in self.files if p.rsplit("/", 1)[0] == folder]
        return SimpleNamespace(entries=[SimpleNamespace(name=n) for n in names],
                               has_more=False, cursor=None)


class TestContentHash:
    def test_small(self):
        data = b"hello"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()
        assert dropbox_content_hash(data) == expected

    def test_multi_block(self):
        data = os.urandom(storage.DROPBOX_BLOCK + 10)
        parts = hashlib.sha256(data[:storage.DROPBOX_BLOCK]).digest() + \
            hashlib.sha256(data[storage.DROPBOX_BLOCK:]).digest()
        assert dropbox_content_hash(data) == hashlib.sha256(parts).hexdigest()


class TestLocalFolder:
    def test_roundtrip(self, tmp_path):
        s = LocalFolderStorage(tmp_path)
        s.upload("a.aes", b"123")
        assert s.download("a.aes") == b"123" and s.list() == ["a.aes"]

    @pytest.mark.parametrize("bad", ["", "../x", "a/b", "a\\b", ".."])
    def test_rejects_path_traversal(self, tmp_path, bad):
        with pytest.raises(StorageError):
            LocalFolderStorage(tmp_path).upload(bad, b"x")

    def test_missing(self, tmp_path):
        with pytest.raises(StorageError):
            LocalFolderStorage(tmp_path).download("nope")


class TestDropboxCodePath:
    def test_upload_download_list(self):
        s = DropboxStorage("/RingCrypter", client=FakeDropboxClient())
        s.upload("x.aes", b"payload")
        assert s.download("x.aes") == b"payload"
        assert s.list() == ["x.aes"]

    def test_upload_confirmation_failure_raises(self):
        s = DropboxStorage("/RingCrypter", client=FakeDropboxClient(corrupt_hash=True))
        with pytest.raises(UploadError):
            s.upload("x.aes", b"payload")

    def test_large_upload_uses_session(self, monkeypatch):
        monkeypatch.setattr(storage, "SIMPLE_UPLOAD_LIMIT", 100)
        monkeypatch.setattr(storage, "SESSION_CHUNK", 64)
        client = FakeDropboxClient()
        s = DropboxStorage("/RC", client=client)
        data = os.urandom(1000)
        s.upload("big.aes", data)
        assert client.files["/RC/big.aes"] == data

    def test_list_missing_folder_is_empty(self):
        from dropbox.exceptions import ApiError
        from dropbox.files import ListFolderError, LookupError as DbxLookupError

        class Client(FakeDropboxClient):
            def files_list_folder(self, folder):
                raise ApiError("req", ListFolderError.path(DbxLookupError.not_found), "msg", "en")

        assert DropboxStorage("/new", client=Client()).list() == []

    def test_download_error_wrapped(self):
        with pytest.raises(StorageError):
            DropboxStorage(client=FakeDropboxClient()).download("missing.aes")

    def test_missing_credentials(self, monkeypatch):
        for var in ("DROPBOX_ACCESS_TOKEN", "DROPBOX_REFRESH_TOKEN", "DROPBOX_APP_KEY"):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(StorageError, match="credentials missing"):
            DropboxStorage()

    def test_full_workflow_through_dropbox_code_path(self, protect, owner_rsa, recipient_rlwe):
        s = DropboxStorage("/RingCrypter", client=FakeDropboxClient())
        data = os.urandom(10_000)
        workflow.upload_bundle(s, protect(data, "d.bin"))
        assert workflow.list_bundles(s) == ["d.bin"]
        dl, _ = workflow.download_bundle(s, "d.bin")
        out, report = workflow.open_bundle(dl, owner_rsa.public_key(), recipient_rlwe)
        assert report.ok and out == data
        # server-side tampering
        s.client.files["/RingCrypter/d.bin.aes"] = dl.encrypted_file[:-1] + b"\x00"
        dl2, _ = workflow.download_bundle(s, "d.bin")
        with pytest.raises(workflow.IntegrityError):
            workflow.open_bundle(dl2, owner_rsa.public_key(), recipient_rlwe)
