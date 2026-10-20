"""SupabaseStorage backend against a MOCKED Supabase client (tests/fakes.py).

These tests exercise our code path only.  Real-service tests: tests/test_supabase_live.py.
"""

import hashlib
import os

import pytest

from fakes import FakeSupabaseClient
from securecloud import storage
from securecloud.storage import ObjectNotFound, StorageError, SupabaseStorage, UploadError


def _store(**kw):
    client = FakeSupabaseClient(**kw)
    return SupabaseStorage("ringcrypter", client=client), client


class TestBasicOperations:
    def test_upload_download(self):
        s, c = _store()
        s.upload("a.txt/v000001/a.txt.aes", b"cipher")
        assert s.download("a.txt/v000001/a.txt.aes") == b"cipher"
        assert c.objects()["a.txt/v000001/a.txt.aes"] == b"cipher"

    def test_upload_is_read_back_and_compared(self):
        s, c = _store()
        s.upload("k", b"data")
        assert c.calls == [("upload", "k"), ("download", "k")]

    def test_corrupted_upload_is_rejected(self):
        s, _ = _store(corrupt_upload=lambda p: True)
        with pytest.raises(UploadError, match="did not confirm"):
            s.upload("k", b"data")

    def test_read_back_can_be_disabled(self):
        client = FakeSupabaseClient()
        s = SupabaseStorage("ringcrypter", client=client, verify_uploads=False)
        s.upload("k", b"data")
        assert client.calls == [("upload", "k")]

    def test_overwrite_uses_upsert(self):
        s, _ = _store()
        s.upload("k", b"one")
        s.upload("k", b"two")                     # would raise 409 without upsert
        assert s.download("k") == b"two"

    def test_upload_error_wrapped(self):
        s, _ = _store(fail_upload=lambda p: True)
        with pytest.raises(UploadError, match="Supabase upload of k failed"):
            s.upload("k", b"x")

    def test_missing_object(self):
        s, _ = _store()
        with pytest.raises(ObjectNotFound):
            s.download("nope")

    def test_missing_bucket_is_storage_error(self):
        s = SupabaseStorage("other", client=FakeSupabaseClient())
        with pytest.raises(StorageError):
            s.download("x")

    @pytest.mark.parametrize("bad", ["", "../x", "a/../b", "/abs", "a//b"])
    def test_rejects_bad_keys(self, bad):
        s, _ = _store()
        with pytest.raises(StorageError):
            s.upload(bad, b"x")


class TestListing:
    def test_recursive_listing_of_folders(self):
        s, _ = _store()
        for k in ("f.pdf/manifest.signed", "f.pdf/v000001/f.pdf.aes", "f.pdf/v000002/f.pdf.aes", "g/x"):
            s.upload(k, b"1")
        assert s.list() == ["f.pdf/manifest.signed", "f.pdf/v000001/f.pdf.aes",
                            "f.pdf/v000002/f.pdf.aes", "g/x"]
        assert s.list("f.pdf/v000002") == ["f.pdf/v000002/f.pdf.aes"]
        assert s.list("missing") == []

    def test_pagination(self, monkeypatch):
        monkeypatch.setattr(storage, "SUPABASE_LIST_PAGE", 2)
        s, c = _store()
        keys = [f"d/obj{i}" for i in range(5)]
        for k in keys:
            s.upload(k, b"1")
        c.list_calls = 0
        assert s.list("d") == keys
        assert c.list_calls == 3                  # 2 + 2 + 1

    def test_delete_in_batches(self, monkeypatch):
        monkeypatch.setattr(storage, "SUPABASE_REMOVE_BATCH", 2)
        s, c = _store()
        for i in range(5):
            s.upload(f"d/{i}", b"1")
        s.delete([f"d/{i}" for i in range(5)])
        assert s.list() == []
        assert sum(1 for call in c.calls if call[0] == "remove") == 3


class TestBucketAndCredentials:
    def test_ensure_bucket_creates_private_bucket(self):
        client = FakeSupabaseClient(buckets=())
        s = SupabaseStorage("ringcrypter", client=client)
        assert "created private" in s.ensure_bucket()
        assert client.buckets["ringcrypter"]["public"] is False

    def test_ensure_bucket_accepts_existing_private(self):
        s, _ = _store()
        assert "private" in s.ensure_bucket()

    def test_public_bucket_is_refused(self):
        s, _ = _store(public=True)
        with pytest.raises(StorageError, match="PUBLIC"):
            s.ensure_bucket()

    def test_missing_bucket_without_create(self):
        s = SupabaseStorage("nope", client=FakeSupabaseClient())
        with pytest.raises(StorageError):
            s.ensure_bucket(create=False)

    def test_missing_credentials(self, monkeypatch):
        for v in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY", "SUPABASE_SECRET_KEY"):
            monkeypatch.delenv(v, raising=False)
        with pytest.raises(StorageError, match="credentials missing"):
            SupabaseStorage()

    def test_client_built_from_env_with_service_role_preferred(self, monkeypatch):
        import supabase
        seen = {}
        monkeypatch.setattr(supabase, "create_client",
                            lambda url, key: seen.update(url=url, key=key) or FakeSupabaseClient())
        monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-role")
        monkeypatch.setenv("SUPABASE_KEY", "anon")
        monkeypatch.setenv("SUPABASE_BUCKET", "ringcrypter")
        s = SupabaseStorage()
        assert seen == {"url": "https://example.supabase.co", "key": "service-role"}
        assert s.bucket == "ringcrypter"

    def test_open_storage_default_backend(self, monkeypatch):
        import supabase
        monkeypatch.setattr(supabase, "create_client", lambda url, key: FakeSupabaseClient(("b",)))
        monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
        monkeypatch.setenv("SUPABASE_KEY", "k")
        s = storage.open_storage("supabase", "b")
        assert isinstance(s, SupabaseStorage) and s.bucket == "b"


def test_large_object_roundtrip():
    s, _ = _store()
    data = os.urandom(3 * 1024 * 1024)
    s.upload("big/v000001/big.aes", data)
    assert hashlib.sha256(s.download("big/v000001/big.aes")).digest() == hashlib.sha256(data).digest()


class TestEnvHandling:
    def test_secret_key_variable_preferred(self, monkeypatch):
        import supabase
        seen = {}
        monkeypatch.setattr(supabase, "create_client",
                            lambda url, key: seen.update(key=key) or FakeSupabaseClient())
        monkeypatch.setenv("SUPABASE_URL", "https://abc.supabase.co")
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_secret_x")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "legacy")
        SupabaseStorage("ringcrypter")
        assert seen["key"] == "sb_secret_x"

    def test_dashboard_url_rejected_with_fix(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://supabase.com/dashboard/project/mzrfabc123")
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_secret_x")
        with pytest.raises(StorageError, match=r"https://mzrfabc123\.supabase\.co"):
            SupabaseStorage("ringcrypter")

    def test_env_file_loading(self, tmp_path, monkeypatch):
        from securecloud import envfile
        monkeypatch.delenv("RINGCRYPTER_NO_DOTENV")          # opt out of the hermetic default
        monkeypatch.delenv("RC_TEST_A", raising=False)
        monkeypatch.delenv("RC_TEST_B", raising=False)
        monkeypatch.setenv("RC_TEST_C", "from-shell")
        f = tmp_path / ".env"
        f.write_text('# comment\nRC_TEST_A=one\nexport RC_TEST_B="two words"\nRC_TEST_C=from-file\n')
        added = envfile.load(f)
        assert os.environ["RC_TEST_A"] == "one" and os.environ["RC_TEST_B"] == "two words"
        assert os.environ["RC_TEST_C"] == "from-shell"          # real environment wins
        assert set(added) == {"RC_TEST_A", "RC_TEST_B"}
        monkeypatch.delenv("RC_TEST_A")
        monkeypatch.delenv("RC_TEST_B")


class TestRetries:
    def test_transient_network_error_is_retried(self, monkeypatch):
        import httpx
        monkeypatch.setattr(storage, "SUPABASE_RETRY_BACKOFF", 0)
        failures = {"n": 0}

        def flaky(path):
            if failures["n"] < 2:
                failures["n"] += 1
                raise httpx.ReadError("WinError 10035")
            return False
        s, c = _store(fail_upload=flaky)
        s.upload("k", b"data")
        assert s.download("k") == b"data" and s.http["retries"] == 2

    def test_permanent_error_not_retried(self, monkeypatch):
        monkeypatch.setattr(storage, "SUPABASE_RETRY_BACKOFF", 0)
        s, _ = _store()
        with pytest.raises(ObjectNotFound):
            s.download("missing")
        assert s.http["retries"] == 0

    def test_gives_up_after_limit(self, monkeypatch):
        import httpx
        monkeypatch.setattr(storage, "SUPABASE_RETRY_BACKOFF", 0)

        def always(path):
            raise httpx.ReadError("down")
        s, _ = _store(fail_upload=always)
        with pytest.raises(UploadError):
            s.upload("k", b"x")
        assert s.http["retries"] == storage.SUPABASE_RETRIES - 1
