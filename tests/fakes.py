"""In-memory stand-in for the Supabase Python SDK client (``supabase.create_client(...)``).

Mimics the parts of ``client.storage`` that SupabaseStorage uses, with the semantics of the
real storage3 2.x API: ``from_(bucket).upload/download/list/remove``, ``get_bucket``,
``create_bucket``; ``list`` returns ONE folder level (folders have ``id: None``) with
limit/offset paging; errors are the real ``storage3.exceptions.StorageApiError``.

This tests OUR code paths; it does not prove anything about the real Supabase service
(see tests/test_supabase_live.py for that).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional

try:
    from storage3.exceptions import StorageApiError
except ImportError:
    class StorageApiError(Exception):  # type: ignore[no-redef]
        """Fallback mock exception when storage3/supabase is not installed."""
        def __init__(self, message: str = "", error: Optional[str] = None, status: Optional[int] = 400) -> None:
            super().__init__(message)
            self.message = message
            self.error = error
            self.status = status


class FakeBucketApi:
    def __init__(self, client: "FakeSupabaseClient", bucket: str) -> None:
        self.c, self.bucket = client, bucket

    @property
    def objects(self) -> Dict[str, bytes]:
        if self.bucket not in self.c.buckets:
            raise StorageApiError("Bucket not found", "Bucket not found", 404)
        return self.c.buckets[self.bucket]["objects"]

    def upload(self, path: str, file: bytes, file_options: Optional[dict] = None):
        self.c.calls.append(("upload", path))
        if self.c.fail_upload and self.c.fail_upload(path):
            raise StorageApiError("simulated network failure", "InternalError", 500)
        objs = self.objects
        upsert = str((file_options or {}).get("upsert", "false")).lower() == "true"
        if path in objs and not upsert:
            raise StorageApiError("The resource already exists", "Duplicate", 409)
        data = bytes(file)
        if self.c.corrupt_upload and self.c.corrupt_upload(path):
            data = data[:-1] + bytes([data[-1] ^ 1]) if data else b"x"
        objs[path] = data
        return SimpleNamespace(path=path, full_path=f"{self.bucket}/{path}", Key=f"{self.bucket}/{path}")

    def download(self, path: str, options=None, query_params=None) -> bytes:
        self.c.calls.append(("download", path))
        objs = self.objects
        if path not in objs:
            raise StorageApiError("Object not found", "not_found", 400)
        return objs[path]

    def list(self, path: Optional[str] = None, options: Optional[dict] = None) -> List[dict]:
        prefix = (path or "").strip("/")
        base = prefix + "/" if prefix else ""
        names: Dict[str, Optional[bytes]] = {}
        for key, data in self.objects.items():
            if not key.startswith(base):
                continue
            rest = key[len(base):]
            if "/" in rest:
                names.setdefault(rest.split("/", 1)[0], None)        # folder
            else:
                names[rest] = data
        entries = [{"name": n, "id": None, "metadata": None} if d is None else
                   {"name": n, "id": str(uuid.uuid5(uuid.NAMESPACE_URL, base + n)),
                    "metadata": {"size": len(d), "mimetype": "application/octet-stream"}}
                   for n, d in sorted(names.items())]
        opts = options or {}
        off, lim = int(opts.get("offset", 0)), int(opts.get("limit", 100))
        self.c.list_calls += 1
        return entries[off:off + lim]

    def remove(self, paths: List[str]) -> List[dict]:
        self.c.calls.append(("remove", tuple(paths)))
        if len(paths) > 1000:
            raise StorageApiError("too many", "InvalidRequest", 400)
        objs = self.objects
        removed = [p for p in paths if objs.pop(p, None) is not None]
        return [{"name": p} for p in removed]


class FakeStorageClient:
    def __init__(self, client: "FakeSupabaseClient") -> None:
        self.c = client

    def from_(self, bucket: str) -> FakeBucketApi:
        return FakeBucketApi(self.c, bucket)

    def get_bucket(self, bucket_id: str):
        if bucket_id not in self.c.buckets:
            raise StorageApiError("Bucket not found", "Bucket not found", 404)
        return SimpleNamespace(id=bucket_id, name=bucket_id, public=self.c.buckets[bucket_id]["public"])

    def create_bucket(self, bucket_id: str, name=None, options=None):
        self.c.buckets[bucket_id] = {"public": bool((options or {}).get("public", False)), "objects": {}}
        return {"name": bucket_id}


class FakeSupabaseClient:
    def __init__(self, buckets=("ringcrypter",), public: bool = False,
                 fail_upload: Optional[Callable[[str], bool]] = None,
                 corrupt_upload: Optional[Callable[[str], bool]] = None) -> None:
        self.buckets = {b: {"public": public, "objects": {}} for b in buckets}
        self.fail_upload = fail_upload
        self.corrupt_upload = corrupt_upload
        self.calls: list = []
        self.list_calls = 0
        self.storage = FakeStorageClient(self)

    def objects(self, bucket: str = "ringcrypter") -> Dict[str, bytes]:
        return self.buckets[bucket]["objects"]
