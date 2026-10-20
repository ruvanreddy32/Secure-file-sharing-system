"""LIVE Supabase Storage end-to-end tests.  These talk to the REAL Supabase service.

Skipped unless credentials are set:
    SUPABASE_URL                     https://<project-ref>.supabase.co
    SUPABASE_SECRET_KEY              (or SUPABASE_SERVICE_ROLE_KEY / SUPABASE_KEY)
(environment variables or a git-ignored .env file in the working directory)
Optional:
    SUPABASE_TEST_BUCKET             private test bucket (default: $SUPABASE_BUCKET, else
                                     "ringcrypter-tests", created if missing)

Run:  python -m pytest -m supabase_live -v
Every object created here is deleted at the end of each test.
"""

import os
import uuid

import pytest

from securecloud import workflow
from securecloud.storage import SupabaseStorage
from securecloud.versioning import PublishError, VersionedRepository, manifest_key

from securecloud import envfile

# Credentials: real environment first, then the git-ignored .env (read WITHOUT polluting the
# environment of the other, hermetic tests).
_ENV = {k: v for k, v in envfile.read().items() if k.startswith("SUPABASE_")}
_ENV.update({k: v for k, v in os.environ.items() if k.startswith("SUPABASE_")})
HAVE_CREDS = bool(_ENV.get("SUPABASE_URL") and any(_ENV.get(k) for k in
                  ("SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY")))

pytestmark = [pytest.mark.supabase_live,
              pytest.mark.skipif(not HAVE_CREDS, reason="Supabase credentials not configured")]


@pytest.fixture(scope="module")
def live_store():
    with pytest.MonkeyPatch.context() as mp:
        for k, v in _ENV.items():
            mp.setenv(k, v)
        bucket = _ENV.get("SUPABASE_TEST_BUCKET") or _ENV.get("SUPABASE_BUCKET") or "ringcrypter-tests"
        s = SupabaseStorage(bucket)       # client is created now; env restored afterwards
    s.ensure_bucket(create=True)          # raises if the bucket is public
    return s


@pytest.fixture
def live_name(live_store):
    name = f"live-{uuid.uuid4().hex[:10]}.bin"
    yield name
    leftovers = live_store.list(name)
    if leftovers:
        live_store.delete(leftovers)


class _DropMhtUpload:
    def __init__(self, inner):
        self.inner, self.name = inner, inner.name

    def upload(self, key, data):
        if key.endswith(workflow.MHT_SUFFIX):
            raise OSError("simulated connection drop")
        self.inner.upload(key, data)

    def download(self, key):
        return self.inner.download(key)

    def list(self, prefix=""):
        return self.inner.list(prefix)

    def delete(self, keys):
        self.inner.delete(keys)


def test_live_raw_object_operations(live_store, live_name):
    key = f"{live_name}/raw/object.bin"
    data = os.urandom(70_000)
    live_store.upload(key, data)                       # includes read-back confirmation
    assert live_store.download(key) == data
    assert key in live_store.list(live_name)
    live_store.delete([key])
    assert key not in live_store.list(live_name)


def test_live_publish_verify_update_tamper(live_store, live_name, protect, owner_rsa, attacker_rsa,
                                           recipient_rlwe):
    repo = VersionedRepository(live_store)
    v1, v2 = os.urandom(50_000), os.urandom(60_000)

    # owner: version 1
    repo.publish(protect(v1, live_name), owner_rsa)
    assert live_name in repo.list_files()
    bundle, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert report.ok and workflow.decrypt_verified(bundle, report, recipient_rlwe) == v1

    # authorized dynamic update: version 2
    repo.update(live_name, v2, owner_rsa, recipient_rlwe.public)
    bundle, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert report.ok and report.version == 2
    assert workflow.decrypt_verified(bundle, report, recipient_rlwe) == v2
    b1, r1 = repo.fetch_verified(live_name, owner_rsa.public_key(), version=1)
    assert r1.ok and workflow.decrypt_verified(b1, r1, recipient_rlwe) == v1

    # interrupted upload of version 3 is never activated
    with pytest.raises(PublishError):
        VersionedRepository(_DropMhtUpload(live_store)).update(live_name, b"v3", owner_rsa,
                                                               recipient_rlwe.public)
    _, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert report.ok and report.version == 2

    # unauthorized update attempt with a different key is refused
    with pytest.raises(Exception):
        repo.update(live_name, b"evil", attacker_rsa, recipient_rlwe.public)

    # server-side tampering of the active encrypted file is detected; decryption refused
    key = repo.keys_for(live_name, 2, owner_rsa.public_key())["encrypted_file"]
    data = bytearray(live_store.download(key))
    data[5000] ^= 1
    live_store.upload(key, bytes(data))
    bundle, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert not report.ok and report.tampered_blocks == [1]
    with pytest.raises(workflow.IntegrityError):
        workflow.decrypt_verified(bundle, report, recipient_rlwe)

    # owner deletes everything
    repo.delete(live_name, owner_rsa)
    assert live_store.list(live_name) == []
    assert manifest_key(live_name) not in live_store.list()


def test_live_block_mode_updates(live_store, live_name, owner_rsa, attacker_rsa, recipient_rlwe, owner_rlwe):
    """ENHANCEMENT (not in the paper): per-block AES-256-GCM + block-level updates on real Supabase."""
    from securecloud import blockmode
    from securecloud.storage import CountingStorage

    counter = CountingStorage(live_store)
    repo = VersionedRepository(counter)
    data = os.urandom(64 * blockmode.BLOCK_SIZE)                  # 256 KiB = 64 blocks
    bundle, _ = blockmode.block_setup_phase(data, live_name, owner_rsa, recipient_rlwe.public,
                                            owner_rlwe.public)
    repo.publish(bundle, owner_rsa)

    # one-block update: exactly 1 block + signed MHT + manifest are uploaded
    counter.reset()
    live_store.http.clear()
    entry, stats = repo.block_patch(live_name, 10 * blockmode.BLOCK_SIZE + 5, b"PATCH", owner_rsa, owner_rlwe)
    assert entry.version == 2 and stats["blocks_changed"] == 1 and stats["unchanged_blocks_reused"] == 63
    assert counter.ops["upload"] == 3 and live_store.http["put_requests"] == 3
    expected = bytearray(data)
    expected[10 * blockmode.BLOCK_SIZE + 5:10 * blockmode.BLOCK_SIZE + 10] = b"PATCH"

    bundle, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert report.ok and workflow.decrypt_verified(bundle, report, recipient_rlwe) == bytes(expected)
    b1, r1 = repo.fetch_verified(live_name, owner_rsa.public_key(), version=1)
    assert r1.ok and workflow.decrypt_verified(b1, r1, recipient_rlwe) == data

    # interrupted block update (signed MHT upload fails) is never activated
    with pytest.raises(PublishError):
        VersionedRepository(_DropMhtUpload(live_store)).block_patch(live_name, 0, b"x", owner_rsa, owner_rlwe)
    _, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert report.ok and report.version == 2

    # unauthorized block update with another RSA key is refused
    with pytest.raises(Exception):
        repo.block_patch(live_name, 0, b"evil", attacker_rsa, owner_rlwe)

    # replay the genuine OLD block 10 into version 2 -> detected, decryption refused
    k1 = repo.keys_for(live_name, 1, owner_rsa.public_key())["blocks"]
    k2 = repo.keys_for(live_name, 2, owner_rsa.public_key())["blocks"]
    live_store.upload(k2[10], live_store.download(k1[10]))
    bundle, report = repo.fetch_verified(live_name, owner_rsa.public_key())
    assert not report.ok and report.tampered_blocks == [10]
    with pytest.raises(workflow.IntegrityError):
        workflow.decrypt_verified(bundle, report, recipient_rlwe)

    repo.delete(live_name, owner_rsa)
    assert live_store.list(live_name) == []
