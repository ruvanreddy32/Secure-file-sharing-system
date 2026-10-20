"""Versioned storage, atomic activation and authorized dynamic updates.

Runs against: Supabase (mocked client), Dropbox (mocked client), local folder.
"""

import json
import os

import pytest

from fakes import FakeSupabaseClient
from test_storage import FakeDropboxClient
from securecloud import mht, signature, workflow
from securecloud.storage import DropboxStorage, LocalFolderStorage, SupabaseStorage
from securecloud.versioning import (Manifest, ManifestError, PublishError, VersionedRepository,
                                    VersionTrustStore, manifest_key, version_keys)
from securecloud.workflow import IntegrityError, decrypt_verified

V1, V2, V3 = os.urandom(9000), os.urandom(12000), b"third version " * 500


@pytest.fixture(params=["supabase", "dropbox", "local"])
def store(request, tmp_path):
    if request.param == "supabase":
        return SupabaseStorage("ringcrypter", client=FakeSupabaseClient())
    if request.param == "dropbox":
        return DropboxStorage("/RingCrypter", client=FakeDropboxClient())
    return LocalFolderStorage(tmp_path / "cloud")


@pytest.fixture
def repo(store):
    return VersionedRepository(store)


@pytest.fixture
def published(repo, protect, owner_rsa):
    repo.publish(protect(V1, "doc.pdf"), owner_rsa)
    return repo


def _keys(repo, owner_rsa, version):
    return repo.keys_for("doc.pdf", version, owner_rsa.public_key())


def _bundle(repo, owner_rsa, version):
    m = repo.read_manifest("doc.pdf", owner_rsa.public_key())
    return repo.download("doc.pdf", m.entry(version))


def _open(repo, owner_rsa, recipient_rlwe, version=None, **kw):
    bundle, report = repo.fetch_verified("doc.pdf", owner_rsa.public_key(), version, **kw)
    if not report.ok:
        with pytest.raises(IntegrityError):
            decrypt_verified(bundle, report, recipient_rlwe)
        return None, report
    return decrypt_verified(bundle, report, recipient_rlwe), report


# --------------------------------------------------------------------------- publish / fetch
class TestPublishAndFetch:
    def test_first_version(self, published, owner_rsa, recipient_rlwe, store):
        assert published.list_files() == ["doc.pdf"]
        assert set(store.list("doc.pdf")) == {manifest_key("doc.pdf"), *_keys(published, owner_rsa, 1).values()}
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out == V1 and report.ok and report.version == 1 and report.manifest_valid

    def test_publish_requires_version_1_for_new_file(self, repo, protect, owner_rsa, recipient_rlwe):
        b1 = protect(V1, "doc.pdf")
        b2, _ = workflow.update_phase(V2, b1, owner_rsa, recipient_rlwe.public)
        with pytest.raises(PublishError, match="first version must be 1"):
            repo.publish(b2, owner_rsa)

    def test_publish_refuses_bundle_not_signed_by_publisher(self, repo, protect, attacker_rsa):
        with pytest.raises(PublishError):
            repo.publish(protect(V1, "doc.pdf"), attacker_rsa)

    def test_republishing_version_1_refused(self, published, protect, owner_rsa):
        with pytest.raises(PublishError, match="update_phase"):
            published.publish(protect(V2, "doc.pdf"), owner_rsa)

    def test_unknown_file(self, repo, owner_rsa):
        bundle, report = repo.fetch_verified("nope", owner_rsa.public_key())
        assert bundle is None and not report.ok


# --------------------------------------------------------------------------- dynamic update
class TestDynamicUpdate:
    def test_update_creates_chained_versions(self, published, owner_rsa, recipient_rlwe):
        e2, timings = published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        e3, _ = published.update("doc.pdf", V3, owner_rsa, recipient_rlwe.public)
        assert (e2.version, e3.version) == (2, 3) and "total_setup_ms" in timings
        m, versions = published.versions("doc.pdf", owner_rsa.public_key())
        assert m.current_version == 3 and [v.version for v in versions] == [1, 2, 3]
        for v, expected in ((None, V3), (1, V1), (2, V2), (3, V3)):
            out, report = _open(published, owner_rsa, recipient_rlwe, v)
            assert out == expected and report.ok
        _, r3 = published.fetch_verified("doc.pdf", owner_rsa.public_key())
        _, r2 = published.fetch_verified("doc.pdf", owner_rsa.public_key(), 2)
        b2 = _bundle(published, owner_rsa, 2)
        assert r3.previous_mht_sha256 == workflow.signed_mht_sha256(b2) and r2.version == 2

    def test_update_phase_chain_fields(self, protect, owner_rsa, recipient_rlwe):
        b1 = protect(V1, "x.bin")
        b2, _ = workflow.update_phase(V2, b1, owner_rsa, recipient_rlwe.public)
        r = workflow.verify_integrity(b2, owner_rsa.public_key(), expected_version=2,
                                      expected_previous_mht_sha256=workflow.signed_mht_sha256(b1))
        assert r.ok and r.version == 2
        wrong = workflow.verify_integrity(b2, owner_rsa.public_key(), expected_version=3)
        assert not wrong.ok and not wrong.version_ok

    def test_update_refused_when_current_version_tampered(self, published, store, owner_rsa, recipient_rlwe):
        k = _keys(published, owner_rsa, 1)["encrypted_file"]
        data = bytearray(store.download(k))
        data[50] ^= 1
        store.upload(k, bytes(data))
        with pytest.raises(IntegrityError, match="Update refused"):
            published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)

    def test_update_phase_refuses_tampered_previous(self, protect, owner_rsa, recipient_rlwe):
        b1 = protect(V1, "x.bin")
        b1.encrypted_file = b1.encrypted_file[:-1] + b"\x00"
        with pytest.raises(IntegrityError):
            workflow.update_phase(V2, b1, owner_rsa, recipient_rlwe.public)

    def test_unauthorized_update_by_other_key_is_refused(self, published, attacker_rsa, recipient_rlwe):
        with pytest.raises((IntegrityError, ManifestError)):
            published.update("doc.pdf", V2, attacker_rsa, recipient_rlwe.public)

    def test_stale_update_refused(self, published, owner_rsa, recipient_rlwe):
        b1 = _bundle(published, owner_rsa, 1)
        b2a, _ = workflow.update_phase(V2, b1, owner_rsa, recipient_rlwe.public)
        b2b, _ = workflow.update_phase(V3, b1, owner_rsa, recipient_rlwe.public)
        published.publish(b2a, owner_rsa)
        with pytest.raises(PublishError):
            published.publish(b2b, owner_rsa)   # built on v1, but v2 is now current


# --------------------------------------------------------------------------- consistency
class FlakyStorage:
    """Wraps a backend; fails uploads whose key matches *fail_on*."""

    def __init__(self, inner, fail_on):
        self.inner, self.fail_on, self.name = inner, fail_on, inner.name

    def upload(self, key, data):
        if self.fail_on(key):
            raise OSError(f"simulated connection drop while uploading {key}")
        self.inner.upload(key, data)

    def download(self, key):
        return self.inner.download(key)

    def list(self, prefix=""):
        return self.inner.list(prefix)

    def delete(self, keys):
        self.inner.delete(keys)


class TestPartialUploads:
    @pytest.mark.parametrize("failing_suffix", [".aes", ".key.rlwe", ".mht.signed"])
    def test_partial_upload_never_activates(self, published, store, owner_rsa, recipient_rlwe,
                                            failing_suffix):
        flaky = VersionedRepository(FlakyStorage(store, lambda k: "v000002" in k
                                                 and k.endswith(failing_suffix)))
        with pytest.raises(PublishError, match="NOT activated"):
            flaky.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        assert not any("v000002" in k for k in store.list("doc.pdf"))   # rolled back
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out == V1 and report.version == 1

    def test_manifest_write_failure_leaves_old_version_active(self, published, store, owner_rsa,
                                                              recipient_rlwe):
        flaky = VersionedRepository(FlakyStorage(store, lambda k: k.endswith("manifest.signed")))
        with pytest.raises(PublishError, match="NOT active"):
            flaky.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        assert any("v000002" in k for k in store.list("doc.pdf"))       # orphaned objects exist
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out == V1 and report.version == 1                       # ...but are not served
        removed = published.cleanup_incomplete("doc.pdf", owner_rsa.public_key())
        assert len(removed) == 3 and all("/v000002-" in k for k in removed)
        published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)  # retry succeeds
        assert _open(published, owner_rsa, recipient_rlwe)[0] == V2

    def test_concurrent_publisher_detected(self, published, store, owner_rsa, recipient_rlwe):
        b1 = _bundle(published, owner_rsa, 1)
        b2_other, _ = workflow.update_phase(V3, b1, owner_rsa, recipient_rlwe.public)
        b2_mine, _ = workflow.update_phase(V2, b1, owner_rsa, recipient_rlwe.public)
        fired = []

        class Racing(FlakyStorage):
            def upload(self, key, data):
                if key.endswith(".mht.signed") and "v000002" in key and not fired:
                    fired.append(1)
                    VersionedRepository(self.inner).publish(b2_other, owner_rsa)  # other writer wins
                self.inner.upload(key, data)

        with pytest.raises(PublishError):
            VersionedRepository(Racing(store, lambda k: False)).publish(b2_mine, owner_rsa)
        assert _open(published, owner_rsa, recipient_rlwe)[0] == V3


# --------------------------------------------------------------------------- attacks on storage
class TestStorageAttacks:
    def test_tampered_current_version(self, published, store, owner_rsa, recipient_rlwe):
        k = _keys(published, owner_rsa, 1)["encrypted_file"]
        data = bytearray(store.download(k))
        data[4096 + 7] ^= 1
        store.upload(k, bytes(data))
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and report.tampered_blocks == [1] and report.manifest_valid

    def test_forged_version_with_forged_manifest(self, published, store, protect, owner_rsa,
                                                 attacker_rsa, recipient_rlwe):
        """Attacker with bucket write access publishes 'v2' signed with their own key."""
        b1 = _bundle(published, owner_rsa, 1)
        evil, _ = workflow.setup_phase(b"malicious", "doc.pdf", attacker_rsa, recipient_rlwe.public,
                                       version=2, previous_mht_sha256=workflow.signed_mht_sha256(b1))
        for attr, key in version_keys("doc.pdf", 2, workflow.signed_mht_sha256(evil)).items():
            store.upload(key, getattr(evil, attr))
        forged = Manifest.from_bytes(signature.split_signed_mht(store.download(manifest_key("doc.pdf")))[0])
        forged.current_version = 2
        forged.versions.append(type(forged.versions[0])(2, workflow.signed_mht_sha256(evil), 1, "now"))
        store.upload(manifest_key("doc.pdf"), signature.create_signed_mht(forged.to_bytes(), attacker_rsa))
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and report.manifest_valid is False

    def test_unsigned_objects_without_manifest_change_are_ignored(self, published, store, attacker_rsa,
                                                                  recipient_rlwe, owner_rsa):
        evil, _ = workflow.setup_phase(b"malicious", "doc.pdf", attacker_rsa, recipient_rlwe.public)
        for attr, key in version_keys("doc.pdf", 2, workflow.signed_mht_sha256(evil)).items():
            store.upload(key, getattr(evil, attr))
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out == V1 and report.version == 1

    def test_manifest_edited_without_resigning(self, published, store, owner_rsa, recipient_rlwe):
        signed = store.download(manifest_key("doc.pdf"))
        store.upload(manifest_key("doc.pdf"), signed.replace(b'"current_version": 1', b'"current_version": 2'))
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and report.manifest_valid is False

    def test_old_version_files_replayed_as_new_version(self, published, store, owner_rsa, recipient_rlwe):
        published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        k1, k2 = _keys(published, owner_rsa, 1), _keys(published, owner_rsa, 2)
        for attr in ("encrypted_file", "encrypted_key", "signed_mht"):
            store.upload(k2[attr], store.download(k1[attr]))
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and not report.ok
        assert not report.version_ok or report.manifest_valid is False

    def test_manifest_rollback_detected_with_min_version(self, published, store, owner_rsa, recipient_rlwe, tmp_path):
        old_manifest = store.download(manifest_key("doc.pdf"))
        published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        store.upload(manifest_key("doc.pdf"), old_manifest)         # replay genuine old manifest
        # Explicit min_version detects rollback:
        out, report = _open(published, owner_rsa, recipient_rlwe, min_version=2)
        assert out is None and "Rollback" in report.summary
        # Persistent trust store ALSO detects rollback even without explicit min_version:
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and "Rollback" in report.summary
        # TOFU limitation: a fresh client that has never seen version 2 accepts version 1 on first use:
        fresh_repo = VersionedRepository(store, trust_store=VersionTrustStore(tmp_path / "fresh_trust.json"))
        fresh_out, fresh_report = _open(fresh_repo, owner_rsa, recipient_rlwe)
        assert fresh_out == V1 and fresh_report.version == 1

    def test_deleted_version_files(self, published, store, owner_rsa, recipient_rlwe):
        store.delete([_keys(published, owner_rsa, 1)["encrypted_key"]])
        out, report = _open(published, owner_rsa, recipient_rlwe)
        assert out is None and "missing" in report.summary

    def test_manifest_of_other_owner_rejected_by_reader(self, published, attacker_rsa):
        with pytest.raises(ManifestError):
            published.read_manifest("doc.pdf", attacker_rsa.public_key())


# --------------------------------------------------------------------------- delete / cleanup
class TestDelete:
    def test_delete_old_version_keeps_chain(self, published, store, owner_rsa, recipient_rlwe):
        published.update("doc.pdf", V2, owner_rsa, recipient_rlwe.public)
        published.update("doc.pdf", V3, owner_rsa, recipient_rlwe.public)
        published.delete("doc.pdf", owner_rsa, version=2)
        _, versions = published.versions("doc.pdf", owner_rsa.public_key())
        assert [v.version for v in versions] == [1, 3]
        assert not any("v000002" in k for k in store.list("doc.pdf"))
        assert _open(published, owner_rsa, recipient_rlwe)[0] == V3     # chain still verifiable
        out, report = _open(published, owner_rsa, recipient_rlwe, 2)
        assert out is None and "not listed" in report.summary

    def test_cannot_delete_active_version(self, published, owner_rsa):
        with pytest.raises(Exception, match="active version"):
            published.delete("doc.pdf", owner_rsa, version=1)

    def test_delete_whole_file(self, published, store, owner_rsa):
        published.delete("doc.pdf", owner_rsa)
        assert store.list("doc.pdf") == [] and published.list_files() == []

    def test_only_owner_can_delete(self, published, attacker_rsa):
        with pytest.raises(ManifestError):
            published.delete("doc.pdf", attacker_rsa)
