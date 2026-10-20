"""LIVE Dropbox end-to-end test (paper §IV, §V).  Talks to the real Dropbox API.

Skipped unless credentials are present:
    DROPBOX_REFRESH_TOKEN + DROPBOX_APP_KEY (+ DROPBOX_APP_SECRET), or DROPBOX_ACCESS_TOKEN
Files are written under $DROPBOX_TEST_FOLDER (default /RingCrypter-tests).
"""

import os
import uuid

import pytest

from securecloud import workflow
from securecloud.storage import DropboxStorage

HAVE_CREDS = bool(os.environ.get("DROPBOX_ACCESS_TOKEN")
                  or (os.environ.get("DROPBOX_REFRESH_TOKEN") and os.environ.get("DROPBOX_APP_KEY")))

pytestmark = [pytest.mark.dropbox_live,
              pytest.mark.skipif(not HAVE_CREDS, reason="Dropbox credentials not configured")]


def test_live_upload_verify_decrypt_and_tamper(protect, owner_rsa, recipient_rlwe):
    store = DropboxStorage(os.environ.get("DROPBOX_TEST_FOLDER", "/RingCrypter-tests"))
    assert store.check_account()
    name = f"live-{uuid.uuid4().hex[:8]}.txt"
    data = os.urandom(50_000)

    workflow.upload_bundle(store, protect(data, name))     # raises unless Dropbox confirms
    assert name in workflow.list_bundles(store)

    dl, _ms = workflow.download_bundle(store, name)
    out, report = workflow.open_bundle(dl, owner_rsa.public_key(), recipient_rlwe)
    assert report.ok and out == data

    tampered = bytearray(dl.encrypted_file)
    tampered[1000] ^= 1
    store.upload(name + workflow.ENC_SUFFIX, bytes(tampered))
    dl2, _ = workflow.download_bundle(store, name)
    with pytest.raises(workflow.IntegrityError):
        workflow.open_bundle(dl2, owner_rsa.public_key(), recipient_rlwe)

    for suffix in (workflow.ENC_SUFFIX, workflow.KEY_SUFFIX, workflow.MHT_SUFFIX):
        store.client.files_delete_v2(f"{store.folder}/{name}{suffix}")
