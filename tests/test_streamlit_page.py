"""Headless test of the Ring Crypter Streamlit page (user verification + gated decryption)."""

import os
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

from securecloud import keys, workflow
from securecloud.storage import LocalFolderStorage

PAGE = str(Path(__file__).resolve().parent.parent / "pages" / "1_Ring_Crypter_Secure_Cloud.py")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("DROPBOX_ACCESS_TOKEN", "DROPBOX_REFRESH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    owner = keys.generate_identity("keys", "owner")
    user = keys.generate_identity("keys", "user")
    data = os.urandom(20_000)
    bundle, _ = workflow.setup_phase(data, "report.bin", keys.load_rsa_private(owner.rsa_private),
                                     keys.load_rlwe_public(user.rlwe_public))
    store = LocalFolderStorage("cloud_local")
    workflow.upload_bundle(store, bundle)
    return data, store


def _verify(at):
    next(b for b in at.button if b.label == "Download & verify integrity").click().run()
    return at


def test_verify_and_decrypt(env):
    data, _ = env
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    assert not at.exception
    _verify(at)
    assert any("Verified" in s.value for s in at.success)
    dec = next(b for b in at.button if b.label == "Decrypt")
    assert not dec.disabled
    dec.click().run()
    assert at.session_state["plain"] == data


def test_tampered_file_blocks_decrypt(env):
    _data, store = env
    enc = bytearray(store.download("report.bin.aes"))
    enc[100] ^= 1
    store.upload("report.bin.aes", bytes(enc))
    at = _verify(AppTest.from_file(PAGE, default_timeout=60).run())
    assert any("INTEGRITY CHECK FAILED" in e.value for e in at.error)
    assert next(b for b in at.button if b.label == "Decrypt").disabled
