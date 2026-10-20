"""Headless tests of the Ring Crypter Streamlit page (Streamlit AppTest)."""

import os
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

from fakes import FakeSupabaseClient
from securecloud import keys, workflow
from securecloud.storage import LocalFolderStorage, SupabaseStorage
from securecloud.versioning import VersionedRepository

PAGE = str(Path(__file__).resolve().parent.parent / "pages" / "1_Ring_Crypter_Secure_Cloud.py")
V1, V2 = os.urandom(20_000), b"second version " * 1000


@pytest.fixture
def ids(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("DROPBOX_ACCESS_TOKEN", "DROPBOX_REFRESH_TOKEN", "SUPABASE_URL",
                "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY", "SUPABASE_SECRET_KEY", "SUPABASE_BUCKET"):
        monkeypatch.delenv(var, raising=False)
    owner = keys.generate_identity("keys", "owner")
    user = keys.generate_identity("keys", "user")
    return (keys.load_rsa_private(owner.rsa_private), keys.load_rlwe_public(user.rlwe_public))


def _publish(store, ids, update=False):
    owner, user_pub = ids
    repo = VersionedRepository(store)
    if update:
        repo.update("report.bin", V2, owner, user_pub)
    else:
        bundle, _ = workflow.setup_phase(V1, "report.bin", owner, user_pub)
        repo.publish(bundle, owner)
    return repo


def _button(at, label):
    return next(b for b in at.button if b.label == label)


def _backend(at):
    return next(r for r in at.radio if r.label == "Backend").value


def _verify(at):
    _button(at, "Download & verify integrity").click().run()
    return at


def test_verify_and_decrypt_local(ids):
    _publish(LocalFolderStorage("cloud_local"), ids)
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    assert not at.exception
    assert _backend(at) == "local"                 # no cloud credentials -> local default
    _verify(at)
    assert any("Verified" in s.value for s in at.success)
    dec = _button(at, "Decrypt")
    assert not dec.disabled
    dec.click().run()
    assert at.session_state["plain"] == V1


def test_version_selection_after_update(ids):
    store = LocalFolderStorage("cloud_local")
    _publish(store, ids)
    _publish(store, ids, update=True)
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    version_box = next(s for s in at.selectbox if s.label == "Version")
    assert version_box.options == ["v2 (active) · RCF1", "v1 · RCF1"]
    _verify(at)
    _button(at, "Decrypt").click().run()
    assert at.session_state["plain"] == V2
    next(s for s in at.selectbox if s.label == "Version").set_value("v1 · RCF1").run()
    _verify(at)
    _button(at, "Decrypt").click().run()
    assert at.session_state["plain"] == V1


def test_tampered_file_blocks_decrypt(ids):
    store = LocalFolderStorage("cloud_local")
    repo = _publish(store, ids)
    k = repo.keys_for("report.bin", 1, ids[0].public_key())["encrypted_file"]
    enc = bytearray(store.download(k))
    enc[100] ^= 1
    store.upload(k, bytes(enc))
    at = _verify(AppTest.from_file(PAGE, default_timeout=60).run())
    assert any("INTEGRITY CHECK FAILED" in e.value for e in at.error)
    assert _button(at, "Decrypt").disabled


@pytest.mark.parametrize("attack,expect_ok", [
    ("Unauthorized update: publish a version signed by an attacker", False),
    ("Interrupted owner upload (partial new version)", True),
    ("Flip one byte of the active encrypted file", False),
])
def test_attacker_tab(ids, attack, expect_ok):
    _publish(LocalFolderStorage("cloud_local"), ids)
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    next(s for s in at.selectbox if s.label == "Attack").set_value(attack).run()
    _button(at, "Apply attack").click().run()
    assert not at.exception
    at = _verify(AppTest.from_file(PAGE, default_timeout=60).run()) if expect_ok else at
    if not expect_ok:
        at = AppTest.from_file(PAGE, default_timeout=60).run()
        if attack.startswith("Unauthorized"):
            # the forged manifest is rejected: the page reports the signed-manifest problem
            assert any("manifest" in e.value.lower() for e in at.error)
            return
        _verify(at)
        assert _button(at, "Decrypt").disabled
    else:
        assert any("Verified" in s.value for s in at.success)
        assert at.session_state["report"].version == 1   # partial v2 never activated


def test_page_on_supabase_backend(ids, monkeypatch):
    import supabase
    client = FakeSupabaseClient()
    monkeypatch.setattr(supabase, "create_client", lambda url, key: client)
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-role-secret-value")
    _publish(SupabaseStorage("ringcrypter", client=client), ids)
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    assert _backend(at) == "supabase"
    rendered = " ".join(str(e.value) for e in (*at.caption, *at.markdown, *at.text_input))
    assert "service-role-secret-value" not in rendered  # never shown to the browser
    _verify(at)
    _button(at, "Decrypt").click().run()
    assert at.session_state["plain"] == V1


# ---------------------------------------------------------------------------
# ENHANCEMENT: per-block (RCB1) files in the page
# ---------------------------------------------------------------------------

def _publish_blocks(store, data=None):
    from securecloud import blockmode
    owner = keys.load_rsa_private("keys/owner_rsa_private.pem")
    bundle, _ = blockmode.block_setup_phase(data or V1, "blocks.bin", owner,
                                            keys.load_rlwe_public("keys/user_rlwe_public.json"),
                                            keys.load_rlwe_public("keys/owner_rlwe_public.json"))
    VersionedRepository(store).publish(bundle, owner)


def test_block_level_edit_and_decrypt(ids):
    _publish_blocks(LocalFolderStorage("cloud_local"))
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    assert not at.exception
    next(n for n in at.number_input if n.label == "Byte offset").set_value(4100).run()
    next(t for t in at.text_input if t.label == "Bytes to write (UTF-8 text)").set_value("PATCHED").run()
    _button(at, "Apply block-level update").click().run()
    assert any("re-encrypted 1 of 5 blocks" in s.value for s in at.success)
    assert at.session_state["blk_result"]["ops_upload"] == 3
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    next(s for s in at.selectbox if s.label == "Protected files in storage").set_value("blocks.bin").run()
    assert next(s for s in at.selectbox if s.label == "Version").options[0] == "v2 (active) · RCB1"
    _verify(at)
    _button(at, "Decrypt").click().run()
    expected = bytearray(V1)
    expected[4100:4107] = b"PATCHED"
    assert at.session_state["plain"] == bytes(expected)


@pytest.mark.parametrize("attack", ["Per-block files: replay an older version of a block",
                                    "Per-block files: swap two blocks"])
def test_block_attacks_detected(ids, attack):
    store = LocalFolderStorage("cloud_local")
    _publish_blocks(store)
    owner = keys.load_rsa_private("keys/owner_rsa_private.pem")
    VersionedRepository(store).block_patch("blocks.bin", 0, b"v2", owner,
                                           keys.load_rlwe_private("keys/owner_rlwe_private.json"))
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    next(s for s in at.selectbox if s.label == "Target").set_value("blocks.bin").run()
    next(s for s in at.selectbox if s.label == "Attack").set_value(attack).run()
    _button(at, "Apply attack").click().run()
    assert any("Applied" in w.value for w in at.warning)
    at = AppTest.from_file(PAGE, default_timeout=60).run()
    next(s for s in at.selectbox if s.label == "Protected files in storage").set_value("blocks.bin").run()
    _verify(at)
    assert any("INTEGRITY CHECK FAILED" in e.value for e in at.error)
    assert _button(at, "Decrypt").disabled
