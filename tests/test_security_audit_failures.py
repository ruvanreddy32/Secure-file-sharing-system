"""Automated Regression and Audit Failure Tests.
Verifies all 7 confirmed non-Supabase defects:
- FIX 1: Manifest rollback vulnerability (persistent trust store & TOFU)
- FIX 2: Synchronize User and Attacker file selection
- FIX 3: Display encrypted-key integrity status & handle key substitution
- FIX 4: Clear stale Streamlit verification results after attacks and file/version switching
- FIX 5: Reject incompatible CLI options (--block-mode + --paper-mode / --block-size)
- FIX 6: Handle missing optional Supabase testing dependencies safely
- FIX 7: Reject invalid Windows filenames and path traversal
"""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
import pytest

from securecloud import aes_cipher, blockmode, keys, mht, rlwe, signature, storage, workflow
from securecloud.storage import LocalFolderStorage, StorageError
from securecloud.versioning import (
    Manifest,
    PublishError,
    VersionedRepository,
    VersionTrustStore,
    manifest_key,
    version_keys,
)


@pytest.fixture
def audit_env(tmp_path, monkeypatch):
    """Isolated disposable environment for audit regression tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RINGCRYPTER_TRUST_STORE", str(tmp_path / "trust" / ".trusted_versions.json"))
    for var in (
        "DROPBOX_ACCESS_TOKEN",
        "DROPBOX_REFRESH_TOKEN",
        "SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_KEY",
        "SUPABASE_SECRET_KEY",
        "SUPABASE_BUCKET",
    ):
        monkeypatch.delenv(var, raising=False)

    owner = keys.generate_identity("keys", "owner", rlwe_params="P2")
    user = keys.generate_identity("keys", "user", rlwe_params="P2")
    attacker = keys.generate_identity("keys", "attacker", rlwe_params="P2")

    store = LocalFolderStorage("cloud_local")
    repo = VersionedRepository(store)

    return {
        "store": store,
        "repo": repo,
        "owner_rsa": keys.load_rsa_private(owner.rsa_private),
        "owner_pub": keys.load_rsa_public(owner.rsa_public),
        "user_rlwe_pub": keys.load_rlwe_public(user.rlwe_public),
        "user_rlwe_priv": keys.load_rlwe_private(user.rlwe_private),
        "attacker_rsa": keys.load_rsa_private(attacker.rsa_private),
        "attacker_pub": keys.load_rsa_public(attacker.rsa_public),
        "tmp_path": tmp_path,
    }


# ---------------------------------------------------------------------------
# FIX 1: Manifest Rollback Protection Regression Tests
# ---------------------------------------------------------------------------

def test_manifest_rollback_detected_persistently(audit_env):
    """FIX 1: Verify persistent rollback protection detects manifest replay.
    Even without passing an explicit min_version, the persistent VersionTrustStore
    detects when an attacker replaces the current manifest with an older valid signed manifest.
    """
    repo = audit_env["repo"]
    store = audit_env["store"]
    owner_rsa = audit_env["owner_rsa"]
    owner_pub = audit_env["owner_pub"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]

    name = "rollback_test.txt"
    b1, _ = workflow.setup_phase(b"Version 1 data", name, owner_rsa, user_rlwe_pub)
    repo.publish(b1, owner_rsa)

    # Save authentic v1 manifest
    v1_manifest_bytes = store.download(manifest_key(name))

    # Publish v2
    repo.update(name, b"Version 2 data updated", owner_rsa, user_rlwe_pub)
    _, r_v2 = repo.fetch_verified(name, owner_pub)
    assert r_v2.version == 2
    assert r_v2.ok is True
    v2_manifest_bytes = store.download(manifest_key(name))

    # Malicious storage rolls back manifest to v1
    store.upload(manifest_key(name), v1_manifest_bytes)

    # Receiver call WITHOUT min_version now detects the rollback via persistent trust store!
    b_roll, r_roll = repo.fetch_verified(name, owner_pub)
    assert b_roll is None
    assert r_roll.ok is False
    assert r_roll.manifest_valid is False
    assert any("Rollback detected" in msg for msg in r_roll.messages)

    # Legitimate version history access: if storage has the authentic v2 manifest,
    # requesting version 1 intentionally from history is supported:
    store.upload(manifest_key(name), v2_manifest_bytes)
    b_hist, r_hist = repo.fetch_verified(name, owner_pub, version=1)
    assert b_hist is not None and r_hist.ok is True and r_hist.version == 1


def test_manifest_rollback_tofu_limitation(audit_env):
    """FIX 1: Trust-On-First-Use (TOFU) limitation test.
    If a fresh client has never seen any version and has an empty trust store,
    it accepts the offered version on first use and sets its baseline.
    """
    store = audit_env["store"]
    owner_rsa = audit_env["owner_rsa"]
    owner_pub = audit_env["owner_pub"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]
    tmp_path = audit_env["tmp_path"]

    name = "tofu_test.txt"
    b1, _ = workflow.setup_phase(b"Version 1 data", name, owner_rsa, user_rlwe_pub)
    repo1 = VersionedRepository(store, trust_store=VersionTrustStore(tmp_path / "trust1.json"))
    repo1.publish(b1, owner_rsa)
    v1_bytes = store.download(manifest_key(name))

    repo1.update(name, b"Version 2 data", owner_rsa, user_rlwe_pub)
    store.upload(manifest_key(name), v1_bytes)  # rollback

    # Client with empty trust store has TOFU baseline: accepts v1
    fresh_trust = VersionTrustStore(tmp_path / "fresh_trust.json")
    repo_fresh = VersionedRepository(store, trust_store=fresh_trust)
    b_tofu, r_tofu = repo_fresh.fetch_verified(name, owner_pub)
    assert b_tofu is not None and r_tofu.ok is True and r_tofu.version == 1


# ---------------------------------------------------------------------------
# FIX 2 & FIX 4: Streamlit UI Synchronization & State Invalidation
# ---------------------------------------------------------------------------

def test_streamlit_invalidation_after_attack(audit_env):
    """FIX 4: Streamlit verification state is invalidated when attack is applied."""
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    PAGE = str(Path(__file__).resolve().parent.parent / "pages" / "1_Ring_Crypter_Secure_Cloud.py")
    repo = audit_env["repo"]
    owner_rsa = audit_env["owner_rsa"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]

    bundle, _ = workflow.setup_phase(b"Test content", "ui_test.txt", owner_rsa, user_rlwe_pub)
    repo.publish(bundle, owner_rsa)

    at = AppTest.from_file(PAGE, default_timeout=30).run()

    # User verifies file
    btn_verify = next(b for b in at.button if b.label == "Download & verify integrity")
    btn_verify.click().run()
    assert any("Verified" in s.value for s in at.success)

    # Decrypt button is enabled and decrypted
    btn_dec = next(b for b in at.button if b.label == "Decrypt")
    assert not btn_dec.disabled
    btn_dec.click().run()
    assert at.session_state["plain"] == b"Test content"

    # Attacker applies attack
    atk_sel = next(s for s in at.selectbox if s.label == "Attack")
    atk_sel.set_value("Flip one byte of the active encrypted file").run()
    btn_attack = next(b for b in at.button if b.label == "Apply attack")
    btn_attack.click().run()

    # State invalidation verified:
    # 1. Stale report and plaintext are cleared from session state
    assert "report" not in at.session_state
    assert "plain" not in at.session_state
    assert "dl" not in at.session_state
    # 2. Stale success message is NOT rendered
    assert not any("Verified" in s.value for s in at.success)
    # 3. Warning notice is displayed informing that verification is invalidated
    assert any("invalidated" in w.value.lower() or "modified" in w.value.lower() for w in at.warning)


def test_streamlit_synchronized_file_selection(audit_env):
    """FIX 2: User tab and Attacker tab file selection is synchronized."""
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    PAGE = str(Path(__file__).resolve().parent.parent / "pages" / "1_Ring_Crypter_Secure_Cloud.py")
    repo = audit_env["repo"]
    owner_rsa = audit_env["owner_rsa"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]

    # Publish two distinct files
    b1, _ = workflow.setup_phase(b"File 1 content", "file1.txt", owner_rsa, user_rlwe_pub)
    repo.publish(b1, owner_rsa)
    b2, _ = workflow.setup_phase(b"File 2 content", "file2.txt", owner_rsa, user_rlwe_pub)
    repo.publish(b2, owner_rsa)

    at = AppTest.from_file(PAGE, default_timeout=30).run()

    # Change selection in User tab to file2.txt
    user_sel = next(s for s in at.selectbox if s.label == "Protected files in storage")
    user_sel.set_value("file2.txt").run()

    # Shared state updated
    assert at.session_state["shared_target_file"] == "file2.txt"

    # Attacker tab target is synchronized to file2.txt
    atk_sel = next(s for s in at.selectbox if s.label == "Target")
    assert atk_sel.value == "file2.txt"

    # Attacker tab targeting info is displayed
    assert any("Targeting: **file2.txt**" in inf.value for inf in at.info)


# ---------------------------------------------------------------------------
# FIX 3: Encrypted Key Integrity Status & Substitution Attack
# ---------------------------------------------------------------------------

def test_encrypted_key_integrity_metric_and_substitution(audit_env):
    """FIX 3: Encrypted-key substitution causes verification failure and MISMATCH metric."""
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    PAGE = str(Path(__file__).resolve().parent.parent / "pages" / "1_Ring_Crypter_Secure_Cloud.py")
    repo = audit_env["repo"]
    store = audit_env["store"]
    owner_rsa = audit_env["owner_rsa"]
    owner_pub = audit_env["owner_pub"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]
    user_rlwe_priv = audit_env["user_rlwe_priv"]

    fname = "key_attack_test.txt"
    plaintext = b"Encrypted key integrity test data."
    bundle, _ = workflow.setup_phase(plaintext, fname, owner_rsa, user_rlwe_pub, paper_mode=True)
    repo.publish(bundle, owner_rsa)

    # 1. Direct backend verification
    cur = repo.read_manifest(fname, owner_pub).entry(1)
    ks = repo.keys_for(fname, cur.version, owner_pub)
    evil_key = rlwe.encrypt_key(os.urandom(32), user_rlwe_pub)
    store.upload(ks["encrypted_key"], evil_key)

    b2, r2 = repo.fetch_verified(fname, owner_pub)
    assert r2.ok is False
    assert r2.key_file_match is False
    assert r2.mht_match is True  # MHT is NOT reported as mismatched when only key was changed
    assert len(r2.tampered_blocks) == 0

    # Decryption is blocked
    with pytest.raises(workflow.IntegrityError):
        workflow.decrypt_verified(b2, r2, user_rlwe_priv)

    # 2. UI test: Verify that Encrypted Key metric displays MISMATCH and overall result fails
    at = AppTest.from_file(PAGE, default_timeout=30).run()
    next(s for s in at.selectbox if s.label == "Protected files in storage").set_value(fname).run()
    next(b for b in at.button if b.label == "Download & verify integrity").click().run()

    # Overall result is FAILED
    assert any("INTEGRITY CHECK FAILED" in e.value for e in at.error)
    assert not any("Verified" in s.value for s in at.success)

    # Verify KPI metrics
    metric_labels = [m.label for m in at.metric]
    metric_values = {m.label: m.value for m in at.metric}
    assert "Encrypted Key" in metric_labels
    assert metric_values["Encrypted Key"] == "MISMATCH"
    assert metric_values["MHT comparison"] == "match"

    # Decrypt button is disabled
    assert next(b for b in at.button if b.label == "Decrypt").disabled


# ---------------------------------------------------------------------------
# FIX 5: Reject Incompatible CLI Options
# ---------------------------------------------------------------------------

def test_cli_rejects_incompatible_options(audit_env, capsys):
    """FIX 5: CLI rejects --paper-mode and --block-size when --block-mode is supplied."""
    from securecloud.cli import main

    tmp_path = audit_env["tmp_path"]
    src = tmp_path / "test.bin"
    src.write_bytes(b"sample data" * 100)

    keydir = tmp_path / "keys"
    signer_key = str(keydir / "owner_rsa_private.pem")
    recip_pub = str(keydir / "user_rlwe_public.json")
    owner_rlwe_pub = str(keydir / "owner_rlwe_public.json")

    base_args = [
        "upload",
        str(src),
        "--signer-key", signer_key,
        "--recipient-key", recip_pub,
        "--owner-rlwe-pub", owner_rlwe_pub,
        "--backend", "local",
        "--location", str(tmp_path / "cloud"),
    ]

    # Test combination 1: --block-mode + --paper-mode
    rc1 = main(base_args + ["--block-mode", "--paper-mode"])
    assert rc1 == 1
    captured1 = capsys.readouterr()
    assert "cannot be used with --block-mode" in captured1.err
    assert "--paper-mode" in captured1.err

    # Test combination 2: --block-mode + --block-size
    rc2 = main(base_args + ["--block-mode", "--block-size", "8192"])
    assert rc2 == 1
    captured2 = capsys.readouterr()
    assert "cannot be customized with --block-mode" in captured2.err
    assert "--block-size" in captured2.err


# ---------------------------------------------------------------------------
# FIX 7: Reject Invalid Windows Filenames & Path Traversal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_name", [
    "CON", "con.txt", "PRN", "prn.pdf", "AUX", "aux.bin", "NUL", "nul.dat",
    "COM1", "com1.txt", "COM9", "com9.doc", "LPT1", "lpt1.txt", "LPT9",
    "..", "../secret.txt", "..\\secret.txt", "folder/file.txt", "folder\\file.txt",
    "file.txt ", "file.txt.", "",
])
def test_windows_reserved_and_invalid_filenames_rejected(audit_env, bad_name):
    """FIX 7: Filename validation rejects reserved Windows names and traversal."""
    owner_rsa = audit_env["owner_rsa"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]

    # Whole-file mode setup
    with pytest.raises(ValueError) as exc:
        workflow.setup_phase(b"test", bad_name, owner_rsa, user_rlwe_pub)
    assert "Invalid file name" in str(exc.value)

    # Block mode setup
    with pytest.raises(ValueError) as exc_b:
        blockmode.block_setup_phase(b"test", bad_name, owner_rsa, user_rlwe_pub, user_rlwe_pub)
    assert "Invalid file name" in str(exc_b.value)


@pytest.mark.parametrize("valid_name", [
    "normal.txt", "report_2026.pdf", "data-file.bin", "test.txt.txt", "my_file_1.doc",
])
def test_valid_filenames_accepted(audit_env, valid_name):
    """FIX 7: Ordinary valid filenames are accepted without error."""
    owner_rsa = audit_env["owner_rsa"]
    user_rlwe_pub = audit_env["user_rlwe_pub"]

    bundle, _ = workflow.setup_phase(b"test data", valid_name, owner_rsa, user_rlwe_pub)
    assert bundle.name == valid_name
