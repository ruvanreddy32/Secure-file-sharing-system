"""The Ring Crypter CLI (paper Fig. 4 actions) driven end to end."""

import os

import pytest

from securecloud.cli import main


@pytest.fixture(scope="module")
def keydir(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    assert main(["keygen", "--name", "owner", "--key-dir", str(d)]) == 0
    assert main(["keygen", "--name", "user", "--key-dir", str(d)]) == 0
    return d


def _setup_args(keydir, src):
    return [str(src), "--signer-key", str(keydir / "owner_rsa_private.pem"),
            "--recipient-key", str(keydir / "user_rlwe_public.json")]


def _src_args(keydir, name, out_dir):
    return [name, "--signer-pub", str(keydir / "owner_rsa_public.pem"), "--from-dir", str(out_dir)]


def test_keygen_refuses_overwrite(keydir):
    assert main(["keygen", "--name", "owner", "--key-dir", str(keydir)]) == 1


def test_encrypt_verify_decrypt_locally(keydir, tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(os.urandom(12_345))
    enc = tmp_path / "enc"
    assert main(["encrypt", *_setup_args(keydir, src), "--out-dir", str(enc)]) == 0
    assert sorted(p.name for p in enc.iterdir()) == \
        ["data.txt.aes", "data.txt.key.rlwe", "data.txt.mht.signed"]
    assert main(["verify", *_src_args(keydir, "data.txt", enc)]) == 0
    out = tmp_path / "restored.txt"
    assert main(["decrypt", *_src_args(keydir, "data.txt", enc),
                 "--rlwe-key", str(keydir / "user_rlwe_private.json"), "--out", str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()


def test_tamper_then_decrypt_refused(keydir, tmp_path, capsys):
    src = tmp_path / "doc.bin"
    src.write_bytes(os.urandom(9000))
    enc = tmp_path / "enc"
    main(["encrypt", *_setup_args(keydir, src), "--out-dir", str(enc)])
    assert main(["tamper", str(enc / "doc.bin.aes"), "--offset", "5000"]) == 0
    out = tmp_path / "never.bin"
    rc = main(["decrypt", *_src_args(keydir, "doc.bin", enc),
               "--rlwe-key", str(keydir / "user_rlwe_private.json"), "--out", str(out)])
    assert rc == 2 and not out.exists()
    assert "Decryption NOT performed" in capsys.readouterr().out


def test_upload_and_decrypt_via_local_backend(keydir, tmp_path):
    src = tmp_path / "x.txt"
    src.write_bytes(b"hello cloud")
    cloud = tmp_path / "cloud"
    assert main(["upload", *_setup_args(keydir, src), "--paper-mode",
                 "--backend", "local", "--location", str(cloud)]) == 0
    out = tmp_path / "x.out"
    assert main(["decrypt", "x.txt", "--signer-pub", str(keydir / "owner_rsa_public.pem"),
                 "--backend", "local", "--location", str(cloud),
                 "--rlwe-key", str(keydir / "user_rlwe_private.json"), "--out", str(out)]) == 0
    assert out.read_bytes() == b"hello cloud"


def test_demo_command():
    assert main(["demo"]) == 0


# ---------------------------------------------------------------------------
# Supabase backend through the CLI (official SDK entry point patched to the fake client)
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_supabase(monkeypatch):
    import supabase
    from fakes import FakeSupabaseClient
    client = FakeSupabaseClient(buckets=())
    monkeypatch.setattr(supabase, "create_client", lambda url, key: client)
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role")
    monkeypatch.delenv("SUPABASE_BUCKET", raising=False)
    return client


def _sb_src(keydir, name):
    return [name, "--signer-pub", str(keydir / "owner_rsa_public.pem"), "--backend", "supabase"]


def test_supabase_full_cli_lifecycle(keydir, tmp_path, fake_supabase, capsys):
    assert main(["supabase-setup"]) == 0
    assert fake_supabase.buckets["ringcrypter"]["public"] is False
    src = tmp_path / "report.pdf"
    src.write_bytes(os.urandom(20_000))
    rlwe_priv = ["--rlwe-key", str(keydir / "user_rlwe_private.json")]

    assert main(["upload", *_setup_args(keydir, src)]) == 0          # default backend = supabase
    assert any(k.startswith("report.pdf/v000001-") for k in fake_supabase.objects())
    out = tmp_path / "r1.pdf"
    assert main(["decrypt", *_sb_src(keydir, "report.pdf"), *rlwe_priv, "--out", str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()

    v1 = src.read_bytes()
    src.write_bytes(b"new content " * 900)                            # dynamic update
    assert main(["update", *_setup_args(keydir, src)]) == 0
    capsys.readouterr()
    assert main(["versions", "report.pdf", "--signer-pub", str(keydir / "owner_rsa_public.pem")]) == 0
    listing = capsys.readouterr().out
    assert "v1" in listing and "v2" in listing and "<- active" in listing
    assert main(["decrypt", *_sb_src(keydir, "report.pdf"), *rlwe_priv, "--out", str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()
    assert main(["decrypt", *_sb_src(keydir, "report.pdf"), *rlwe_priv, "--version", "1",
                 "--out", str(out)]) == 0
    assert out.read_bytes() == v1

    # tamper with the active version in the bucket -> exit 2, no output
    key = next(k for k in fake_supabase.objects() if k.startswith("report.pdf/v000002-") and k.endswith(".aes"))
    data = bytearray(fake_supabase.objects()[key])
    data[100] ^= 1
    fake_supabase.objects()[key] = bytes(data)
    bad = tmp_path / "never.pdf"
    assert main(["decrypt", *_sb_src(keydir, "report.pdf"), *rlwe_priv, "--out", str(bad)]) == 2
    assert not bad.exists()
    assert main(["verify", *_sb_src(keydir, "report.pdf")]) == 2

    # update refused while the active version is tampered
    assert main(["update", *_setup_args(keydir, src)]) == 2

    assert main(["list"]) == 0
    assert main(["delete", "report.pdf", "--signer-key", str(keydir / "owner_rsa_private.pem"),
                 "--version", "1"]) == 0
    assert main(["delete", "report.pdf", "--signer-key", str(keydir / "owner_rsa_private.pem")]) == 0
    assert fake_supabase.objects() == {}


def test_cli_rollback_and_cleanup_local(keydir, tmp_path):
    cloud = ["--backend", "local", "--location", str(tmp_path / "cloud")]
    src = tmp_path / "a.txt"
    src.write_bytes(b"one" * 100)
    assert main(["upload", *_setup_args(keydir, src), *cloud]) == 0
    manifest = tmp_path / "cloud" / "a.txt" / "manifest.signed"
    old = manifest.read_bytes()
    src.write_bytes(b"two" * 100)
    assert main(["update", *_setup_args(keydir, src), *cloud]) == 0
    manifest.write_bytes(old)                                         # replay old manifest
    pub = ["--signer-pub", str(keydir / "owner_rsa_public.pem")]
    assert main(["verify", "a.txt", *pub, *cloud, "--min-version", "2"]) == 2
    # Persistent rollback protection rejects rollback even without --min-version:
    assert main(["verify", "a.txt", *pub, *cloud]) == 2
    # Fresh trust store without prior knowledge accepts v1 (first-use trust limitation):
    fresh_trust = tmp_path / "fresh_cli_trust.json"
    import os
    orig_trust = os.environ.get("RINGCRYPTER_TRUST_STORE")
    os.environ["RINGCRYPTER_TRUST_STORE"] = str(fresh_trust)
    try:
        assert main(["verify", "a.txt", *pub, *cloud]) == 0
    finally:
        if orig_trust is not None:
            os.environ["RINGCRYPTER_TRUST_STORE"] = orig_trust
        else:
            os.environ.pop("RINGCRYPTER_TRUST_STORE", None)
    assert main(["cleanup", "a.txt", *pub, *cloud]) == 0              # v2 now unreferenced
    assert not any("v000002" in p.as_posix() for p in (tmp_path / "cloud").rglob("*"))


def test_supabase_missing_credentials_message(keydir, tmp_path, monkeypatch, capsys):
    for v in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY", "SUPABASE_SECRET_KEY"):
        monkeypatch.delenv(v, raising=False)
    src = tmp_path / "x"
    src.write_bytes(b"x")
    assert main(["upload", *_setup_args(keydir, src)]) == 1
    assert "SUPABASE_URL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# ENHANCEMENT: per-block (RCB1) files through the CLI
# ---------------------------------------------------------------------------

def test_cli_block_mode_lifecycle(keydir, tmp_path, capsys):
    cloud = ["--backend", "local", "--location", str(tmp_path / "cloud")]
    owner = ["--signer-key", str(keydir / "owner_rsa_private.pem"),
             "--owner-rlwe-key", str(keydir / "owner_rlwe_private.json")]
    src = tmp_path / "doc.bin"
    original = os.urandom(10 * 4096 + 77)
    src.write_bytes(original)
    assert main(["upload", *_setup_args(keydir, src), *cloud, "--block-mode"]) == 1     # owner key missing
    assert main(["upload", *_setup_args(keydir, src), *cloud, "--block-mode",
                 "--owner-rlwe-pub", str(keydir / "owner_rlwe_public.json")]) == 0
    capsys.readouterr()

    assert main(["block-update", "doc.bin", "--offset", "5000", "--text", "HELLO", *owner, *cloud]) == 0
    out = capsys.readouterr().out
    assert "blocks_changed                     1" in out and "storage ops_upload" in out
    patch = tmp_path / "blk"
    patch.write_bytes(b"\x42" * 4096)
    assert main(["block-update", "doc.bin", "--block", "2", "--data-file", str(patch), *owner, *cloud]) == 0

    expected = bytearray(original)
    expected[5000:5005] = b"HELLO"
    expected[2 * 4096:3 * 4096] = b"\x42" * 4096
    expected = bytes(expected) + b"tail"
    src.write_bytes(expected)
    assert main(["block-sync", str(src), *owner, *cloud]) == 0
    assert "blocks_changed                     1" in capsys.readouterr().out   # only the tail block

    pub = ["--signer-pub", str(keydir / "owner_rsa_public.pem")]
    restored = tmp_path / "restored"
    assert main(["decrypt", "doc.bin", *pub, *cloud, "--rlwe-key", str(keydir / "user_rlwe_private.json"),
                 "--out", str(restored)]) == 0
    assert restored.read_bytes() == expected
    assert main(["decrypt", "doc.bin", *pub, *cloud, "--rlwe-key", str(keydir / "user_rlwe_private.json"),
                 "--version", "1", "--out", str(restored)]) == 0
    assert restored.read_bytes() == original
    capsys.readouterr()
    assert main(["versions", "doc.bin", *pub, *cloud]) == 0
    assert capsys.readouterr().out.count("RCB1") == 4

    # tamper with a block of the ACTIVE version -> verification fails (exit 2)
    from securecloud import keys as K
    from securecloud.storage import LocalFolderStorage
    from securecloud.versioning import VersionedRepository
    repo = VersionedRepository(LocalFolderStorage(tmp_path / "cloud"))
    active_blocks = repo.keys_for("doc.bin", 4, K.load_rsa_public(keydir / "owner_rsa_public.pem"))["blocks"]
    blk = tmp_path / "cloud" / active_blocks[0]
    data = bytearray(blk.read_bytes())
    data[60] ^= 1
    blk.write_bytes(bytes(data))
    assert main(["verify", "doc.bin", *pub, *cloud]) == 2


def test_cli_block_demo():
    assert main(["demo-blocks"]) == 0
