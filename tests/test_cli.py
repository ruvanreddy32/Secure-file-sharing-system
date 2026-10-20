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
