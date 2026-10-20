"""File-type tests (paper Table II) and boundary tests."""

import io
import os
import struct
import wave
import zipfile
from xml.etree import ElementTree

import pytest

from evaluation.sample_files import FILE_TYPES, make_file
from securecloud import aes_cipher
from securecloud.workflow import IntegrityError, open_bundle, verify_integrity


def _validate(kind: str, data: bytes) -> None:
    """The generated sample is a genuine file of its type."""
    if kind == "Text":
        data.decode("ascii")
    elif kind == "Audio":
        with wave.open(io.BytesIO(data)) as w:
            assert w.getnframes() > 0 and w.getsampwidth() == 2
    elif kind == "Image":
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        Image = pytest.importorskip("PIL.Image")
        im = Image.open(io.BytesIO(data))
        im.load()
        assert im.size[0] == 128
    elif kind == "Video":
        assert data[:4] == b"RIFF" and data[8:12] == b"AVI "
        assert struct.unpack("<I", data[4:8])[0] == len(data) - 8
        assert b"movi" in data and b"idx1" in data
    elif kind in ("Document", "Excel"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert z.testzip() is None
            for name in z.namelist():
                ElementTree.fromstring(z.read(name))
    elif kind == "PDF":
        assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
        pypdf = pytest.importorskip("pypdf")
        assert len(pypdf.PdfReader(io.BytesIO(data)).pages) >= 1


@pytest.mark.parametrize("kind", list(FILE_TYPES))
class TestFileTypes:
    def test_sample_is_valid_and_about_100kb(self, kind):
        name, data = make_file(kind, 102_400)
        _validate(kind, data)
        assert abs(len(data) - 102_400) / 102_400 < 0.02

    def test_roundtrip_and_tamper(self, kind, protect, owner_rsa, recipient_rlwe):
        name, data = make_file(kind, 102_400)
        b = protect(data, name)
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert report.ok and out == data
        _validate(kind, out)
        bad = bytearray(b.encrypted_file)
        bad[len(bad) // 3] ^= 0x80
        b.encrypted_file = bytes(bad)
        assert not verify_integrity(b, owner_rsa.public_key()).ok
        with pytest.raises(IntegrityError):
            open_bundle(b, owner_rsa.public_key(), recipient_rlwe)


class TestBoundaries:
    OVERHEAD = aes_cipher.HEADER_SIZE + aes_cipher.TAG_SIZE  # 32 bytes

    @pytest.mark.parametrize("size", [0, 1, 4096 - 32, 4096 - 31, 4096, 4097, 3 * 4096 + 7])
    def test_sizes(self, size, protect, owner_rsa, recipient_rlwe):
        data = os.urandom(size)
        b = protect(data)
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert out == data
        expected_blocks = -(-(size + self.OVERHEAD) // 4096)
        assert report.block_count == expected_blocks

    def test_empty_file_tamper_detected(self, protect, owner_rsa):
        b = protect(b"")
        b.encrypted_file = b.encrypted_file[:-1] + bytes([b.encrypted_file[-1] ^ 1])
        assert not verify_integrity(b, owner_rsa.public_key()).ok

    def test_exact_multiple_of_block_size(self, protect, owner_rsa, recipient_rlwe):
        data = os.urandom(4096 * 4 - self.OVERHEAD)       # ciphertext exactly 4 blocks
        b = protect(data)
        assert len(b.encrypted_file) == 4096 * 4
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert report.block_count == 4 and out == data

    @pytest.mark.parametrize("block_size", [1, 64, 1000, 65536])
    def test_custom_block_sizes(self, block_size, protect, owner_rsa, recipient_rlwe):
        data = os.urandom(5000)
        b = protect(data, block_size=block_size)
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert report.block_size == block_size and out == data

    @pytest.mark.slow
    def test_large_file_20mb(self, protect, owner_rsa, recipient_rlwe):
        data = os.urandom(20 * 1024 * 1024)
        b = protect(data, "big.bin")
        out, report = open_bundle(b, owner_rsa.public_key(), recipient_rlwe)
        assert out == data and report.block_count == -(-(len(data) + self.OVERHEAD) // 4096)
        bad = bytearray(b.encrypted_file)
        bad[15 * 1024 * 1024] ^= 1
        b.encrypted_file = bytes(bad)
        r = verify_integrity(b, owner_rsa.public_key())
        assert not r.ok and r.tampered_blocks == [15 * 1024 * 1024 // 4096]
