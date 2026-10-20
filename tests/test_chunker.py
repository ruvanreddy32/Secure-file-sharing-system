"""tests/test_chunker.py — Gherkin Sprint 1: chunking scenarios."""

import pytest
from merkle.chunker import chunk_bytes, chunk_file
import tempfile, os


# ---------------------------------------------------------------------------
# Scenario: Chunking a file into fixed-size blocks
# ---------------------------------------------------------------------------

class TestChunkBytes:
    def test_block_count_18000_bytes(self):
        """18 000 bytes / 4 096 = 4 full blocks + 1 partial → 5 blocks."""
        data = b"x" * 18_000
        blocks = chunk_bytes(data, 4096)
        assert len(blocks) == 5

    def test_last_block_length_is_remainder(self):
        """Last block length == 18 000 mod 4 096 == 1 024 (no padding)."""
        data = b"x" * 18_000
        blocks = chunk_bytes(data, 4096)
        assert blocks[-1]["length"] == 18_000 % 4_096

    def test_no_physical_padding(self):
        """Sum of block lengths equals original data length exactly."""
        data = b"y" * 18_000
        blocks = chunk_bytes(data, 4096)
        total = sum(b["length"] for b in blocks)
        assert total == 18_000

    def test_offsets_are_sequential(self):
        """Each block's offset equals index * block_size."""
        data = b"z" * (4_096 * 3)
        blocks = chunk_bytes(data, 4096)
        for b in blocks:
            assert b["offset"] == b["index"] * 4_096

    def test_indices_are_sequential(self):
        data = b"a" * 12_000
        blocks = chunk_bytes(data, 4096)
        for i, b in enumerate(blocks):
            assert b["index"] == i

    def test_data_content_matches_original(self):
        data = bytes(range(256)) * 20  # 5 120 bytes
        blocks = chunk_bytes(data, 256)
        reconstructed = b"".join(b["data"] for b in blocks)
        assert reconstructed == data

    def test_exact_multiple_of_block_size(self):
        """When size is an exact multiple, no odd last block."""
        data = b"k" * 8_192  # exactly 2 × 4 096
        blocks = chunk_bytes(data, 4096)
        assert len(blocks) == 2
        assert all(b["length"] == 4_096 for b in blocks)

    def test_single_block_smaller_than_block_size(self):
        data = b"small"
        blocks = chunk_bytes(data, 4096)
        assert len(blocks) == 1
        assert blocks[0]["length"] == 5

    def test_raises_on_empty_data(self):
        with pytest.raises(ValueError):
            chunk_bytes(b"", 4096)

    def test_raises_on_zero_block_size(self):
        with pytest.raises(ValueError):
            chunk_bytes(b"hello", 0)


class TestChunkFile:
    def test_chunk_file_matches_chunk_bytes(self, tmp_path):
        data = b"file content " * 500
        p = tmp_path / "test.bin"
        p.write_bytes(data)
        blocks = chunk_file(str(p), 256)
        expected = chunk_bytes(data, 256)
        assert len(blocks) == len(expected)
        for a, b in zip(blocks, expected):
            assert a["data"] == b["data"]
            assert a["offset"] == b["offset"]
            assert a["length"] == b["length"]
