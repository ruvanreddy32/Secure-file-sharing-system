"""
merkle/chunker.py — Fixed-size file block splitter.

Splits raw bytes (or a file on disk) into a list of block descriptors.
No physical padding is applied — the last block contains only the bytes
that remain in the file.

Block descriptor schema (dict):
    index   (int):   Zero-based block number.
    offset  (int):   Byte offset of the block's first byte in the original file.
    length  (int):   Number of bytes in this block (< block_size for the last block).
    data    (bytes): Raw block payload.
"""

from pathlib import Path
from typing import List, Dict, Union


def chunk_bytes(data: bytes, block_size: int = 4096) -> List[Dict]:
    """Split *data* into fixed-size blocks.

    Args:
        data:       Raw bytes to split.
        block_size: Maximum number of bytes per block (default 4 096).

    Returns:
        Ordered list of block descriptors.  The last block may be smaller
        than *block_size*; it is **never** zero-padded.

    Raises:
        ValueError: If *data* is empty or *block_size* < 1.
    """
    if block_size < 1:
        raise ValueError(f"block_size must be ≥ 1, got {block_size}")
    if not data:
        raise ValueError("Cannot chunk empty data")

    blocks: List[Dict] = []
    offset = 0
    index = 0
    while offset < len(data):
        chunk = data[offset : offset + block_size]
        blocks.append(
            {
                "index": index,
                "offset": offset,
                "length": len(chunk),
                "data": chunk,
            }
        )
        offset += block_size
        index += 1
    return blocks


def chunk_file(path: Union[str, Path], block_size: int = 4096) -> List[Dict]:
    """Read a file from *path* and split it into fixed-size blocks.

    Args:
        path:       Path to the file.
        block_size: Maximum number of bytes per block (default 4 096).

    Returns:
        Ordered list of block descriptors (same schema as :func:`chunk_bytes`).
    """
    path = Path(path)
    data = path.read_bytes()
    return chunk_bytes(data, block_size)
