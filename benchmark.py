"""
benchmark.py — Real wall-clock timing: full-file SHA-256 vs Merkle proof verification.

Sizes tested: 1 MB, 10 MB, 100 MB.
Larger sizes (500 MB, 1 GB) are omitted to keep the benchmark practical on
development machines; see README.md for details.

Output: results.csv with columns:
    file_size_label, file_size_bytes, n_blocks,
    full_hash_ms, merkle_verify_ms, speedup_ratio

Usage:
    python benchmark.py
"""

import csv
import hashlib
import os
import time
import tempfile
import math
import random

from merkle.chunker import chunk_bytes
from merkle.tree import MerkleTree
from merkle.proof import get_proof, verify_proof

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCK_SIZE = 4096  # bytes — standard block size
RESULTS_CSV = "results.csv"

# (label, size_in_bytes)
FILE_SIZES = [
    ("1 MB",   1 * 1024 * 1024),
    ("10 MB",  10 * 1024 * 1024),
    ("100 MB", 100 * 1024 * 1024),
]

VERIFY_BLOCK_INDEX = 0  # always verify the first block for consistency
WARMUP_RUNS = 1         # number of warm-up iterations (discarded)
TIMED_RUNS = 3          # number of timed iterations to average


# ---------------------------------------------------------------------------
# Measurement helpers
# ---------------------------------------------------------------------------

def _generate_data(size: int) -> bytes:
    """Generate *size* bytes of pseudo-random data using os.urandom."""
    return os.urandom(size)


def measure_full_hash(data: bytes, runs: int = TIMED_RUNS) -> float:
    """Return the average wall-clock time (ms) to SHA-256 the entire *data* blob."""
    # Warm-up
    for _ in range(WARMUP_RUNS):
        hashlib.sha256(data).hexdigest()

    total = 0.0
    for _ in range(runs):
        t0 = time.perf_counter()
        hashlib.sha256(data).hexdigest()
        total += time.perf_counter() - t0

    return (total / runs) * 1000  # convert to ms


def measure_merkle_verify(data: bytes, block_size: int = BLOCK_SIZE,
                           verify_index: int = VERIFY_BLOCK_INDEX,
                           runs: int = TIMED_RUNS) -> tuple:
    """Return (avg_verify_ms, n_blocks, tree_height).

    Measures only the verify_proof call (not tree construction), since the
    tree would already be cached in a real system.
    """
    blocks = chunk_bytes(data, block_size)
    tree = MerkleTree(blocks, block_size)
    proof = get_proof(tree, verify_index)
    block_data = blocks[verify_index]["data"]
    root_hash = tree.root.hash

    # Warm-up
    for _ in range(WARMUP_RUNS):
        verify_proof(block_data, proof, root_hash)

    total = 0.0
    for _ in range(runs):
        t0 = time.perf_counter()
        verify_proof(block_data, proof, root_hash)
        total += time.perf_counter() - t0

    avg_ms = (total / runs) * 1000
    return avg_ms, len(blocks), tree.height


# ---------------------------------------------------------------------------
# Main benchmark loop
# ---------------------------------------------------------------------------

def run_benchmark() -> None:
    print("=" * 65)
    print("Merkle Tree Integrity — Performance Benchmark")
    print(f"Block size : {BLOCK_SIZE:,} bytes")
    print(f"Timed runs : {TIMED_RUNS}")
    print("=" * 65)

    rows = []

    for label, size in FILE_SIZES:
        print(f"\n[{label}]  Generating {size:,} bytes …", flush=True)
        data = _generate_data(size)

        print(f"  Measuring full-file SHA-256 …", flush=True)
        full_hash_ms = measure_full_hash(data)

        print(f"  Building Merkle tree & measuring proof verify …", flush=True)
        merkle_ms, n_blocks, height = measure_merkle_verify(data)

        speedup = full_hash_ms / merkle_ms if merkle_ms > 0 else float("inf")

        row = {
            "file_size_label": label,
            "file_size_bytes": size,
            "n_blocks": n_blocks,
            "tree_height": height,
            "full_hash_ms": round(full_hash_ms, 4),
            "merkle_verify_ms": round(merkle_ms, 6),
            "speedup_ratio": round(speedup, 1),
        }
        rows.append(row)

        print(
            f"  Full SHA-256  : {full_hash_ms:>10.4f} ms\n"
            f"  Merkle verify : {merkle_ms:>10.6f} ms   "
            f"(proof len={height}, blocks={n_blocks:,})\n"
            f"  Speed-up      : {speedup:>10.1f}×"
        )

    # Write CSV
    fieldnames = list(rows[0].keys())
    with open(RESULTS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n✓ Results written to {RESULTS_CSV}")
    print("=" * 65)

    # Print summary table
    print(
        f"\n{'Size':<10} {'Blocks':>8} {'Height':>7} "
        f"{'Full(ms)':>12} {'Merkle(ms)':>14} {'Speedup':>10}"
    )
    print("-" * 65)
    for r in rows:
        print(
            f"{r['file_size_label']:<10} {r['n_blocks']:>8,} {r['tree_height']:>7} "
            f"{r['full_hash_ms']:>12.4f} {r['merkle_verify_ms']:>14.6f} "
            f"{r['speedup_ratio']:>9.1f}×"
        )


if __name__ == "__main__":
    # Windows consoles default to cp1252, which cannot print "✓" / "×".
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    run_benchmark()
