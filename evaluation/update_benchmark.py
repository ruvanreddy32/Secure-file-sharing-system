"""
evaluation/update_benchmark.py — Whole-file updates (paper workflow, RCF1) vs block-level updates
(ENHANCEMENT, RCB1) on IDENTICAL plaintext files.

Scenario "edit-1-block": overwrite 16 bytes inside one 4096-byte block (middle of the file).
    RCF1: VersionedRepository.update   -> verify current version, re-encrypt + re-hash + re-sign +
                                          re-upload the whole file (paper's Setup phase on N+1)
    RCB1: VersionedRepository.block_patch -> authenticate signed MHT, re-encrypt the 1 block,
                                          merkle/updater.py path update, upload block + MHT
Scenario "edit-8-blocks": overwrite 16 bytes in 8 evenly spaced blocks.
    RCF1: update (as above)
    RCB1: block_patch_many -> the 8 blocks are read, re-encrypted and uploaded as ONE version
Scenario "edit-8-blocks-sync": same edits, but the owner only has the new file.
    RCF1: update (as above)
    RCB1: block_sync -> download + verify ALL blocks, diff, upload only the 8 changed blocks

Measured per update (median over --reps): wall time; plaintext bytes AES-encrypted; ciphertext
bytes SHA-256-hashed and number of SHA-256 operations (leaves + internal nodes); logical storage
operations and bytes (CountingStorage); for Supabase also real HTTP requests incl. upload
read-backs and retries.  Every run checks that both files decrypt to the same expected content.

    python -m evaluation.update_benchmark                              # local folder
    python -m evaluation.update_benchmark --backend supabase --sizes 65536,262144,1048576 --reps 3
    python -m evaluation.update_benchmark --plot-only
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List

from evaluation.paper_benchmark import INK2, SERIES, SURFACE, GRID, _style, environment
from securecloud import blockmode, envfile, mht, rlwe, signature, storage, workflow
from securecloud.versioning import VersionedRepository

OUT = Path(__file__).resolve().parent / "results"
BS = blockmode.BLOCK_SIZE
MODES = {"RCF1": "whole-file update (paper)", "RCB1": "block-level update (enhancement)"}


def _tree_nodes(n_leaves: int) -> int:
    from merkle.tree import MerkleTree
    return sum(len(l) for l in MerkleTree.from_leaf_hashes(["0" * 64] * n_leaves, BS).level_hashes())


def _edit(data: bytes, offsets: List[int], rnd: bytes) -> bytes:
    out = bytearray(data)
    for o in offsets:
        out[o:o + 16] = rnd
    return bytes(out)


def run(backend: str, sizes: List[int], reps: int, location: str = None) -> List[Dict]:
    owner = signature.generate_keypair()
    user_rl, owner_rl = rlwe.generate_keypair(), rlwe.generate_keypair()
    tmp = tempfile.mkdtemp()
    base = storage.LocalFolderStorage(Path(tmp) / "cloud") if backend == "local" \
        else storage.open_storage(backend, location)
    if isinstance(base, storage.SupabaseStorage):
        print("[supabase]", base.ensure_bucket(create=False))
    counter = storage.CountingStorage(base)
    repo = VersionedRepository(counter)
    rows: List[Dict] = []
    for size in sizes:
        n = blockmode.block_count_for(size)
        data = os.urandom(size)
        tag = os.urandom(3).hex()
        wf, bm = f"bench-wf-{size}-{tag}.bin", f"bench-bm-{size}-{tag}.bin"
        bundle, _ = workflow.setup_phase(data, wf, owner, user_rl.public)
        repo.publish(bundle, owner)
        bbundle, _ = blockmode.block_setup_phase(data, bm, owner, user_rl.public, owner_rl.public)
        repo.publish(bbundle, owner)
        cur = data
        try:
            for scenario, k in (("edit-1-block", 1), ("edit-8-blocks", min(8, n)),
                                ("edit-8-blocks-sync", min(8, n))):
                offsets = sorted({((i * n) // k) * BS + 100 for i in range(k)}) if k > 1 \
                    else [(n // 2) * BS + 100]
                for rep in range(reps):
                    new = _edit(cur, offsets, os.urandom(16))
                    # ---- whole-file (paper) ----
                    counter.reset()
                    t0 = time.perf_counter()
                    repo.update(wf, new, owner, user_rl.public)
                    wall = (time.perf_counter() - t0) * 1000
                    enc = size + 32
                    nodes = _tree_nodes(-(-enc // BS))
                    rows.append(dict(backend=backend, size_bytes=size, blocks=n, scenario=scenario,
                                     mode="RCF1", rep=rep, wall_ms=wall,
                                     plaintext_bytes_encrypted=size,
                                     ciphertext_bytes_hashed=2 * enc,       # verify current + build new
                                     sha256_ops=2 * nodes, metadata_nodes=nodes, **counter.snapshot()))
                    # ---- block-level (enhancement) ----
                    counter.reset()
                    t0 = time.perf_counter()
                    if scenario == "edit-1-block":
                        _, st = repo.block_patch(bm, offsets[0], new[offsets[0]:offsets[0] + 16], owner, owner_rl)
                        verify_hash_bytes, verify_ops = 0, 0
                    elif scenario == "edit-8-blocks":
                        _, st = repo.block_patch_many(bm, [(o, new[o:o + 16]) for o in offsets], owner, owner_rl)
                        verify_hash_bytes, verify_ops = 0, 0
                    else:
                        _, st = repo.block_sync(bm, new, owner, owner_rl)
                        verify_hash_bytes, verify_ops = size + n * blockmode.OVERHEAD, _tree_nodes(n)
                    wall = (time.perf_counter() - t0) * 1000
                    reads = st.get("blocks_read_for_partial_writes", 0)
                    rows.append(dict(backend=backend, size_bytes=size, blocks=n, scenario=scenario,
                                     mode="RCB1", rep=rep, wall_ms=wall,
                                     plaintext_bytes_encrypted=st["plaintext_bytes_encrypted"],
                                     ciphertext_bytes_hashed=st["ciphertext_bytes_hashed"]
                                     + reads * (BS + blockmode.OVERHEAD) + verify_hash_bytes,
                                     sha256_ops=st["sha256_leaf_hashes"] + st["sha256_internal_hashes"]
                                     + reads + verify_ops, metadata_nodes=st["metadata_nodes"],
                                     **counter.snapshot()))
                    cur = new
                # correctness: both formats decrypt to the same expected content
                for name in (wf, bm):
                    b, r = repo.fetch_verified(name, owner.public_key())
                    assert r.ok and workflow.decrypt_verified(b, r, user_rl) == cur, name
                print(f"[{backend}] {size:>9} B  {scenario:<14} done ({reps} reps)", flush=True)
        finally:
            for name in (wf, bm):
                try:
                    repo.delete(name, owner)
                except Exception as exc:  # noqa: BLE001
                    print("cleanup failed:", exc)
    return rows


def summarize(rows: List[Dict]) -> List[Dict]:
    keys = sorted({(r["backend"], r["size_bytes"], r["scenario"], r["mode"]) for r in rows})
    out = []
    for b, size, sc, mode in keys:
        sel = [r for r in rows if (r["backend"], r["size_bytes"], r["scenario"], r["mode"]) == (b, size, sc, mode)]
        agg = {"backend": b, "size_bytes": size, "blocks": sel[0]["blocks"], "scenario": sc, "mode": mode,
               "reps": len(sel)}
        numeric = dict.fromkeys(k for r in sel for k, v in r.items()
                                if k not in agg and k != "rep" and isinstance(v, (int, float)))
        for k in numeric:
            agg[k if k != "wall_ms" else "wall_ms_median"] = statistics.median(r.get(k, 0) for r in sel)
        out.append(agg)
    return out


def write_csv(path: Path, rows: List[Dict]) -> None:
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, restval=0)
        w.writeheader()
        w.writerows(rows)


def _size_label(kib: float) -> str:
    return f"{kib / 1024:g} MiB" if kib >= 1024 else f"{kib:g} KiB"


def _num(v: float, _pos=None) -> str:
    for div, unit in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if v >= div:
            return f"{v / div:g}{unit}"
    return f"{v:g}"


def plot(summary: List[Dict], outdir: Path) -> List[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import ticker
    made = []
    colors = {"RCF1": SERIES["4096"], "RCB1": SERIES["paper"]}
    for backend in sorted({r["backend"] for r in summary}):
        for metric, label, fname, logy in (
                ("wall_ms_median", "median wall time per update (ms)", "time", True),
                ("bytes_uploaded", "bytes uploaded per update", "upload", True),
                ("plaintext_bytes_encrypted", "plaintext bytes AES-encrypted per update", "encrypt", True)):
            fig, axes = plt.subplots(1, 2, figsize=(11, 3.8), facecolor=SURFACE)
            # (the third scenario, edit-8-blocks-sync, is reported in the CSV / PERFORMANCE_RESULTS)
            for ax, sc in zip(axes, ("edit-1-block", "edit-8-blocks")):
                xs_all = set()
                for mode in ("RCF1", "RCB1"):
                    pts = sorted((r["size_bytes"], r[metric]) for r in summary
                                 if r["backend"] == backend and r["scenario"] == sc and r["mode"] == mode)
                    if not pts:
                        continue
                    xs = [p[0] / 1024 for p in pts]
                    xs_all.update(xs)
                    ax.plot(xs, [max(p[1], 1e-3) for p in pts], color=colors[mode], linewidth=2,
                            marker="o", markersize=5, label=MODES[mode])
                _style(ax, f"{sc} — {backend}", "file size (log scale)", label + (" — log scale" if logy else ""))
                ax.set_xscale("log", base=2)
                ax.xaxis.set_major_locator(ticker.FixedLocator(sorted(xs_all)))
                ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _p: _size_label(v)))
                ax.xaxis.set_minor_locator(ticker.NullLocator())
                if logy:
                    ax.set_yscale("log")
                    ax.yaxis.set_major_locator(ticker.LogLocator(base=10, subs=(1, 2, 5)))
                    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_num))
                    ax.yaxis.set_minor_locator(ticker.NullLocator())
                    lo = min(l.get_ydata().min() for l in ax.get_lines())
                    hi = max(l.get_ydata().max() for l in ax.get_lines())
                    ax.set_ylim(lo / 1.6, hi * 1.6)
                ax.grid(axis="y", color=GRID, linewidth=0.8, which="major")
                ax.legend(frameon=False, fontsize=8, labelcolor=INK2, ncol=2, loc="lower left",
                          bbox_to_anchor=(0, 1.0), borderaxespad=0.2)
            fig.tight_layout()
            p = outdir / f"update_{fname}_{backend}.png"
            fig.savefig(p, dpi=150, facecolor=SURFACE, bbox_inches="tight")
            plt.close(fig)
            made.append(p)
    return made


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=storage.BACKENDS, default="local")
    ap.add_argument("--location")
    ap.add_argument("--sizes", default="65536,262144,1048576,4194304,16777216")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--plot-only", action="store_true")
    args = ap.parse_args(argv)
    envfile.load()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.plot_only:
        rows = run(args.backend, [int(s) for s in args.sizes.split(",")], args.reps, args.location)
        write_csv(OUT / f"update_benchmark_raw_{args.backend}.csv", rows)
        write_csv(OUT / f"update_benchmark_{args.backend}.csv", summarize(rows))
        env = environment()
        env.update(backend=args.backend, reps=str(args.reps), sizes=args.sizes)
        (OUT / f"update_benchmark_env_{args.backend}.json").write_text(json.dumps(env, indent=2))
    summary = []
    for f in sorted(OUT.glob("update_benchmark_*.csv")):
        if "_raw_" in f.name:
            continue
        for r in csv.DictReader(f.open()):
            summary.append({k: (v if k in ("backend", "scenario", "mode") else float(v or 0))
                            for k, v in r.items()})
    for p in plot(summary, OUT):
        print("wrote", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
