"""
evaluation/paper_benchmark.py — Reproduction of the paper's performance analysis (§VI).

Experiment 1 (Table I, Figs. 5–6): text files of 10, 20, 50, 100, 150, 200, 250, 500,
    750 and 1000 KB (KB = 1024 bytes): Setup-phase time and Integrity-Verification time.
Experiment 2 (Table II, Figs. 7–8): Text, Audio, Video, Image, Document, PDF and Excel
    files of ~100 KB each: Setup-phase time and Integrity-Verification time.

Both experiments run in two MHT blocking modes:
    "4096"  : 4096-byte blocks (default of this implementation)
    "paper" : 2 blocks / 3-node tree (paper §V-C(2))

Measured per run (time.perf_counter, milliseconds):
    setup  : aes_encrypt, rlwe_key_encrypt, sha256_block_hashing, mht_construction,
             mht_file_write, rsa_sign, total_setup
    verify : rsa_verify, mht_parse, sha256_block_hashing, mht_construction, mht_compare,
             total_verify
    decrypt: rlwe_key_decrypt, aes_decrypt
    (optional --dropbox) upload and download of the three files via the real Dropbox API

Each configuration: WARMUP discarded runs, then RUNS timed runs; the median is reported
(plus mean / std / min / max in the CSV).  Keys are generated once (timed separately).

Usage:
    python -m evaluation.paper_benchmark                 # local (no network)
    python -m evaluation.paper_benchmark --dropbox       # also time real Dropbox transfers
    python -m evaluation.paper_benchmark --runs 50
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from evaluation.sample_files import FILE_TYPES, make_file, make_text
from securecloud import rlwe, signature, workflow

OUT = Path(__file__).resolve().parent / "results"
SIZES_KB = [10, 20, 50, 100, 150, 200, 250, 500, 750, 1000]          # Table I
TYPE_SIZE = 100 * 1024                                                # Table II

# Approximate values READ BY EYE from the published Figs. 5–8 (no tables of numbers
# are given in the paper).  Java 1.8, Windows 7, Core i3 2.40 GHz, 4 GB RAM.
PAPER_FIG5_SETUP_MS = dict(zip(SIZES_KB, [2740, 2450, 2640, 2720, 2710, 2350, 2290, 2420, 2290, 2500]))
PAPER_FIG6_VERIFY_MS = dict(zip(SIZES_KB, [3540, 3720, 3610, 3910, 3890, 3650, 3910, 3630, 3550, 3660]))
PAPER_FIG7_SETUP_MS = dict(zip(FILE_TYPES, [3100, 2560, 2620, 2580, 2540, 2620, 2890]))
PAPER_FIG8_VERIFY_MS = dict(zip(FILE_TYPES, [3490, 3700, 3410, 3170, 3230, 3500, 3120]))


def environment() -> Dict[str, str]:
    import cryptography
    import numpy
    info = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": str(os.cpu_count()),
        "cryptography": cryptography.__version__,
        "numpy": numpy.__version__,
    }
    try:
        import dropbox
        info["dropbox_sdk"] = dropbox.__version__
    except Exception:  # pragma: no cover
        pass
    return info


def run_once(data: bytes, name: str, keys_, paper_mode: bool, store=None) -> Dict[str, float]:
    owner_rsa, recipient = keys_
    bundle, t = workflow.setup_phase(data, name, owner_rsa, recipient.public, paper_mode=paper_mode)
    row = {f"setup.{k}": v for k, v in t.items()}
    if store is not None:
        up = workflow.upload_bundle(store, bundle)
        row["net.upload_total_ms"] = sum(up.values())
        bundle, dl_ms = workflow.download_bundle(store, name)
        row["net.download_total_ms"] = dl_ms
    report = workflow.verify_integrity(bundle, owner_rsa.public_key())
    if not report.ok:
        raise RuntimeError(f"verification unexpectedly failed for {name}: {report.summary}")
    row.update({f"verify.{k}": v for k, v in report.timings_ms.items()})
    dec_t: Dict[str, float] = {}
    out = workflow.decrypt_verified(bundle, report, recipient, dec_t)
    if out != data:
        raise RuntimeError(f"decryption mismatch for {name}")
    row.update({f"decrypt.{k}": v for k, v in dec_t.items()})
    row["decrypt.total_ms"] = sum(dec_t.values())
    row["block_count"] = report.block_count
    return row


def measure(data: bytes, name: str, keys_, paper_mode: bool, runs: int, warmup: int, store=None):
    for _ in range(warmup):
        run_once(data, name, keys_, paper_mode, store)
    samples = [run_once(data, name, keys_, paper_mode, store) for _ in range(runs)]
    stats: Dict[str, float] = {"block_count": samples[0]["block_count"]}
    for key in samples[0]:
        if key == "block_count":
            continue
        vals = [s[key] for s in samples]
        stats[f"{key}.median"] = statistics.median(vals)
        stats[f"{key}.mean"] = statistics.fmean(vals)
        stats[f"{key}.std"] = statistics.pstdev(vals)
        stats[f"{key}.min"] = min(vals)
        stats[f"{key}.max"] = max(vals)
    return stats


def write_csv(path: Path, rows: List[Dict]) -> None:
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------- plots
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES = {"4096": "#2a78d6", "paper": "#eb6834"}          # categorical slots 1, 2
LABEL = {"4096": "this work, 4096-B blocks", "paper": "this work, paper mode (2 blocks)"}
PAPER_INK = "#52514e"


def _style(ax, title, xlabel, ylabel):
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=INK, fontsize=11, fontweight="semibold", pad=24)
    ax.set_xlabel(xlabel, color=INK2, fontsize=9)
    ax.set_ylabel(ylabel, color=INK2, fontsize=9)
    ax.tick_params(colors=INK2, labelsize=8, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.set_ylim(0, ax.get_ylim()[1] * 1.06)


def plot_all(size_rows, type_rows, outdir: Path) -> List[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    made = []

    def save(fig, fname):
        p = outdir / fname
        fig.savefig(p, dpi=150, facecolor=SURFACE, bbox_inches="tight")
        plt.close(fig)
        made.append(p)

    for metric, paper_vals, fig_no, what in (
            ("setup.total_setup_ms", PAPER_FIG5_SETUP_MS, 5, "Setup phase"),
            ("verify.total_verify_ms", PAPER_FIG6_VERIFY_MS, 6, "Integrity verification")):
        fig, (ax_new, ax_old) = plt.subplots(1, 2, figsize=(11, 3.8), facecolor=SURFACE)
        for mode in ("4096", "paper"):
            rows = [r for r in size_rows if r["mode"] == mode]
            xs = [r["size_kb"] for r in rows]
            ys = [r[f"{metric}.median"] for r in rows]
            ax_new.plot(xs, ys, color=SERIES[mode], linewidth=2, marker="o", markersize=5,
                        label=LABEL[mode])
            ax_new.annotate(LABEL[mode].replace("this work, ", ""), (xs[-1], ys[-1]),
                            xytext=(4, 0), textcoords="offset points", color=INK2, fontsize=8,
                            va="center")
        _style(ax_new, f"{what} time vs file size — measured (this work)", "file size (KB)",
               "median time (ms)")
        ax_new.legend(frameon=False, fontsize=8, labelcolor=INK2, ncol=2, loc="lower left",
                      bbox_to_anchor=(0, 1.0), borderaxespad=0.2)
        ax_old.plot(list(paper_vals), list(paper_vals.values()), color=PAPER_INK, linewidth=2,
                    marker="o", markersize=5, linestyle="--")
        _style(ax_old, f"Paper Fig. {fig_no} (approx., read from published plot)",
               "file size (KB)", "time (ms)")
        fig.tight_layout()
        save(fig, f"fig{fig_no}_{'setup' if fig_no == 5 else 'verify'}_vs_size.png")

    kinds = list(FILE_TYPES)
    for metric, paper_vals, fig_no, what in (
            ("setup.total_setup_ms", PAPER_FIG7_SETUP_MS, 7, "Setup phase"),
            ("verify.total_verify_ms", PAPER_FIG8_VERIFY_MS, 8, "Integrity verification")):
        fig, (ax_new, ax_old) = plt.subplots(1, 2, figsize=(11, 3.8), facecolor=SURFACE)
        width = 0.38
        for j, mode in enumerate(("4096", "paper")):
            rows = {r["type"]: r for r in type_rows if r["mode"] == mode}
            xs = [i + (j - 0.5) * (width + 0.02) for i in range(len(kinds))]
            ax_new.bar(xs, [rows[k][f"{metric}.median"] for k in kinds], width=width,
                       color=SERIES[mode], label=LABEL[mode], edgecolor=SURFACE, linewidth=1)
        ax_new.set_xticks(range(len(kinds)), kinds)
        _style(ax_new, f"{what} time by file type (~100 KB) — measured", "file type",
               "median time (ms)")
        ax_new.legend(frameon=False, fontsize=8, labelcolor=INK2, ncol=2, loc="lower left",
                      bbox_to_anchor=(0, 1.0), borderaxespad=0.2)
        ax_old.bar(range(len(kinds)), list(paper_vals.values()), width=0.6, color="#a8a7a2",
                   edgecolor=SURFACE)
        ax_old.set_xticks(range(len(kinds)), kinds)
        _style(ax_old, f"Paper Fig. {fig_no} (approx., read from published plot)", "file type",
               "time (ms)")
        fig.tight_layout()
        save(fig, f"fig{fig_no}_{'setup' if fig_no == 7 else 'verify'}_vs_type.png")

    # Stage breakdown for the largest file (single series -> single hue, sorted)
    big = next(r for r in size_rows if r["mode"] == "4096" and r["size_kb"] == max(SIZES_KB))
    stages = {
        "AES-256 encrypt": "setup.aes_encrypt_ms", "Ring-LWE key encrypt": "setup.rlwe_key_encrypt_ms",
        "SHA-256 block hashing (setup)": "setup.sha256_block_hashing_ms",
        "MHT construction (setup)": "setup.mht_construction_ms", "RSA sign": "setup.rsa_sign_ms",
        "RSA verify": "verify.rsa_verify_ms",
        "SHA-256 block hashing (verify)": "verify.sha256_block_hashing_ms",
        "MHT construction (verify)": "verify.mht_construction_ms",
        "MHT compare": "verify.mht_compare_ms",
        "Ring-LWE key decrypt": "decrypt.rlwe_key_decrypt_ms", "AES-256 decrypt": "decrypt.aes_decrypt_ms",
    }
    items = sorted(((lbl, big[f"{k}.median"]) for lbl, k in stages.items()), key=lambda x: x[1])
    fig, ax = plt.subplots(figsize=(8, 4.2), facecolor=SURFACE)
    ax.barh([i[0] for i in items], [i[1] for i in items], color=SERIES["4096"], height=0.6)
    for y, (_lbl, v) in enumerate(items):
        ax.text(v, y, f" {v:.2f} ms", va="center", color=INK2, fontsize=8)
    _style(ax, f"Per-stage time, {max(SIZES_KB)} KB text file (4096-B blocks)", "median time (ms)", "")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(v for _, v in items) * 1.25)
    ax.set_ylim(-0.6, len(items) - 0.4)
    ax.set_title(ax.get_title(loc="left"), loc="left", color=INK, fontsize=11,
                 fontweight="semibold", pad=8)
    fig.tight_layout()
    save(fig, "stage_breakdown_1000kb.png")
    return made


def load_csv(path: Path) -> List[Dict]:
    rows = list(csv.DictReader(path.open()))
    for r in rows:
        for k, v in r.items():
            if k in ("experiment", "mode", "type", "file"):
                continue
            r[k] = float(v) if "." in v else int(v)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--dropbox", action="store_true", help="also time real Dropbox upload/download")
    ap.add_argument("--rlwe-params", default=rlwe.DEFAULT_PARAMS, choices=sorted(rlwe.PARAMS))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--plot-only", action="store_true", help="re-draw figures from existing CSVs")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    if args.plot_only:
        for p in plot_all(load_csv(outdir / "table1_sizes.csv"), load_csv(outdir / "table2_types.csv"), outdir):
            print("wrote", p)
        return 0

    store = None
    if args.dropbox:
        from securecloud.storage import DropboxStorage
        store = DropboxStorage(os.environ.get("DROPBOX_BENCH_FOLDER", "/RingCrypter-bench"))
        print("Dropbox account:", store.check_account())

    t0 = time.perf_counter()
    owner_rsa = signature.generate_keypair()
    t_rsa = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    recipient = rlwe.generate_keypair(args.rlwe_params)
    t_rlwe = (time.perf_counter() - t0) * 1000
    keys_ = (owner_rsa, recipient)
    env = environment()
    env.update({"runs": str(args.runs), "warmup": str(args.warmup), "rlwe_params": args.rlwe_params,
                "rsa_bits": str(owner_rsa.key_size), "network": "dropbox" if store else "none (local)",
                "keygen_rsa3072_ms": f"{t_rsa:.1f}", "keygen_rlwe_ms": f"{t_rlwe:.2f}"})
    print(json.dumps(env, indent=2))

    size_rows, type_rows = [], []
    for mode in ("4096", "paper"):
        for kb in SIZES_KB:
            data = make_text(kb * 1024, seed=kb)
            s = measure(data, f"text_{kb}kb.txt", keys_, mode == "paper", args.runs, args.warmup, store)
            size_rows.append({"experiment": "TableI", "mode": mode, "size_kb": kb, "bytes": len(data), **s})
            print(f"[{mode:>5}] {kb:>5} KB  setup {s['setup.total_setup_ms.median']:8.3f} ms   "
                  f"verify {s['verify.total_verify_ms.median']:8.3f} ms   blocks {s['block_count']}")
        for kind in FILE_TYPES:
            name, data = make_file(kind, TYPE_SIZE)
            s = measure(data, name, keys_, mode == "paper", args.runs, args.warmup, store)
            type_rows.append({"experiment": "TableII", "mode": mode, "type": kind, "file": name,
                              "bytes": len(data), **s})
            print(f"[{mode:>5}] {kind:>9} ({len(data)} B)  setup {s['setup.total_setup_ms.median']:8.3f} ms"
                  f"   verify {s['verify.total_verify_ms.median']:8.3f} ms")

    write_csv(outdir / "table1_sizes.csv", size_rows)
    write_csv(outdir / "table2_types.csv", type_rows)
    (outdir / "environment.json").write_text(json.dumps(env, indent=2))
    for p in plot_all(size_rows, type_rows, outdir):
        print("wrote", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
