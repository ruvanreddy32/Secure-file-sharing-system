# Ring Crypter: Integrity Verification of Files Uploaded to Cloud Storage

An implementation of the IEEE paper

> P. Parida, S. Konhar, B. Mishra, D. Jena, **"Design and Implementation of an Efficient Tool to
> Verify Integrity of Files Uploaded to Cloud Storage"**, 7th International Conference on
> Communication Systems and Network Technologies (CSNT 2017), pp. 62–66.
> DOI [10.1109/CSNT.2017.13](https://doi.org/10.1109/CSNT.2017.13) ·
> [IEEE Xplore 8418512](https://ieeexplore.ieee.org/document/8418512)

built on top of the Merkle-tree repository
[MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees](https://github.com/MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees).
The repository's Merkle tree (`merkle/`), visualizer (`app.py`) and benchmark are kept; the
paper's encryption, signature, cloud, and verification workflow is added in `securecloud/`.

| Document | Contents |
|---|---|
| [RESEARCH_GAP_ANALYSIS.md](RESEARCH_GAP_ANALYSIS.md) | paper vs. original repository, before any change |
| [PAPER_IMPLEMENTATION_MAPPING.md](PAPER_IMPLEMENTATION_MAPPING.md) | every paper component → file / function |
| [TEST_RESULTS.md](TEST_RESULTS.md) | 208 passed, 1 skipped (live Dropbox) |
| [PERFORMANCE_RESULTS.md](PERFORMANCE_RESULTS.md) | reproduction of Tables I–II / Figs. 5–8 |
| [IMPLEMENTATION_LIMITATIONS.md](IMPLEMENTATION_LIMITATIONS.md) | deviations, assumptions, unverified parts |

> **Status of the Dropbox integration:** implemented with the official SDK and tested against a
> fake SDK client, but **not yet verified against the real Dropbox service** (no credentials were
> available). Run the live test in [Configure Dropbox](#configure-dropbox) to verify it.

## System architecture (paper §IV, Figs. 2–3)

```
 OWNER                                                        CLOUD (Dropbox)
 ─────                                                        ───────────────
 file ──AES-256-GCM(K)──────────────► <name>.aes ───────────┐
 K ────Ring-LWE(recipient pk)───────► <name>.key.rlwe ──────┼──► upload (each upload confirmed
 <name>.aes ─blocks─SHA-256─► MHT ──► MHT file              │     by Dropbox content_hash)
 MHT file ──RSA-PSS sign(Kpri)──────► <name>.mht.signed ────┘

 USER                                                                         
 ────                                                                         
 download 3 files
   (2a) verify RSA signature of <name>.mht.signed with Kpub ── fail ─► STOP (no decryption)
   (1)  re-run Setup: blocks → SHA-256 → MHT of downloaded <name>.aes
   (2b) compare recomputed MHT with signed MHT (all nodes, file name, key-file hash)
          └─ mismatch ─► STOP, report modified block indices
   ok ─► Ring-LWE decrypt K ─► AES-256-GCM decrypt ─► original file
```

## Algorithms implemented

| Paper element | Implementation |
|---|---|
| AES-256 file encryption | AES-256-**GCM**, random 96-bit nonce, 256-bit key from the OS CSPRNG (`securecloud/aes_cipher.py`) |
| Ring-LWE encryption of the file key (Mishra & Jena [24], LPR [25]) | LPR ring-LWE in Z_q[x]/(xⁿ+1): `p = r1 − a·r2`; `c1 = a·e1 + e2`, `c2 = p·e1 + e3 + m̄`; `m′ = c1·r2 + c2`. Parameter sets **P1 (256, 7681, 11.31/√2π)** and **P2 (512, 12289, 12.18/√2π)** (de Clercq et al., DATE 2015); discrete Gaussian sampler; 2-coefficient bit encoding (`securecloud/rlwe.py`) |
| SHA-256 block hashing, hex | `hashlib.sha256(block).hexdigest()` over the **encrypted** file |
| Merkle Hash Tree | parent = SHA-256(hex(left) ‖ hex(right)) up to one root (`merkle/tree.py`, original repo). 4096-byte blocks by default; `--paper-mode` gives the paper's 2-leaf / 3-node tree |
| MHT file | text file with every node hash in hex, plus block parameters (`securecloud/mht.py`) |
| RSA digital signature | RSA-3072, RSASSA-PSS-SHA256 over the exact MHT-file bytes → signed MHT file (`securecloud/signature.py`) |
| Integrity verification | signature check → MHT regeneration → node-by-node comparison → modified-block localization (`securecloud/workflow.py`) |
| Decrypt only after verification | `decrypt_verified` refuses unless given a successful report bound (by SHA-256) to the exact downloaded bytes |
| Cloud storage | Dropbox via the official `dropbox` SDK; offline local-folder backend (not cloud) (`securecloud/storage.py`) |

## Installation

Requirements: Python ≥ 3.10 (developed and tested on CPython 3.14.4, Windows 11).

```bash
pip install -r requirements.txt
# optional, only used by tests to validate generated sample files:
pip install pillow pypdf
```

## Quick start (no cloud account needed)

```bash
python -m securecloud demo
```

This generates temporary keys, runs the owner's Setup phase, uploads to a **local folder**,
downloads, verifies, and decrypts. It then flips one byte of the stored ciphertext and shows that
verification fails and decryption is refused.

## How to use: command line (paper Fig. 4 actions)

```bash
# 1. Keys (once). Private keys go to keys/ (git-ignored). Share only *_public files.
python -m securecloud keygen --name owner                 # RSA (signing) + Ring-LWE
python -m securecloud keygen --name user --rlwe-params P2 # recipient
#    optional: protect private keys with a passphrase held in an env var
#    set RC_PASS=...   then add --passphrase-env RC_PASS

# 2. Owner: "Encrypt to Local Storage" (writes data.txt.aes / .key.rlwe / .mht.signed)
python -m securecloud encrypt data.txt --signer-key keys/owner_rsa_private.pem \
       --recipient-key keys/user_rlwe_public.json --out-dir encrypted [--paper-mode]

# 2'. Owner: "Upload to DropBox"
python -m securecloud upload data.txt --signer-key keys/owner_rsa_private.pem \
       --recipient-key keys/user_rlwe_public.json --backend dropbox

# 3. User: integrity check only
python -m securecloud verify data.txt --signer-pub keys/owner_rsa_public.pem --backend dropbox

# 4. User: "Decrypt from DropBox" / "Decrypt Locally" (always verifies first)
python -m securecloud decrypt data.txt --signer-pub keys/owner_rsa_public.pem \
       --rlwe-key keys/user_rlwe_private.json --backend dropbox --out restored.txt
python -m securecloud decrypt data.txt --signer-pub keys/owner_rsa_public.pem \
       --rlwe-key keys/user_rlwe_private.json --from-dir encrypted --out restored.txt

# Demonstrate tamper detection on a local copy
python -m securecloud tamper encrypted/data.txt.aes --offset 5000
python -m securecloud decrypt data.txt ... --from-dir encrypted   # exit code 2, nothing written

python -m securecloud list --backend dropbox
```

Use `--backend local --location <folder>` for an offline folder instead of Dropbox. Exit codes:
`0` success, `2` integrity verification failed (no decryption), `1` other error.

## How to use: web UI

```bash
streamlit run app.py
```

* **Ring Crypter Secure Cloud** page (sidebar): generate/load keys; tab 1, the owner protects a
  file and saves or uploads it; tab 2, the user downloads, verifies (signature / MHT / key-file
  status, modified blocks, timings) and decrypts (the button is disabled unless verification
  passed); tab 3 simulates attacks on the stored copy.
* **app** page: the original interactive Merkle-tree visualizer (see below).

## Configure Dropbox

1. Create an app at <https://www.dropbox.com/developers/apps> (Scoped access, *App folder* is
   enough) and enable the permissions `files.content.write`, `files.content.read`,
   `files.metadata.read`.
2. Get a long-lived refresh token (PKCE flow, nothing is stored by the tool):
   ```bash
   set DROPBOX_APP_KEY=<app key>            # PowerShell: $env:DROPBOX_APP_KEY="<app key>"
   python -m securecloud dropbox-auth       # open the URL, approve, paste the code
   ```
3. Set the environment variables (never commit them; `.env` files are git-ignored):

   | Variable | Required | Meaning |
   |---|---|---|
   | `DROPBOX_REFRESH_TOKEN` | yes* | from step 2 |
   | `DROPBOX_APP_KEY` | yes* | app key |
   | `DROPBOX_APP_SECRET` | no | only for non-PKCE apps |
   | `DROPBOX_ACCESS_TOKEN` | alt.* | short-lived token instead of the refresh token |
   | `DROPBOX_FOLDER` | no | remote folder, default `/RingCrypter` |

4. Verify the real integration end to end:
   ```bash
   python -m pytest -m dropbox_live -v          # upload → download → verify → decrypt → tamper
   python -m securecloud demo --backend dropbox
   python -m evaluation.paper_benchmark --dropbox   # includes network timings
   ```

## Testing

```bash
python -m pytest              # 208 passed, 1 skipped (live Dropbox without credentials)
python -m pytest -m "not slow"
python -m pytest -m dropbox_live -v
```

## Performance evaluation (paper §VI)

```bash
python -m evaluation.paper_benchmark --runs 30   # Table I sizes + Table II types → evaluation/results/
python -m evaluation.rlwe_failure_rate           # Ring-LWE decryption-failure study
```

Results, graphs and the comparison with the paper are in
[PERFORMANCE_RESULTS.md](PERFORMANCE_RESULTS.md).

## Project structure

```
merkle/                 (original) Merkle tree: chunker, node, tree*, proof, tamper, updater
securecloud/            (new) paper implementation
    aes_cipher.py       AES-256-GCM
    rlwe.py             Ring-LWE (LPR) key encryption, P1/P2
    mht.py              MHT of the ciphertext, MHT text file, comparison
    signature.py        RSA-PSS, signed MHT file
    keys.py             identity generation / loading
    storage.py          Dropbox (official SDK) + local folder
    workflow.py         setup phase, verification, gated decryption
    cli.py              "Ring Crypter" CLI (python -m securecloud)
pages/1_Ring_Crypter_Secure_Cloud.py   (new) Streamlit page for the workflow
app.py                  (original) Streamlit Merkle visualizer
benchmark.py            (original) full-hash vs proof benchmark (*Windows fix)
evaluation/             (new) sample-file generator, paper benchmark, results/
tests/                  original 67 tests + 142 new
```
`*` = original file, extended (`MerkleTree.from_leaf_hashes`, `level_hashes`).

---

## Original repository: Merkle tree features (kept)

The original project implements a binary Merkle hash tree for O(log n) file integrity
verification, with a live Streamlit visualizer powered by Pyvis.

| Feature | Details |
|---|---|
| Block-level hashing | Fixed-size blocks (configurable, default 4 KB), no padding |
| O(log n) verification | Proof path from leaf to root; single block proven without reading others |
| Tamper localization | Exact block index returned by recursive tree comparison |
| O(log n) updates | Only rehash modified leaf + ancestors (not full tree) |
| Interactive demo | Pyvis tree with hover tooltips, drag/zoom, colour-coded paths |
| Real benchmarks | `python benchmark.py` → `results.csv` (1 / 10 / 100 MB) |

Design decisions (unchanged): odd-leaf duplication (the last node of an odd level is paired with
itself); leaf = `sha256(block)`, internal = `sha256(left_hex + right_hex)`; Pyvis hierarchical
layout with colour coding (blue proof path, cyan siblings, red tampered, green updated, purple
root).

| Operation | Complexity |
|---|---|
| Build tree | O(n) |
| Verify one block | O(log n) |
| Localise tamper | O(k · log n) |
| Update one block | O(log n) |

## Attribution and license

* Merkle-tree code, visualizer and original benchmark: © the authors of
  [MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees](https://github.com/MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees).
  The original repository contains no LICENSE file; confirm redistribution terms with its author.
* Methodology: Parida, Konhar, Mishra & Jena (CSNT 2017). Ring-LWE parameters: de Clercq, Sinha Roy,
  Vercauteren & Verbauwhede (DATE 2015). Ring-LWE scheme: Lyubashevsky, Peikert & Regev.
