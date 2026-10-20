# Ring Crypter: Integrity Verification of Files Uploaded to Cloud Storage

An implementation of the IEEE paper

> P. Parida, S. Konhar, B. Mishra, D. Jena, **"Design and Implementation of an Efficient Tool to
> Verify Integrity of Files Uploaded to Cloud Storage"**, 7th International Conference on
> Communication Systems and Network Technologies (CSNT 2017), pp. 62–66.
> DOI [10.1109/CSNT.2017.13](https://doi.org/10.1109/CSNT.2017.13) ·
> [IEEE Xplore 8418512](https://ieeexplore.ieee.org/document/8418512)

built on top of the Merkle-tree repository
[MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees](https://github.com/MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees).
The repository's Merkle tree (`merkle/`), visualizer (`app.py`) and benchmark are kept. The
paper's encryption, signature, cloud, and verification workflow is added in `securecloud/`.

**Cloud storage:** the paper used Dropbox. This implementation uses **Supabase Storage (Free
plan)** by default, through the official `supabase` Python SDK and a **private** bucket. Dropbox
remains available as an optional backend, and a local folder is available for offline use.

| Document | Contents |
|---|---|
| [RESEARCH_GAP_ANALYSIS.md](RESEARCH_GAP_ANALYSIS.md) | paper vs. original repository, before any change |
| [PAPER_IMPLEMENTATION_MAPPING.md](PAPER_IMPLEMENTATION_MAPPING.md) | every paper component → file / function |
| [TEST_RESULTS.md](TEST_RESULTS.md) | 326 passed, 3 skipped (live cloud tests) |
| [PERFORMANCE_RESULTS.md](PERFORMANCE_RESULTS.md) | reproduction of Tables I–II / Figs. 5–8 |
| [IMPLEMENTATION_LIMITATIONS.md](IMPLEMENTATION_LIMITATIONS.md) | deviations, assumptions, unverified parts |

> **Status of the cloud integration:** the Supabase backend is **verified against a real Supabase
> project**: the live end-to-end tests and `demo --backend supabase` passed (TEST_RESULTS.md §0b).
> Dropbox (optional) is implemented but not verified against the real service.

## System architecture (paper §IV, Figs. 2–3)

```
 OWNER                                                       SUPABASE STORAGE (private bucket)
 ─────                                                       ─────────────────────────────────
 file ──AES-256-GCM(K)─────────────► <name>.aes ──────────┐  <name>/v000001-<id>/<name>.aes
 K ────Ring-LWE(recipient pk)──────► <name>.key.rlwe ─────┼► <name>/v000001-<id>/<name>.key.rlwe
 <name>.aes ─blocks─SHA-256─► MHT ─► MHT file             │  <name>/v000001-<id>/<name>.mht.signed
 MHT file ──RSA-PSS sign(Kpri)─────► <name>.mht.signed ───┘  (each upload confirmed by read-back)
                                     signed manifest ──────► <name>/manifest.signed   (written LAST
                                                                                       = activation)
 USER
 ────
 read + verify the signed manifest (owner key) → pick version → download the 3 objects
   (2a) verify RSA signature of <name>.mht.signed with Kpub ─── fail ─► STOP (no decryption)
   (1)  re-run Setup: blocks → SHA-256 → MHT of the downloaded <name>.aes
   (2b) compare recomputed MHT with signed MHT (all nodes, file name, key-file hash,
        version number, hash-chain link to the previous version)
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
| MHT file | text file with every node hash in hex, plus block parameters, version and chain link (`securecloud/mht.py`) |
| RSA digital signature | RSA-3072, RSASSA-PSS-SHA256 over the exact MHT-file bytes → signed MHT file (`securecloud/signature.py`) |
| Integrity verification | signature check → MHT regeneration → node-by-node comparison → modified-block localization (`securecloud/workflow.py`) |
| Decrypt only after verification | `decrypt_verified` refuses unless given a successful report bound (by SHA-256) to the exact downloaded bytes |
| Cloud storage | Supabase Storage (default, private bucket); Dropbox (optional); local folder (offline) (`securecloud/storage.py`) |
| Versioning + authorized dynamic updates (paper §VII future work) | signed manifest, atomic activation, signed version hash-chain (`securecloud/versioning.py`, `workflow.update_phase`) |
| *Enhancement, not in the paper:* block-level updates | per-block AES-256-GCM format RCB1, `merkle/updater.py` path updates, content-addressed blocks (`securecloud/blockmode.py`) |

## Installation

Requirements: Python ≥ 3.10 (developed and tested on CPython 3.14.4, Windows 11).

```bash
pip install -r requirements.txt
# optional, only used by tests to validate generated sample files:
pip install pillow pypdf
```

## Quick start (no cloud account needed)

```bash
python -m securecloud demo                    # local folder
python -m securecloud demo --backend supabase # the same against your Supabase project
```

The demo runs these steps:
1. Publishes version 1, then verifies and decrypts it.
2. Publishes an **authorized update** (version 2).
3. Simulates an **interrupted upload** of version 3 and shows that it never becomes active.
4. Flips one byte of the stored ciphertext and shows that verification fails and decryption is refused.
5. Deletes everything it created.

## Configure Supabase

1. Create a project at <https://supabase.com> (the Free plan is enough).
2. In the dashboard, open **Project Settings → API Keys** and copy the **Project URL** and a
   **secret / service_role** key.
3. Put the credentials in a **`.env` file in the project folder**. It is git-ignored and loaded
   automatically by the CLI, the Streamlit page and the live tests; real environment variables
   take precedence over it. **Never commit it.**
   ```
   SUPABASE_URL=https://<project-ref>.supabase.co
   SUPABASE_SECRET_KEY=sb_secret_...
   SUPABASE_BUCKET=secure-files
   ```
   Use the **API URL** `https://<project-ref>.supabase.co`, not the dashboard link
   `https://supabase.com/dashboard/project/<project-ref>`; the tool rejects the latter and tells you
   the correct one. You can also set the same variables in the shell
   (`$env:SUPABASE_URL = "..."`).
   (bash: `export SUPABASE_URL=...`). To persist them on Windows, use `setx` or a git-ignored
   `.env` loaded by your shell.

   | Variable | Required | Meaning |
   |---|---|---|
   | `SUPABASE_URL` | yes | project URL |
   | `SUPABASE_SECRET_KEY` | yes* | server-side secret key (`sb_secret_…`), bypasses Row Level Security |
   | `SUPABASE_SERVICE_ROLE_KEY` | alt.* | legacy service_role JWT key |
   | `SUPABASE_KEY` | alt.* | another key whose role has Storage policies on the bucket |
   | `SUPABASE_BUCKET` | no | bucket id, default `ringcrypter` |
   | `SUPABASE_TEST_BUCKET` | no | bucket for live tests, default `ringcrypter-tests` |
   | `RINGCRYPTER_BACKEND` | no | default CLI backend (`supabase`) |

   The service-role key is read **only by the server-side process** (the CLI or the Streamlit
   server) and is never displayed or sent to a browser. Do not put it in any client-side code.
4. Create or check the **private** bucket:
   ```bash
   python -m securecloud supabase-setup      # creates 'ringcrypter' if missing; fails if it is public
   ```
5. Verify the real integration end to end:
   ```bash
   python -m pytest -m supabase_live -v                # real upload/download/update/tamper/delete
   # (set SUPABASE_TEST_BUCKET=secure-files to run in your existing bucket instead of creating 'ringcrypter-tests')
   python -m securecloud demo --backend supabase
   python -m evaluation.paper_benchmark --cloud supabase   # timings incl. network
   ```

Free-plan limits at the time of writing: 1 GB of storage and a 50 MB maximum file size per upload.
Check the current limits in your project settings. Large files therefore fail at upload with a
clear error, and the version is not activated.

## How to use: command line (paper Fig. 4 actions)

Default backend: `supabase`. Pass `--backend dropbox` or `--backend local --location <dir>` for the
other backends.

```bash
# 1. Keys (once). Private keys go to keys/ (git-ignored). Share only *_public files.
python -m securecloud keygen --name owner                 # RSA (signing) + Ring-LWE
python -m securecloud keygen --name user                  # recipient

# 2. Owner: "Upload" -> version 1 (all 3 uploads confirmed, then the manifest activates it)
python -m securecloud upload report.pdf --signer-key keys/owner_rsa_private.pem --recipient-key keys/user_rlwe_public.json

# 3. Owner: authorized dynamic update -> version 2 (current version is verified first)
python -m securecloud update report.pdf --signer-key keys/owner_rsa_private.pem --recipient-key keys/user_rlwe_public.json

# 4. User: list, inspect versions, verify, "Decrypt from cloud" (always verifies first)
python -m securecloud list
python -m securecloud versions report.pdf --signer-pub keys/owner_rsa_public.pem
python -m securecloud verify  report.pdf --signer-pub keys/owner_rsa_public.pem --backend supabase
python -m securecloud decrypt report.pdf --signer-pub keys/owner_rsa_public.pem --backend supabase --rlwe-key keys/user_rlwe_private.json --out restored.pdf
python -m securecloud decrypt report.pdf ... --backend supabase --version 1      # an older version
python -m securecloud decrypt report.pdf ... --backend supabase --min-version 2  # reject rollback

# 5. Owner: housekeeping
python -m securecloud delete  report.pdf --signer-key keys/owner_rsa_private.pem --version 1   # old version
python -m securecloud cleanup report.pdf --signer-pub keys/owner_rsa_public.pem               # interrupted uploads
python -m securecloud delete  report.pdf --signer-key keys/owner_rsa_private.pem               # everything

# Local-only variant: "Encrypt to Local Storage" / "Decrypt Locally"
python -m securecloud encrypt report.pdf --signer-key ... --recipient-key ... --out-dir encrypted
python -m securecloud tamper  encrypted/report.pdf.aes --offset 5000
python -m securecloud decrypt report.pdf --signer-pub ... --rlwe-key ... --from-dir encrypted   # exit 2
```

Exit codes: `0` success, `2` integrity verification failed (nothing decrypted), `1` other error.

## How to use: web UI

```bash
streamlit run app.py
```

Open the **Ring Crypter Secure Cloud** page in the sidebar, then pick the backend (Supabase by
default when credentials are set) and generate or load keys.

* **Tab 1, Owner:** open a file, then **Run Setup phase & publish** as a new file (version 1) or as
  an **update** of an existing file.
* **Tab 2, User:** choose a file and version, **Download & verify integrity** (manifest, signature,
  MHT, version and modified blocks), then **Decrypt**. The button stays disabled unless
  verification passed.
* **Tab 3, Attacker:** flip or truncate the ciphertext, edit or re-sign the MHT, replace the key
  file, publish an **unauthorized update** signed by another key, simulate an **interrupted owner
  upload**, or replay an old manifest.

The **app** page is the original interactive Merkle-tree visualizer.

## Enhancement: block-level dynamic updates (NOT part of the IEEE paper)

The paper encrypts the **whole file** with AES-256 (format `RCF1`). That remains the default and
is unchanged. As an **additional, opt-in** format, `RCB1` applies AES-256-GCM to each 4096-byte
block separately. Each block gets its own random nonce, and its index, file id and version are
bound in the GCM associated data. The signed MHT (v3) binds the file length, block count, version
chain and key files. Editing a block then re-encrypts only that block, updates the Merkle tree
along one path with the original repository's `merkle/updater.py`, re-signs, and uploads only the
changed block plus the signed metadata. Unchanged ciphertext blocks are stored once
(content-addressed) and shared by all versions.

```bash
# owner: publish in per-block format (needs the owner's Ring-LWE public key for its copy of K)
python -m securecloud upload report.pdf --block-mode --signer-key keys/owner_rsa_private.pem \
       --recipient-key keys/user_rlwe_public.json --owner-rlwe-pub keys/owner_rlwe_public.json

# owner: change bytes at an offset / replace block 7 / upload only the blocks that differ
python -m securecloud block-update report.pdf --offset 5000 --text "EDITED" --signer-key keys/owner_rsa_private.pem --owner-rlwe-key keys/owner_rlwe_private.json
python -m securecloud block-update report.pdf --block 7 --data-file new_block.bin --signer-key ... --owner-rlwe-key ...
python -m securecloud block-sync   report.pdf --signer-key ... --owner-rlwe-key ...

# user: exactly as before — verify then decrypt (any version)
python -m securecloud decrypt report.pdf --signer-pub keys/owner_rsa_public.pem --backend supabase --rlwe-key keys/user_rlwe_private.json

python -m securecloud demo-blocks --backend supabase      # end-to-end demo with replay attack
python -m evaluation.update_benchmark                     # whole-file vs block-level (local)
```

Each block update prints the work done: blocks re-encrypted, SHA-256 operations, objects and bytes
uploaded and downloaded, and (on Supabase) the real HTTP requests. In the Streamlit page, choose
**Per-block AES-256-GCM** when publishing a new file and use **Block-level edit**.

**Trade-offs** (details in IMPLEMENTATION_LIMITATIONS.md §4b):
- **Edit locations are visible:** the storage provider can see *which blocks* changed between versions.
- **Metadata is still O(n):** the paper's MHT file lists every node.
- **Full reads are many requests:** reading a whole file means n small object GETs.

Use the paper's whole-file format when the location of edits must stay confidential.

## Dropbox (optional alternative backend)

1. Create an app at <https://www.dropbox.com/developers/apps> (Scoped access) with the
   `files.content.write`, `files.content.read` and `files.metadata.read` permissions.
2. Set `DROPBOX_APP_KEY`, then run `python -m securecloud dropbox-auth` and set the printed
   `DROPBOX_REFRESH_TOKEN`. `DROPBOX_ACCESS_TOKEN` also works.
3. Use `--backend dropbox`, and run `python -m pytest -m dropbox_live -v` to verify.

## Testing

```bash
python -m pytest                        # 326 passed, 3 skipped (live cloud tests without credentials)
python -m pytest -m supabase_live -v    # real Supabase (needs credentials)
python -m pytest -m dropbox_live -v     # real Dropbox  (needs credentials)
```

## Performance evaluation (paper §VI)

```bash
python -m evaluation.paper_benchmark --runs 30          # Table I sizes + Table II types → evaluation/results/
python -m evaluation.paper_benchmark --cloud supabase   # + real network upload/download timings
python -m evaluation.rlwe_failure_rate                  # Ring-LWE decryption-failure study
```

## Project structure

```
merkle/                 (original) Merkle tree: chunker, node, tree*, proof, tamper, updater
securecloud/            (new) paper implementation
    aes_cipher.py       AES-256-GCM
    rlwe.py             Ring-LWE (LPR) key encryption, P1/P2
    mht.py              MHT of the ciphertext, MHT text file (version + chain), comparison
    signature.py        RSA-PSS, signed MHT file
    keys.py             identity generation / loading
    storage.py          Supabase (default) · Dropbox (optional) · local folder
    versioning.py       signed manifest, atomic activation, authorized updates, delete/cleanup
    blockmode.py        ENHANCEMENT: per-block AES-256-GCM (RCB1) + block-level updates
    envfile.py          git-ignored .env loading (real env vars win)
    workflow.py         setup phase, update phase, verification, gated decryption
    cli.py              "Ring Crypter" CLI (python -m securecloud)
pages/1_Ring_Crypter_Secure_Cloud.py   (new) Streamlit page for the workflow
app.py                  (original) Streamlit Merkle visualizer
benchmark.py            (original) full-hash vs proof benchmark (*Windows fix)
evaluation/             (new) sample-file generator, paper benchmark, update benchmark, results/
tests/                  original 67 tests + 262 new (fakes.py = mocked Supabase client)
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
