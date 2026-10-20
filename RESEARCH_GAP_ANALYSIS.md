# Research Gap Analysis

**Paper:** P. Parida, S. Konhar, B. Mishra, D. Jena, *"Design and Implementation of an Efficient
Tool to Verify Integrity of Files Uploaded to Cloud Storage"*, 7th Int. Conf. on Communication
Systems and Network Technologies (CSNT 2017), pp. 62–66, DOI 10.1109/CSNT.2017.13
(IEEE Xplore 8418512).

**Starting repository:** `MR-WHOAMEYE/Efficient_File_Integrity_Verification_Using_Merkle-Trees`
(snapshot in this folder, analysed **before** any modification).

## 1. How this analysis was produced

1. Read the full paper PDF, Sections I–VII and Figures 1–8.
2. Read every source file of the repository (`merkle/*.py`, `app.py`, `benchmark.py`, `tests/*.py`,
   `requirements.txt`, project docs), not just the README.
3. Ran the repository before modifying it:
   * `pytest tests/` → **67 passed** (Python 3.14.4, Windows 11).
   * `streamlit run app.py --server.headless true` → server started, `/_stcore/health` returned `ok`.
   * `python benchmark.py` → timings computed, then **crashed** on the final
     `print("✓ ...")` with `UnicodeEncodeError` on a cp1252 Windows console (pre-existing bug;
     `results.csv` is written before the crash).
4. Searched the repository for any cryptography beyond hashing:
   `grep -ri "aes|rsa|sign|encrypt|dropbox|lwe|cryptography"` → **no matches** in source code.

## 2. What the paper requires (extracted from the PDF)

| # | Requirement | Paper location |
|---|---|---|
| R1 | Encrypt the plaintext file with **AES-256** under a symmetric file key K | §IV, §V-C "Initialization" |
| R2 | Encrypt K with **Ring-LWE** public-key encryption (scheme of Mishra & Jena [24], built on Lyubashevsky–Peikert–Regev [25]) and save it in a file | §II (last para.), §IV |
| R3 | **SHA-256** hash of each block of the **encrypted** file, converted to hex | §III-B, §V-C Setup (1) |
| R4 | Divide the encrypted file into blocks | §III-A, §V-C Setup (1) |
| R5 | **Merkle Hash Tree**: parent = H(H(left) ‖ H(right)), repeated to a single root | §III-A, Fig. 1 |
| R6 | Every node hash stored **in hex in a text file** (the "MHT file") | §V-C Setup (2) |
| R7 | **RSA** key pair (Kpub, Kpri) generated for signing | §V-C Initialization |
| R8 | MHT file **signed** with Kpri and stored as a new **signed MHT file** | §III-C, §V-C Setup (3) |
| R9 | Signature of the signed MHT file **verified** with Kpub; stop on failure | §V-C Integrity Verification (2) |
| R10 | Upload encrypted file + encrypted key file + signed MHT file to **Dropbox** | §IV, Fig. 2, Fig. 3, §V-C Setup (3) |
| R11 | Download the three files; **re-run the Setup phase** on the downloaded ciphertext; **compare** recomputed MHT with uploaded MHT; show success/failure | §IV, §V-C Integrity Verification (1)–(2), Fig. 4 |
| R12 | **Decrypt only if verification succeeds** (recover K with Ring-LWE, then AES-decrypt) | §IV, §V-C Integrity Verification (2) |
| R13 | Tool with Encrypt / Upload / Decrypt-locally / Decrypt-from-Dropbox actions | Fig. 4 |
| R14 | **Performance evaluation**: Setup time and Integrity-Verification time for 10 text-file sizes (Table I, 10 KB–1000 KB; Figs. 5–6) and 7 file types at 100 KB (Table II; Figs. 7–8) | §VI |

Under-specified points in the paper (recorded here and resolved in `IMPLEMENTATION_LIMITATIONS.md`):

* **AES mode, IV handling and padding** are not stated.
* **Ring-LWE parameters** are not stated; the paper defers to Mishra & Jena [24] (CCEM 2016), whose
  full text could not be obtained. The scheme in [24] builds on [25] (the LPR toolkit). The standard
  2015 parameter sets for LPR encryption, P1 = (n=256, q=7681, s=11.31) and P2 = (512, 12289, 12.18),
  were confirmed from de Clercq et al., DATE 2015.
* **Block size / number of blocks**: §III-A (Fig. 1) describes a general n-leaf tree, but §V-C(2)
  says the implementation builds "a merkle hash tree of height 2 containing 3 nodes", which is a
  2-leaf tree.
* **RSA padding / key size / signature encoding** are not stated. Reference [35] in §V-C is the
  ElGamal paper, but the text says "RSA based digital signature algorithm".
* **Exact contents of the "Setup time" measurement** (whether AES and upload are included) are not stated.

## 3. Comparison table

Status legend: **Implemented**: it matches the paper and can be reused as is. **Partial**: related
code exists but needs adaptation. **Missing**: nothing exists.

| Research Paper Requirement | Existing Repository Implementation | Status | Required Modification |
|---|---|---|---|
| **AES-256 encryption** (R1, §IV, §V-C) | None. No encryption code anywhere; `requirements.txt` has no crypto library. | **Missing** | New module: AES-256 with a CSPRNG key, authenticated mode (GCM), self-describing ciphertext format, and decryption. |
| **Ring-LWE key encryption** (R2, §II, §IV) | None. | **Missing** | New module implementing LPR Ring-LWE PKE (keygen / encrypt / decrypt) with a discrete Gaussian sampler, negacyclic polynomial arithmetic in Z_q[x]/(xⁿ+1), parameter sets P1/P2, an encoding of the 256-bit AES key, and key and ciphertext serialization. |
| **SHA-256 hashing** (R3, §III-B) | `merkle/tree.py:33-35` `_sha256` → `hashlib.sha256(...).hexdigest()`; `merkle/proof.py:96`. Hex output, as the paper requires. | **Implemented** (applied to plaintext only) | Reuse as is, but apply it to the **AES ciphertext** instead of the plaintext. |
| **File block generation** (R4, §V-C(1)) | `merkle/chunker.py:19` `chunk_bytes` / `:56` `chunk_file`: fixed-size blocks, no padding. Raises `ValueError` on empty input (`tests/test_chunker.py:64`). | **Partial** | Reuse. Add a "paper mode" that splits into exactly 2 blocks (3-node tree, §V-C(2)). Empty plaintexts are covered automatically because an AES-GCM ciphertext is never empty. |
| **Merkle Hash Tree** (R5, §III-A, Fig. 1) | `merkle/tree.py:38-131` `MerkleTree`: bottom-up build, `sha256(left_hex + right_hex)`, odd-node duplication. `merkle/node.py`. | **Implemented** (core) | Reuse. The hex concatenation matches "hashed then converted to hex, then concatenated". Add reconstruction of a tree **from stored leaf hashes** so that a downloaded MHT file can be compared node by node and tampering localized. |
| **MHT metadata (text) file** (R6, §V-C(2)) | None. The tree exists only in memory and the root is never persisted. | **Missing** | New serializer/parser: deterministic UTF-8 text file listing every node hash in hex, level by level, plus the root and the block parameters. |
| **RSA key generation** (R7) | None. | **Missing** | New module: RSA key pair (3072-bit) via `cryptography`, PEM storage, optional passphrase encryption of the private key, kept outside version control. |
| **RSA digital signatures** (R8, §III-C) | None. | **Missing** | Sign the exact MHT-file bytes (RSA-PSS / SHA-256) and write the **signed MHT file** (MHT text + armored signature). |
| **Signature verification** (R9) | None. | **Missing** | Parse the signed MHT file, verify with Kpub, and reject on any modification, wrong key, or replaced signature. |
| **Dropbox integration** (R10) | None. `app.py:654` accepts local uploads to the Streamlit page only. | **Missing** | New storage layer using the current official Dropbox SDK (`dropbox` v12): upload, download, list, and per-upload `content_hash` check. Credentials only from environment variables. A local-folder backend for offline use, clearly labelled as **not** Dropbox. |
| **File integrity verification** (R11, §V-C) | Building blocks exist: `merkle/proof.py:71` `verify_proof` (single block against a root), `merkle/tamper.py:27` `find_tampered_blocks` (tree-vs-tree, assumes the **same leaf count**). There is **no trusted reference**: the root is not stored, signed, or loaded from anywhere. The app compares only against an in-memory tree. | **Partial** | New workflow: verify signature → re-run Setup on the downloaded ciphertext → compare the full recomputed MHT with the signed one → success/failure message. Reuse `find_tampered_blocks` to report exact tampered blocks (the paper's stated future work), and guard it against differing leaf counts (truncation/extension). |
| **Decryption after verification** (R12) | None. | **Missing** | Decrypt the key with Ring-LWE, then AES-decrypt, reachable **only** through the verified path. The decryptor checks that it receives the exact bytes that were verified. |
| **Tool / UI** (R13, Fig. 4) | `app.py` (Streamlit + Pyvis) visualizes plaintext Merkle trees: verify, tamper, and update a block. | **Partial** | Keep `app.py` unchanged. Add a CLI (`python -m securecloud …`) with the Fig. 4 actions and a Streamlit page for the secure owner/receiver workflow. |
| **Performance evaluation** (R14, §VI, Tables I–II, Figs. 5–8) | `benchmark.py`: full-file SHA-256 vs single-block proof for 1/10/100 MB random data. This is a different experiment (no encryption, no signature, no setup/verify phases, different sizes and no file types). Crashes on Windows console. | **Partial** (wrong experiment) | New benchmark reproducing Table I (10 sizes) and Table II (7 real file types at ≈100 KB), with per-stage timings (AES, Ring-LWE, hashing, MHT, sign, verify, decrypt), graphs, and environment details. Fix the console crash in the existing `benchmark.py`. |
| **Tests** | 67 unit tests for chunker/tree/proof/tamper/updater only. | **Partial** | Add functional, tampering, file-type, boundary, storage, and Dropbox tests (the live Dropbox tests run only when credentials are present). |

## 4. Reusable existing components

* `merkle/chunker.py`: block generation (reused unchanged).
* `merkle/tree.py`: SHA-256 MHT construction (reused; extended with a leaf-hash constructor).
* `merkle/tamper.py`: block-level tamper localization (reused, with a leaf-count guard in the new workflow).
* `merkle/proof.py`, `merkle/updater.py`, `app.py`: Merkle proofs, dynamic update, and visualization
  are kept as extra features. They are not part of the paper's workflow.

## 5. Conclusion of the analysis

The repository implements **only the Merkle-tree data structure** (R3–R5, applied to plaintext). It
does **not** implement the paper's system: there is no encryption (R1, R2), no persisted or signed
MHT metadata (R6–R9), no cloud storage (R10), no verification against a trusted signed reference
(R11), no gated decryption (R12), and no reproduction of the paper's experiments (R14). These are
implemented in the new `securecloud/` package and mapped in `PAPER_IMPLEMENTATION_MAPPING.md`.

## 6. Addendum (later change): cloud provider

This analysis describes the repository **before** implementation. Since then, the cloud backend
has been changed from Dropbox (as in the paper) to **Supabase Storage** (Free plan, official
`supabase` SDK, private bucket), because no Dropbox credentials were available. Dropbox is kept as
an optional backend. Versioned storage with atomic activation and authorized dynamic updates
(paper §VII future work) was added at the same time. See `PAPER_IMPLEMENTATION_MAPPING.md` §6 and
`IMPLEMENTATION_LIMITATIONS.md` §1.1 and §4.
