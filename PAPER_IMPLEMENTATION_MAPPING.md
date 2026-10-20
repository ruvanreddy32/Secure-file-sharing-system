# Paper → Implementation Mapping

Paper: Parida, Konhar, Mishra & Jena, *Design and Implementation of an Efficient Tool to Verify
Integrity of Files Uploaded to Cloud Storage*, CSNT 2017 (DOI 10.1109/CSNT.2017.13).

Legend for **Origin**: **Reused**: original repository code used unchanged. **Modified**: original
code extended. **New**: written for this implementation.

## 1. Owner side: Initialization and Setup phase (§IV, §V-C, Figs. 2–3)

| Paper component | Paper ref. | File · function | Origin | Notes |
|---|---|---|---|---|
| RSA key pair Kpub / Kpri | §V-C Initialization | `securecloud/signature.py` · `generate_keypair`, `private_key_to_pem`, `public_key_to_pem`; `securecloud/keys.py` · `generate_identity` | New | RSA-3072, e = 65537, PEM; optional passphrase |
| Ring-LWE key pair (recipient) | §IV, [24], [25] | `securecloud/rlwe.py` · `generate_keypair` (p = r1 − a·r2) | New | P1/P2 of de Clercq et al. 2015 |
| AES file key K | §IV | `securecloud/aes_cipher.py` · `generate_file_key` | New | 256-bit, OS CSPRNG |
| AES-256 encryption of the file | §IV, §V-C Init. | `securecloud/aes_cipher.py` · `encrypt_bytes` | New | AES-256-GCM, random 96-bit nonce |
| Encrypt K with Ring-LWE, save in a file | §IV | `securecloud/rlwe.py` · `encrypt_key` → `encrypt_bits` | New | c1 = a·e1 + e2, c2 = p·e1 + e3 + m̄ |
| Discrete Gaussian error distribution χ | [25] | `securecloud/rlwe.py` · `sample_gaussian`, `_cdt` | New | inversion sampling, 12σ tail, 128-bit table |
| Ring arithmetic Z_q[x]/(xⁿ+1) | [25] | `securecloud/rlwe.py` · `poly_mul`, `poly_add` | New | exact negacyclic convolution |
| (1) Node generation: split the encrypted file into blocks | §V-C Setup (1) | `merkle/chunker.py` · `chunk_bytes`; `securecloud/mht.py` · `choose_block_size` | Reused + New | 4096-B blocks, or 2 blocks in paper mode |
| (1) SHA-256 of every block, in hex | §III-B, §V-C (1) | `securecloud/mht.py` · `hash_blocks` (≡ `merkle/tree.py` · `MerkleTree._hash_leaf`) | Reused rule | `hashlib.sha256(...).hexdigest()` |
| (2) MHT: H(H(i) ‖ H(j)) up to the root | §III-A, Fig. 1, §V-C (2) | `merkle/tree.py` · `MerkleTree._build`, `_hash_pair` | Reused | hex-string concatenation; odd node paired with itself |
| (2) Rebuild the tree from stored leaf hashes | §V-C Integrity (2) | `merkle/tree.py` · `MerkleTree.from_leaf_hashes`, `level_hashes` | **Modified** | added so the stored MHT can be compared node by node |
| (2) "Each hashed node … stored in hex format in a text file" (MHT file) | §V-C (2) | `securecloud/mht.py` · `generate_mht`, `serialize` | New | deterministic UTF-8 text, one node per line |
| "Height 2, 3 nodes" tree | §V-C (2) | `securecloud/mht.py` · `choose_block_size(paper_mode=True)` | New | CLI `--paper-mode` |
| (3) Sign the MHT file with Kpri → signed MHT file | §III-C, §V-C (3) | `securecloud/signature.py` · `sign`, `create_signed_mht` | New | RSASSA-PSS-SHA256 |
| Whole Setup phase (timed) | §V-C, §VI | `securecloud/workflow.py` · `setup_phase` | New | returns bundle + per-stage timings |
| Upload encrypted file, encrypted key, signed MHT to Dropbox | §IV, Fig. 2, §V-C (3) | `securecloud/workflow.py` · `upload_bundle`; `securecloud/storage.py` · `DropboxStorage.upload` | New | official SDK; each upload confirmed by `content_hash` |
| "Encrypt to Local Storage" | Fig. 4 | `securecloud/workflow.py` · `save_bundle`; CLI `encrypt` | New | |

## 2. Receiver side: Integrity Verification and decryption (§IV, §V-C)

| Paper component | Paper ref. | File · function | Origin | Notes |
|---|---|---|---|---|
| Download the three files | §IV, Fig. 2 | `securecloud/workflow.py` · `download_bundle`; `securecloud/storage.py` · `DropboxStorage.download` | New | |
| (2a) Verify the signature of the signed MHT file with Kpub | §V-C Integrity (2) | `securecloud/signature.py` · `verify_signed_mht`, `split_signed_mht`; called in `workflow.verify_integrity` | New | the workflow stops if this fails |
| Parse the authenticated MHT file | §V-C Integrity (2) | `securecloud/mht.py` · `parse` | New | also checks the file is self-consistent |
| (1) Re-run the Setup phase on the downloaded ciphertext | §V-C Integrity (1) | `securecloud/mht.py` · `generate_mht` (uses the **signed** block size) | New + Reused | |
| (2b) Compare the uploaded MHT with the calculated MHT | §V-C Integrity (2) | `securecloud/mht.py` · `compare` | New | every node compared, not only the root |
| Locate modified blocks (paper §VII *future work*) | §VII | `merkle/tamper.py` · `find_tampered_blocks` (called from `mht.compare`) | Reused | plus a leaf-count guard for truncation and extension |
| Success / failure message ("Downloaded Data Verified!!!") | Fig. 4 | `securecloud/workflow.py` · `VerificationReport.summary` | New | |
| Do not decrypt unless verified | §IV, §V-C (2) | `securecloud/workflow.py` · `decrypt_verified`, `open_bundle`, `IntegrityError` | New | requires an `ok` report bound to the exact bytes (SHA-256 digest) |
| Recover K with Ring-LWE | §IV, [24] | `securecloud/rlwe.py` · `decrypt_key` → `decrypt_bits` (m′ = c1·r2 + c2) | New | |
| AES-256 decryption | §IV | `securecloud/aes_cipher.py` · `decrypt_bytes` | New | GCM tag must verify |
| "Decrypt Locally" / "Decrypt from DropBox" | Fig. 4 | CLI `decrypt --from-dir` / `decrypt --backend dropbox` (`securecloud/cli.py` · `cmd_decrypt`) | New | |

## 3. Tool / user interface (Fig. 4)

| Fig. 4 button | CLI (`python -m securecloud …`) | Streamlit (`pages/1_Ring_Crypter_Secure_Cloud.py`) |
|---|---|---|
| Open a File | positional `FILE` | "Open a file" uploader |
| Encrypt to Local Storage | `encrypt` | "Encrypt to Local Storage" |
| Upload to DropBox | `upload --backend dropbox` | "Upload to Dropbox" |
| Decrypt Locally | `decrypt NAME --from-dir DIR` | (local-folder backend) |
| Decrypt from DropBox | `decrypt NAME --backend dropbox` | "Download & verify integrity" → "Decrypt" |
| *(extra)* key generation | `keygen` | "Generate owner+user" |
| *(extra)* attack simulation | `tamper` | tab "3 · Attacker" |
| *(extra)* end-to-end demo | `demo [--backend dropbox]` | n/a |

## 4. Performance evaluation (§VI)

| Paper item | Implementation |
|---|---|
| Table I (10 text-file sizes) → Figs. 5, 6 | `evaluation/paper_benchmark.py` · `SIZES_KB`, `measure`, `plot_all` → `evaluation/results/table1_sizes.csv`, `fig5_setup_vs_size.png`, `fig6_verify_vs_size.png` |
| Table II (7 file types × 100 KB) → Figs. 7, 8 | `evaluation/sample_files.py` · `FILE_TYPES`, `make_file`; `evaluation/paper_benchmark.py` → `table2_types.csv`, `fig7_setup_vs_type.png`, `fig8_verify_vs_type.png` |
| Environment description | `evaluation/paper_benchmark.py` · `environment` → `environment.json` |
| *(extra)* per-stage breakdown | `stage_breakdown_1000kb.png` |
| *(extra)* Ring-LWE failure-rate study | `evaluation/rlwe_failure_rate.py` → `rlwe_failure_rate.json` |

## 5. Original repository features kept

| Feature | File | Status |
|---|---|---|
| Plaintext Merkle visualizer (verify / tamper / update) | `app.py` | unchanged; now the main page of a two-page Streamlit app |
| O(log n) Merkle proofs | `merkle/proof.py` | unchanged |
| O(log n) dynamic block update | `merkle/updater.py` | unchanged (the paper's §VII future work on dynamic updates is **not** wired into the signed workflow) |
| Full-hash vs proof benchmark | `benchmark.py` | Windows console crash fixed (UTF-8 stdout) |
| 67 original unit tests | `tests/test_{chunker,tree,proof,tamper,updater}.py` | all still pass |
