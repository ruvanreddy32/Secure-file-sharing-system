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
| Upload encrypted file, encrypted key, signed MHT to cloud storage (paper: Dropbox) | §IV, Fig. 2, §V-C (3) | `securecloud/versioning.py` · `VersionedRepository.publish`; `securecloud/storage.py` · `SupabaseStorage.upload` (default), `DropboxStorage.upload` (optional) | New | **Supabase replaces Dropbox** (see §6); private bucket; each upload confirmed (Supabase: SHA-256 read-back, Dropbox: `content_hash`) |
| "Encrypt to Local Storage" | Fig. 4 | `securecloud/workflow.py` · `save_bundle`; CLI `encrypt` | New | |

## 2. Receiver side: Integrity Verification and decryption (§IV, §V-C)

| Paper component | Paper ref. | File · function | Origin | Notes |
|---|---|---|---|---|
| Download the three files | §IV, Fig. 2 | `securecloud/versioning.py` · `VersionedRepository.fetch_verified`, `download`; `securecloud/storage.py` · `SupabaseStorage.download` | New | the signed manifest is checked first (§6) |
| (2a) Verify the signature of the signed MHT file with Kpub | §V-C Integrity (2) | `securecloud/signature.py` · `verify_signed_mht`, `split_signed_mht`; called in `workflow.verify_integrity` | New | the workflow stops if this fails |
| Parse the authenticated MHT file | §V-C Integrity (2) | `securecloud/mht.py` · `parse` | New | also checks the file is self-consistent |
| (1) Re-run the Setup phase on the downloaded ciphertext | §V-C Integrity (1) | `securecloud/mht.py` · `generate_mht` (uses the **signed** block size) | New + Reused | |
| (2b) Compare the uploaded MHT with the calculated MHT | §V-C Integrity (2) | `securecloud/mht.py` · `compare` | New | every node compared, not only the root |
| Locate modified blocks (paper §VII *future work*) | §VII | `merkle/tamper.py` · `find_tampered_blocks` (called from `mht.compare`) | Reused | plus a leaf-count guard for truncation and extension |
| Success / failure message ("Downloaded Data Verified!!!") | Fig. 4 | `securecloud/workflow.py` · `VerificationReport.summary` | New | |
| Do not decrypt unless verified | §IV, §V-C (2) | `securecloud/workflow.py` · `decrypt_verified`, `open_bundle`, `IntegrityError` | New | requires an `ok` report bound to the exact bytes (SHA-256 digest) |
| Recover K with Ring-LWE | §IV, [24] | `securecloud/rlwe.py` · `decrypt_key` → `decrypt_bits` (m′ = c1·r2 + c2) | New | |
| AES-256 decryption | §IV | `securecloud/aes_cipher.py` · `decrypt_bytes` | New | GCM tag must verify |
| "Decrypt Locally" / "Decrypt from DropBox" | Fig. 4 | CLI `decrypt --from-dir` / `decrypt --backend supabase` (or `dropbox`) (`securecloud/cli.py` · `cmd_decrypt`) | New | `--version N`, `--min-version N` |

## 3. Tool / user interface (Fig. 4)

| Fig. 4 button | CLI (`python -m securecloud …`) | Streamlit (`pages/1_Ring_Crypter_Secure_Cloud.py`) |
|---|---|---|
| Open a File | positional `FILE` | "Open a file" uploader |
| Encrypt to Local Storage | `encrypt` | "Encrypt to Local Storage" |
| Upload to DropBox | `upload` (default backend Supabase; `--backend dropbox` optional) | "Run Setup phase & publish" |
| Decrypt Locally | `decrypt NAME --from-dir DIR` | (local-folder backend) |
| Decrypt from DropBox | `decrypt NAME --backend supabase` | "Download & verify integrity" → "Decrypt" |
| *(extra)* dynamic update | `update FILE` | "Publish as" → existing file |
| *(extra)* versions / delete / cleanup | `versions`, `delete`, `cleanup` | version selector in tab 2 |
| *(extra)* bucket check | `supabase-setup` | "Check bucket is private" |
| *(extra)* key generation | `keygen` | "Generate owner+user" |
| *(extra)* attack simulation | `tamper` | tab "3 · Attacker" |
| *(extra)* end-to-end demo | `demo [--backend supabase]` | n/a |

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
| O(log n) dynamic block update | `merkle/updater.py` | unchanged, visualizer only. The signed workflow updates whole-file versions (§6), because AES-GCM prevents in-place block updates |
| Full-hash vs proof benchmark | `benchmark.py` | Windows console crash fixed (UTF-8 stdout) |
| 67 original unit tests | `tests/test_{chunker,tree,proof,tamper,updater}.py` | all still pass |

## 6. Cloud storage change (Dropbox → Supabase) and dynamic updates

| Component | Paper ref. | File · function | Origin | Notes |
|---|---|---|---|---|
| Storage interface: `upload / download / list(prefix) / delete` with nested keys | §IV | `securecloud/storage.py` · `Storage`, `_safe_key` | Modified | rejects `..`, empty segments, backslashes, absolute keys |
| **Supabase Storage backend** (default) | §IV (provider substituted) | `securecloud/storage.py` · `SupabaseStorage` (`upload`, `download`, `list`, `delete`, `ensure_bucket`, `_client_from_env`) | **New** | official `supabase` SDK; env-only credentials; private bucket enforced; read-back confirmation; recursive listing with paging; batched delete |
| Dropbox backend (optional) | §IV | `securecloud/storage.py` · `DropboxStorage` | Modified | nested keys, recursive listing, delete |
| Local folder (offline) | — | `securecloud/storage.py` · `LocalFolderStorage` | Modified | nested keys, delete with empty-folder pruning |
| Backend selection | — | `securecloud/storage.py` · `open_storage`, `BACKENDS`; CLI `--backend` (default `supabase`) | Modified | |
| Versioned layout `<name>/v<N>-<id>/…` + `manifest.signed` | — | `securecloud/versioning.py` · `version_keys`, `manifest_key`, `Manifest`, `VersionEntry` | **New** | per-attempt folders prevent concurrent writers from clobbering each other |
| Signed manifest (active-version pointer) | §III-C (same signature scheme) | `securecloud/versioning.py` · `read_manifest`, `_write_manifest` | **New** | RSASSA-PSS-SHA256 via `signature.create_signed_mht` / `verify_signed_mht` |
| Atomic activation (no partial versions) | — | `securecloud/versioning.py` · `publish`, `_discard`, `cleanup_incomplete` | **New** | upload 3 objects → re-check manifest → write manifest last |
| Authorized dynamic update (paper §VII future work) | §VII | `securecloud/workflow.py` · `update_phase`, `signed_mht_sha256`; `securecloud/versioning.py` · `update` | **New** | verifies the current version, then re-runs Setup with version N+1 and the chain link |
| Version fields in the MHT file (format v2) | §V-C (2) | `securecloud/mht.py` · `MHTData.version`, `previous_mht_sha256`, `serialize`, `parse` | Modified | v1 files still accepted; hashing/tree rules unchanged |
| Version / chain verification | §V-C | `securecloud/workflow.py` · `verify_integrity(expected_version=, expected_previous_mht_sha256=)`; `versioning.fetch_verified` | Modified / New | also manifest ↔ signed-MHT hash binding, rollback check (`min_version`) |
| Owner housekeeping | — | `securecloud/versioning.py` · `delete`, `versions`, `list_files`; CLI `delete`, `versions`, `list`, `cleanup` | **New** | |
| Streamlit integration | Fig. 4 | `pages/1_Ring_Crypter_Secure_Cloud.py` | Modified | Supabase default, publish/update, version picker, attacks incl. unauthorized update / interrupted upload / rollback |
| Benchmark network timings | §VI | `evaluation/paper_benchmark.py --cloud supabase` | Modified | `--dropbox` kept as alias |

**Unchanged by this change** (byte-for-byte): `securecloud/aes_cipher.py`, `securecloud/rlwe.py`,
`securecloud/signature.py`, `securecloud/keys.py`, and everything in `merkle/`. AES-256-GCM,
Ring-LWE (P1/P2), SHA-256, the Merkle Hash Tree rules and RSA-PSS are exactly as before.

## 7. ENHANCEMENT (not part of the IEEE paper): per-block AES-256-GCM and block-level updates

The paper's whole-file workflow (§1–§2, format **RCF1**) is unchanged and remains the default.
**RCB1** is an additional, opt-in encrypted-file format. It reuses the paper's primitives, but the
idea of encrypting per block and updating individual blocks is **ours, not the authors'**.

| Component | File · function | Origin | Notes |
|---|---|---|---|
| Per-block AES-256-GCM, random 96-bit nonce per block | `securecloud/blockmode.py` · `encrypt_block`, `decrypt_block`, `parse_block_header` | **New** | 44-byte overhead/block (28-byte header + tag) |
| Authenticated block binding | `blockmode.block_aad` | **New** | AAD = format ‖ file-id ‖ block index ‖ written-in-version ‖ block size |
| Signed metadata v3 (format, file id, plaintext length, block count, version, chain link, both key-file hashes, nonce budget, all nodes) | `securecloud/mht.py` · `HEADER_V3`, `MHTData` (v3 fields), `serialize`, `parse` | Modified | RCF1 still writes v2 byte-for-byte; v1/v2 still parse |
| Setup of an RCB1 file (v1) | `blockmode.block_setup_phase` | **New** | K Ring-LWE-encrypted for recipient **and** owner |
| Receiver verification (signature → regenerate MHT from downloaded blocks → compare → header/nonce/length/key-file checks) | `blockmode.block_verify_integrity` | **New** | same paper steps, applied to the block list |
| Decryption only after verification | `blockmode.block_decrypt_verified` (dispatched from `workflow.decrypt_verified`) | **New** | digest-bound to the verified bytes |
| Block-level update planning (patch, multi-patch, replace block, sync/diff) | `blockmode.plan_patch`, `plan_patches`, `plan_replace_block`, `plan_sync` | **New** | only partially-overwritten blocks are read |
| Incremental Merkle update | `blockmode.build_block_update` → **`merkle/updater.py` · `update_block`** (reused) | Reused | O(log n) rehash per changed leaf; rebuild from leaf hashes only if the block count changes |
| Re-signing each authorized update | `blockmode.build_block_update` → `signature.create_signed_mht` | Reused | version N+1, previous = SHA-256(signed MHT N) |
| Content-addressed block storage (unchanged blocks never re-uploaded) | `securecloud/versioning.py` · `block_key`, `block_mht_key`, `block_key_file_keys`, `publish_blocks` | **New** | object id = Merkle leaf hash |
| Authorized block update on cloud storage | `versioning.VersionedRepository.block_patch`, `block_patch_many`, `block_replace`, `block_sync`, `_block_update` | **New** | uploads changed blocks + signed MHT, checks referenced blocks exist, then activates the manifest |
| Format-aware fetch / delete / cleanup (shared-block GC) | `versioning._fetch_block_version`, `_version_objects`, `delete`, `cleanup_incomplete`, `keys_for` | **New / Modified** | blocks shared with live versions are never deleted |
| Version format in manifest | `versioning.VersionEntry.format` (default `RCF1`) | Modified | old manifests without the field still load |
| I/O and work accounting | `storage.CountingStorage`, `SupabaseStorage.http` (+ retries) | **New** | logical ops/bytes and real HTTP requests |
| CLI | `cli.py` · `upload --block-mode`, `block-update`, `block-sync`, `demo-blocks` | **New** | prints blocks changed, hashes, objects and bytes |
| Streamlit | `pages/1_Ring_Crypter_Secure_Cloud.py` · format selector, "Block-level edit", block replay / swap attacks | Modified | |
| Benchmark whole-file vs block-level updates | `evaluation/update_benchmark.py` | **New** | identical files; local + real Supabase |
| Tests | `tests/test_blockmode.py` (98), block cases in `test_cli.py`, `test_streamlit_page.py`, `test_supabase_live.py` | **New** | |
