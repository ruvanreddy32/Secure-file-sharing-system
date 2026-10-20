# Test Results

**Command:** `python -m pytest -v -rs`
**Date:** 2026-10-20 · **Platform:** Windows 11, CPython 3.14.4, pytest 9.1.1
**Full log:** `evaluation/results/pytest_output.txt`

```
collected 209 items
...
SKIPPED [1] tests\test_dropbox_live.py:23: Dropbox credentials not configured
======================= 208 passed, 1 skipped in 6.45s ========================
```

| Result | Count |
|---|---:|
| Passed | **208** |
| Failed | **0** |
| Skipped | **1**: the live Dropbox test (no credentials available, see below) |

Baseline before any change: the original repository's 67 tests passed (`67 passed in 0.26s`). They
all still pass, unmodified.

## 1. Tests per file

| File | Tests | Covers |
|---|---:|---|
| `test_chunker.py` *(original)* | 11 | block splitting |
| `test_tree.py` *(original 22 + 7 new)* | 29 | MHT build; **new:** `from_leaf_hashes` / `level_hashes` rebuild equality |
| `test_proof.py` *(original)* | 12 | Merkle proofs |
| `test_tamper.py` *(original)* | 10 | tamper localization |
| `test_updater.py` *(original)* | 12 | O(log n) updates |
| `test_crypto_primitives.py` | 36 | AES-256-GCM, Ring-LWE, RSA-PSS |
| `test_mht_file.py` | 16 | MHT of ciphertext, MHT text file, comparison |
| `test_workflow.py` | 31 | functional and tampering, end to end |
| `test_filetypes_boundaries.py` | 28 | 7 file types, boundary sizes, 20 MiB file |
| `test_storage.py` | 16 | local folder, Dropbox code path (fake client), content hash, missing-folder listing |
| `test_cli.py` | 5 | CLI keygen/encrypt/verify/decrypt/upload/tamper/demo |
| `test_streamlit_page.py` | 2 | Streamlit page via `AppTest`: verify → decrypt; tampered file disables Decrypt |
| `test_dropbox_live.py` | 1 | **real** Dropbox round trip + tamper (SKIPPED) |

## 2. Requirement → test evidence

### Functional tests (all PASSED)
| Requirement | Test(s) |
|---|---|
| Encryption and decryption | `TestAES::test_roundtrip[0,1,15,16,17,4096,100000]`, `test_unmodified_file_verifies_and_decrypts` |
| Correct Merkle-tree generation | `test_paper_figure1_rule_8_leaves` (hand-computed H(1,8) per Fig. 1), `test_matches_repository_merkle_tree`, `test_paper_mode_gives_3_node_tree`, `test_mht_is_over_ciphertext_not_plaintext` |
| RSA signature generation and verification | `TestRSASignature::*`, `test_signed_mht_roundtrip`, `test_key_size` (3072) |
| Ring-LWE key encryption | `test_key_roundtrip[P1-2]`, `[P2-1]`, `test_public_key_relation`, `test_poly_mul_matches_schoolbook`, `test_x_to_the_n_is_minus_one`, `test_gaussian_sampler_statistics[P1,P2]`, `test_parameters_match_de_clercq_2015` |
| Upload/download workflow | `test_upload_download_roundtrip_local_folder`, `test_full_workflow_through_dropbox_code_path` (fake SDK client), `test_upload_and_decrypt_via_local_backend` (CLI) |
| Integrity verification of unchanged files | `test_unmodified_file_verifies_and_decrypts`, `test_verify_and_decrypt` (Streamlit) |
| Restoration of original contents | every round-trip test asserts `out == original` byte for byte |
| Upload confirmation | `test_upload_confirmation_failure_raises`, `test_large_upload_uses_session` |

### Tampering tests (all PASSED). Each asserts: verification fails, **and** `open_bundle` and `decrypt_verified` both raise `IntegrityError`.
| Attack | Test | Detected by |
|---|---|---|
| Modify one file block | `test_modify_one_block` → reports block `[3]` | MHT comparison |
| Modify multiple blocks | `test_modify_multiple_blocks` → `[0, 2, 6]` | MHT comparison |
| Modify last partial block | `test_single_bit_in_last_partial_block` | MHT comparison |
| Delete part of a file (truncate) | `test_delete_part_of_file` | size + MHT |
| Delete bytes in the middle | `test_delete_bytes_in_middle` | MHT |
| Append data | `test_append_data` | size + MHT |
| Empty downloaded file | `test_empty_downloaded_file` | size |
| Replace file with random content | `test_replace_with_different_content_same_size` | MHT |
| Replace file with another genuinely encrypted file of the same owner | `test_replace_with_other_validly_encrypted_file` | MHT and key-file hash |
| Swap a whole signed bundle under another name | `test_swap_bundle_between_file_names` | signed file name |
| Modify MHT metadata | `test_modify_mht_metadata` | RSA signature |
| Recompute the MHT to match a tampered file | `test_attacker_rewrites_mht_to_match_tampered_file` | RSA signature |
| Replace the signature (attacker key) | `test_replace_signature`, `test_attacker_signs_forged_mht_with_own_key` | RSA signature |
| Remove / corrupt the signature | `test_signature_removed`, `test_corrupted_signature_bytes` | RSA signature |
| Verify with an incorrect public key | `test_incorrect_public_key` | RSA signature |
| Modify the encrypted key file | `test_modified_encrypted_key_file` | signed key-file hash |
| Decrypt after failed verification | `test_decryption_blocked_after_failed_verification` (also with a forged `ok=True` flag), `test_report_of_other_bundle_cannot_unlock`, `test_decrypt_requires_a_report`, CLI `test_tamper_then_decrypt_refused` (exit code 2, no output file), Streamlit `test_tampered_file_blocks_decrypt` (Decrypt button disabled) | gate in `decrypt_verified` |
| Wrong recipient | `test_wrong_recipient_cannot_decrypt` | Ring-LWE + AES-GCM tag |
| Tampering in paper mode (3-node tree) | `test_paper_mode_detects_tampering` | MHT |
| Tampering on the (fake) Dropbox server | `test_full_workflow_through_dropbox_code_path` | MHT |

### File-type tests (all PASSED)
Each of **Text (.txt), Audio (.wav), Video (.avi), Image (.png), Document (.docx), PDF (.pdf),
Spreadsheet (.xlsx)** at ≈100 KB is: (a) validated as a genuine file of that type (WAV via `wave`,
PNG via Pillow, PDF via pypdf, DOCX/XLSX ZIP + XML parse, AVI RIFF structure); (b) protected,
verified, decrypted byte-identical, and re-validated; (c) tampered and rejected.

### Boundary tests (all PASSED)
Plaintext sizes **0** (empty), **1**, **4064/4065** (ciphertext exactly 4096 / 4097 B), **4096,
4097, 12295** (uneven), exact multiple of the block size, custom block sizes **1, 64, 1000, 65536**,
and a **20 MiB** file whose tampered block (index 3840) is localized exactly.

## 3. Skipped / not executed

| Test | Why | How to run |
|---|---|---|
| `test_dropbox_live.py::test_live_upload_verify_decrypt_and_tamper` | No Dropbox credentials in this environment. **Real Dropbox integration is therefore unverified.** | Set `DROPBOX_REFRESH_TOKEN` + `DROPBOX_APP_KEY` (+ `DROPBOX_APP_SECRET`) or `DROPBOX_ACCESS_TOKEN`, then `python -m pytest -m dropbox_live -v` |

## 4. Other executed checks

| Check | Result |
|---|---|
| `python -m securecloud demo` (local folder) | verification PASSED, decrypted output identical; after flipping 1 byte: "Merkle root mismatch: 4 MHT node(s) differ; modified block(s): 3", decryption refused |
| `streamlit run app.py` (headless, both pages) | server started, `/_stcore/health` → `ok` |
| `python benchmark.py` (original) | completes after the UTF-8 stdout fix (previously crashed with `UnicodeEncodeError`) |
| `python -m evaluation.paper_benchmark --runs 30` | completed; see `PERFORMANCE_RESULTS.md` |
| `python -m evaluation.rlwe_failure_rate --trials 3000` | 0 bit errors with the implemented encoding (P1, P2) |

## 5. Failing cases found during development (and fixed)

| Issue | Fix |
|---|---|
| Original `benchmark.py` crashed on Windows consoles (`'charmap' codec can't encode '✓'`) | stdout reconfigured to UTF-8 in `__main__` |
| Sample PDF generator overshot the 100 KB target by 3.4 % (page slicing ignored the line count) | slice pages to `min(i + 50, n)` |
| Benchmark CSV re-plot parsed the mode label `"4096"` as an integer | `load_csv` keeps label columns as strings (`--plot-only`) |
| Ring-LWE with 1 coefficient per bit measured 0.40 % / 1.59 % key-decryption failure (P1/P2) | 2-coefficient encoding (0 failures measured) |
