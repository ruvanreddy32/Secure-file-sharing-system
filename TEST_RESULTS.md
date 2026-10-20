# Test Results

**Command:** `python -m pytest -v -rs`
**Date:** 2026-10-20 · **Platform:** Windows 11, CPython 3.14.4, pytest 9.1.1, supabase 2.33.0
**Full log:** `evaluation/results/pytest_output.txt`

```
collected 329 items
...
SKIPPED [1] tests\test_dropbox_live.py:23: Dropbox credentials not configured
SKIPPED [1] tests\test_supabase_live.py:64: Supabase credentials not configured
SKIPPED [1] tests\test_supabase_live.py:74: Supabase credentials not configured
======================= 326 passed, 3 skipped in 17.73s =======================
```

| Result | Count |
|---|---:|
| Passed | **326** |
| Failed | **0** |
| Skipped | **3**: the live cloud tests (2 Supabase, 1 Dropbox); no credentials in this environment |

## 0. What was verified where (read this first)

| Feature | Tested locally (mocked / offline) | Verified against the real Supabase service |
|---|---|---|
| AES-256-GCM, Ring-LWE, SHA-256, MHT, RSA-PSS | ✅ real implementations, no mocks | n/a (no cloud involved) |
| Supabase upload / download / list / delete | ✅ mocked client (`tests/fakes.py`) | ❌ **not run**: no credentials |
| Supabase upload confirmation (read-back SHA-256) | ✅ mocked, incl. corrupted-upload rejection | ❌ not run |
| Private-bucket enforcement / creation | ✅ mocked | ❌ not run |
| Credentials from environment, service-role preference | ✅ `create_client` patched; no secret rendered by the UI | ❌ not run |
| Real SDK API compatibility | ✅ real `supabase.create_client(...)` built offline; all called methods exist with compatible parameters; network error maps to `StorageError` | ❌ no request reached Supabase |
| Versioning, atomic activation, partial-upload safety | ✅ on mocked Supabase, mocked Dropbox, and the real local filesystem | ❌ not run |
| Authorized dynamic updates, unauthorized-update rejection | ✅ same three backends | ❌ not run |
| Tamper detection after download | ✅ same three backends | ❌ not run |
| CLI with Supabase backend | ✅ mocked client | ❌ not run |
| Streamlit page with Supabase backend | ✅ `AppTest`, mocked client | ❌ not run |
| Dropbox (optional backend) | ✅ mocked client | ❌ not run against real Dropbox |

**Update:** the live Supabase tests were later run against a real project and passed (§0b). In the
table above, ❌ marks what the *default* run (no credentials) does not cover. §0b lists what was
verified live.

## 0b. Live verification against the real Supabase service (2026-10-20)

Project `mzrfdupvythavlxbzfsn` (Free plan), private bucket `secure-files`, key type `sb_secret_…`
(the key value appears in no file).

| Check | Command | Result |
|---|---|---|
| Bucket exists and is private | `python -m securecloud supabase-setup --no-create` | `bucket 'secure-files' exists and is private` |
| Raw upload (with read-back confirmation), download, list, delete | `pytest -m supabase_live` → `test_live_raw_object_operations` | **PASSED** |
| Publish v1 → verify → decrypt; authorized update v2 → verify/decrypt v2 and v1; interrupted v3 upload not activated; update with another RSA key refused; server-side tampering detected (block 1) and decryption refused; owner deletes everything | `pytest -m supabase_live` → `test_live_publish_verify_update_tamper` | **PASSED** (2 passed in 41.26 s) |
| End-to-end demo | `python -m securecloud demo --backend supabase` | **DEMO PASSED**: v1 verified and identical; v2 active; interrupted v3 "NOT activated"; 1-byte tamper → "modified block(s): 1", decryption refused; 7 objects cleaned up |
| No leftovers | list bucket afterwards | 0 objects |

Notes: the two `DeprecationWarning`s during the live run come from inside the `supabase` SDK
(`supabase/_sync/client.py`), not from this code. Not exercised live: the Streamlit page on Supabase
(tested only with the mocked client), the paper benchmark with `--cloud supabase`, and uploads near
the 50 MB Free-plan limit.

## 1. Tests per file

| File | Tests | Covers |
|---|---:|---|
| `test_chunker.py` *(original)* | 11 | block splitting |
| `test_tree.py` *(original 22 + 7)* | 29 | MHT build; `from_leaf_hashes` / `level_hashes` |
| `test_proof.py` *(original)* | 12 | Merkle proofs |
| `test_tamper.py` *(original)* | 10 | tamper localization |
| `test_updater.py` *(original)* | 12 | O(log n) updates |
| `test_crypto_primitives.py` | 36 | AES-256-GCM, Ring-LWE, RSA-PSS |
| `test_mht_file.py` | 19 | MHT of ciphertext, MHT text file (v2 version fields, v1 compatibility), comparison |
| `test_workflow.py` | 31 | functional and tampering, end to end |
| `test_filetypes_boundaries.py` | 28 | 7 file types, boundary sizes, 20 MiB file |
| `test_storage.py` | 19 | local folder and Dropbox code path: nested keys, recursive list, delete, path safety, content hash |
| **`test_supabase_storage.py`** | **24** | **Supabase backend (mocked client)**: upload/download, read-back confirmation, corrupted upload, upsert, errors, recursive listing + paging, batched delete, private-bucket check/creation, env credentials, `open_storage` |
| **`test_versioning.py`** | **80** | 26 cases × **3 backends** (mocked Supabase, mocked Dropbox, local) + 2 backend-independent: publish, dynamic update chain, partial uploads, manifest-write failure, concurrent publisher, storage attacks, delete/cleanup |
| `test_cli.py` | 8 | CLI incl. **full Supabase lifecycle** (setup → upload → decrypt → update → versions → tamper → refused update → delete), rollback + cleanup, missing-credential message |
| `test_streamlit_page.py` | 7 | Streamlit `AppTest`: verify/decrypt, version picker, tamper, attacker tab (unauthorized update, interrupted upload, byte flip), **Supabase backend** + secret never rendered |
| **`test_supabase_live.py`** | 2 | **REAL Supabase** (SKIPPED): raw object ops; publish/update/interrupted upload/unauthorized update/tamper/delete |
| `test_dropbox_live.py` | 1 | real Dropbox (SKIPPED) |

The original repository's 67 tests all still pass, unmodified.

## 2. Requirement → test evidence (all PASSED locally)

### Supabase storage (mocked client)
| Requirement | Test(s) |
|---|---|
| Encrypted uploads, downloads, listing, deletion | `test_upload_download`, `test_recursive_listing_of_folders`, `test_pagination`, `test_delete_in_batches`, `test_large_object_roundtrip` |
| Upload success checked | `test_upload_is_read_back_and_compared`, `test_corrupted_upload_is_rejected`, `test_upload_error_wrapped` |
| Private bucket | `test_ensure_bucket_creates_private_bucket`, `test_public_bucket_is_refused` |
| Credentials only from env; service role preferred | `test_client_built_from_env_with_service_role_preferred`, `test_missing_credentials`, CLI `test_supabase_missing_credentials_message` |
| Service-role key not exposed in frontend | `test_page_on_supabase_backend` (secret value absent from all rendered captions, markdown and inputs) |
| Key file and signed MHT stored alongside the ciphertext, in a private bucket | `test_first_version[supabase]` (exact object set: manifest + 3 objects in one version folder) |

### Versioning and consistency (each × supabase / dropbox / local)
| Requirement | Test(s) |
|---|---|
| Versioned storage | `test_update_creates_chained_versions` (v1, v2, v3 all retrievable and verified) |
| Partial uploads never activate | `test_partial_upload_never_activates[.aes / .key.rlwe / .mht.signed]` |
| Manifest write failure → old version stays active; cleanup; retry | `test_manifest_write_failure_leaves_old_version_active` |
| Concurrent publisher does not corrupt the winner | `test_concurrent_publisher_detected` (this test found a real bug, fixed with per-attempt version folders) |
| Stale or out-of-order version refused | `test_stale_update_refused`, `test_publish_requires_version_1_for_new_file`, `test_republishing_version_1_refused` |

### Authorized dynamic updates
| Requirement | Test(s) |
|---|---|
| Owner update creates a signed hash chain | `test_update_creates_chained_versions`, `test_update_phase_chain_fields` |
| Update refused if the current version is tampered | `test_update_refused_when_current_version_tampered`, `test_update_phase_refuses_tampered_previous` |
| Update with another key refused | `test_unauthorized_update_by_other_key_is_refused` |
| Forged version + forged manifest (attacker key) rejected by reader | `test_forged_version_with_forged_manifest` |
| Unreferenced objects ignored | `test_unsigned_objects_without_manifest_change_are_ignored` |
| Manifest edited without re-signing | `test_manifest_edited_without_resigning` |
| Old version replayed as new | `test_old_version_files_replayed_as_new_version` |
| Manifest rollback | `test_manifest_rollback_detected_with_min_version` (detected with `min_version`; without it the older genuine version is served, as documented) |
| Delete keeps the chain verifiable; only the owner deletes | `test_delete_old_version_keeps_chain`, `test_cannot_delete_active_version`, `test_only_owner_can_delete`, `test_delete_whole_file` |

### Paper workflow, tampering, file types, boundaries (unchanged from before; all PASSED)
| Area | Tests |
|---|---|
| AES / Ring-LWE / RSA / MHT correctness | `test_crypto_primitives.py`, `test_mht_file.py` |
| Tampering: modified blocks, truncation, append, replacement, MHT edits, replaced/removed signature, wrong public key, key-file swap, decryption after failed verification | `test_workflow.py::TestTampering` (23 tests) |
| 7 file types (txt, wav, avi, png, docx, pdf, xlsx), validated before and after round trip | `test_filetypes_boundaries.py::TestFileTypes` |
| Empty, 1-byte, uneven, exact-multiple, custom block sizes, 20 MiB | `test_filetypes_boundaries.py::TestBoundaries` |

## 3. Skipped / not executed

| Test | Why | How to run |
|---|---|---|
| `test_supabase_live.py` (2 tests) | skipped in the default run without credentials; **run separately with credentials and PASSED** (§0b) | `python -m pytest -m supabase_live -v` with `SUPABASE_URL` + `SUPABASE_SECRET_KEY` set (env or `.env`) |
| `test_dropbox_live.py::test_live_upload_verify_decrypt_and_tamper` | no Dropbox credentials | `python -m pytest -m dropbox_live -v` |

## 4. Other executed checks

| Check | Result |
|---|---|
| `python -m securecloud demo` (local folder) | v1 verified and decrypted; authorized update to v2; interrupted v3 "NOT activated", active version still 2; 1-byte tamper → "modified block(s): 1", decryption refused; cleanup removed 7 objects; **DEMO PASSED** |
| Real Supabase SDK, offline construction | `create_client` → `storage.from_()` methods `upload(path, file, file_options)`, `download(path, …)`, `list(path, options)`, `remove(paths)`, `get_bucket(id)`, `create_bucket(id, name, options)`. All match our calls. |
| `streamlit run app.py` (headless, both pages) | `/_stcore/health` → `ok`, no tracebacks |

## 5. Failing cases found during development (and fixed)

| Issue | Fix |
|---|---|
| **Concurrent publishers of the same version wrote into the same `v000002/` folder; the loser's rollback deleted the winner's active files** (found by `test_concurrent_publisher_detected`) | each publish attempt uses its own folder `v<N>-<first 16 hex of SHA-256(signed MHT)>` |
| Local-folder delete left empty version directories | prune empty parent folders after delete |
| Original `benchmark.py` crashed on Windows consoles (`UnicodeEncodeError`) | stdout reconfigured to UTF-8 |
| Sample PDF generator overshot the 100 KB target by 3.4 % | page slicing fixed |
| Benchmark CSV re-plot parsed the mode label `"4096"` as an integer | `load_csv` keeps label columns as strings |
| Ring-LWE with 1 coefficient per bit: 0.40 % / 1.59 % key-decryption failure (P1/P2) | 2-coefficient encoding (0 failures measured) |
