# Failed Test Cases and Identified Defects

This document catalogs every reproducible failure case, security vulnerability, functional bug, and UI defect discovered during the comprehensive audit of Ring Crypter, along with the resolution and verification status following remediation.

---

## Index of Defects and Remediation Status

| Test ID | Defect Name | Feature Involved | Severity | Initial Classification | Remediation Status | Verification |
|---|---|---|---|---|---|---|
| **FAIL-SEC-01** | Silent Manifest Rollback Vulnerability | Versioning & Anti-Rollback | **High** | Confirmed Security Vulnerability | **FIXED & VERIFIED** | `tests/test_versioning.py`, `tests/test_cli.py`, `tests/test_security_audit_failures.py` |
| **FAIL-UI-01** | Target File Selectbox Desynchronization Between Tabs | Streamlit Multi-tab State | **Medium** | Functional / UI Bug | **FIXED & VERIFIED** | `tests/test_security_audit_failures.py::test_streamlit_synchronized_file_selection` |
| **FAIL-UI-02** | Omission of Key-Match Status from Dashboard KPI Tiles | UI Verification Reporting | **Medium** | UI Display Bug | **FIXED & VERIFIED** | `tests/test_security_audit_failures.py::test_encrypted_key_integrity_metric_and_substitution` |
| **FAIL-UI-03** | Stale Verification & Plaintext State Retained After Tampering | Streamlit Session Lifecycle | **Medium** | UI State Bug | **FIXED & VERIFIED** | `tests/test_security_audit_failures.py::test_streamlit_invalidation_after_attack` |
| **FAIL-CLI-01** | Incompatible `--paper-mode` Silently Ignored with `--block-mode` | CLI Parameter Validation | **Low** | Functional Bug | **FIXED & VERIFIED** | `tests/test_security_audit_failures.py::test_cli_rejects_incompatible_options` |
| **FAIL-DEP-01** | Test Suite Collection Crash on Missing `storage3` Dependency | Test Suite Harness | **Low** | Test Environment Issue | **FIXED & VERIFIED** | `tests/fakes.py` guarded import; pytest collection verified |
| **FAIL-SEC-02** | Insufficient Filename Sanitization for Windows Reserved Names | Filename Validation | **Low** | Input Validation Gap | **FIXED & VERIFIED** | `tests/test_security_audit_failures.py::test_windows_reserved_and_invalid_filenames_rejected` |
| **SUPABASE-ALL**| Supabase Cloud Storage Configuration & Live Tests | Cloud Storage Integration | N/A | Excluded From Scope | **DEFERRED — NOT FIXED OR TESTED** | Supabase credentials not configured; live tests skipped |

---

## Detailed Defect Reports & Verification

### Test ID: FAIL-SEC-01
* **Test Name:** Silent Manifest Rollback Vulnerability
* **Feature Involved:** Version Manifest & Anti-Rollback (`securecloud/versioning.py`, `pages/1_Ring_Crypter_Secure_Cloud.py`)
* **Initial Audit Finding:** When a receiver called `fetch_verified()` without `min_version`, an untrusted cloud storage provider could replace the active `manifest.signed` with an older, genuine signed manifest. The client verified the signature and accepted the old version as current.
* **Root Cause:** Manifest document lacked an independent freshness check or persistent client-side version anchor.
* **Remediation Applied:**
  1. Implemented `VersionTrustStore` in `securecloud/versioning.py`, persisting `{file_name: highest_trusted_version}` in an independent local state file (`keys/.trusted_versions.json` or `RINGCRYPTER_TRUST_STORE`).
  2. In `VersionedRepository.fetch_verified()`, computed `effective_min = max(min_version or 0, trusted_version)`. If `m.current_version < effective_min`, returns `bundle=None`, `fail.manifest_valid = False`, `fail.ok = False`, with diagnostic `"Rollback detected: storage offers version X, but version Y was seen/trusted before"`.
  3. On successful publication (`publish()`, `_activate()`) and verification, updated trusted version in `VersionTrustStore`.
  4. Preserved intentional access to older versions in legitimate version history requests (`fetch_verified(..., version=1)` when current authentic manifest is version 2).
  5. Documented Trust-On-First-Use (TOFU) limitation when no prior local record exists.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_versioning.py`, `tests/test_cli.py`, and `tests/test_security_audit_failures.py`.

---

### Test ID: FAIL-UI-01
* **Test Name:** Target File Selectbox Desynchronization Between Tabs
* **Feature Involved:** Streamlit UI Tab Switching (`pages/1_Ring_Crypter_Secure_Cloud.py`)
* **Initial Audit Finding:** The User tab and Attacker tab selectboxes maintained independent internal states. In multi-file configurations (e.g. `siddu.txt` and `siddu2.txt`), the Attacker tab defaulted to the first file while the User tab inspected another, leading users to attack one file while inspecting another.
* **Root Cause:** User tab used an unkeyed selectbox, while Attacker tab used `key="atk_target"`.
* **Remediation Applied:**
  1. Synchronized target selection between User tab (`key="user_target"`) and Attacker tab (`key="atk_target"`) using `ss["shared_target_file"]` and two-way callback synchronization.
  2. In Attacker tab, explicitly displayed targeting information banner: `Targeting: <name> | Active Version: v<ver> | Format: <fmt>`.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_security_audit_failures.py::test_streamlit_synchronized_file_selection`.

---

### Test ID: FAIL-UI-02
* **Test Name:** Omission of Key-Match Status from Dashboard KPI Tiles
* **Feature Involved:** Integrity Verification Dashboard Display (`pages/1_Ring_Crypter_Secure_Cloud.py`)
* **Initial Audit Finding:** The dashboard rendered 5 KPI metric cards (Signed Manifest, RSA Signature, MHT comparison, Version, Modified blocks). When an encrypted key file was substituted, ciphertext was untouched so MHT comparison showed "match" and 0 modified blocks. All 5 KPI tiles appeared green/valid despite the overall verification failure.
* **Root Cause:** `r.key_file_match` was checked in backend but omitted from the KPI tile columns.
* **Remediation Applied:**
  1. Expanded metrics row to 6 columns, adding `c[3].metric("Encrypted Key", "MATCH" if r.key_file_match else "MISMATCH")`.
  2. Formatted overall verification banner with prominent outcome: `VERIFICATION SUCCESS` or `INTEGRITY CHECK FAILED`.
  3. Ensured key substitution displays `MHT comparison: match`, `Encrypted Key: MISMATCH`, overall verification failed, and Decrypt button disabled.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_security_audit_failures.py::test_encrypted_key_integrity_metric_and_substitution`.

---

### Test ID: FAIL-UI-03
* **Test Name:** Stale Verification & Plaintext State Retained After Tampering
* **Feature Involved:** Streamlit Session Lifecycle Management (`pages/1_Ring_Crypter_Secure_Cloud.py`)
* **Initial Audit Finding:** When an attack was applied in the Attacker tab, `st.session_state` retained prior verification reports (`report`), downloaded bundle (`dl`), and decrypted plaintext (`plain`), leaving the User tab displaying "Verification PASSED" until manually re-verified.
* **Root Cause:** Attack execution modified storage but did not clear verification/decryption session keys.
* **Remediation Applied:**
  1. Created `_invalidate_verification(reason)` helper.
  2. Purged `report`, `dl`, `dl_name`, `dl_version`, and `plain` upon applying attacks, switching target files, changing versions, or publishing updates.
  3. Triggered `st.rerun()` upon attack execution with warning notification requiring fresh verification.
  4. Blocked Decrypt button and download access when verification is invalidated.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_security_audit_failures.py::test_streamlit_invalidation_after_attack`.

---

### Test ID: FAIL-CLI-01
* **Test Name:** Incompatible `--paper-mode` Silently Ignored with `--block-mode`
* **Feature Involved:** CLI Argument Parsing and Validation (`securecloud/cli.py`)
* **Initial Audit Finding:** The CLI accepted `--paper-mode` and `--block-mode` together without error, silently ignoring `--paper-mode`.
* **Root Cause:** Mutual exclusion was defined between `--paper-mode` and `--block-size`, but not against `--block-mode`.
* **Remediation Applied:**
  1. Added explicit mutual exclusion validation in `cmd_upload()`.
  2. Rejects `--block-mode` with `--paper-mode` with `error: --paper-mode (2 blocks / 3-node tree) cannot be used with --block-mode (per-block 4096-byte encryption)`.
  3. Rejects `--block-mode` with `--block-size` with `error: --block-size cannot be customized with --block-mode (fixed at 4096 bytes)`.
  4. Returns exit code 1.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_security_audit_failures.py::test_cli_rejects_incompatible_options`.

---

### Test ID: FAIL-DEP-01
* **Test Name:** Test Suite Collection Crash on Missing `storage3` Dependency
* **Feature Involved:** Test Harness Configuration (`tests/fakes.py`)
* **Initial Audit Finding:** `pytest` crashed during test collection across 4 test files if `storage3` / `supabase` was not installed.
* **Root Cause:** Unconditional top-level import `from storage3.exceptions import StorageApiError` in `tests/fakes.py`.
* **Remediation Applied:**
  1. Wrapped import in `try/except ImportError` block in `tests/fakes.py`.
  2. Defined fallback `StorageApiError` class when `storage3` is absent.
  3. Unrelated local and cryptographic tests collect and run independently.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified test collection under clean environment.

---

### Test ID: FAIL-SEC-02
* **Test Name:** Insufficient Filename Sanitization for Windows Reserved Names
* **Feature Involved:** File Upload Validation (`securecloud/workflow.py`, `securecloud/blockmode.py`)
* **Initial Audit Finding:** Filenames with Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) or path traversal attempts were accepted during `setup_phase()`.
* **Root Cause:** Filename validation only checked for empty strings and slash separators.
* **Remediation Applied:**
  1. Created `validate_file_name(name)` in `securecloud/workflow.py`.
  2. Rejects Windows reserved device names (`WINDOWS_RESERVED`), directory separators (`/`, `\\`), path traversal (`.`, `..`), and trailing dots/spaces with clear `ValueError`.
  3. Enforced in both whole-file `setup_phase()` and block-mode `block_setup_phase()`.
* **Remediation Status:** **FIXED & VERIFIED**.
* **Regression Tests:** Verified in `tests/test_security_audit_failures.py::test_windows_reserved_and_invalid_filenames_rejected`.

---

## Deferred Supabase-Related Items

**Status: DEFERRED — NOT FIXED OR TESTED**

As explicitly specified in the audit requirements:
- Supabase credentials have not been configured.
- Local Folder storage (`cloud_local`) is used for all implementation and verification.
- Existing Supabase integration in `securecloud/storage.py` and `tests/test_supabase_storage.py` has been strictly preserved without modifications.
- Live Supabase integration tests (`tests/test_supabase_live.py`) are skipped gracefully during pytest execution.
