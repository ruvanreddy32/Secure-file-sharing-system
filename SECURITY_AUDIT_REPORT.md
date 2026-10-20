# Comprehensive Security and Integrity Audit Report

**Target System:** Ring Crypter — Secure File Integrity Verification  
**Reference Paper:** *Design and Implementation of an Efficient Tool to Verify Integrity of Files Uploaded to Cloud Storage* — Parida, Konhar, Mishra & Jena, IEEE CSNT 2017  
**Date of Audit:** October 20, 2026 (Remediated & Verified)  
**Audit Scope:** End-to-end cryptographic pipeline, Merkle Hash Trees, Ring-LWE key encapsulation, RSA signatures, signed version manifests, dynamic updates, block-level encryption (RCB1), storage backends (Local Folder, Supabase, Dropbox), CLI commands, and Streamlit user interface.

---

## 1. Executive Summary

Ring Crypter implements and extends the integrity verification architecture specified in Parida et al. (IEEE CSNT 2017). The paper's core protocol involves whole-file AES-256 encryption, Ring-LWE public-key encryption of the symmetric file key, SHA-256 Merkle Hash Tree (MHT) construction over the ciphertext, RSA digital signing of the MHT file, and three-file bundle storage on an untrusted cloud.

An exhaustive audit of the codebase, cryptographic primitives, test suite, and UI state was conducted. All seven confirmed non-Supabase defects identified during the audit have been **fixed, verified, and backed by automated regression tests**. Supabase cloud integration remains preserved and deferred for future testing when live credentials are provided.

### Remediation Summary:

| Defect ID | Description | Severity | Status | Verification Reference |
|---|---|---|---|---|
| **FIX 1** | Manifest Rollback Vulnerability | High | **Fixed & Verified** | `VersionTrustStore` persistent anti-rollback |
| **FIX 2** | User & Attacker Tab Desynchronization | Medium | **Fixed & Verified** | Synchronized state & targeting banner |
| **FIX 3** | Encrypted Key Integrity Status Missing from KPI Tiles | Medium | **Fixed & Verified** | 6th KPI column & prominent result |
| **FIX 4** | Stale Streamlit Verification Results Retained | Medium | **Fixed & Verified** | `_invalidate_verification()` & `st.rerun()` |
| **FIX 5** | CLI Incompatible Options Accepted Silently | Low | **Fixed & Verified** | Mutual exclusion validation (exit 1) |
| **FIX 6** | Missing `storage3` Dependency Collection Crash | Low | **Fixed & Verified** | Graceful import guard in `tests/fakes.py` |
| **FIX 7** | Windows Reserved Filenames Accepted | Low | **Fixed & Verified** | Early `validate_file_name()` validation |
| **SUPABASE**| Supabase Cloud Configuration & Live Tests | N/A | **DEFERRED — NOT FIXED OR TESTED** | Excluded per task constraints |

---

## 2. Threat Model & Security Assumptions

The audit evaluated Ring Crypter against the following threat model:

* **Trust Boundaries:**
  * **File Owner (Trusted):** Generates keys, creates versions, signs MHTs and manifests with RSA private key.
  * **Authorized Receiver (Trusted):** Possesses owner's RSA public key and recipient's Ring-LWE private key. Does not decrypt without successful verification.
  * **Local Client Environment (Trusted):** Stores cryptographic keys and the local `VersionTrustStore` reference file.
  * **Cloud Storage Provider (Untrusted / Adversarial):** May inspect stored objects (honest-but-curious), modify ciphertexts, truncate files, substitute keys, replay older blocks/manifests, drop network packets, or forge updates.
  * **External Attacker (Adversarial):** Can attempt to upload unauthorized updates, forge digital signatures, or manipulate local/cloud state.
* **Security Objectives:**
  1. *Confidentiality:* Plaintext file content and symmetric keys must never be revealed to unauthorized parties or cloud providers.
  2. *Integrity & Tamper Detection:* Any alteration to ciphertext, metadata, or keys must be detected *prior* to decryption.
  3. *Authenticity:* Stored objects must be verifiably authenticated as originating from the legitimate owner.
  4. *Anti-Rollback & Freshness:* Stale versions must not be accepted as the active state.
  5. *Atomicity:* Partial or interrupted uploads must never become active.

---

## 3. Component-by-Component Security Evaluation

### 3.1 AES-256-GCM File & Block Encryption (`securecloud/aes_cipher.py`, `blockmode.py`)
* **Whole-File Mode (RCF1):** Uses AES-256-GCM with a fresh 32-byte key from OS CSPRNG (`os.urandom(32)`). A 12-byte random nonce is generated per encryption. Nonce collisions across 500 consecutive encryptions were 0. The format magic `b"RCF1"` is bound as Additional Authenticated Data (AAD).
* **Per-Block Mode (RCB1):** Encrypts each 4096-byte block independently under the same file key.
  * *AAD Binding:* AAD binds `MAGIC || file_id (16B) || block_index (8B) || written_version (4B) || block_size (4B)`. This prevents block-swapping, cross-file splicing, and replay attacks across versions even if Merkle checks were bypassed.
  * *Nonce Budget:* Capped at $2^{32}$ encryptions under one key in accordance with NIST SP 800-38D. Verifier enforces nonce uniqueness.

### 3.2 Ring-LWE Key Encapsulation (`securecloud/rlwe.py`)
* **Scheme:** Implements LPR Ring-LWE encryption following de Clercq et al. (DATE 2015) over $R_q = \mathbb{Z}_q[x]/(x^n + 1)$. Parameter sets:
  * `P1`: $n=256, q=7681, \sigma \approx 4.51$ (medium-term security, 2 ciphertexts per 256-bit key).
  * `P2`: $n=512, q=12289, \sigma \approx 4.86$ (long-term security, 1 ciphertext per 256-bit key).
* **Reliability:** Decryption failure rate on `P2` was tested over 20 randomized trials and achieved 100% success due to the 2x redundancy encoding (two coefficients per key bit).
* **Limitation (Documented):** The discrete Gaussian sampler uses inversion over a cumulative distribution table in pure Python (`bisect`), which is not constant-time. While vulnerable to local timing side-channels, it is safe against remote cloud adversaries.

### 3.3 Digital Signatures (`securecloud/signature.py`)
* **Scheme:** RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length = 32 bytes on 3072-bit RSA keys.
* **Armored Container:** Signs the exact raw byte stream of the MHT text file. Any alteration to the MHT header, tree nodes, or signature block immediately invalidates the signature. Tested against bit flips (Attack 3) and re-signing by unauthorized keys (Attack 4); both rejected 100% of the time.

### 3.4 Merkle Hash Trees (`securecloud/mht.py`, `merkle/`)
* **Tree Rule:** Parents are computed as `SHA-256(hex(left) || hex(right))`. Odd nodes at any level are paired with themselves.
* **Modes:**
  * *Paper Mode:* Encrypted file is divided into 2 blocks, producing a 2-leaf, 3-node tree (§V-C(2)).
  * *4096-byte Mode:* Encrypted file is chunked into 4096-byte blocks, providing granular tamper localization.
* **Key Binding Extension:** The IEEE paper signed only the MHT of the ciphertext. Ring Crypter adds the line `encrypted-key-sha256: <hex>` to the signed MHT, binding the key to the MHT signature.

### 3.5 Versioned Repository & Anti-Rollback (`securecloud/versioning.py`)
* **Atomic Publishing:** Version $N+1$ objects are uploaded first. If any upload fails, unreferenced objects are purged and the manifest remains unchanged (Attack 7 verified).
* **Persistent Rollback Protection:** The repository now incorporates `VersionTrustStore`, recording the highest genuine version verified for each file. Replays of older signed manifests are detected and rejected (`r.ok = False`, `r.manifest_valid = False`), preventing rollback attacks.

### 3.6 Storage Security (`securecloud/storage.py`)
* **LocalFolderStorage:** Enforces strict path normalization in `_safe_key()`. Rejects `..`, empty path segments, leading slashes, and backslashes. Prevents directory traversal attacks.
* **SupabaseStorage:** Enforces private bucket access, rejects public dashboard URLs, authenticates via server-side environment variables, and verifies uploads via read-back digests. (Live tests deferred).

---

## 4. Remediation of the Phase 2 Reported Bug

### 4.1 Summary of the Bug
When Attack 5 ("Replace the active encrypted key file") was tested in Streamlit, the UI appeared to report success with 0 modified blocks.

### 4.2 Root Causes Identified & Addressed:
1. **Target File Desynchronization:** User tab and Attacker tab selectboxes maintained independent state. With multiple files in `cloud_local`, the Attacker tab attacked `siddu.txt` while the User tab re-verified `siddu2.txt`.
   * **Fix:** Synchronized both tabs with `ss["shared_target_file"]` and added explicit targeting confirmation in the Attacker tab.
2. **Missing Encrypted Key KPI Tile:** The UI displayed 5 metric tiles (Manifest, Signature, MHT match, Version, Modified blocks). Because key substitution does not alter ciphertext bytes, MHT matched and 0 blocks were modified. All 5 tiles showed green/valid metrics.
   * **Fix:** Added a 6th metric card for "Encrypted Key" displaying `MATCH` / `MISMATCH` and prominent verification outcome status.
3. **Stale Session State:** Applying an attack did not purge previous verification reports or plaintext.
   * **Fix:** Added `_invalidate_verification()` and `st.rerun()`, immediately clearing old results and blocking decryption.

---

## 5. Audit & Test Suite Results

Full automated testing was conducted across the entire repository:

* **Tests Collected:** 473
* **Tests Passed:** 467
* **Tests Failed:** 0
* **Tests Skipped:** 6 (live cloud integration tests requiring external API credentials)
* **Execution Time:** ~55.8 seconds

---

## 6. Security Limitations & Trust Assumptions

1. **Local Trust Store Security:** `VersionTrustStore` relies on a local JSON file (`keys/.trusted_versions.json` by default). Rollback protection assumes an attacker cannot directly modify files within the client's local key directory.
2. **Trust On First Use (TOFU):** If a client downloads a file for the first time without prior out-of-band knowledge of its version, it must trust the initial manifest received. Subsequent rollbacks below that baseline are prevented.
3. **Discrete Gaussian Side-Channels:** The Ring-LWE implementation in `securecloud/rlwe.py` is in pure Python and not constant-time. While secure against remote storage adversaries, local cache/timing side-channel attacks are possible on shared host hardware.
4. **Supabase Cloud Verification Status:** Live cloud testing on Supabase was deferred because credentials were not provided. Local Folder storage testing confirmed backend logic correctness.
