# Attack Test Results: Ring Crypter Security Audit

This document records the empirical results of testing all attack options available in the Ring Crypter integrity verification system (both CLI and Streamlit Attacker simulation harness), updated following remediation of all confirmed defects.

Testing was conducted using disposable local files under isolated environments (`LocalFolderStorage`) without modifying or deleting existing files in `cloud_local`.

---

## Summary Matrix

| # | Attack Option | Target Format | Stored Data Changed | Expected Rejection Point | Actual Rejection Point | Verification Outcome | Decryption Outcome | Result |
|---|---|---|---|---|---|---|---|---|
| **1** | Flip one encrypted-file byte | RCF1 / RCB1 | Yes | Merkle Tree leaf comparison (§V-C Step 2b) | `mht.compare()` detects leaf hash mismatch | `r.ok = False`, `r.mht_match = False` | Refused (`IntegrityError`) | **PASS** |
| **2** | Truncate encrypted file | RCF1 / RCB1 | Yes | MHT size check & leaf count | `stored.encrypted_file_size != computed.encrypted_file_size` | `r.ok = False`, `r.size_changed = True` | Refused (`IntegrityError`) | **PASS** |
| **3** | Modify MHT metadata | RCF1 / RCB1 | Yes | RSA signature verification (§V-C Step 2a) | `signature.verify_signed_mht()` raises `InvalidSignature` | `r.ok = False`, `r.signature_valid = False` | Refused (`IntegrityError`) | **PASS** |
| **4** | Re-sign MHT with attacker key | RCF1 / RCB1 | Yes | RSA signature verification under owner public key | `signature.verify_signed_mht()` fails | `r.ok = False`, `r.signature_valid = False` | Refused (`IntegrityError`) | **PASS** |
| **5** | Replace active encrypted AES key file | RCF1 / RCB1 | Yes | Encrypted key hash check against signed MHT | `computed.encrypted_key_sha256 != stored.encrypted_key_sha256` | `r.ok = False`, `r.key_file_match = False`, UI displays `MISMATCH` | Refused (`IntegrityError`), Decrypt button disabled | **PASS (Backend & UI Display FIXED)** |
| **6** | Unauthorized version update | RCF1 / RCB1 | Yes | Manifest signature verification under owner key | `repo.read_manifest()` raises `ManifestError` | `r.ok = False`, `r.manifest_valid = False` | Refused (`bundle = None`) | **PASS** |
| **7** | Interrupted owner upload | RCF1 / RCB1 | Yes (partial) | Atomic activation check in `repo.publish()` | `repo.publish()` catches upload error, does not write manifest | Active version remains `v1` (`r.ok = True`) | `v1` decrypts cleanly | **PASS** |
| **8** | Manifest rollback (without `min_version`) | RCF1 / RCB1 | Yes | Monotonic version validation / anti-rollback | `VersionTrustStore` comparison in `fetch_verified()` | `r.ok = False`, `r.manifest_valid = False`, `"Rollback detected"` | Refused (`bundle = None`) | **PASS (FIXED via TrustStore)** |
| **8a**| Manifest rollback (with `min_version`) | RCF1 / RCB1 | Yes | Pinned client version check | `fetch_verified()` detects `current_version < min_version` | `r.ok = False`, `r.manifest_valid = False` | Refused (`bundle = None`) | **PASS** |
| **9** | Replay older encrypted block | RCB1 | Yes | Merkle leaf hash matching in MHT v3 | Recomputed leaf hash differs from signed MHT leaf | `r.ok = False`, `r.mht_match = False` | Refused (`IntegrityError`) | **PASS** |
| **10**| Swap two blocks | RCB1 | Yes | Merkle leaf order and AES-GCM AAD block index | `mht.compare()` detects differing leaf hashes | `r.ok = False`, `r.mht_match = False` | Refused (`IntegrityError`) | **PASS** |

---

## Detailed Attack Execution Logs & Remediation Notes

### Attack 1 — Flip One Encrypted-File Byte
* **Execution:** Selected byte offset 20 of `attack1_flip.txt.aes` and flipped bit 0 (`d[20] ^= 0x01`).
* **Verification Result:** `signature_valid = True`, `mht_match = False`, `tampered_blocks = [0]`.
* **Decryption Result:** Refused by `decrypt_verified()`.
* **Conclusion:** PASS. Tampering localized to block 0; decryption blocked.

---

### Attack 2 — Truncate Encrypted File
* **Execution:** Truncated `attack2_trunc.txt.aes` to 50% of its byte length.
* **Verification Result:** `size_changed = True`, `mht_match = False`, `tampered_blocks = [0, 1]`.
* **Decryption Result:** Refused by `decrypt_verified()`.
* **Conclusion:** PASS. Truncation detected immediately upon tree recomputation.

---

### Attack 3 — Modify MHT Metadata
* **Execution:** Altered one character of leaf hash `L0 0` in `attack3_mht.txt.mht.signed`.
* **Verification Result:** `signature_valid = False`.
* **Decryption Result:** Refused by `decrypt_verified()`.
* **Conclusion:** PASS. RSASSA-PSS signature integrity check failed before tree parsing.

---

### Attack 4 — Re-Sign MHT With Attacker Key
* **Execution:** Extracted raw MHT text body from `attack4_resign.txt.mht.signed` and re-signed it using an attacker RSA-3072 private key.
* **Verification Result:** `signature_valid = False` (Owner public key failed to verify attacker signature).
* **Decryption Result:** Refused by `decrypt_verified()`.
* **Conclusion:** PASS. Attacker signature is not trusted by receiver holding owner public key.

---

### Attack 5 — Replace Encrypted AES Key File
* **Execution:** Generated new random 256-bit AES key, encrypted under recipient's Ring-LWE public key, and uploaded to `<name>.key.rlwe`.
* **Verification Result:**
  * `signature_valid`: `True`
  * `mht_match`: `True` (Ciphertext was unchanged, correctly distinguishing ciphertext from key!)
  * `tampered_blocks`: `[]` (None)
  * `key_file_match`: `False`
  * `ok`: `False`
  * `summary`: `INTEGRITY CHECK FAILED: Encrypted key file does not match the signed MHT metadata`
* **Remediation & UI State:**
  * Added 6th metric column in UI dashboard: `Encrypted Key: MISMATCH`.
  * Highlighted overall verification result with error banner.
  * Synchronized target selectbox across tabs so attacks target the active file.
  * Cleared stale verification report and disabled Decrypt button.
* **Decryption Result:** Strictly blocked.
* **Conclusion:** **PASS (Fully Remediated)**.

---

### Attack 6 — Unauthorized Version Update
* **Execution:** Attacker prepared version 2 of `attack6_unauth.txt`, signed MHT with attacker RSA key, forged `manifest.signed` signed with attacker RSA key, and uploaded to storage.
* **Verification Result:** `ManifestError: Manifest signature invalid`.
* **Decryption Result:** Blocked (`bundle = None`).
* **Conclusion:** PASS. Forged manifest rejected at manifest verification layer.

---

### Attack 7 — Interrupted Owner Upload
* **Execution:** Dropped upload of `.mht.signed` during dynamic update.
* **Verification Result:** Upload exception caught, incomplete version deleted, manifest unchanged.
* **Decryption Result:** Version 1 decrypts cleanly.
* **Conclusion:** PASS. Atomicity preserved; partial versions never become active.

---

### Attack 8 — Manifest Rollback
* **Execution:** Replaced active `manifest.signed` (version 2) with older genuine `manifest.signed` (version 1).
* **Initial Audit Finding:** Accepted silently when called without `min_version` (High-severity vulnerability).
* **Remediation:**
  * Integrated `VersionTrustStore` persistent anti-rollback tracking.
  * Calling `fetch_verified()` without `min_version` now queries `VersionTrustStore`, detecting that version 2 was previously trusted.
  * Returns `r.manifest_valid = False`, `r.ok = False`, with `"Rollback detected: storage offers version 1, but version 2 was seen before"`.
  * Preserved intentional version history inspection via `fetch_verified(..., version=1)`.
* **Decryption Result:** Strictly blocked.
* **Conclusion:** **PASS (Fully Remediated)**.

---

### Attack 9 — Replay an Older Encrypted Block (Per-Block RCB1)
* **Execution:** In RCB1 file, substituted version 2 block 0 with version 1 block 0.
* **Verification Result:** `mht_match = False`, `tampered_blocks = [0]`.
* **Decryption Result:** Blocked by verification report; AES-GCM AAD mismatch if forced.
* **Conclusion:** PASS. Replay rejected at both Merkle leaf verification and AEAD layer.

---

### Attack 10 — Swap Two Blocks (Per-Block RCB1)
* **Execution:** Swapped ciphertext blocks 0 and 1 in storage.
* **Verification Result:** `mht_match = False`, `tampered_blocks = [0, 1]`.
* **Decryption Result:** Blocked by verification report.
* **Conclusion:** PASS. Merkle tree and AAD detect position tampering.
