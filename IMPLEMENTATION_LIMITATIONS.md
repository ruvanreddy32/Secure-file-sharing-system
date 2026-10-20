# Implementation Limitations and Deviations

This file lists every point where the implementation is not, or cannot be shown to be, an exact
reproduction of the paper (Parida et al., CSNT 2017). For each point it gives the reason and the
effect on faithfulness.

## 1. Not verified in this environment

### 1.1 Cloud provider: Supabase instead of Dropbox; not yet run against the real service
* **Deviation:** the paper stores the three objects on **Dropbox**. Because no Dropbox credentials
  were available, the default backend is now **Supabase Storage (Free plan)**, accessed through the
  official `supabase` Python SDK (2.33.0 tested) and a **private** bucket. The paper's protocol does
  not depend on the provider: the objects stored, and what is verified after download, are identical.
  Dropbox remains available as an optional backend (`--backend dropbox`).
* **Status:** **verified against a real Supabase project** (Free plan, private bucket) on
  2026-10-20: both live tests passed and `demo --backend supabase` passed (see TEST_RESULTS.md §0b).
  Not exercised live: the Streamlit page on Supabase, benchmark network timings, and uploads near
  the 50 MB limit.
* **What was tested locally:**
  * every Supabase code path against an in-memory mock (`tests/fakes.py`) that reproduces storage3's
    semantics: one folder level per `list` with folders as `id: None`, limit/offset paging, upsert
    and 409 conflicts, 400 "not_found", the real `storage3.exceptions.StorageApiError`, plus bucket
    get/create and the public flag;
  * the real SDK objects built offline (`create_client(...)` → `storage.from_(bucket)`) to confirm
    that every method we call exists with compatible parameters, and that a network failure surfaces
    as a `StorageError`, not as "object not found".

  This proves our logic, not the service.
* **What is ready:** `tests/test_supabase_live.py` runs these against the real service and deletes
  everything it creates: raw upload/download/list/delete; publish v1; authorized update to v2;
  interrupted v3 upload not activated; unauthorized update refused; server-side tampering detected
  and decryption refused; whole-file delete. It runs once `SUPABASE_URL` and a key are set (README §
  "Configure Supabase"). `python -m securecloud demo --backend supabase` and
  `python -m evaluation.paper_benchmark --cloud supabase` exercise it interactively and with timings.
* **Effect:** the Supabase backend is verified for the operations above. **Dropbox** remains
  implemented but unverified (no credentials).
* **Upload confirmation differs per provider:** Dropbox returns a `content_hash`, which we compare.
  Supabase's upload response has no content digest, so we **read each object back** and compare
  SHA-256. This doubles transfer for uploads; it can be disabled with
  `SupabaseStorage(verify_uploads=False)`.

### 1.2 The original paper's numbers cannot be reproduced numerically
* The paper reports results only as plots (Figs. 5–8, Java 1.8, Windows 7, Core i3 2.40 GHz). Our
  "paper" values in `PERFORMANCE_RESULTS.md` are **approximations read by eye** from those plots.
* The paper does not say what its "Setup time" and "Verification time" include. Their magnitudes
  (≈2.3–3.1 s and ≈3.1–3.9 s) are 3 orders of magnitude above our local measurements (≈2–4 ms). They
  most likely include JVM start-up, Dropbox network I/O, or key generation. We report local
  computation separately and network time only with `--cloud supabase` / `--cloud dropbox`. A
  Supabase network time is not comparable to the paper's Dropbox time in any case.
* **Effect:** only **trends** (dependence on size and type) can be compared, not absolute values.

## 2. Under-specified in the paper: engineering choices

| # | Paper says | Our choice | Why | Effect on faithfulness |
|---|---|---|---|---|
| 2.1 | "AES-256" (no mode / IV / padding) | **AES-256-GCM**, random 96-bit nonce, 4-byte format magic as AAD | authenticated, standard (SP 800-38D), no padding oracle | Compatible with the paper. GCM's tag adds a second integrity layer **after** the MHT check, and a mis-recovered key is detected. |
| 2.2 | "RSA based digital signature algorithm" (no padding, size, hash) | **RSA-3072, RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32 B** | current best practice; PKCS#1 v1.5 also acceptable but PSS has a security proof | Same workflow; the signature bytes differ from any 2017 Java implementation. |
| 2.3 | Reference [35] next to "RSA … signature" is ElGamal's paper | we follow the **text** (RSA) | the text, Fig. 3 and §V-C all say RSA | none |
| 2.4 | "merkle hash tree of height 2 containing 3 nodes" (§V-C) vs general n-leaf tree (§III-A, Fig. 1) | default **4096-B blocks** (n-leaf tree, the repository's convention); **`--paper-mode`** gives exactly 2 leaves + root | the 3-node tree cannot localize tampering; the n-leaf tree implements Fig. 1 and the §VII future work | Both modes are implemented, tested, and benchmarked. |
| 2.5 | "Each of the hashed node … stored in hex format in a text file" | our own deterministic text format (`securecloud/mht.py`) | the paper gives no format | Content is as described (all nodes, hex). Layout is ours. |
| 2.6 | "converted to hex", concatenate, rehash | parent = SHA-256(hex(left) ‖ hex(right)) as ASCII; odd node paired with itself | matches the paper's wording and the repository's existing rule | There is no leaf/internal domain separation (as in the paper). This is safe here because the signed metadata fixes the block size and block count. |
| 2.7 | MHT file signed (only) | MHT file additionally records `file-name`, `encrypted-key-sha256`, and (format v2) `version` and `previous-mht-sha256` | binds the encrypted-key file, the file name and the version chain to the signature | **Extension.** It rejects a swapped key file, a swapped bundle, or a re-ordered or forged version **before** decryption. It removes nothing from the paper, and v1 MHT files still parse. |
| 2.8 | Signature file layout not given | MHT bytes + armored signature block | | none |
| 2.9 | Key storage not discussed | PEM / JSON in `keys/` (git-ignored), optional passphrase (scrypt + AES-GCM for Ring-LWE, PKCS#8 BestAvailableEncryption for RSA) | never commit secrets | none |

## 3. Ring-LWE: what could and could not be recovered

* **Missing specification:** the paper does not give the Ring-LWE scheme details. It cites
  Mishra & Jena, *Securing files in the cloud*, CCEM 2016 [24], whose full text **could not be
  obtained**, so its exact parameters, encoding and implementation are unknown.
* **What we implemented:** the LPR ring-LWE public-key encryption of reference [25] (Lyubashevsky,
  Peikert, Regev). It uses the exact formulation and the parameter sets **P1 = (256, 7681,
  11.31/√2π)** and **P2 = (512, 12289, 12.18/√2π)** from de Clercq, Sinha Roy, Vercauteren,
  Verbauwhede, *Efficient Software Implementation of Ring-LWE Encryption*, DATE 2015 (text checked
  against the PDF). These are the standard ring-LWE encryption parameters from the period of [24].
  **This is an assumption.** [24] may have used different parameters.
* **No substitution:** the key is **not** encrypted with RSA, Kyber/ML-KEM (Module-LWE), or any
  other scheme. No maintained Python library provides plain LPR ring-LWE encryption: liboqs dropped
  NewHope, and Kyber is a different problem. So the scheme is implemented directly (≈330 lines).
* **Engineering differences from de Clercq et al.:**
  | Aspect | de Clercq et al. | Ours | Effect |
  |---|---|---|---|
  | Polynomial multiplication | NTT | exact integer negacyclic convolution (numpy) | identical results, slower (≈0.3–0.8 ms per operation, irrelevant here) |
  | Gaussian sampler | Knuth–Yao, 2⁻⁹⁰ statistical distance | CDT inversion, 12σ tail, 128-bit probabilities, `os.urandom` | same distribution to well below 2⁻⁹⁰ precision loss from the table; **not constant-time** (timing side channel; acceptable for a research tool, not for production) |
  | Message encoding | 1 bit per coefficient | **each key bit in 2 coefficients (i, i+n/2)**, decoded by summed distance | measured key-failure rate with 1 coefficient/bit: **0.40 % (P1), 1.59 % (P2)** per 256-bit key; with ours: **0 errors in 1 152 000 bits** (`evaluation/results/rlwe_failure_rate.json`) |
  | Ciphertexts per AES key | — | P1: 2, P2: 1 | ciphertext size: P1 2 KiB, P2 2 KiB of coefficients (+JSON/base64 overhead) |
* **Residual failure probability:** the double encoding gives an estimated per-bit failure below
  10⁻⁸. A failure would be **detected**, never silent: the AES-GCM tag rejects a wrong key, and the
  user would ask the owner to re-encrypt K.
* **Security level:** the P1/P2 security estimates are from 2014–2015 and predate current lattice
  estimators. For production post-quantum use, a standardized KEM (ML-KEM, FIPS 203) would be
  preferable. That would be a deliberate deviation from the paper and is **not** done here.

## 4. Versioned storage and dynamic updates (added with the Supabase change)

The paper's §VII names "dynamic updating of files with integrity check" as future work.
It is implemented as follows; the cryptographic algorithms are unchanged.

* **Granularity of the paper workflow (RCF1): whole-file versions.** An update re-runs the paper's
  Setup phase on the new content (fresh AES key, Ring-LWE key encryption, MHT, RSA signature) and
  publishes it as version N+1. With whole-file AES-GCM any edit re-randomizes the entire
  ciphertext, so block-level updates are impossible in this format. Block-level updates are
  provided by the separate **per-block format RCB1** (§4b), which is an enhancement and **not part
  of the paper**.
* **Authorization:** only the holder of the owner's RSA private key can publish a version that
  verifies. The owner first verifies the current version (`update_phase`), each version's signed MHT
  names the previous version's signed-MHT hash, and the manifest is signed by the same key. Storage
  write access alone is not enough: forged versions and manifests are rejected by readers
  (`tests/test_versioning.py::TestStorageAttacks`). Storage-level access control (who may write to
  the bucket) is Supabase's job. With a service-role key, anyone holding that key can *delete*
  objects; integrity checks detect this but cannot prevent it.
* **Atomic activation:** the three objects of a new version go to a folder unique to that attempt
  (`v<N>-<16 hex of SHA-256(signed MHT)>`), and only then is the signed manifest written. Each object
  write on Supabase or Dropbox is atomic, so readers see either the old or the new version, never a
  partial one. Failed attempts are rolled back where possible; leftovers are never served and are
  removed by `cleanup`. Tested with failures injected at each of the three uploads and at the
  manifest write.
* **Concurrency:** the publisher re-reads the manifest before activating and aborts if it changed.
  This narrows the race window but is **not** a compare-and-swap. Two owners activating in the
  same instant could both write; the last manifest wins, and the other version stays unreferenced
  (consistent, not corrupted). Supabase Storage offers no conditional writes to close this fully.
* **Rollback / freshness:** a storage provider or attacker can replay an *older genuine* signed
  manifest and serve an older genuine version. That version still verifies, because it is authentic,
  just not the latest. Readers that remember the highest version they have seen can pass
  `--min-version` / `min_version=` to detect this. A fully trusted "latest" would need an external
  timestamp or transparency log (not in the paper).
* **Delete:** deleting an old version removes its objects but keeps a `deleted` entry in the signed
  manifest so the hash chain of later versions stays verifiable. The active version cannot be
  deleted alone.

## 4b. ENHANCEMENT: per-block AES-256-GCM format (RCB1) — not part of the IEEE paper

`securecloud/blockmode.py`. The paper encrypts the whole file (implemented unchanged as RCF1,
still the default). RCB1 is an *additional*, opt-in format: the same primitives (AES-256-GCM,
Ring-LWE key encryption, SHA-256, Merkle Hash Tree, RSA-PSS) applied per 4096-byte block, so an
authorized owner can update individual blocks. Its trade-offs:

* **Leakage that the paper's format does not have:** the storage provider learns *which block
  indices changed* between versions, because unchanged ciphertext blocks are shared objects. It also
  sees the file size rounded to blocks and the number of edits. A whole-file re-encryption (RCF1)
  hides where an edit happened. Use RCF1 where the edit location is sensitive.
* **Same file key across versions:** K stays fixed so that unchanged blocks remain valid. Each
  block encryption uses a fresh random 96-bit nonce. The total number of block encryptions under
  K is signed (`key-block-encryptions`) and capped at 2³², the NIST SP 800-38D limit for random
  IVs; beyond it the owner must re-key by publishing a new file. Readers also reject duplicate
  nonces within a version. Nonces are not checked across versions, which would need all historical
  block headers; the random-nonce collision probability within the cap is the standard ≤ 2⁻³²
  bound.
* **Owner holds a second Ring-LWE copy of K** (`*.owner.key.rlwe`, bound by hash in the signed
  metadata) so it can re-encrypt changed blocks without re-keying. Whoever holds the owner's
  Ring-LWE private key can recover K.
* **Metadata is still O(n):** the paper stores *every* MHT node in the signed MHT file. A block
  update therefore re-serializes, re-signs and uploads O(n) metadata, about 2n × 73 bytes (≈ 600 KB
  at 16 MiB), even though data work is O(k) blocks plus O(k·log n) tree hashes. Measured:
  PERFORMANCE_RESULTS.md §8. Storing only leaves, or signing just the root, would make metadata
  O(1) to O(log n), but would depart further from the paper's MHT-file design and is not done.
* **The owner's update path trusts its own signed metadata:** `block_patch` authenticates the
  current signed MHT with the owner's key, skips the O(n) re-derivation of internal nodes for that
  owner-signed file, and verifies only the blocks it must read (partial writes). It does **not**
  re-verify untouched blocks, which are referenced by hash and verified by every reader. If a
  shared block object is already corrupted in storage, the new version inherits the corruption and
  readers detect it. Activation is refused if a referenced block object is *missing*.
* **Many small objects:** each block is a separate storage object. Reading a whole file or a
  `block_sync` therefore needs n GET requests (parallelized, 8 workers). On real Supabase this makes
  full reads slower than one large object; see PERFORMANCE_RESULTS.md §8 (`edit-8-blocks-sync`).
* **Transient network errors** occurred on real Supabase under parallel transfers (`WinError
  10035`). Idempotent operations are retried up to 3 times with exponential backoff, and retries are
  counted in the HTTP statistics. A failure after retries aborts the update without activating it.
* **Format switch:** a file keeps its format across versions (RCF1 updates via `update`, RCB1 via
  `block-update` / `block-sync`); converting a file between formats means publishing it again.

## 5. Scope limitations

* **In-memory processing:** files are read fully into memory for encryption and hashing. Tested up
  to 20 MiB (`test_large_file_20mb`). Very large files (GB) would need streaming AES-GCM and
  streaming block hashing.
* **Supabase Free-plan limits:** 1 GB of total storage and a 50 MB per-file upload limit at the
  time of writing. Larger encrypted files fail at upload; the version is not activated and the
  error is reported. Resumable (TUS) uploads are not implemented.
* **Supabase object names:** the remote key is `<file name>/v<N>-<id>/<file name>.<suffix>`. File
  names with characters that Supabase rejects in object keys will fail at upload with the provider's
  error message.
* **Single recipient per upload:** K is encrypted for one Ring-LWE public key (which can be the
  owner's own). Multi-recipient sharing would repeat `rlwe.encrypt_key` per recipient.
* **Key distribution / PKI:** the verifier must obtain the owner's genuine RSA public key out of band.
  The paper makes the same assumption.
* **Desktop GUI:** the paper's tool is a Java Swing app (Fig. 4). We provide the same actions as a
  CLI and a Streamlit page rather than a Java GUI.
* **Language/platform:** Python 3.14 / Windows 11 instead of Java 1.8 / Windows 7.
* **No LICENSE file** was present in the original repository. Its code is kept with attribution
  (README); redistribution terms should be confirmed with the original author.
