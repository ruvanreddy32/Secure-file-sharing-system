# Implementation Limitations and Deviations

This file lists every point where the implementation is not, or cannot be shown to be, an exact
reproduction of the paper (Parida et al., CSNT 2017). For each point it gives the reason and the
effect on faithfulness.

## 1. Not verified in this environment

### 1.1 Live Dropbox integration was not tested end to end
* **Status:** the Dropbox backend (`securecloud/storage.py` · `DropboxStorage`) is implemented with
  the official SDK (`dropbox` 12.2.3). It was **not** run against the real Dropbox service, because
  no Dropbox credentials were available while it was developed.
* **What was tested:** our Dropbox code path (single and chunked uploads, `content_hash` upload
  confirmation, download, listing, error wrapping, missing-credential handling, and the full
  workflow including server-side tampering) against an in-memory **fake** client that mimics the SDK
  method signatures (`tests/test_storage.py`). This proves our logic, not the service.
* **What is ready:** `tests/test_dropbox_live.py` uploads, verifies, decrypts, tampers, and
  re-verifies against real Dropbox. It runs automatically once credentials are set (see README §
  "Configure Dropbox"). `python -m securecloud demo --backend dropbox` and
  `python -m evaluation.paper_benchmark --dropbox` do the same interactively and with timings.
* **Effect:** Dropbox support should be treated as **implemented but unverified** until one of the
  commands above passes with real credentials.

### 1.2 The original paper's numbers cannot be reproduced numerically
* The paper reports results only as plots (Figs. 5–8, Java 1.8, Windows 7, Core i3 2.40 GHz). Our
  "paper" values in `PERFORMANCE_RESULTS.md` are **approximations read by eye** from those plots.
* The paper does not say what its "Setup time" and "Verification time" include. Their magnitudes
  (≈2.3–3.1 s and ≈3.1–3.9 s) are 3 orders of magnitude above our local measurements (≈2–4 ms). They
  most likely include JVM start-up, Dropbox network I/O, or key generation. We report local
  computation separately and network time only with `--dropbox`.
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
| 2.7 | MHT file signed (only) | MHT file additionally records `file-name` and `encrypted-key-sha256` | binds the encrypted-key file and the file name to the signature | **Extension.** It rejects a swapped key file or swapped bundle **before** decryption. It removes nothing from the paper. |
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

## 4. Scope limitations

* **In-memory processing:** files are read fully into memory for encryption and hashing. Tested up
  to 20 MiB (`test_large_file_20mb`). Very large files (GB) would need streaming AES-GCM and
  streaming block hashing.
* **Dynamic updates with integrity (§VII future work)** are not part of the signed workflow. The
  repository's `merkle/updater.py` (O(log n) leaf update) is kept but not connected to re-signing.
* **Single recipient per upload:** K is encrypted for one Ring-LWE public key (which can be the
  owner's own). Multi-recipient sharing would repeat `rlwe.encrypt_key` per recipient.
* **Key distribution / PKI:** the verifier must obtain the owner's genuine RSA public key out of band.
  The paper makes the same assumption.
* **Desktop GUI:** the paper's tool is a Java Swing app (Fig. 4). We provide the same actions as a
  CLI and a Streamlit page rather than a Java GUI.
* **Language/platform:** Python 3.14 / Windows 11 instead of Java 1.8 / Windows 7.
* **No LICENSE file** was present in the original repository. Its code is kept with attribution
  (README); redistribution terms should be confirmed with the original author.
