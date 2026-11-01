# Secure File Sharing System — Project Description

## 1. Project overview

**Secure File Sharing System** (also called **Ring Crypter**) is a secure cloud-file-sharing and integrity-verification system. It allows a file owner to store and share a confidential file through an untrusted cloud provider while giving an authorised receiver a way to determine whether the downloaded data is authentic and unchanged **before any plaintext is released**.

The project implements and extends the ideas in the base paper:

> Parida, P., Konhar, S., Mishra, B., & Jena, D. (2017). *Design and Implementation of an Efficient Tool to Verify Integrity of Files Uploaded to Cloud Storage.* IEEE CSNT 2017, pp. 62–66. DOI: [10.1109/CSNT.2017.13](https://doi.org/10.1109/CSNT.2017.13)

The system is designed for a cloud provider that is available for storage but is not trusted for confidentiality, integrity, freshness, or correct publication of a file. It provides a Streamlit dashboard and command-line interface, with Supabase Storage as the default backend and Dropbox or a local folder as alternatives.

## 2. Base-paper problem statement

Cloud storage makes files convenient to share, but the file owner has limited control once an object is uploaded. A cloud provider, attacker, software fault, or storage failure may alter, truncate, replace, or return an older copy of a file. A normal download therefore does not establish that a receiver obtained the file the owner originally published.

The base paper addresses this problem: **how can a receiver verify the integrity of an encrypted file stored in cloud storage, while preserving confidentiality and allowing the owner to prove the file’s origin?** Its proposed security pipeline combines:

1. AES encryption to protect file contents.
2. Ring-LWE public-key encryption to protect the AES key during sharing.
3. A Merkle Hash Tree (MHT) to represent file integrity hierarchically.
4. An RSA digital signature to authenticate the integrity information.
5. Verification before decryption, so data that fails integrity checks is not decrypted.

The Merkle tree is important because it divides a file into hashed pieces. Rather than merely stating that an entire file has changed, the receiver can compare authenticated and recomputed tree nodes to locate changed blocks.

## 3. Limitations of the base-paper approach

The paper provides a strong conceptual security architecture, but its implementation scope is intentionally small. This project treats the following as the key practical limitations to address.

| Base-paper limitation | Why it matters in a real sharing system |
|---|---|
| The MHT demonstration uses only two leaves and three nodes. | Real files have many blocks, so the integrity structure must scale beyond a demonstration tree and identify affected block indices. |
| AES mode, RSA key size, and signature padding are not fully specified. | Security-critical choices should be explicit, authenticated, and consistently implemented. |
| Dynamic file updates are described as future work. | Without version handling, an update can be interrupted, mixed with old objects, or replaced by a previous valid version. |
| No per-block authenticated update format is defined. | Re-encrypting and uploading an entire file for a small edit wastes bandwidth and compute. |
| The original system targets Dropbox through an older Java SDK. | A modern implementation needs maintainable backends, private-object storage, validation after upload, and reproducible configuration. |
| The basic proposal does not provide a complete publication protocol. | Uploading ciphertext, keys, and metadata separately can expose incomplete or inconsistent state to receivers. |

## 4. Project objective

The objective is to turn the paper’s core idea into a complete and testable system that can securely publish, verify, decrypt, update, and audit files stored on an untrusted cloud service.

More specifically, the project must:

- keep file contents confidential from the cloud provider;
- authenticate the owner and detect ciphertext or metadata tampering;
- verify integrity before permitting decryption;
- pinpoint modified ciphertext blocks;
- safely publish complete file versions and detect rollback attempts;
- make small edits efficient through authenticated block-level updates; and
- provide usable web and CLI workflows with tests and tampering simulations.

## 5. Approach used in this project

### 5.1 Hybrid cryptographic protection

The system uses a hybrid design because symmetric encryption is efficient for bulk file data, while public-key cryptography is suitable for sharing a small secret key.

1. The owner generates a fresh 256-bit AES key for the file.
2. The plaintext is encrypted with **AES-256-GCM**. GCM provides confidentiality and authentication, and uses a random 96-bit nonce.
3. The AES key is encrypted for the receiver with the project’s Ring-LWE/LPR public-key implementation. The cloud therefore stores an encrypted key rather than the usable AES key.
4. The encrypted file is split into 4096-byte ciphertext blocks. Each block is SHA-256 hashed and assembled into a binary Merkle Hash Tree.
5. The owner signs the serialized MHT and its metadata using **RSA-3072 with RSASSA-PSS, SHA-256, and MGF1**.

The signed tree authenticates the expected ciphertext structure. AES-GCM protects each encrypted payload, while the Merkle tree and signature make the complete stored representation independently verifiable.

### 5.2 Verify-before-decrypt gate

The receiver is not allowed to decrypt merely because it possesses the Ring-LWE private key. The workflow first:

1. validates the owner’s RSA-PSS signature;
2. downloads the ciphertext and recomputes its block hashes and Merkle tree;
3. compares the recomputed tree with the signed tree, including intermediate nodes;
4. records any modified block indices in a `VerificationReport`; and
5. binds the successful report to a SHA-256 digest of the exact downloaded ciphertext bytes.

`decrypt_verified()` refuses to decrypt unless the supplied report is valid and is bound to those same bytes. If verification fails, plaintext is withheld. This enforces the paper’s pre-decryption principle as a program-level security invariant rather than as a UI convention.

### 5.3 Scalable Merkle-tree integrity checking

Instead of the paper’s two-leaf example, the project builds a binary MHT over all 4096-byte ciphertext blocks. A leaf is `SHA-256(block)` and an internal node is the SHA-256 hash of the two child hashes. When a level has an odd number of nodes, the final node is paired with itself.

This permits file-wide verification while retaining useful localisation: recursive comparison between the recomputed tree and signed tree identifies the altered leaf blocks. The project also retains a paper-compatible three-node mode for reproducing the original demonstration.

### 5.4 Atomic version publication and anti-rollback protection

To solve the dynamic-update gap, every published version is stored under a versioned path such as:

```text
<filename>/
  v000001-<id>/
    <filename>.aes
    <filename>.key.rlwe
    <filename>.mht.signed
  manifest.signed
```

The system uploads and validates version objects first. Only after they have been successfully written and checked does it publish `manifest.signed`, the RSA-signed active-version pointer. The manifest is the activation point, so an interrupted upload is not presented as a complete version.

Each manifest records version information and hashes that bind the version’s signed MHT. A local `VersionTrustStore` remembers the highest version previously accepted for a file. If a provider serves an older, genuinely signed manifest after a newer one has been seen, the receiver rejects it as a rollback attempt. The first connection uses trust-on-first-use, so a separate trusted timestamp or transparency service would still be needed to prevent a rollback before the receiver has ever observed the file.

### 5.5 RCB1 authenticated block-level update format

The major extension is **RCB1**, an opt-in per-block encrypted format. Whole-file mode (RCF1) re-encrypts and republishes the full file after any change. RCB1 instead protects every 4096-byte plaintext block independently using AES-256-GCM.

Each RCB1 block contains its format marker, block index, written-in version, nonce, ciphertext, and GCM tag. Its additional authenticated data is conceptually:

```text
"RCB1" || file_id || block_index || written_version || block_size
```

This binds a block to its file, position, version, and size. Consequently, an attacker cannot safely splice a block into another file, swap two positions, or replay a block from an earlier version. When an edit occurs, the system determines the affected blocks, re-encrypts and uploads only those blocks, updates their Merkle paths, creates a new signed metadata version, and activates it through the signed manifest. Unchanged content-addressed ciphertext blocks can be reused.

For a small edit in a large file, this reduces the encrypted and uploaded data substantially. It is not always faster: for a small file with many modified blocks, the extra network requests for block objects can make whole-file mode preferable.

### 5.6 Storage, usability, and evaluation

The project provides a storage abstraction with Supabase private buckets, Dropbox, and local-folder implementations. Supabase configuration is loaded from `.env`; uploads include SHA-256 read-back checks. The Streamlit dashboard exposes owner, receiver, and attacker-simulation flows, while the CLI supports key generation, upload, verification/decryption, version updates, and RCB1 block updates.

The evaluation suite reproduces the paper-style benchmarks and compares whole-file and block-level updates. Automated tests cover cryptographic primitives, storage adapters, versioning, verification gates, rollback behavior, block updates, and end-to-end workflows.

## 6. What the project solves

Compared with the base paper, this project delivers a concrete, deployable extension:

- explicit modern cryptographic choices: AES-256-GCM and RSA-3072/PSS;
- scalable 4096-byte Merkle trees with tamper localisation;
- cryptographically enforced verification before decryption;
- signed manifests and atomic multi-object publication;
- local detection of version rollback after a trusted version has been observed;
- RCB1 authenticated block updates with Merkle-path recomputation;
- current cloud-storage integrations, visualisation, CLI tooling, simulations, and tests.

## 7. Remaining limitations

This project improves on the paper but does not claim to solve every cloud-security problem. Current limitations include:

- a single signing owner and designated recipients; collaborative writes would require stronger multi-party access control, such as threshold signatures;
- in-memory MHT construction for very large files;
- observable update locations in RCB1, which can reveal edit locality to the storage provider;
- linear-sized serialized MHT metadata for exceptionally large files; and
- trust-on-first-use for the first manifest seen by a receiver, because the manifest has no independently trusted timestamp.

These limitations define the next research steps rather than weakening the system’s core guarantee: a receiver who has the correct owner key and a valid verification report will decrypt only authenticated, integrity-checked ciphertext.
