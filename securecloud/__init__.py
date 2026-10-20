"""
securecloud — Implementation of Parida, Konhar, Mishra & Jena, "Design and Implementation of an
Efficient Tool to Verify Integrity of Files Uploaded to Cloud Storage", CSNT 2017.

Modules:
    aes_cipher – AES-256-GCM file encryption (§IV)
    rlwe       – Ring-LWE (LPR) encryption of the AES file key (§II, §IV)
    mht        – SHA-256 Merkle Hash Tree of the encrypted file + MHT file (§III-A, §V-C)
    signature  – RSA-PSS signing of the MHT file / signed MHT file (§III-C, §V-C)
    keys       – RSA and Ring-LWE identity generation and storage
    storage    – Supabase Storage (default), Dropbox (optional) and local-folder backends (§IV, Fig. 2)
    workflow   – Setup phase, integrity verification, gated decryption (§V-C), dynamic update
    versioning – versioned storage: signed manifest, atomic activation, authorized updates
    cli        – "Ring Crypter" command-line tool (Fig. 4)
"""

from .workflow import (  # noqa: F401
    IntegrityError,
    ProtectedBundle,
    VerificationReport,
    decrypt_verified,
    download_bundle,
    open_bundle,
    setup_phase,
    upload_bundle,
    verify_integrity,
)
