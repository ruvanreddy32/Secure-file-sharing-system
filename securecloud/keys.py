"""
securecloud/keys.py — Key generation and storage for owners and recipients.

An identity has two key pairs:

* RSA (Kpri, Kpub)     — the owner signs MHT files with Kpri; anyone verifies with Kpub.
* Ring-LWE (r2, (a,p)) — the owner encrypts the AES file key with the
                          recipient's Ring-LWE public key; the recipient decrypts it.

Files written by :func:`generate_identity` (in ``key_dir``, default ``keys/``,
which is git-ignored)::

    <name>_rsa_private.pem     <name>_rsa_public.pem
    <name>_rlwe_private.json   <name>_rlwe_public.json

Private keys can be passphrase-protected; the passphrase is read from an
environment variable by the CLI so it never appears on the command line.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from . import rlwe, signature


@dataclass
class IdentityPaths:
    rsa_private: Path
    rsa_public: Path
    rlwe_private: Path
    rlwe_public: Path


def identity_paths(key_dir: Union[str, Path], name: str) -> IdentityPaths:
    d = Path(key_dir)
    return IdentityPaths(d / f"{name}_rsa_private.pem", d / f"{name}_rsa_public.pem",
                         d / f"{name}_rlwe_private.json", d / f"{name}_rlwe_public.json")


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)  # best effort; Windows ignores most mode bits
    except OSError:
        pass


def generate_identity(key_dir: Union[str, Path], name: str, *,
                      rlwe_params: str = rlwe.DEFAULT_PARAMS,
                      passphrase: Optional[bytes] = None,
                      overwrite: bool = False) -> IdentityPaths:
    paths = identity_paths(key_dir, name)
    Path(key_dir).mkdir(parents=True, exist_ok=True)
    existing = [p for p in vars(paths).values() if p.exists()]
    if existing and not overwrite:
        raise FileExistsError(f"Keys already exist: {', '.join(map(str, existing))}")

    rsa_key = signature.generate_keypair()
    _write_private(paths.rsa_private, signature.private_key_to_pem(rsa_key, passphrase))
    paths.rsa_public.write_bytes(signature.public_key_to_pem(rsa_key.public_key()))

    rlwe_key = rlwe.generate_keypair(rlwe_params)
    _write_private(paths.rlwe_private, rlwe.private_key_to_bytes(rlwe_key, passphrase))
    paths.rlwe_public.write_bytes(rlwe.public_key_to_bytes(rlwe_key.public))
    return paths


def load_rsa_private(path: Union[str, Path], passphrase: Optional[bytes] = None):
    return signature.load_private_key(Path(path).read_bytes(), passphrase)


def load_rsa_public(path: Union[str, Path]):
    return signature.load_public_key(Path(path).read_bytes())


def load_rlwe_private(path: Union[str, Path], passphrase: Optional[bytes] = None):
    return rlwe.private_key_from_bytes(Path(path).read_bytes(), passphrase)


def load_rlwe_public(path: Union[str, Path]):
    return rlwe.public_key_from_bytes(Path(path).read_bytes())


def passphrase_from_env(var: Optional[str]) -> Optional[bytes]:
    if not var:
        return None
    value = os.environ.get(var)
    if value is None:
        raise KeyError(f"Environment variable {var} is not set")
    return value.encode()


def describe(paths: IdentityPaths) -> Dict[str, str]:
    return {k: str(v) for k, v in vars(paths).items()}
