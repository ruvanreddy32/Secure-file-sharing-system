"""
securecloud/signature.py — RSA digital signature of the MHT file (paper §III-C, §V-C).

"The public key Kpub and private key Kpri are generated for digitally signing,
using RSA based digital signature algorithm.  [...] The MHT file is signed with
private key Kpri and then stored in a new signed MHT file."

Modern choices (the paper does not specify them):
* RSA-3072 keys (NIST SP 800-57 level ~128-bit), public exponent 65537.
* RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length = 32 bytes.
* Keys stored as PEM (PKCS#8 private / SubjectPublicKeyInfo public); the
  private key can be encrypted with a passphrase.

Signed MHT file = the exact MHT-file bytes followed by an armored signature::

    <MHT file bytes, ending in "\\n">
    -----BEGIN RING-CRYPTER SIGNATURE-----
    algorithm: RSASSA-PSS-SHA256
    signer-key-sha256: <fingerprint of the signer's public key>
    <base64 signature, 64 chars per line>
    -----END RING-CRYPTER SIGNATURE-----
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_BITS = 3072
ALGORITHM = "RSASSA-PSS-SHA256"
BEGIN = b"-----BEGIN RING-CRYPTER SIGNATURE-----\n"
END = b"-----END RING-CRYPTER SIGNATURE-----\n"
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


class SignatureError(Exception):
    """Raised when a signed MHT file is malformed or its signature is invalid."""


def generate_keypair(bits: int = RSA_KEY_BITS) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_key_to_pem(key: rsa.RSAPrivateKey, passphrase: Optional[bytes] = None) -> bytes:
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def public_key_to_pem(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem: bytes, passphrase: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=passphrase)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SignatureError("Signing key is not an RSA private key")
    return key


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise SignatureError("Verification key is not an RSA public key")
    return key


def fingerprint(pub: rsa.RSAPublicKey) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def sign(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.sign(data, _PSS, hashes.SHA256())


def verify(data: bytes, sig: bytes, pub: rsa.RSAPublicKey) -> bool:
    try:
        pub.verify(sig, data, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def create_signed_mht(mht_bytes: bytes, key: rsa.RSAPrivateKey) -> bytes:
    """Setup step (3): sign the MHT file and produce the signed MHT file."""
    if not mht_bytes.endswith(b"\n"):
        raise ValueError("MHT file must end with a newline")
    b64 = base64.b64encode(sign(mht_bytes, key))
    body = b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return (mht_bytes + BEGIN
            + f"algorithm: {ALGORITHM}\n".encode()
            + f"signer-key-sha256: {fingerprint(key.public_key())}\n".encode()
            + body + b"\n" + END)


def split_signed_mht(signed: bytes) -> Tuple[bytes, bytes]:
    """Return (mht_bytes, signature) from a signed MHT file without verifying."""
    pos = signed.rfind(BEGIN)
    if pos < 0 or not signed.endswith(END) or signed.count(BEGIN) != 1:
        raise SignatureError("Signed MHT file has no (or more than one) signature block")
    mht_bytes, armor = signed[:pos], signed[pos + len(BEGIN): -len(END)]
    lines = armor.decode("ascii", errors="replace").split("\n")
    if len(lines) < 3 or lines[0] != f"algorithm: {ALGORITHM}" \
            or not lines[1].startswith("signer-key-sha256: "):
        raise SignatureError("Unsupported or malformed signature header")
    try:
        sig = base64.b64decode("".join(lines[2:]), validate=True)
    except ValueError as exc:
        raise SignatureError("Signature is not valid base64") from exc
    return mht_bytes, sig


def verify_signed_mht(signed: bytes, pub: rsa.RSAPublicKey) -> bytes:
    """Integrity-verification step (2a): check the signature; return the authenticated MHT bytes.

    Raises:
        SignatureError: malformed file, wrong key, modified MHT, or replaced signature.
    """
    mht_bytes, sig = split_signed_mht(signed)
    if not verify(mht_bytes, sig, pub):
        raise SignatureError("RSA signature verification FAILED: the MHT file or its "
                             "signature was modified, or it was signed with a different key")
    return mht_bytes
