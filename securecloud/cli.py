"""
securecloud/cli.py — "Ring Crypter" command-line tool (paper Fig. 4).

    python -m securecloud keygen   --name alice
    python -m securecloud encrypt  FILE ...          # "Encrypt to Local Storage"
    python -m securecloud upload   FILE ...          # "Upload to DropBox"
    python -m securecloud decrypt  NAME --from-dir D # "Decrypt Locally"   (verify first)
    python -m securecloud decrypt  NAME --backend dropbox   # "Decrypt from DropBox"
    python -m securecloud verify   NAME ...          # integrity check only
    python -m securecloud list     --backend dropbox
    python -m securecloud tamper   FILE --offset N   # demo helper: flip bytes
    python -m securecloud dropbox-auth               # obtain a refresh token
    python -m securecloud demo     [--backend dropbox]

Exit status: 0 success, 2 integrity verification failed, 1 other error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from . import keys, rlwe, storage, workflow


def _print_timings(title: str, timings: Dict[str, float]) -> None:
    print(f"  {title}:")
    for k, v in timings.items():
        print(f"    {k:<28} {v:10.3f} ms")


def _print_report(report: workflow.VerificationReport) -> None:
    print(f"  RSA signature valid   : {report.signature_valid}")
    if report.signature_valid:
        print(f"  MHT blocks / size     : {report.block_count} x {report.block_size} B")
        print(f"  stored root           : {report.stored_root}")
        print(f"  recomputed root       : {report.computed_root or '-'}")
        print(f"  MHT match             : {report.mht_match}")
        print(f"  key file match        : {report.key_file_match}")
        if report.tampered_blocks:
            print(f"  modified blocks       : {report.tampered_blocks[:50]}"
                  + (" ..." if len(report.tampered_blocks) > 50 else ""))
    print("  RESULT: " + report.summary)


def _add_setup_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("file", help="plaintext file to protect")
    p.add_argument("--signer-key", required=True, help="owner's RSA private key (PEM)")
    p.add_argument("--recipient-key", required=True, help="recipient's Ring-LWE public key (JSON)")
    p.add_argument("--passphrase-env", help="env var holding the RSA private-key passphrase")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--block-size", type=int, help="MHT block size in bytes (default 4096)")
    g.add_argument("--paper-mode", action="store_true",
                   help="split the encrypted file into 2 blocks (3-node MHT, paper §V-C(2))")


def _add_source_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="original file name, e.g. data.txt")
    p.add_argument("--signer-pub", required=True, help="owner's RSA public key (PEM)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-dir", help="directory holding the three bundle files")
    src.add_argument("--backend", choices=["dropbox", "local"], help="cloud backend")
    p.add_argument("--location", help="Dropbox folder (default /RingCrypter) or local folder")


def _setup(args) -> workflow.ProtectedBundle:
    signer = keys.load_rsa_private(args.signer_key, keys.passphrase_from_env(args.passphrase_env))
    recipient = keys.load_rlwe_public(args.recipient_key)
    src = Path(args.file)
    bundle, t = workflow.setup_phase(src.read_bytes(), src.name, signer, recipient,
                                     block_size=args.block_size, paper_mode=args.paper_mode)
    print(f"Setup phase complete for {src.name} ({src.stat().st_size} bytes)")
    _print_timings("timings", t)
    return bundle


def _load(args) -> workflow.ProtectedBundle:
    if args.from_dir:
        return workflow.load_bundle(args.from_dir, args.name)
    store = storage.open_storage(args.backend, args.location)
    bundle, ms = workflow.download_bundle(store, args.name)
    print(f"Downloaded 3 files for {args.name} from {store.name} in {ms:.1f} ms")
    return bundle


def cmd_keygen(args) -> int:
    paths = keys.generate_identity(args.key_dir, args.name, rlwe_params=args.rlwe_params,
                                   passphrase=keys.passphrase_from_env(args.passphrase_env),
                                   overwrite=args.force)
    print(json.dumps(keys.describe(paths), indent=2))
    print("Keep the *_private files secret. Share the *_public files.")
    return 0


def cmd_encrypt(args) -> int:
    bundle = _setup(args)
    for p in workflow.save_bundle(bundle, args.out_dir):
        print(f"  wrote {p}")
    return 0


def cmd_upload(args) -> int:
    bundle = _setup(args)
    store = storage.open_storage(args.backend, args.location)
    t = workflow.upload_bundle(store, bundle)
    _print_timings(f"uploaded to {store.name} (each upload confirmed)", t)
    return 0


def cmd_verify(args) -> int:
    report = workflow.verify_integrity(_load(args), keys.load_rsa_public(args.signer_pub))
    _print_report(report)
    _print_timings("timings", report.timings_ms)
    return 0 if report.ok else 2


def cmd_decrypt(args) -> int:
    bundle = _load(args)
    report = workflow.verify_integrity(bundle, keys.load_rsa_public(args.signer_pub))
    _print_report(report)
    if not report.ok:
        print("  Decryption NOT performed.")
        return 2
    priv = keys.load_rlwe_private(args.rlwe_key, keys.passphrase_from_env(args.passphrase_env))
    plaintext = workflow.decrypt_verified(bundle, report, priv, report.timings_ms)
    out = Path(args.out or args.name)
    out.write_bytes(plaintext)
    _print_timings("timings", report.timings_ms)
    print(f"  Decrypted {len(plaintext)} bytes -> {out}")
    return 0


def cmd_list(args) -> int:
    store = storage.open_storage(args.backend, args.location)
    for name in workflow.list_bundles(store):
        print(name)
    return 0


def cmd_tamper(args) -> int:
    path = Path(args.file)
    data = bytearray(path.read_bytes())
    if args.truncate is not None:
        data = data[: args.truncate]
    else:
        for i in range(args.offset, min(args.offset + args.length, len(data))):
            data[i] ^= 0xFF
    path.write_bytes(bytes(data))
    print(f"Modified {path} (now {len(data)} bytes)")
    return 0


def cmd_dropbox_auth(args) -> int:
    import dropbox

    app_key = os.environ.get("DROPBOX_APP_KEY")
    if not app_key:
        print("Set DROPBOX_APP_KEY (and DROPBOX_APP_SECRET if not using PKCE) first.")
        return 1
    flow = dropbox.DropboxOAuth2FlowNoRedirect(app_key, use_pkce=True, token_access_type="offline")
    print("1. Open:", flow.start())
    print("2. Click 'Allow' and copy the authorization code.")
    code = input("3. Paste the code here: ").strip()
    res = flow.finish(code)
    print("\nSet this environment variable (do NOT commit it):")
    print(f"  DROPBOX_REFRESH_TOKEN={res.refresh_token}")
    return 0


def cmd_demo(args) -> int:
    """End-to-end demonstration: keys -> setup -> upload -> download -> verify -> decrypt,
    then tamper with the stored encrypted file and show that decryption is refused."""
    with tempfile.TemporaryDirectory() as tmp:
        kdir = Path(tmp) / "keys"
        owner = keys.generate_identity(kdir, "owner")
        user = keys.generate_identity(kdir, "user")
        plaintext = (b"Ring Crypter demo: integrity of files uploaded to cloud storage.\n" * 400)
        name = "data.txt"
        bundle, t = workflow.setup_phase(plaintext, name, keys.load_rsa_private(owner.rsa_private),
                                         keys.load_rlwe_public(user.rlwe_public))
        print("[owner] Setup phase:")
        _print_timings("timings", t)
        if args.backend == "dropbox":
            store = storage.open_storage("dropbox", args.location)
        else:
            store = storage.LocalFolderStorage(Path(tmp) / "cloud")
            print("[note] using LOCAL FOLDER storage (not Dropbox)")
        _print_timings(f"[owner] upload to {store.name}", workflow.upload_bundle(store, bundle))

        dl, ms = workflow.download_bundle(store, name)
        print(f"[user] downloaded in {ms:.1f} ms")
        pub = keys.load_rsa_public(owner.rsa_public)
        out, report = workflow.open_bundle(dl, pub, keys.load_rlwe_private(user.rlwe_private))
        _print_report(report)
        print(f"[user] decrypted file matches original: {out == plaintext}")

        print("\n[attacker] flipping one byte of the stored encrypted file ...")
        enc = bytearray(dl.encrypted_file)
        enc[len(enc) // 2] ^= 0x01
        store.upload(name + workflow.ENC_SUFFIX, bytes(enc))
        dl2, _ = workflow.download_bundle(store, name)
        try:
            workflow.open_bundle(dl2, pub, keys.load_rlwe_private(user.rlwe_private))
            print("[user] ERROR: tampering not detected")
            return 1
        except workflow.IntegrityError as exc:
            _print_report(exc.report)
            print("[user] decryption refused, as required.")
        return 0 if out == plaintext else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m securecloud",
                                 description="Ring Crypter: integrity verification of files "
                                             "uploaded to cloud storage (CSNT 2017).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate RSA + Ring-LWE key pairs")
    p.add_argument("--name", required=True)
    p.add_argument("--key-dir", default="keys")
    p.add_argument("--rlwe-params", default=rlwe.DEFAULT_PARAMS, choices=sorted(rlwe.PARAMS))
    p.add_argument("--passphrase-env", help="env var holding a passphrase for the private keys")
    p.add_argument("--force", action="store_true", help="overwrite existing keys")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="setup phase; write the 3 files locally")
    _add_setup_args(p)
    p.add_argument("--out-dir", default="encrypted")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("upload", help="setup phase; upload the 3 files")
    _add_setup_args(p)
    p.add_argument("--backend", choices=["dropbox", "local"], default="dropbox")
    p.add_argument("--location")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("verify", help="integrity verification only")
    _add_source_args(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("decrypt", help="verify integrity, then decrypt")
    _add_source_args(p)
    p.add_argument("--rlwe-key", required=True, help="recipient's Ring-LWE private key (JSON)")
    p.add_argument("--passphrase-env", help="env var holding the Ring-LWE key passphrase")
    p.add_argument("--out", help="output path (default: NAME)")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("list", help="list protected files in storage")
    p.add_argument("--backend", choices=["dropbox", "local"], default="dropbox")
    p.add_argument("--location")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("tamper", help="demo helper: modify a local file")
    p.add_argument("file")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--length", type=int, default=1)
    p.add_argument("--truncate", type=int, help="truncate to this many bytes instead")
    p.set_defaults(func=cmd_tamper)

    p = sub.add_parser("dropbox-auth", help="obtain a Dropbox refresh token (PKCE)")
    p.set_defaults(func=cmd_dropbox_auth)

    p = sub.add_parser("demo", help="end-to-end demonstration incl. tamper detection")
    p.add_argument("--backend", choices=["dropbox", "local"], default="local")
    p.add_argument("--location")
    p.set_defaults(func=cmd_demo)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (storage.StorageError, FileNotFoundError, FileExistsError, KeyError,
            ValueError, rlwe.RLWEError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
