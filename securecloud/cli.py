"""
securecloud/cli.py — "Ring Crypter" command-line tool (paper Fig. 4).

    python -m securecloud keygen   --name alice
    python -m securecloud supabase-setup                     # check / create the PRIVATE bucket
    python -m securecloud encrypt  FILE ...                  # "Encrypt to Local Storage"
    python -m securecloud upload   FILE ...                  # "Upload" (version 1) — Supabase default
    python -m securecloud update   FILE --name NAME ...      # authorized dynamic update (version N+1)

  Enhancement (NOT part of the paper) — per-block AES-256-GCM files (format RCB1):
    python -m securecloud upload FILE --block-mode --owner-rlwe-pub keys/owner_rlwe_public.json ...
    python -m securecloud block-update NAME --offset N --data-file F ...   # re-encrypt/upload only
    python -m securecloud block-update NAME --block I --data-file F ...    #   the affected blocks
    python -m securecloud block-sync   FILE ...                            # only differing blocks
    python -m securecloud demo-blocks  [--backend supabase]
    python -m securecloud verify   NAME ...                  # integrity check only
    python -m securecloud decrypt  NAME --from-dir D         # "Decrypt Locally"      (verify first)
    python -m securecloud decrypt  NAME [--version N]        # "Decrypt from cloud"   (verify first)
    python -m securecloud list | versions NAME | delete NAME | cleanup NAME
    python -m securecloud tamper   FILE --offset N           # demo helper: flip bytes
    python -m securecloud dropbox-auth                       # optional Dropbox backend
    python -m securecloud demo     [--backend supabase]

--backend: supabase (default; --location = bucket), dropbox (--location = folder), local
(--location = directory, offline, NOT a cloud).

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

from . import blockmode, envfile, keys, rlwe, storage, workflow
from .versioning import PublishError, VersionedRepository

DEFAULT_BACKEND = os.environ.get("RINGCRYPTER_BACKEND", "supabase")


def _print_timings(title: str, timings: Dict[str, float]) -> None:
    print(f"  {title}:")
    for k, v in timings.items():
        print(f"    {k:<34} {v:10.3f} ms")


def _print_report(report: workflow.VerificationReport) -> None:
    if report.manifest_valid is not None:
        print(f"  signed manifest valid : {report.manifest_valid}")
    print(f"  RSA signature valid   : {report.signature_valid}")
    if report.signature_valid:
        print(f"  version               : {report.version}"
              + ("" if report.version_ok else "  (VERSION CHECK FAILED)"))
        print(f"  MHT blocks / size     : {report.block_count} x {report.block_size} B")
        print(f"  stored root           : {report.stored_root}")
        print(f"  recomputed root       : {report.computed_root or '-'}")
        print(f"  MHT match             : {report.mht_match}")
        print(f"  key file match        : {report.key_file_match}")
        if report.tampered_blocks:
            print(f"  modified blocks       : {report.tampered_blocks[:50]}"
                  + (" ..." if len(report.tampered_blocks) > 50 else ""))
    print("  RESULT: " + report.summary)


def _add_backend_args(p: argparse.ArgumentParser, required: bool = False) -> None:
    p.add_argument("--backend", choices=storage.BACKENDS, default=None if required else DEFAULT_BACKEND,
                   help=f"storage backend (default {DEFAULT_BACKEND})")
    p.add_argument("--location", help="Supabase bucket / Dropbox folder / local directory")


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
    src.add_argument("--backend", choices=storage.BACKENDS, help="cloud backend")
    p.add_argument("--location", help="Supabase bucket / Dropbox folder / local directory")
    p.add_argument("--version", type=int, help="version to fetch (default: active version)")
    p.add_argument("--min-version", type=int,
                   help="reject if the storage offers an older active version (rollback check)")


def _repo(args) -> VersionedRepository:
    return VersionedRepository(storage.open_storage(args.backend, args.location))


def _signer(args):
    return keys.load_rsa_private(args.signer_key, keys.passphrase_from_env(args.passphrase_env))


def _setup(args) -> workflow.ProtectedBundle:
    src = Path(args.file)
    bundle, t = workflow.setup_phase(src.read_bytes(), src.name, _signer(args),
                                     keys.load_rlwe_public(args.recipient_key),
                                     block_size=args.block_size, paper_mode=args.paper_mode)
    print(f"Setup phase complete for {src.name} ({src.stat().st_size} bytes)")
    _print_timings("timings", t)
    return bundle


def _load_and_verify(args):
    pub = keys.load_rsa_public(args.signer_pub)
    if args.from_dir:
        bundle = workflow.load_bundle(args.from_dir, args.name)
        return bundle, workflow.verify_integrity(bundle, pub)
    repo = _repo(args)
    bundle, report = repo.fetch_verified(args.name, pub, args.version, args.min_version)
    print(f"Fetched '{args.name}' from {repo.storage.name} storage")
    return bundle, report


def cmd_keygen(args) -> int:
    paths = keys.generate_identity(args.key_dir, args.name, rlwe_params=args.rlwe_params,
                                   passphrase=keys.passphrase_from_env(args.passphrase_env),
                                   overwrite=args.force)
    print(json.dumps(keys.describe(paths), indent=2))
    print("Keep the *_private files secret. Share the *_public files.")
    return 0


def cmd_supabase_setup(args) -> int:
    s = storage.SupabaseStorage(args.bucket)
    print(s.ensure_bucket(create=not args.no_create))
    return 0


def cmd_encrypt(args) -> int:
    bundle = _setup(args)
    for p in workflow.save_bundle(bundle, args.out_dir):
        print(f"  wrote {p}")
    return 0


def cmd_upload(args) -> int:
    if getattr(args, "block_mode", False) and getattr(args, "paper_mode", False):
        print("error: --paper-mode (2 blocks / 3-node tree) cannot be used with --block-mode (per-block 4096-byte encryption)", file=sys.stderr)
        return 1
    if getattr(args, "block_mode", False) and getattr(args, "block_size", None):
        print("error: --block-size cannot be customized with --block-mode (fixed at 4096 bytes)", file=sys.stderr)
        return 1
    if args.block_mode:
        if not args.owner_rlwe_pub:
            print("error: --block-mode needs --owner-rlwe-pub (owner's Ring-LWE public key)", file=sys.stderr)
            return 1
        src = Path(args.file)
        bundle, t = blockmode.block_setup_phase(src.read_bytes(), src.name, _signer(args),
                                                keys.load_rlwe_public(args.recipient_key),
                                                keys.load_rlwe_public(args.owner_rlwe_pub))
        print(f"Setup phase (per-block AES-256-GCM, {len(bundle.blocks)} blocks) for {src.name}")
        _print_timings("timings", t)
    else:
        bundle = _setup(args)
    repo = _repo(args)
    entry = repo.publish(bundle, _signer(args))
    print(f"  uploaded to {repo.storage.name}: '{bundle.name}' version {entry.version} is ACTIVE "
          "(all uploads confirmed, then manifest activated)")
    return 0


def cmd_update(args) -> int:
    src = Path(args.file)
    name = args.name or src.name
    repo = _repo(args)
    entry, t = repo.update(name, src.read_bytes(), _signer(args), keys.load_rlwe_public(args.recipient_key),
                           block_size=args.block_size, paper_mode=args.paper_mode)
    _print_timings("setup timings (new version)", t)
    print(f"  '{name}' updated to version {entry.version} (signed, chained to version "
          f"{entry.version - 1}, now ACTIVE)")
    return 0


def _counting_repo(args):
    counter = storage.CountingStorage(storage.open_storage(args.backend, args.location))
    return VersionedRepository(counter), counter


def _print_block_stats(stats, counter) -> None:
    print("  work done for this update:")
    for k in ("blocks_total", "blocks_changed", "blocks_read_for_partial_writes",
              "unchanged_blocks_reused", "plaintext_bytes_encrypted", "ciphertext_bytes_hashed",
              "sha256_leaf_hashes", "sha256_internal_hashes", "merkle_mode", "signed_mht_bytes"):
        if k in stats:
            print(f"    {k:<34} {stats[k]}")
    for k, v in sorted(counter.snapshot().items()):
        print(f"    storage {k:<26} {v}")


def _read_data(args) -> bytes:
    if args.data_file:
        return Path(args.data_file).read_bytes()
    return args.text.encode()


def cmd_block_update(args) -> int:
    repo, counter = _counting_repo(args)
    signer = _signer(args)
    owner_priv = keys.load_rlwe_private(args.owner_rlwe_key, keys.passphrase_from_env(args.passphrase_env))
    data = _read_data(args)
    if args.block is not None:
        entry, stats = repo.block_replace(args.name, args.block, data, signer, owner_priv)
    else:
        entry, stats = repo.block_patch(args.name, args.offset, data, signer, owner_priv)
    print(f"  '{args.name}' block-level update -> version {entry.version} ACTIVE")
    _print_block_stats(stats, counter)
    return 0


def cmd_block_sync(args) -> int:
    repo, counter = _counting_repo(args)
    src = Path(args.file)
    owner_priv = keys.load_rlwe_private(args.owner_rlwe_key, keys.passphrase_from_env(args.passphrase_env))
    entry, stats = repo.block_sync(args.name or src.name, src.read_bytes(), _signer(args), owner_priv)
    print(f"  '{args.name or src.name}' synced -> version {entry.version} ACTIVE")
    _print_block_stats(stats, counter)
    return 0


def cmd_verify(args) -> int:
    _bundle, report = _load_and_verify(args)
    _print_report(report)
    _print_timings("timings", report.timings_ms)
    return 0 if report.ok else 2


def cmd_decrypt(args) -> int:
    bundle, report = _load_and_verify(args)
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
    for name in _repo(args).list_files():
        print(name)
    return 0


def cmd_versions(args) -> int:
    m, versions = _repo(args).versions(args.name, keys.load_rsa_public(args.signer_pub))
    for e in versions:
        flag = "  <- active" if e.version == m.current_version else ""
        print(f"  v{e.version:<4} {e.format}  {e.encrypted_size:>10} B  {e.created_utc}  "
              f"mht {e.mht_sha256[:16]}{flag}")
    return 0


def cmd_delete(args) -> int:
    removed = _repo(args).delete(args.name, _signer(args), args.version)
    print(f"  removed {len(removed)} object(s)")
    return 0


def cmd_cleanup(args) -> int:
    removed = _repo(args).cleanup_incomplete(args.name, keys.load_rsa_public(args.signer_pub))
    print(f"  removed {len(removed)} unreferenced object(s) from incomplete uploads")
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


class _FailOnce:
    """Demo helper: wraps a backend and drops the connection on the first matching upload."""

    def __init__(self, inner, marker: str) -> None:
        self.inner, self.marker, self.name, self.fired = inner, marker, inner.name, False

    def upload(self, key, data):
        if not self.fired and self.marker in key:
            self.fired = True
            raise OSError(f"simulated connection drop while uploading {key}")
        self.inner.upload(key, data)

    def download(self, key):
        return self.inner.download(key)

    def list(self, prefix=""):
        return self.inner.list(prefix)

    def delete(self, keys_):
        self.inner.delete(keys_)


def cmd_demo(args) -> int:
    """End-to-end demonstration on the chosen backend:
    publish v1 -> verify/decrypt -> authorized update v2 -> failed (partial) upload of v3 is not
    activated -> tamper with the active version -> decryption refused -> clean up."""
    with tempfile.TemporaryDirectory() as tmp:
        kdir = Path(tmp) / "keys"
        owner_p, user_p = keys.generate_identity(kdir, "owner"), keys.generate_identity(kdir, "user")
        owner, owner_pub = keys.load_rsa_private(owner_p.rsa_private), keys.load_rsa_public(owner_p.rsa_public)
        user_pub, user = keys.load_rlwe_public(user_p.rlwe_public), keys.load_rlwe_private(user_p.rlwe_private)
        if args.backend == "local":
            store = storage.LocalFolderStorage(Path(tmp) / "cloud")
            print("[note] using LOCAL FOLDER storage (offline, not a cloud)")
        else:
            store = storage.open_storage(args.backend, args.location)
            if isinstance(store, storage.SupabaseStorage):
                print("[supabase]", store.ensure_bucket())
        repo = VersionedRepository(store)
        name = f"demo-{os.urandom(3).hex()}.txt"
        v1 = b"Ring Crypter demo, version 1.\n" * 400
        v2 = b"Ring Crypter demo, version 2 (authorized update).\n" * 300
        ok = True
        try:
            bundle, t = workflow.setup_phase(v1, name, owner, user_pub)
            _print_timings("[owner] setup phase v1", t)
            repo.publish(bundle, owner)
            print(f"[owner] published {name} v1 to {store.name}")

            b, r = repo.fetch_verified(name, owner_pub)
            _print_report(r)
            ok &= workflow.decrypt_verified(b, r, user) == v1
            print(f"[user] v1 decrypted and identical: {ok}")

            entry, _ = repo.update(name, v2, owner, user_pub)
            b, r = repo.fetch_verified(name, owner_pub)
            ok &= r.ok and r.version == 2 and workflow.decrypt_verified(b, r, user) == v2
            print(f"[owner] authorized update -> active version {entry.version}; user verified + "
                  f"decrypted v2: {r.ok}")

            try:
                VersionedRepository(_FailOnce(store, "/v000003-")).update(name, b"v3", owner, user_pub)
                ok = False
            except PublishError as exc:
                print(f"[owner] v3 upload interrupted -> {exc}")
            _b, r = repo.fetch_verified(name, owner_pub)
            ok &= r.ok and r.version == 2
            print(f"[user] active version is still {r.version} (partial v3 never activated)")

            k = repo.keys_for(name, 2, owner_pub)["encrypted_file"]
            enc = bytearray(store.download(k))
            enc[len(enc) // 2] ^= 0x01
            store.upload(k, bytes(enc))
            print("\n[attacker] flipped one byte of the active encrypted file in storage")
            b, r = repo.fetch_verified(name, owner_pub)
            _print_report(r)
            try:
                workflow.decrypt_verified(b, r, user)
                ok = False
                print("[user] ERROR: tampering not detected")
            except workflow.IntegrityError:
                print("[user] decryption refused, as required.")
        finally:
            try:
                n = len(repo.delete(name, owner))
                print(f"[owner] cleaned up {n} demo object(s)")
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                print(f"[warn] cleanup failed: {exc}")
        print("\nDEMO", "PASSED" if ok else "FAILED")
        return 0 if ok else 1


def cmd_demo_blocks(args) -> int:
    """Enhancement demo (NOT part of the paper): per-block AES-256-GCM + block-level updates."""
    with tempfile.TemporaryDirectory() as tmp:
        kdir = Path(tmp) / "keys"
        owner_p, user_p = keys.generate_identity(kdir, "owner"), keys.generate_identity(kdir, "user")
        owner, owner_pub = keys.load_rsa_private(owner_p.rsa_private), keys.load_rsa_public(owner_p.rsa_public)
        owner_rl = keys.load_rlwe_private(owner_p.rlwe_private)
        user_pub, user = keys.load_rlwe_public(user_p.rlwe_public), keys.load_rlwe_private(user_p.rlwe_private)
        if args.backend == "local":
            base = storage.LocalFolderStorage(Path(tmp) / "cloud")
            print("[note] using LOCAL FOLDER storage (offline, not a cloud)")
        else:
            base = storage.open_storage(args.backend, args.location)
            if isinstance(base, storage.SupabaseStorage):
                print("[supabase]", base.ensure_bucket())
        counter = storage.CountingStorage(base)
        repo = VersionedRepository(counter)
        name = f"blockdemo-{os.urandom(3).hex()}.bin"
        data = bytearray(os.urandom(64 * 1024))                          # 16 blocks
        ok = True
        try:
            bundle, _ = blockmode.block_setup_phase(bytes(data), name, owner, user_pub, owner_rl.public)
            counter.reset()
            repo.publish(bundle, owner)
            print(f"[owner] published {name}: {len(bundle.blocks)} encrypted blocks; storage "
                  f"{counter.snapshot()}")

            counter.reset()
            entry, stats = repo.block_patch(name, 5000, b"EDITED", owner, owner_rl)
            data[5000:5006] = b"EDITED"
            print(f"[owner] patched 6 bytes at offset 5000 -> version {entry.version}")
            _print_block_stats(stats, counter)
            ok &= stats["blocks_changed"] == 1 and counter.ops["upload"] == 3   # block + MHT + manifest

            b, r = repo.fetch_verified(name, owner_pub)
            _print_report(r)
            ok &= r.ok and workflow.decrypt_verified(b, r, user) == bytes(data)
            print(f"[user] v2 verified and decrypted correctly: {ok}")
            b1, r1 = repo.fetch_verified(name, owner_pub, version=1)
            print(f"[user] v1 still available and verified: {r1.ok}")
            ok &= r1.ok

            keys_v2 = repo.keys_for(name, 2, owner_pub)["blocks"]
            keys_v1 = repo.keys_for(name, 1, owner_pub)["blocks"]
            old_block1 = base.download(keys_v1[1])
            base.upload(keys_v2[1], old_block1)        # replay the OLD block 1 into version 2
            print("\n[attacker] replaced block 1 of version 2 with the genuine block 1 of version 1")
            b, r = repo.fetch_verified(name, owner_pub)
            _print_report(r)
            try:
                workflow.decrypt_verified(b, r, user)
                ok = False
            except workflow.IntegrityError:
                print("[user] decryption refused, as required.")
            ok &= (not r.ok) and r.tampered_blocks == [1]
        finally:
            try:
                n = len(repo.delete(name, owner))
                print(f"[owner] cleaned up {n} demo object(s)")
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                print(f"[warn] cleanup failed: {exc}")
        print("\nBLOCK DEMO", "PASSED" if ok else "FAILED")
        return 0 if ok else 1


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

    p = sub.add_parser("supabase-setup", help="check that the Supabase bucket exists and is private")
    p.add_argument("--bucket", help="bucket id (default $SUPABASE_BUCKET or 'ringcrypter')")
    p.add_argument("--no-create", action="store_true", help="do not create a missing bucket")
    p.set_defaults(func=cmd_supabase_setup)

    p = sub.add_parser("encrypt", help="setup phase; write the 3 files locally")
    _add_setup_args(p)
    p.add_argument("--out-dir", default="encrypted")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("upload", help="setup phase; publish version 1 to cloud storage")
    _add_setup_args(p)
    _add_backend_args(p)
    p.add_argument("--block-mode", action="store_true",
                   help="ENHANCEMENT: per-block AES-256-GCM (RCB1) enabling block-level updates")
    p.add_argument("--owner-rlwe-pub", help="owner's Ring-LWE public key (block mode)")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("update", help="authorized dynamic update: publish version N+1")
    _add_setup_args(p)
    p.add_argument("--name", help="remote file name (default: basename of FILE)")
    _add_backend_args(p)
    p.set_defaults(func=cmd_update)

    for cmd, helptext in (("block-update", "ENHANCEMENT: update bytes/blocks of an RCB1 file"),
                          ("block-sync", "ENHANCEMENT: upload only the blocks that differ")):
        p = sub.add_parser(cmd, help=helptext)
        if cmd == "block-update":
            p.add_argument("name")
            where = p.add_mutually_exclusive_group(required=True)
            where.add_argument("--offset", type=int, help="byte offset to write at (may extend the file)")
            where.add_argument("--block", type=int, help="replace this whole block")
            what = p.add_mutually_exclusive_group(required=True)
            what.add_argument("--data-file")
            what.add_argument("--text")
            p.set_defaults(func=cmd_block_update)
        else:
            p.add_argument("file")
            p.add_argument("--name", help="remote file name (default: basename of FILE)")
            p.set_defaults(func=cmd_block_sync)
        p.add_argument("--signer-key", required=True, help="owner's RSA private key")
        p.add_argument("--owner-rlwe-key", required=True, help="owner's Ring-LWE PRIVATE key (recovers K)")
        p.add_argument("--passphrase-env")
        _add_backend_args(p)

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
    _add_backend_args(p)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("versions", help="list the versions of a file (verified manifest)")
    p.add_argument("name")
    p.add_argument("--signer-pub", required=True)
    _add_backend_args(p)
    p.set_defaults(func=cmd_versions)

    p = sub.add_parser("delete", help="delete a file, or one non-active version (owner only)")
    p.add_argument("name")
    p.add_argument("--signer-key", required=True)
    p.add_argument("--passphrase-env")
    p.add_argument("--version", type=int)
    _add_backend_args(p)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("cleanup", help="remove objects left by interrupted uploads")
    p.add_argument("name")
    p.add_argument("--signer-pub", required=True)
    _add_backend_args(p)
    p.set_defaults(func=cmd_cleanup)

    p = sub.add_parser("tamper", help="demo helper: modify a local file")
    p.add_argument("file")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--length", type=int, default=1)
    p.add_argument("--truncate", type=int, help="truncate to this many bytes instead")
    p.set_defaults(func=cmd_tamper)

    p = sub.add_parser("dropbox-auth", help="obtain a Dropbox refresh token (optional backend)")
    p.set_defaults(func=cmd_dropbox_auth)

    p = sub.add_parser("demo-blocks", help="ENHANCEMENT demo: per-block encryption + block updates")
    p.add_argument("--backend", choices=storage.BACKENDS, default="local")
    p.add_argument("--location")
    p.set_defaults(func=cmd_demo_blocks)

    p = sub.add_parser("demo", help="end-to-end demonstration incl. update, partial upload, tamper")
    p.add_argument("--backend", choices=storage.BACKENDS, default="local")
    p.add_argument("--location")
    p.set_defaults(func=cmd_demo)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    envfile.load()  # git-ignored .env in the current directory; real env vars win
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except workflow.IntegrityError as exc:
        print(f"integrity error: {exc}", file=sys.stderr)
        return 2
    except (storage.StorageError, FileNotFoundError, FileExistsError, KeyError,
            ValueError, rlwe.RLWEError, blockmode.BlockFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
