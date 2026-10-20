"""
pages/1_Ring_Crypter_Secure_Cloud.py — Streamlit page for the paper's workflow (Fig. 4 "Ring Crypter").

Owner : choose file -> AES-256 -> Ring-LWE key encryption -> SHA-256 blocks -> MHT -> RSA sign
        -> publish version 1, or an authorized dynamic update (version N+1)
User  : pick file + version -> signed manifest -> download -> verify RSA signature -> rebuild MHT
        -> compare -> decrypt only if verified
Attack: modify the stored objects to demonstrate detection.

Two encrypted-file formats:
  * Whole-file AES-256-GCM (RCF1) — the paper's workflow (default).
  * Per-block AES-256-GCM (RCB1) — ENHANCEMENT, not part of the paper: block-level updates that
    re-encrypt and upload only the changed 4096-byte blocks.

Security note: this page runs on the Streamlit SERVER.  Supabase credentials (including a
service-role / secret key) are read from environment variables or a git-ignored .env file by
securecloud.storage on the server and are never rendered or sent to the browser.
"""

from __future__ import annotations

import os

import streamlit as st

from securecloud import blockmode, envfile, keys, mht, rlwe, signature, storage, workflow
from securecloud.versioning import (Manifest, PublishError, VersionedRepository, manifest_key,
                                    version_keys)

st.set_page_config(page_title="Ring Crypter — Secure Cloud", page_icon="🔐", layout="wide")
envfile.load()  # server-side only: git-ignored .env, never sent to the browser
st.title("Ring Crypter — integrity verification of files uploaded to cloud storage")
st.caption("Parida, Konhar, Mishra & Jena, CSNT 2017 — AES-256 · Ring-LWE · SHA-256 Merkle Hash "
           "Tree · RSA digital signature · cloud storage (Supabase)")

ss = st.session_state
FORMATS = {"RCF1": "Whole-file AES-256-GCM (paper)",
           "RCB1": "Per-block AES-256-GCM (enhancement, not in the paper)"}

# ── Sidebar: keys and storage ────────────────────────────────────────────────
with st.sidebar:
    st.header("Keys")
    key_dir = st.text_input("Key directory", "keys")
    params = st.selectbox("Ring-LWE parameter set", sorted(rlwe.PARAMS), index=1,
                          help="P1=(256,7681,11.31), P2=(512,12289,12.18) — de Clercq et al. 2015")
    c1, c2 = st.columns(2)
    if c1.button("Generate owner+user", use_container_width=True):
        for who in ("owner", "user"):
            keys.generate_identity(key_dir, who, rlwe_params=params, overwrite=True)
        st.success(f"Keys written to {key_dir}/")
    if c2.button("Load keys", use_container_width=True) or "keys" not in ss:
        try:
            o, u = keys.identity_paths(key_dir, "owner"), keys.identity_paths(key_dir, "user")
            ss["keys"] = {
                "owner_rsa": keys.load_rsa_private(o.rsa_private),
                "owner_pub": keys.load_rsa_public(o.rsa_public),
                "owner_rlwe_pub": keys.load_rlwe_public(o.rlwe_public),
                "owner_rlwe": keys.load_rlwe_private(o.rlwe_private),
                "user_rlwe_pub": keys.load_rlwe_public(u.rlwe_public),
                "user_rlwe": keys.load_rlwe_private(u.rlwe_private),
            }
        except (FileNotFoundError, ValueError, rlwe.RLWEError) as exc:
            ss.pop("keys", None)
            st.info(f"No usable keys yet ({type(exc).__name__}). Click 'Generate owner+user'.")
    if "keys" in ss:
        st.caption("Owner RSA key: " + signature.fingerprint(ss["keys"]["owner_pub"])[:16] + "…")

    st.header("Cloud storage")
    have_sb = bool(os.environ.get("SUPABASE_URL") and storage.supabase_key_from_env())
    have_dbx = bool(os.environ.get("DROPBOX_ACCESS_TOKEN") or os.environ.get("DROPBOX_REFRESH_TOKEN"))
    labels = {"supabase": "Supabase Storage", "dropbox": "Dropbox (optional)",
              "local": "Local folder (offline, not a cloud)"}
    backend = st.radio("Backend", list(labels), format_func=labels.get,
                       index=0 if have_sb else (1 if have_dbx else 2))
    default_loc = {"supabase": os.environ.get("SUPABASE_BUCKET", "ringcrypter"),
                   "dropbox": "/RingCrypter", "local": "cloud_local"}[backend]
    location = st.text_input("Bucket / folder", default_loc)
    if backend == "supabase":
        st.caption("Credentials: " + ("configured on the server" if have_sb else
                   "missing — set SUPABASE_URL and SUPABASE_SECRET_KEY (.env), then restart"))
        if have_sb and st.button("Check bucket is private"):
            try:
                st.success(storage.SupabaseStorage(location).ensure_bucket())
            except storage.StorageError as exc:
                st.error(str(exc))
    if backend == "dropbox" and not have_dbx:
        st.warning("Set DROPBOX_REFRESH_TOKEN + DROPBOX_APP_KEY (or DROPBOX_ACCESS_TOKEN) and restart.")


class _DropSignedMhtUpload:
    """Simulates a connection drop: uploads of signed MHT files fail, everything else works."""

    def __init__(self, inner) -> None:
        self.inner, self.name = inner, inner.name

    def upload(self, key, data):
        if key.endswith(workflow.MHT_SUFFIX):
            raise OSError(f"simulated connection drop while uploading {key}")
        self.inner.upload(key, data)

    def download(self, key):
        return self.inner.download(key)

    def list(self, prefix=""):
        return self.inner.list(prefix)

    def delete(self, keys_):
        self.inner.delete(keys_)


def _base_storage():
    return storage.open_storage(backend, location)


def _repo(counting: bool = False):
    s = _base_storage()
    if counting:
        s = storage.CountingStorage(s)
    return VersionedRepository(s)


def _timings_table(t):
    st.table({"stage": list(t), "value": [f"{v:.3f}" if isinstance(v, float) else str(v)
                                          for v in t.values()]})


def _names():
    try:
        return _repo().list_files()
    except storage.StorageError as exc:
        st.error(str(exc))
        return []


def _active_format(name):
    try:
        m = _repo().read_manifest(name, K["owner_pub"])
        return m.entry(m.current_version).format if m else None
    except storage.StorageError:
        return None


if "keys" not in ss:
    st.stop()
K = ss["keys"]


def _invalidate_verification(reason=None):
    """Clear cached verification, downloaded bundle, and decrypted data."""
    ss.pop("report", None)
    ss.pop("dl", None)
    ss.pop("dl_name", None)
    ss.pop("dl_version", None)
    ss.pop("plain", None)
    if reason:
        ss["stale_notice"] = reason


if "shared_target_file" not in ss:
    _init_names = _names()
    ss["shared_target_file"] = _init_names[0] if _init_names else ""


def _on_user_target_change():
    sel = ss.get("user_target", "")
    ss["shared_target_file"] = sel
    ss["atk_target"] = sel
    _invalidate_verification("Target file changed. Please run fresh verification.")


def _on_atk_target_change():
    sel = ss.get("atk_target", "")
    ss["shared_target_file"] = sel
    ss["user_target"] = sel
    _invalidate_verification("Target file changed. Fresh verification is required.")


def _on_user_version_change():
    _invalidate_verification("Target version changed. Please run fresh verification.")


owner_tab, user_tab, attack_tab = st.tabs(["1 · Owner: protect, upload & update",
                                           "2 · User: download, verify, decrypt",
                                           "3 · Attacker: tamper with the cloud copy"])

# ── Owner ────────────────────────────────────────────────────────────────────
with owner_tab:
    up = st.file_uploader("Open a file", key="owner_file")
    existing = _names()
    target = st.selectbox("Publish as", ["(new file — version 1)"] + existing,
                          help="Choose an existing file to publish an authorized dynamic update")
    if target.startswith("(new"):
        fmt = st.radio("Encryption format", list(FORMATS), format_func=FORMATS.get, horizontal=True)
    else:
        fmt = _active_format(target) or "RCF1"
        st.caption(f"Existing file format: {FORMATS[fmt]}"
                   + (" — only changed blocks will be re-encrypted and uploaded" if fmt == "RCB1" else ""))
    paper = False
    if fmt == "RCF1":
        mode = st.radio("MHT blocking", ["4096-byte blocks (block-level localization)",
                                         "Paper mode: 2 blocks / 3-node tree (§V-C)"], horizontal=True)
        paper = mode.startswith("Paper")
    if up is not None and st.button("Run Setup phase & publish", type="primary"):
        try:
            repo = _repo(counting=True)
            stats = None
            if target.startswith("(new"):
                if fmt == "RCB1":
                    bundle, t = blockmode.block_setup_phase(up.getvalue(), up.name, K["owner_rsa"],
                                                            K["user_rlwe_pub"], K["owner_rlwe_pub"])
                else:
                    bundle, t = workflow.setup_phase(up.getvalue(), up.name, K["owner_rsa"],
                                                     K["user_rlwe_pub"], paper_mode=paper)
                entry = repo.publish(bundle, K["owner_rsa"])
            elif fmt == "RCB1":
                entry, stats = repo.block_sync(target, up.getvalue(), K["owner_rsa"], K["owner_rlwe"])
                t = {k: v for k, v in stats.items() if k.endswith("_ms")}
                bundle = None
            else:
                entry, t = repo.update(target, up.getvalue(), K["owner_rsa"], K["user_rlwe_pub"],
                                       paper_mode=paper)
                bundle = repo.download(target, repo.read_manifest(target, K["owner_pub"]).entry(entry.version))
            ss["bundle"], ss["setup_t"], ss["entry"] = bundle, t, entry
            ss["io"] = {**(stats or {}), **repo.storage.snapshot()}
            _invalidate_verification("New version published. Run fresh verification.")
            st.success(f"Version {entry.version} ({entry.format}) uploaded (each upload confirmed) "
                       "and activated.")
        except (PublishError, workflow.IntegrityError, storage.StorageError, ValueError) as exc:
            st.error(f"Not published: {exc}")
    if up is not None and fmt == "RCF1" and st.button("Encrypt to Local Storage only"):
        bundle, t = workflow.setup_phase(up.getvalue(), up.name, K["owner_rsa"], K["user_rlwe_pub"],
                                         paper_mode=paper)
        st.success("Saved: " + ", ".join(map(str, workflow.save_bundle(bundle, "encrypted"))))
        ss["bundle"], ss["setup_t"] = bundle, t
    if "setup_t" in ss:
        b = ss.get("bundle")
        if b is not None:
            m = mht.parse(signature.split_signed_mht(b.signed_mht)[0])
            st.subheader(f"{b.name} — version {m.version} ({m.encryption_format})")
            st.write(f"**{m.block_count}** blocks of {m.block_size} B · root `{m.root}`")
        _timings_table(ss["setup_t"])
        if ss.get("io"):
            with st.expander("Storage operations and work done"):
                _timings_table(ss["io"])
        if isinstance(b, workflow.ProtectedBundle):
            cols = st.columns(3)
            for col, (fname, data) in zip(cols, b.files().items()):
                col.download_button(f"⬇ {fname}", data, file_name=fname)
        if b is not None:
            with st.expander("Signed MHT file"):
                txt = b.signed_mht.decode()
                st.code(txt if len(txt) < 20000 else txt[:20000] + "\n…", language="text")

    st.divider()
    st.subheader("Block-level edit (per-block files only — enhancement)")
    block_files = [n for n in existing if _active_format(n) == "RCB1"]
    if not block_files:
        st.caption("No per-block (RCB1) files yet: publish a new file with the per-block format.")
    else:
        bf = st.selectbox("File", block_files, key="blk_file")
        off = st.number_input("Byte offset", min_value=0, value=0, step=1, key="blk_off")
        text = st.text_input("Bytes to write (UTF-8 text)", "EDITED", key="blk_text")
        if st.button("Apply block-level update"):
            try:
                repo = _repo(counting=True)
                entry, stats = repo.block_patch(bf, int(off), text.encode(), K["owner_rsa"], K["owner_rlwe"])
                ss["blk_result"] = {"new version": entry.version, **stats, **repo.storage.snapshot()}
                _invalidate_verification(f"File '{bf}' updated. Run fresh verification.")
                st.success(f"'{bf}' → version {entry.version}: re-encrypted {stats['blocks_changed']} of "
                           f"{stats['blocks_total']} blocks; uploaded "
                           f"{repo.storage.ops['upload']} objects ({repo.storage.bytes_up:,} B).")
            except (PublishError, workflow.IntegrityError, storage.StorageError, ValueError) as exc:
                st.error(f"Not updated: {exc}")
        if ss.get("blk_result"):
            _timings_table(ss["blk_result"])

# ── User ─────────────────────────────────────────────────────────────────────
with user_tab:
    if "stale_notice" in ss:
        st.warning(ss.pop("stale_notice"))
    names = _names()
    if ss.get("shared_target_file") not in names and names:
        ss["shared_target_file"] = names[0]
    idx_u = names.index(ss["shared_target_file"]) if ss.get("shared_target_file") in names else 0
    name = st.selectbox("Protected files in storage", names, index=idx_u, key="user_target",
                        on_change=_on_user_target_change)
    version = None
    if name:
        try:
            man, versions = _repo().versions(name, K["owner_pub"])
            opts = [f"v{e.version}" + (" (active)" if e.version == man.current_version else "")
                    + f" · {e.format}" for e in reversed(versions)]
            version = int(st.selectbox("Version", opts, key="user_version",
                                       on_change=_on_user_version_change).split()[0][1:])
        except storage.StorageError as exc:  # includes ManifestError
            st.error(f"Signed manifest problem: {exc}")
    if name and st.button("Download & verify integrity", type="primary"):
        bundle, report = _repo().fetch_verified(name, K["owner_pub"], version)
        ss["dl"], ss["report"], ss["dl_name"], ss["dl_version"] = bundle, report, name, version
        ss.pop("plain", None)
    if "report" in ss and ss.get("dl_name") == name and ss.get("dl_version") == version:
        r = ss["report"]
        (st.success if r.ok else st.error)(r.summary)
        c = st.columns(6)
        c[0].metric("Signed manifest", {True: "valid", False: "INVALID", None: "-"}[r.manifest_valid])
        c[1].metric("RSA signature", "valid" if r.signature_valid else "INVALID")
        c[2].metric("MHT comparison", "match" if r.mht_match else "MISMATCH")
        c[3].metric("Encrypted Key", "MATCH" if r.key_file_match else "MISMATCH")
        c[4].metric("Version", f"{r.version}" + ("" if r.version_ok else " ✗"))
        c[5].metric("Modified blocks", len(r.tampered_blocks))
        if r.tampered_blocks:
            st.write("Modified block indices:", r.tampered_blocks[:200])
        st.write(f"stored root `{r.stored_root or '-'}`  \nrecomputed root `{r.computed_root or '-'}`")
        if r.timings_ms:
            _timings_table(r.timings_ms)
        if st.button("Decrypt", disabled=not r.ok,
                     help=None if r.ok else "Decryption is blocked because verification failed"):
            try:
                ss["plain"] = workflow.decrypt_verified(ss["dl"], r, K["user_rlwe"], r.timings_ms)
            except Exception as exc:  # noqa: BLE001 - shown to the user
                st.error(f"Decryption failed: {exc}")
        if "plain" in ss and r.ok:
            st.success(f"Decrypted {len(ss['plain']):,} bytes.")
            st.download_button(f"⬇ {name}", ss["plain"], file_name=name)

# ── Attacker ─────────────────────────────────────────────────────────────────
with attack_tab:
    if "atk_notice" in ss:
        st.warning(ss.pop("atk_notice"))
    st.write("Modify what is stored in the cloud, then re-run verification in tab 2.")
    names_a = _names()
    if ss.get("shared_target_file") not in names_a and names_a:
        ss["shared_target_file"] = names_a[0]
    idx_a = names_a.index(ss["shared_target_file"]) if ss.get("shared_target_file") in names_a else 0
    target_a = st.selectbox("Target", names_a, index=idx_a, key="atk_target",
                            on_change=_on_atk_target_change)
    if target_a:
        try:
            _man = _repo().read_manifest(target_a, K["owner_pub"])
            _cur = _man.entry(_man.current_version) if _man else None
            st.info(f"Targeting: **{target_a}** · Active Version: **v{_cur.version if _cur else '?'}** · Format: **{_cur.format if _cur else '?'}**")
        except Exception:
            st.info(f"Targeting: **{target_a}**")
    attacks = ["Flip one byte of the active encrypted file",
               "Truncate the active encrypted file",
               "Modify a hash in the active MHT file",
               "Re-sign the active MHT with an attacker key",
               "Replace the active encrypted key file",
               "Unauthorized update: publish a version signed by an attacker",
               "Interrupted owner upload (partial new version)",
               "Roll back the manifest to an older genuine version",
               "Per-block files: replay an older version of a block",
               "Per-block files: swap two blocks"]
    attack = st.selectbox("Attack", attacks)
    offset = st.number_input("Byte offset (flip)", min_value=0, value=5000)
    if target_a and st.button("Apply attack", type="secondary"):
        repo = _repo()
        s = repo.storage
        try:
            man = repo.read_manifest(target_a, K["owner_pub"])
            cur = man.entry(man.current_version)
            ks = repo.keys_for(target_a, cur.version, K["owner_pub"])
            is_block = cur.format == "RCB1"
            if attack.startswith("Per-block") and not is_block:
                raise ValueError("this attack needs a per-block (RCB1) file")
            if attack.startswith("Flip"):
                key = ks["blocks"][min(int(offset) // blockmode.BLOCK_SIZE, len(ks["blocks"]) - 1)] \
                    if is_block else ks["encrypted_file"]
                d = bytearray(s.download(key))
                d[min(int(offset) % blockmode.BLOCK_SIZE if is_block else int(offset), len(d) - 1)] ^= 0x01
                s.upload(key, bytes(d))
            elif attack.startswith("Truncate"):
                if is_block:
                    s.delete([ks["blocks"][-1]])
                else:
                    d = s.download(ks["encrypted_file"])
                    s.upload(ks["encrypted_file"], d[: len(d) // 2])
            elif attack.startswith("Modify"):
                d = s.download(ks["signed_mht"])
                i = d.index(b"\nL0 0 ") + 7
                s.upload(ks["signed_mht"], d[:i] + (b"0" if d[i:i + 1] != b"0" else b"1") + d[i + 1:])
            elif attack.startswith("Re-sign"):
                body, _ = signature.split_signed_mht(s.download(ks["signed_mht"]))
                s.upload(ks["signed_mht"], signature.create_signed_mht(body, signature.generate_keypair()))
            elif attack.startswith("Replace"):
                s.upload(ks["encrypted_key"], rlwe.encrypt_key(os.urandom(32), K["user_rlwe_pub"]))
            elif attack.startswith("Unauthorized"):
                evil_key = signature.generate_keypair()
                evil, _ = workflow.setup_phase(b"attacker content", target_a, evil_key, K["user_rlwe_pub"],
                                               version=cur.version + 1, previous_mht_sha256=cur.mht_sha256)
                for attr, key in version_keys(target_a, cur.version + 1,
                                              workflow.signed_mht_sha256(evil)).items():
                    s.upload(key, getattr(evil, attr))
                forged = Manifest.from_bytes(signature.split_signed_mht(s.download(manifest_key(target_a)))[0])
                forged.current_version = cur.version + 1
                forged.versions.append(type(cur)(cur.version + 1, workflow.signed_mht_sha256(evil),
                                                 len(evil.encrypted_file), "forged"))
                s.upload(manifest_key(target_a), signature.create_signed_mht(forged.to_bytes(), evil_key))
            elif attack.startswith("Interrupted"):
                flaky = VersionedRepository(_DropSignedMhtUpload(s))
                try:
                    if is_block:
                        flaky.block_patch(target_a, 0, b"half-uploaded", K["owner_rsa"], K["owner_rlwe"])
                    else:
                        flaky.update(target_a, b"half-uploaded version", K["owner_rsa"], K["user_rlwe_pub"])
                except PublishError as exc:
                    st.info(f"Owner's upload failed: {exc}")
            elif attack.startswith("Roll back"):
                old = st.session_state.get("old_manifests", {}).get(target_a)
                if man.current_version < 2 or old is None:
                    raise ValueError("needs an older manifest captured earlier on this tab "
                                     "(open this tab, publish an update, then apply)")
                s.upload(manifest_key(target_a), old)
            elif attack.endswith("older version of a block"):
                older = [e for e in man.versions if e.version < cur.version and not e.deleted]
                if not older:
                    raise ValueError("needs at least two versions (apply a block-level update first)")
                old_blocks = repo.keys_for(target_a, older[-1].version, K["owner_pub"])["blocks"]
                idx = next((i for i, (a, b) in enumerate(zip(old_blocks, ks["blocks"])) if a != b), None)
                if idx is None:
                    raise ValueError("no block differs between the last two versions")
                s.upload(ks["blocks"][idx], s.download(old_blocks[idx]))   # genuine but stale block
            else:  # swap two blocks
                if len(ks["blocks"]) < 2:
                    raise ValueError("needs at least two blocks")
                a, b = s.download(ks["blocks"][0]), s.download(ks["blocks"][1])
                s.upload(ks["blocks"][0], b)
                s.upload(ks["blocks"][1], a)
            _invalidate_verification(f"Storage for '{target_a}' was modified by attack ({attack}). Verification invalidated; fresh verification required.")
            ss["atk_notice"] = f"Applied: {attack} on {target_a}"
            st.rerun()
        except Exception as exc:  # noqa: BLE001 - shown to the user
            st.error(f"Attack could not be applied: {exc}")
    if target_a:
        # remember the current genuine manifest so a later rollback attack can replay it
        try:
            st.session_state.setdefault("old_manifests", {}).setdefault(
                target_a, _repo().storage.download(manifest_key(target_a)))
        except storage.StorageError:
            pass
