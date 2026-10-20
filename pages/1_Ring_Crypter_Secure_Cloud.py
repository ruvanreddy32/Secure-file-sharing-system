"""
pages/1_Ring_Crypter_Secure_Cloud.py — Streamlit page for the paper's workflow (Fig. 4 "Ring Crypter").

Owner : choose file -> AES-256 -> Ring-LWE key encryption -> SHA-256 blocks -> MHT -> RSA sign
        -> save locally ("Encrypt to Local Storage") or upload ("Upload to DropBox")
User  : download -> verify RSA signature -> rebuild MHT -> compare -> decrypt only if verified
Attack: modify the stored files to demonstrate detection.
"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from securecloud import keys, mht, rlwe, signature, storage, workflow

st.set_page_config(page_title="Ring Crypter — Secure Cloud", page_icon="🔐", layout="wide")
st.title("Ring Crypter — integrity verification of files uploaded to cloud storage")
st.caption("Parida, Konhar, Mishra & Jena, CSNT 2017 — AES-256 · Ring-LWE · SHA-256 Merkle Hash "
           "Tree · RSA digital signature · Dropbox")

ss = st.session_state

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
                "user_rlwe_pub": keys.load_rlwe_public(u.rlwe_public),
                "user_rlwe": keys.load_rlwe_private(u.rlwe_private),
            }
        except (FileNotFoundError, ValueError, rlwe.RLWEError) as exc:
            ss.pop("keys", None)
            st.info(f"No usable keys yet ({type(exc).__name__}). Click 'Generate owner+user'.")
    if "keys" in ss:
        st.caption("Owner RSA key: " + signature.fingerprint(ss["keys"]["owner_pub"])[:16] + "…")

    st.header("Cloud storage")
    have_dbx = bool(os.environ.get("DROPBOX_ACCESS_TOKEN") or os.environ.get("DROPBOX_REFRESH_TOKEN"))
    backend = st.radio("Backend", ["Dropbox", "Local folder (offline, not Dropbox)"],
                       index=0 if have_dbx else 1)
    location = st.text_input("Dropbox folder / local folder",
                             "/RingCrypter" if backend == "Dropbox" else "cloud_local")
    if backend == "Dropbox" and not have_dbx:
        st.warning("Set DROPBOX_REFRESH_TOKEN + DROPBOX_APP_KEY (or DROPBOX_ACCESS_TOKEN) and restart.")


def _store():
    return storage.open_storage("dropbox" if backend == "Dropbox" else "local", location)


def _timings_table(t):
    st.table({"stage": list(t), "time (ms)": [f"{v:.3f}" for v in t.values()]})


if "keys" not in ss:
    st.stop()
K = ss["keys"]

owner_tab, user_tab, attack_tab = st.tabs(["1 · Owner: protect & upload",
                                           "2 · User: download, verify, decrypt",
                                           "3 · Attacker: tamper with cloud copy"])

# ── Owner ────────────────────────────────────────────────────────────────────
with owner_tab:
    up = st.file_uploader("Open a file", key="owner_file")
    mode = st.radio("MHT blocking", ["4096-byte blocks (block-level localization)",
                                     "Paper mode: 2 blocks / 3-node tree (§V-C)"], horizontal=True)
    if up is not None and st.button("Run Setup phase", type="primary"):
        bundle, t = workflow.setup_phase(up.getvalue(), up.name, K["owner_rsa"], K["user_rlwe_pub"],
                                         paper_mode=mode.startswith("Paper"))
        ss["bundle"], ss["setup_t"] = bundle, t
    if "bundle" in ss:
        b = ss["bundle"]
        st.subheader(f"Protected: {b.name}")
        m = mht.parse(signature.split_signed_mht(b.signed_mht)[0])
        st.write(f"Encrypted size **{len(b.encrypted_file):,} B** · **{m.block_count}** blocks of "
                 f"{m.block_size} B · root `{m.root}`")
        _timings_table(ss["setup_t"])
        cols = st.columns(3)
        for col, (fname, data) in zip(cols, b.files().items()):
            col.download_button(f"⬇ {fname}", data, file_name=fname)
        with st.expander("Signed MHT file"):
            txt = b.signed_mht.decode()
            st.code(txt if len(txt) < 20000 else txt[:20000] + "\n…", language="text")
        c1, c2 = st.columns(2)
        if c1.button("Encrypt to Local Storage"):
            paths = workflow.save_bundle(b, "encrypted")
            st.success("Saved: " + ", ".join(map(str, paths)))
        if c2.button(f"Upload to {backend.split(' ')[0]}"):
            try:
                t = workflow.upload_bundle(_store(), b)
                st.success("All three uploads confirmed by the storage provider.")
                _timings_table(t)
            except storage.StorageError as exc:
                st.error(str(exc))

# ── User ─────────────────────────────────────────────────────────────────────
with user_tab:
    try:
        names = workflow.list_bundles(_store())
    except storage.StorageError as exc:
        names = []
        st.error(str(exc))
    name = st.selectbox("Protected files in storage", names)
    if name and st.button("Download & verify integrity", type="primary"):
        bundle, dl_ms = workflow.download_bundle(_store(), name)
        report = workflow.verify_integrity(bundle, K["owner_pub"])
        ss["dl"], ss["report"], ss["dl_ms"] = bundle, report, dl_ms
        ss.pop("plain", None)
    if "report" in ss and ss["dl"].name == name:
        r = ss["report"]
        (st.success if r.ok else st.error)(r.summary)
        c = st.columns(4)
        c[0].metric("RSA signature", "valid" if r.signature_valid else "INVALID")
        c[1].metric("MHT comparison", "match" if r.mht_match else "MISMATCH")
        c[2].metric("Key file", "match" if r.key_file_match else "MISMATCH")
        c[3].metric("Modified blocks", len(r.tampered_blocks))
        if r.tampered_blocks:
            st.write("Modified block indices:", r.tampered_blocks[:200])
        st.write(f"stored root `{r.stored_root}`  \nrecomputed root `{r.computed_root}`")
        _timings_table({"download": ss["dl_ms"], **r.timings_ms})
        if st.button("Decrypt", disabled=not r.ok,
                     help=None if r.ok else "Decryption is blocked because verification failed"):
            try:
                ss["plain"] = workflow.decrypt_verified(ss["dl"], r, K["user_rlwe"], r.timings_ms)
            except (workflow.IntegrityError, Exception) as exc:  # noqa: BLE001 - shown to user
                st.error(f"Decryption failed: {exc}")
        if "plain" in ss:
            st.success(f"Decrypted {len(ss['plain']):,} bytes.")
            st.download_button(f"⬇ {name}", ss["plain"], file_name=name)

# ── Attacker ─────────────────────────────────────────────────────────────────
with attack_tab:
    st.write("Modify the copy stored in the cloud, then re-run verification in tab 2.")
    try:
        names_a = workflow.list_bundles(_store())
    except storage.StorageError:
        names_a = []
    target = st.selectbox("Target", names_a, key="atk_target")
    attack = st.selectbox("Attack", ["Flip one byte of the encrypted file",
                                     "Truncate the encrypted file",
                                     "Modify a hash in the MHT file",
                                     "Re-sign the MHT with an attacker key",
                                     "Replace the encrypted key file"])
    offset = st.number_input("Byte offset (flip)", min_value=0, value=5000)
    if target and st.button("Apply attack", type="secondary"):
        s = _store()
        enc_name, key_name, mht_name = (target + sfx for sfx in
                                        (workflow.ENC_SUFFIX, workflow.KEY_SUFFIX, workflow.MHT_SUFFIX))
        if attack.startswith("Flip"):
            d = bytearray(s.download(enc_name))
            d[min(int(offset), len(d) - 1)] ^= 0x01
            s.upload(enc_name, bytes(d))
        elif attack.startswith("Truncate"):
            d = s.download(enc_name)
            s.upload(enc_name, d[: len(d) // 2])
        elif attack.startswith("Modify"):
            d = s.download(mht_name)
            i = d.index(b"\nL0 0 ") + 7
            s.upload(mht_name, d[:i] + (b"0" if d[i:i + 1] != b"0" else b"1") + d[i + 1:])
        elif attack.startswith("Re-sign"):
            body, _ = signature.split_signed_mht(s.download(mht_name))
            s.upload(mht_name, signature.create_signed_mht(body, signature.generate_keypair()))
        else:
            other = rlwe.encrypt_key(os.urandom(32), K["user_rlwe_pub"])
            s.upload(key_name, other)
        st.warning(f"Applied: {attack} on {target}")
