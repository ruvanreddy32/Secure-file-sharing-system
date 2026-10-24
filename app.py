"""
app.py — Merkle Tree File Integrity Verifier
Streamlit dashboard: sidebar controls + main panel visualization.
Layout: sidebar (controls) | main panel (KPIs, Pyvis tree, legend, banner, proof details)
Icons: Google Material Icons (no emojis)
Tree:  Pyvis, hierarchical UD layout, physics off, auto-center on active path
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from typing import Dict, List, Optional, Tuple

import streamlit as st
import streamlit.components.v1 as components

from merkle.chunker import chunk_bytes
from merkle.node import MerkleNode
from merkle.proof import get_proof, get_proof_path_ids, verify_proof
from merkle.tamper import find_tampered_blocks, get_ancestor_ids
from merkle.tree import MerkleTree
from merkle.updater import update_block as _update_block

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Merkle Tree Integrity Verifier",
    page_icon="🌲",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Google Material Icons + CSS
# ─────────────────────────────────────────────────────────────────────────────

st.markdown(
    """
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <style>
    /* ── Base ── */
    html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }

    .stApp { background: #0d1117; }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #161b22 0%, #0d1117 100%);
        border-right: 1px solid #21262d;
    }
    [data-testid="stSidebar"] .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        letter-spacing: 0.02em;
        font-size: 0.83rem;
        transition: all 0.2s ease;
    }

    /* ── App title in sidebar ── */
    .app-title {
        display: flex; align-items: center; gap: 10px;
        padding: 4px 0 2px;
    }
    .app-title .icon {
        font-family: 'Material Icons Round';
        font-size: 26px;
        color: #58a6ff;
        line-height: 1;
    }
    .app-title h2 {
        margin: 0; font-size: 1.15rem; font-weight: 700;
        color: #e6edf3; letter-spacing: -0.01em;
    }
    .app-subtitle {
        color: #8b949e; font-size: 0.75rem; margin: 2px 0 0 36px;
        line-height: 1.4;
    }

    /* ── Sidebar section headers ── */
    .sb-section {
        display: flex; align-items: center; gap: 6px;
        color: #8b949e; font-size: 0.7rem; font-weight: 600;
        text-transform: uppercase; letter-spacing: 0.1em;
        margin: 14px 0 6px;
    }
    .sb-section .icon {
        font-family: 'Material Icons Round';
        font-size: 14px; color: #58a6ff;
    }

    /* ── File info badge ── */
    .file-badge {
        background: #161b22; border: 1px solid #30363d;
        border-radius: 8px; padding: 8px 12px;
        margin: 6px 0 10px; font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem; color: #8b949e;
    }
    .file-badge .fname { color: #58a6ff; font-weight: 500; }

    /* ── KPI tile row ── */
    .kpi-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 18px;
    }
    .kpi-card {
        background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 14px 16px;
        text-align: left;
        position: relative;
        overflow: hidden;
    }
    .kpi-card::before {
        content: '';
        position: absolute; top: 0; left: 0; right: 0;
        height: 2px;
        background: var(--accent, #58a6ff);
    }
    .kpi-card .kpi-icon {
        font-family: 'Material Icons Round';
        font-size: 18px;
        color: var(--accent, #58a6ff);
        opacity: 0.8;
    }
    .kpi-card .kpi-label {
        font-size: 0.67rem; font-weight: 600;
        text-transform: uppercase; letter-spacing: 0.09em;
        color: #8b949e; margin: 4px 0 6px;
    }
    .kpi-card .kpi-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.25rem; font-weight: 600;
        color: #e6edf3; word-break: break-all;
        line-height: 1.2;
    }
    .kpi-card .kpi-sub {
        font-size: 0.65rem; color: #6e7681; margin-top: 3px;
    }

    /* ── Tree container ── */
    .tree-wrapper {
        border: 1px solid #30363d;
        border-radius: 12px;
        overflow: hidden;
        background: #0d1117;
        margin-bottom: 14px;
    }
    .tree-header {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 16px;
        background: #161b22;
        border-bottom: 1px solid #21262d;
        font-size: 0.8rem; font-weight: 600;
        color: #8b949e; letter-spacing: 0.04em;
    }
    .tree-header .icon {
        font-family: 'Material Icons Round';
        font-size: 16px; color: #58a6ff;
    }

    /* ── Legend ── */
    .legend-row {
        display: flex; flex-wrap: wrap; gap: 18px;
        align-items: center;
        padding: 10px 4px;
        border-bottom: 1px solid #21262d;
        margin-bottom: 14px;
    }
    .legend-item {
        display: flex; align-items: center; gap: 6px;
        font-size: 0.73rem; color: #8b949e; font-weight: 500;
    }
    .legend-dot {
        width: 10px; height: 10px;
        border-radius: 3px;
        flex-shrink: 0;
    }
    .legend-label { color: #c9d1d9; }

    /* ── Result banner ── */
    .result-banner {
        display: flex; align-items: center; gap: 12px;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 14px;
        font-size: 0.9rem; font-weight: 600;
        border-left: 4px solid;
    }
    .result-banner .icon {
        font-family: 'Material Icons Round';
        font-size: 22px;
        flex-shrink: 0;
    }
    .result-banner.ok {
        background: #0a2e1a; border-color: #2ea043; color: #56d364;
    }
    .result-banner.err {
        background: #2e0a0a; border-color: #f85149; color: #ff7b72;
    }
    .result-banner.info {
        background: #0a1929; border-color: #1f6feb; color: #58a6ff;
    }
    .result-banner.warn {
        background: #2a1e00; border-color: #d29922; color: #e3b341;
    }
    .result-banner .detail {
        font-weight: 400; font-size: 0.8rem;
        color: inherit; opacity: 0.8; margin-top: 2px;
    }

    /* ── Proof details table ── */
    .proof-table {
        width: 100%; border-collapse: collapse;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.73rem;
    }
    .proof-table th {
        background: #161b22;
        color: #8b949e;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.65rem;
        letter-spacing: 0.08em;
        padding: 8px 12px;
        border-bottom: 1px solid #30363d;
        text-align: left;
    }
    .proof-table td {
        padding: 7px 12px;
        border-bottom: 1px solid #1c2128;
        color: #c9d1d9;
        vertical-align: top;
    }
    .proof-table tr:hover td { background: #161b22; }
    .proof-table .hash-full {
        color: #58a6ff; word-break: break-all; line-height: 1.5;
    }
    .proof-table .step-num {
        color: #6e7681; font-weight: 600; white-space: nowrap;
    }
    .proof-table .match { color: #56d364; font-weight: 600; }
    .proof-table .mismatch { color: #ff7b72; font-weight: 600; }
    .proof-table .side-badge {
        display: inline-block;
        padding: 1px 7px;
        border-radius: 4px;
        font-size: 0.68rem;
        font-weight: 600;
    }
    .proof-table .left  { background: #1a2c3d; color: #58a6ff; }
    .proof-table .right { background: #1a3d2c; color: #56d364; }

    /* ── Empty state ── */
    .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: #6e7681;
    }
    .empty-state .icon {
        font-family: 'Material Icons Round';
        font-size: 48px;
        color: #30363d;
        display: block;
        margin-bottom: 12px;
    }
    .empty-state h3 { color: #8b949e; font-size: 1rem; margin: 0 0 6px; }
    .empty-state p  { font-size: 0.8rem; margin: 0; }

    /* ── Streamlit overrides ── */
    .stExpander > div > div { background: #161b22 !important; }
    .stExpander header { background: #1c2128 !important; }
    [data-testid="stExpanderToggleIcon"] { color: #58a6ff !important; }
    div[data-testid="stNumberInput"] label,
    div[data-testid="stSelectbox"] label,
    div[data-testid="stTextInput"] label { font-size: 0.78rem !important; color: #8b949e !important; }

    /* ── Number input +/- stepper buttons fix ── */
    /* Reset both stepper buttons to identical neutral style,
       overriding any accidental primary-button colour bleed */
    [data-testid="stNumberInput"] button {
        background: #21262d !important;
        border: 1px solid #30363d !important;
        color: #c9d1d9 !important;
        border-radius: 6px !important;
        box-shadow: none !important;
        cursor: pointer !important;
        transition: background 0.15s ease, border-color 0.15s ease !important;
    }
    [data-testid="stNumberInput"] button:hover {
        background: #30363d !important;
        border-color: #58a6ff !important;
        color: #e6edf3 !important;
    }
    [data-testid="stNumberInput"] button:disabled {
        opacity: 0.35 !important;
        cursor: not-allowed !important;
    }
    /* Also style the number input text field */
    [data-testid="stNumberInput"] input {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        color: #e6edf3 !important;
        font-family: "JetBrains Mono", monospace !important;
        font-size: 0.85rem !important;
    }
    [data-testid="stNumberInput"] input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 0 2px rgba(88,166,255,0.15) !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────────────────────────────────────
# Sample files (generated in memory)
# ─────────────────────────────────────────────────────────────────────────────

def _gen_lorem() -> bytes:
    para = (
        "The Merkle tree is a fundamental data structure in cryptography and "
        "distributed systems. Named after Ralph Merkle, it is a tree in which "
        "every leaf node is labelled with the cryptographic hash of a data block, "
        "and every non-leaf node is labelled with the hash of its child nodes. "
        "This allows efficient and secure verification of large data structures.\n\n"
    )
    return (para * 20).encode()

def _gen_csv() -> bytes:
    header = "id,filename,size_bytes,sha256,modified_at\n"
    rows = [
        f"{i},document_{i:04d}.bin,{1024 * (i % 64 + 1)},"
        f"{hashlib.sha256(f'row{i}'.encode()).hexdigest()},2024-0{(i%9)+1}-{(i%28)+1:02d}T12:00:00Z\n"
        for i in range(1, 180)
    ]
    return (header + "".join(rows)).encode()

def _gen_json() -> bytes:
    import json as _json
    obj = {
        "dataset": "merkle-integrity-demo",
        "version": "1.0",
        "blocks": [
            {"index": i, "hash": hashlib.sha256(f"block{i}".encode()).hexdigest(),
             "size": 4096, "verified": True}
            for i in range(60)
        ],
    }
    return _json.dumps(obj, indent=2).encode()

SAMPLE_FILES: Dict[str, bytes] = {
    "sample_lorem_ipsum.txt": _gen_lorem(),
    "sample_file_manifest.csv": _gen_csv(),
    "sample_block_index.json": _gen_json(),
}

# ─────────────────────────────────────────────────────────────────────────────
# Color palette
# ─────────────────────────────────────────────────────────────────────────────

_C_DEFAULT  = "#37474F"   # dark slate — default internal
_C_LEAF     = "#263238"   # darker — leaf (unselected)
_C_ROOT     = "#4A148C"   # deep purple — root
_C_VERIFY   = "#0D47A1"   # deep blue — proof path main
_C_SIBLING  = "#006064"   # dark cyan — sibling nodes in proof
_C_TAMPER   = "#B71C1C"   # deep red — tampered path
_C_UPDATE   = "#1B5E20"   # deep green — updated path
_C_BORDER   = "#ffffff22"

LEGEND_ITEMS = [
    (_C_ROOT,    "Root"),
    (_C_LEAF,    "Leaf (default)"),
    (_C_VERIFY,  "Proof path"),
    (_C_SIBLING, "Sibling (proof)"),
    (_C_TAMPER,  "Tampered path"),
    (_C_UPDATE,  "Updated path"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Session state
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULTS = {
    "file_data":         None,
    "file_name":         None,
    "file_size":         0,
    "block_size":        4096,
    "tree_built":        False,
    "original_tree":     None,
    "current_tree":      None,
    "trusted_root":      None,
    "current_bytes":     None,
    "highlight":         {},   # id(node) → color hex
    "focus_vids":        [],   # pyvis VIDs to auto-center
    "last_op_count":     0,
    "last_op_label":     "SHA-256 calls",
    "last_action":       "—",
    "status_msg":        "",
    "status_type":       "info",   # ok | err | info | warn
    "status_icon":       "info",
    "proof_steps":       [],   # for Proof Details panel
    "proof_block_idx":   None,
    "tampered_indices":  [],
    "is_tampered":       False,
}

for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ─────────────────────────────────────────────────────────────────────────────
# Helper: compute displayable proof steps
# ─────────────────────────────────────────────────────────────────────────────

def _compute_proof_steps(block_data: bytes, proof: List[dict], trusted_root: str) -> List[dict]:
    """Return a list of dicts describing each step in the proof verification."""
    steps = []
    candidate = hashlib.sha256(block_data).hexdigest()
    steps.append({
        "step_label": "Leaf hash",
        "operation":  f"sha256(block_data)",
        "hash_in":    block_data.hex()[:32] + "…",
        "hash_out":   candidate,
        "side":       None,
    })
    for i, item in enumerate(proof):
        if item["side"] == "right":
            combined_hex = candidate + item["hash"]
            op = f"sha256(candidate ‖ sibling_right)"
        else:
            combined_hex = item["hash"] + candidate
            op = f"sha256(sibling_left ‖ candidate)"
        new_candidate = hashlib.sha256(combined_hex.encode()).hexdigest()
        steps.append({
            "step_label": f"Level {i + 1}",
            "operation":  op,
            "sibling":    item["hash"],
            "side":       item["side"],
            "hash_out":   new_candidate,
        })
        candidate = new_candidate
    return steps

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Pyvis HTML builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_pyvis_html(
    tree: MerkleTree,
    highlight: Dict[int, str],
    focus_py_ids: List[int],
) -> str:
    """Build and return Pyvis HTML with auto-center JS injected."""
    try:
        from pyvis.network import Network
    except ImportError:
        return "<p style='color:#ff7b72'>pyvis not installed. Run: pip install pyvis</p>"

    net = Network(
        height="560px",
        width="100%",
        directed=True,
        bgcolor="#0d1117",
        font_color="#c9d1d9",
    )
    net.set_options(json.dumps({
        "layout": {
            "hierarchical": {
                "enabled": True,
                "direction": "UD",
                "sortMethod": "directed",
                "levelSeparation": 80,
                "nodeSpacing": 120,
                "treeSpacing": 200,
                "parentCentralization": True,
                "blockShifting": True,
                "edgeMinimization": True,
            }
        },
        "physics": {"enabled": False},
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.45}},
            "color": {"color": "#30363d", "highlight": "#58a6ff", "hover": "#58a6ff"},
            "smooth": {"type": "cubicBezier", "forceDirection": "vertical"},
            "width": 1.2,
        },
        "nodes": {
            "font": {"size": 10, "face": "JetBrains Mono, monospace", "color": "#c9d1d9"},
            "borderWidth": 2,
            "borderWidthSelected": 3,
            "shadow": {"enabled": True, "size": 6, "x": 2, "y": 2},
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 80,
            "dragNodes": True,
            "zoomView": True,
            "navigationButtons": False,
        },
    }))

    # ── DFS traversal
    node_id_map: Dict[int, int] = {}
    counter: List[int] = [0]
    visited: set = set()
    edges_added: set = set()

    def _vid(node: MerkleNode) -> int:
        py = id(node)
        if py not in node_id_map:
            node_id_map[py] = counter[0]; counter[0] += 1
        return node_id_map[py]

    def _visit(node: MerkleNode, level: int) -> None:
        vid = _vid(node)
        if vid in visited:
            return
        visited.add(vid)
        py = id(node)

        # Label and tooltip
        if node.is_leaf:
            label = f"L{node.block_index}\n{node.hash[:8]}"
            title = (
                f"<b>Leaf — Block {node.block_index}</b><br>"
                f"<span style='font-family:monospace;font-size:11px'>{node.hash}</span>"
            )
        else:
            is_root = node.parent is None
            label = ("ROOT\n" if is_root else "") + node.hash[:8]
            title = (
                f"<b>{'Root' if is_root else 'Internal'} node</b><br>"
                f"<span style='font-family:monospace;font-size:11px'>{node.hash}</span>"
            )

        # Color
        if py in highlight:
            color = highlight[py]
        elif node.parent is None:
            color = _C_ROOT
        elif node.is_leaf:
            color = _C_LEAF
        else:
            color = _C_DEFAULT

        # Make highlighted nodes more prominent
        border_color = "#ffffff" if py in highlight else "#30363d"
        size_extra = 4 if py in highlight else 0

        net.add_node(
            vid,
            label=label,
            title=title,
            level=level,
            shape="box",
            color={"background": color, "border": border_color,
                   "highlight": {"background": color, "border": "#ffffff"},
                   "hover": {"background": color, "border": "#58a6ff"}},
            margin={"top": 8, "bottom": 8, "left": 10, "right": 10},
            font={"size": 11 + size_extra},
        )

        if not node.is_leaf:
            if node.left is not None:
                _visit(node.left, level + 1)
                lv = _vid(node.left)
                if (vid, lv) not in edges_added:
                    edges_added.add((vid, lv)); net.add_edge(vid, lv)
            if node.right is not None and node.right is not node.left:
                _visit(node.right, level + 1)
                rv = _vid(node.right)
                if (vid, rv) not in edges_added:
                    edges_added.add((vid, rv)); net.add_edge(vid, rv)

    _visit(tree.root, 0)

    # ── Write to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8")
    tmp.close()
    try:
        net.save_graph(tmp.name)
        with open(tmp.name, "r", encoding="utf-8") as f:
            html_str = f.read()
    finally:
        os.unlink(tmp.name)

    # ── Inject auto-center JS
    focus_vids = [node_id_map[py] for py in focus_py_ids if py in node_id_map]
    focus_js = f"""
<script>
(function() {{
    var _focusAttempts = 0;
    function tryFocus() {{
        if (typeof network === 'undefined') {{
            if (_focusAttempts++ < 20) setTimeout(tryFocus, 150);
            return;
        }}
        var nodes = {json.dumps(focus_vids)};
        if (nodes.length > 0) {{
            network.fit({{
                nodes: nodes,
                animation: {{ duration: 700, easingFunction: 'easeInOutQuad' }}
            }});
        }} else {{
            network.fit({{ animation: {{ duration: 400 }} }});
        }}
    }}
    setTimeout(tryFocus, 400);
}})();
</script>
"""
    html_str = html_str.replace("</body>", focus_js + "</body>")
    return html_str

# ─────────────────────────────────────────────────────────────────────────────
# Helper: reset
# ─────────────────────────────────────────────────────────────────────────────

def _reset_all():
    for k, v in _DEFAULTS.items():
        if k not in ("file_data", "file_name", "file_size", "block_size"):
            st.session_state[k] = (v() if callable(v) else v) if not isinstance(v, (list, dict)) else type(v)(v)

def _rebuild_tree(data: bytes, block_size: int) -> None:
    blocks = chunk_bytes(data, block_size)
    tree = MerkleTree(blocks, block_size)
    st.session_state.tree_built    = True
    st.session_state.original_tree = tree
    st.session_state.current_tree  = tree
    st.session_state.trusted_root  = tree.root.hash
    st.session_state.current_bytes = bytearray(data)
    st.session_state.highlight     = {}
    st.session_state.focus_vids    = []
    st.session_state.last_op_count = 0
    st.session_state.last_op_label = "SHA-256 calls"
    st.session_state.last_action   = "Tree built"
    st.session_state.status_msg    = f"Tree built from {len(blocks)} blocks (height {tree.height})."
    st.session_state.status_type   = "info"
    st.session_state.status_icon   = "account_tree"
    st.session_state.proof_steps   = []
    st.session_state.proof_block_idx = None
    st.session_state.tampered_indices = []
    st.session_state.is_tampered   = False

# ─────────────────────────────────────────────────────────────────────────────
# ── SIDEBAR ──────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:

    # Title
    st.markdown(
        """
        <div class="app-title">
          <span class="icon">account_tree</span>
          <h2>Merkle Integrity</h2>
        </div>
        <p class="app-subtitle">
          O(log n) file integrity verification via SHA-256 Merkle trees
        </p>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    # ── File selector ──
    st.markdown(
        '<div class="sb-section"><span class="icon">folder_open</span>File Source</div>',
        unsafe_allow_html=True,
    )
    source = st.radio(
        "Source", ["Upload a file", "Use sample file"],
        label_visibility="collapsed", horizontal=False,
    )

    if source == "Upload a file":
        uploaded = st.file_uploader(
            "Upload", type=None, label_visibility="collapsed",
        )
        if uploaded is not None:
            raw = uploaded.read()
            st.session_state.file_data = raw
            st.session_state.file_name = uploaded.name
            st.session_state.file_size = len(raw)
    else:
        sample_choice = st.selectbox(
            "Sample file", list(SAMPLE_FILES.keys()),
            label_visibility="collapsed",
        )
        raw = SAMPLE_FILES[sample_choice]
        st.session_state.file_data = raw
        st.session_state.file_name = sample_choice
        st.session_state.file_size = len(raw)

    # File info badge
    if st.session_state.file_name:
        size_kb = st.session_state.file_size / 1024
        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"
        st.markdown(
            f'<div class="file-badge">'
            f'<span class="fname">{st.session_state.file_name}</span><br>'
            f'{size_str} &nbsp;·&nbsp; {st.session_state.file_size:,} bytes'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Block size ──
    st.markdown(
        '<div class="sb-section"><span class="icon">tune</span>Configuration</div>',
        unsafe_allow_html=True,
    )
    # Use a key so Streamlit owns the widget state; initialise once from session_state.
    # Do NOT pass value= on every run or +/- buttons fight the externally-written value.
    if "block_size_input" not in st.session_state:
        st.session_state["block_size_input"] = st.session_state.block_size
    st.number_input(
        "Block size (bytes)", min_value=16, max_value=65536,
        step=512, key="block_size_input",
    )
    # Keep block_size in sync (block_size_input is the live value)
    st.session_state.block_size = st.session_state["block_size_input"]

    if st.session_state.file_data:
        n_preview = math.ceil(st.session_state.file_size / st.session_state["block_size_input"])
        st.caption(f"→ {n_preview} blocks, tree height {math.ceil(math.log2(max(n_preview, 2)))}")

    # ── Build Tree button ──
    btn_build = st.button(
        "Build Tree",
        type="primary",
        use_container_width=True,
        disabled=st.session_state.file_data is None,
    )

    tree_ready = st.session_state.tree_built
    n_blocks   = len(st.session_state.current_tree.leaves) if tree_ready else 1

    # ── Action sections (only visible after tree is built) ──
    if tree_ready:
        st.divider()
        st.markdown(
            '<div class="sb-section"><span class="icon">science</span>Actions</div>',
            unsafe_allow_html=True,
        )

        # ── Verify Block ──
        with st.expander("Verify Block", expanded=False):
            st.caption("Check one block against the trusted root without reading others.")
            v_idx = st.number_input(
                "Block index", min_value=0, max_value=n_blocks - 1,
                value=0, step=1, key="v_idx",
            )
            btn_verify = st.button(
                "Verify", use_container_width=True, key="btn_verify",
            )

        # ── Tamper Block ──
        with st.expander("Tamper Block", expanded=False):
            st.caption("Simulate an attacker flipping bytes in one block.")
            t_idx = st.number_input(
                "Block index", min_value=0, max_value=n_blocks - 1,
                value=0, step=1, key="t_idx",
            )
            t_val = st.text_input(
                "Corruption value (leave blank = bit-flip first byte)",
                value="", placeholder="e.g.  CORRUPTED",
                key="t_val",
            )
            btn_tamper = st.button(
                "Tamper", use_container_width=True, key="btn_tamper",
            )

        # ── Update Block ──
        with st.expander("Update Block", expanded=False):
            st.caption("Legitimately update one block — only O(log n) rehashes.")
            u_idx = st.number_input(
                "Block index", min_value=0, max_value=n_blocks - 1,
                value=0, step=1, key="u_idx",
            )
            u_val = st.text_input(
                "New block content (leave blank = random bytes)",
                value="", placeholder="Enter new content…",
                key="u_val",
            )
            btn_update = st.button(
                "Update", use_container_width=True, key="btn_update",
            )

        st.divider()
        btn_reset = st.button(
            "Reset to Original",
            use_container_width=True,
            key="btn_reset",
        )

    else:
        # Placeholders so references don't blow up below
        btn_verify = btn_tamper = btn_update = btn_reset = False
        v_idx = t_idx = u_idx = 0
        t_val = u_val = ""

# ─────────────────────────────────────────────────────────────────────────────
# ── ACTION HANDLERS ───────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

if btn_build and st.session_state.file_data:
    _rebuild_tree(st.session_state.file_data, st.session_state.block_size)
    st.rerun()

if btn_reset and tree_ready:
    _rebuild_tree(st.session_state.file_data, st.session_state.block_size)
    st.rerun()

if btn_verify and tree_ready:
    tree = st.session_state.current_tree
    blk_data = tree.blocks[v_idx]["data"]
    proof = get_proof(tree, v_idx)
    is_ok, ops = verify_proof(blk_data, proof, st.session_state.trusted_root)

    main_ids, sib_ids = get_proof_path_ids(tree, v_idx)
    hl: Dict[int, str] = {}
    for nid in main_ids:  hl[nid] = _C_VERIFY
    for nid in sib_ids:   hl[nid] = _C_SIBLING

    st.session_state.highlight       = hl
    st.session_state.focus_vids      = main_ids + sib_ids
    st.session_state.last_op_count   = ops
    st.session_state.last_op_label   = "SHA-256 calls"
    st.session_state.last_action     = f"Verify block {v_idx}"
    st.session_state.proof_steps     = _compute_proof_steps(blk_data, proof, st.session_state.trusted_root)
    st.session_state.proof_block_idx = v_idx

    if is_ok:
        st.session_state.status_msg  = f"Integrity Verified — Block {v_idx} matches the trusted root."
        st.session_state.status_type = "ok"
        st.session_state.status_icon = "verified"
    else:
        st.session_state.status_msg  = f"Tampering Detected — Block {v_idx} does not match the trusted root."
        st.session_state.status_type = "err"
        st.session_state.status_icon = "gpp_bad"

if btn_tamper and tree_ready:
    current = bytearray(st.session_state.current_bytes)
    tree = st.session_state.current_tree
    blk_info = st.session_state.original_tree.blocks[t_idx]
    offset = blk_info["offset"]

    if t_val.strip():
        patch = t_val.encode("utf-8")
        end = min(offset + len(patch), offset + blk_info["length"])
        current[offset:end] = patch[: end - offset]
    else:
        current[offset] ^= 0xFF

    st.session_state.current_bytes = bytes(current)
    new_blocks = chunk_bytes(st.session_state.current_bytes, st.session_state.block_size)
    new_tree = MerkleTree(new_blocks, st.session_state.block_size)
    st.session_state.current_tree = new_tree

    tampered = find_tampered_blocks(st.session_state.original_tree, new_tree)
    st.session_state.tampered_indices = tampered
    st.session_state.is_tampered = True

    hl = {}
    focus = []
    for ti in tampered:
        path = get_ancestor_ids(new_tree, ti)
        for nid in path: hl[nid] = _C_TAMPER
        focus.extend(path)

    st.session_state.highlight     = hl
    st.session_state.focus_vids    = focus
    st.session_state.last_op_count = new_tree.op_count
    st.session_state.last_op_label = "SHA-256 (full rebuild)"
    st.session_state.last_action   = f"Tamper block {t_idx}"
    st.session_state.proof_steps   = []
    st.session_state.proof_block_idx = t_idx

    idx_str = ", ".join(str(i) for i in tampered)
    st.session_state.status_msg  = (
        f"Tampering Detected — Block(s) {idx_str} differ from trusted tree. "
        f"Full rebuild cost: {new_tree.op_count} SHA-256 calls (O(n))."
    )
    st.session_state.status_type = "err"
    st.session_state.status_icon = "report"

if btn_update and tree_ready:
    tree = st.session_state.current_tree
    if u_val.strip():
        new_data = u_val.encode("utf-8")
    else:
        new_data = os.urandom(st.session_state.block_size)

    internal_ops = _update_block(tree, u_idx, new_data)
    total_ops = internal_ops + 1  # +1 for the leaf hash

    # Sync current_bytes
    blk = tree.blocks[u_idx]
    cb = bytearray(st.session_state.current_bytes)
    bsize = st.session_state.block_size
    cb[blk["offset"]: blk["offset"] + bsize] = (
        new_data[:bsize] if len(new_data) >= bsize
        else new_data + bytes(bsize - len(new_data))
    )
    st.session_state.current_bytes = bytes(cb)
    st.session_state.current_tree  = tree
    st.session_state.trusted_root  = tree.root.hash
    st.session_state.is_tampered   = False
    st.session_state.tampered_indices = []

    path = get_ancestor_ids(tree, u_idx)
    hl   = {nid: _C_UPDATE for nid in path}

    st.session_state.highlight     = hl
    st.session_state.focus_vids    = path
    st.session_state.last_op_count = total_ops
    st.session_state.last_op_label = "SHA-256 (O(log n))"
    st.session_state.last_action   = f"Update block {u_idx}"
    st.session_state.proof_steps   = []
    st.session_state.proof_block_idx = u_idx
    st.session_state.status_msg  = (
        f"Block {u_idx} Updated — Only {total_ops} SHA-256 calls (tree height = "
        f"{tree.height}, O(log n) vs O(n) for a full rebuild)."
    )
    st.session_state.status_type = "ok"
    st.session_state.status_icon = "sync"

# ─────────────────────────────────────────────────────────────────────────────
# ── MAIN PANEL ────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

# ── Empty state ──────────────────────────────────────────────────────────────
if not tree_ready:
    st.markdown(
        """
        <div class="empty-state">
          <span class="icon" style="font-family:'Material Icons Round';font-size:64px;
                color:#21262d;display:block;margin-bottom:16px;">account_tree</span>
          <h3 style="color:#8b949e;margin:0 0 8px;">No tree loaded</h3>
          <p style="color:#6e7681;font-size:0.82rem;margin:0;">
            Select or upload a file in the sidebar, then click
            <strong style="color:#58a6ff">Build Tree</strong>.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# ── Live references ───────────────────────────────────────────────────────────
tree      = st.session_state.current_tree
orig_tree = st.session_state.original_tree
n_blocks  = len(tree.leaves)
height    = tree.height
root_short = st.session_state.trusted_root[:16] + "…"
ops_val   = st.session_state.last_op_count
ops_label = st.session_state.last_op_label
file_status = "Tampered" if st.session_state.is_tampered else "Intact"

# ── KPI tiles ────────────────────────────────────────────────────────────────
kpi_html = f"""
<div class="kpi-row">
  <div class="kpi-card" style="--accent:#58a6ff">
    <div class="kpi-icon">grid_view</div>
    <div class="kpi-label">Total Blocks</div>
    <div class="kpi-value">{n_blocks}</div>
    <div class="kpi-sub">Block size: {st.session_state.block_size:,} B</div>
  </div>
  <div class="kpi-card" style="--accent:#bc8cff">
    <div class="kpi-icon">stacked_line_chart</div>
    <div class="kpi-label">Tree Height</div>
    <div class="kpi-value">{height}</div>
    <div class="kpi-sub">O(log {n_blocks}) ≈ {height} levels</div>
  </div>
  <div class="kpi-card" style="--accent:#3fb950">
    <div class="kpi-icon">fingerprint</div>
    <div class="kpi-label">Trusted Root Hash</div>
    <div class="kpi-value" style="font-size:0.78rem;">{root_short}</div>
    <div class="kpi-sub">SHA-256 of entire tree</div>
  </div>
  <div class="kpi-card" style="--accent:{'#f85149' if st.session_state.is_tampered else '#e3b341'}">
    <div class="kpi-icon">functions</div>
    <div class="kpi-label">Hash Ops — This Action</div>
    <div class="kpi-value">{ops_val}</div>
    <div class="kpi-sub">{ops_label}</div>
  </div>
</div>
"""
st.markdown(kpi_html, unsafe_allow_html=True)

# ── Tree visualization ────────────────────────────────────────────────────────
# Cap tree display for very large trees
MAX_DISPLAY_LEAVES = 200
if n_blocks > MAX_DISPLAY_LEAVES:
    st.warning(
        f"Tree has {n_blocks} leaves — displaying first {MAX_DISPLAY_LEAVES} for performance. "
        f"Use a larger block size to reduce leaf count.",
        icon=None,
    )
    cap_data = bytes(st.session_state.current_bytes)[: st.session_state.block_size * MAX_DISPLAY_LEAVES]
    cap_blocks = chunk_bytes(cap_data, st.session_state.block_size)
    display_tree = MerkleTree(cap_blocks, st.session_state.block_size)
    display_highlight: Dict[int, str] = {}
    focus_py_ids: List[int] = []
else:
    display_tree = tree
    display_highlight = st.session_state.highlight
    focus_py_ids = [
        py for py in st.session_state.highlight
        if py in [id(n) for n in tree.leaves + [tree.root]]
        or True  # include all highlighted
    ]
    # Rebuild focus list from session
    focus_py_ids = list(st.session_state.highlight.keys())

last_action_display = st.session_state.last_action
tree_html = _build_pyvis_html(display_tree, display_highlight, focus_py_ids)

st.markdown(
    f"""
    <div class="tree-wrapper">
      <div class="tree-header">
        <span class="icon">account_tree</span>
        MERKLE TREE &nbsp;·&nbsp; {n_blocks} leaves &nbsp;·&nbsp; height {height}
        &nbsp;&nbsp;
        <span style="margin-left:auto;font-weight:400;color:#6e7681">
          Last: {last_action_display}
        </span>
      </div>
    """,
    unsafe_allow_html=True,
)
components.html(tree_html, height=570, scrolling=False)
st.markdown("</div>", unsafe_allow_html=True)

# ── Legend ────────────────────────────────────────────────────────────────────
legend_items_html = "".join(
    f'<div class="legend-item">'
    f'<div class="legend-dot" style="background:{color}"></div>'
    f'<span class="legend-label">{label}</span>'
    f'</div>'
    for color, label in LEGEND_ITEMS
)
st.markdown(
    f'<div class="legend-row">'
    f'<span style="font-size:0.68rem;font-weight:600;text-transform:uppercase;'
    f'letter-spacing:.09em;color:#6e7681;margin-right:4px;">Node states:</span>'
    f'{legend_items_html}'
    f'</div>',
    unsafe_allow_html=True,
)

# ── Result banner ─────────────────────────────────────────────────────────────
if st.session_state.status_msg:
    icon_map = {"ok": "check_circle", "err": "report", "info": "info", "warn": "warning"}
    icon_name = st.session_state.status_icon or icon_map.get(st.session_state.status_type, "info")
    st.markdown(
        f"""
        <div class="result-banner {st.session_state.status_type}">
          <span class="icon" style="font-family:'Material Icons Round'">{icon_name}</span>
          <div>
            <div>{st.session_state.status_msg}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ── Proof Details (expandable) ─────────────────────────────────────────────────
steps = st.session_state.proof_steps
b_idx = st.session_state.proof_block_idx

with st.expander(
    f"Proof Details — Block {b_idx}" if b_idx is not None else "Proof Details",
    expanded=False,
):
    if not steps:
        st.markdown(
            "<p style='color:#6e7681;font-size:0.82rem;padding:8px 0'>"
            "Run a Verify action to see the step-by-step proof here.</p>",
            unsafe_allow_html=True,
        )
    else:
        trusted = st.session_state.trusted_root
        final_candidate = steps[-1]["hash_out"]
        match = final_candidate == trusted

        rows_html = ""
        for i, s in enumerate(steps):
            side_badge = ""
            sibling_cell = "—"
            if s.get("side"):
                badge_cls = s["side"]
                side_badge = f'<span class="side-badge {badge_cls}">{s["side"].upper()}</span>'
                sibling_cell = (
                    f'<span title="{s["sibling"]}" style="cursor:pointer">'
                    f'{s["sibling"][:20]}…</span>'
                )
            rows_html += f"""
            <tr>
              <td class="step-num">{s['step_label']}</td>
              <td>{s['operation']}</td>
              <td>{side_badge} {sibling_cell}</td>
              <td class="hash-full"><span title="{s['hash_out']}">{s['hash_out'][:20]}…</span></td>
            </tr>
            """

        match_cls  = "match"   if match else "mismatch"
        match_text = "MATCH — Integrity verified" if match else "MISMATCH — Tampering detected"

        st.markdown(
            f"""
            <table class="proof-table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Operation</th>
                  <th>Sibling</th>
                  <th>Output hash (hover for full)</th>
                </tr>
              </thead>
              <tbody>
                {rows_html}
                <tr>
                  <td class="step-num">Trusted root</td>
                  <td colspan="2">
                    Candidate vs trusted root
                  </td>
                  <td class="{match_cls}">
                    {match_text}<br>
                    <span style="font-weight:400;color:#6e7681;font-size:0.68rem">
                      candidate: {final_candidate[:20]}…<br>
                      trusted:   {trusted[:20]}…
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
            """,
            unsafe_allow_html=True,
        )
