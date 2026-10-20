# Sprint Plan — Merkle Tree File Integrity Verification

## Sprint 1 — Core Data Structures ✅
**Goal:** A working, tested Merkle tree built from a real file.

**Deliverables:**
- `merkle/node.py` — `MerkleNode` (hash, left, right, parent, block_index, is_leaf)
- `merkle/chunker.py` — `chunk_file`, `chunk_bytes` (no physical padding)
- `merkle/tree.py` — `MerkleTree` (bottom-up SHA-256, odd-leaf duplication, `op_count`, `height`)

**Exit criteria:**
- All `test_chunker.py` and `test_tree.py` scenarios pass
- 18000-byte file → 5 blocks, last block length = 18000 % 4096
- 8 leaves → height 3, single root
- Root hash changes on any single-byte mutation

---

## Sprint 2 — Proof & Verification ✅
**Goal:** O(log n) block proof; detect and localise tampering.

**Deliverables:**
- `merkle/proof.py` — `get_proof`, `verify_proof` (returns `(bool, ops)`)
- `merkle/tamper.py` — `find_tampered_blocks` (recursive descent)

**Exit criteria:**
- Valid proof → True; tampered block's proof → False
- Proof length == tree height for 1024 blocks
- `find_tampered_blocks` returns exact index for single and multi-block tampering

---

## Sprint 3 — Dynamic Update & Benchmarking ✅
**Goal:** Cheap legitimate updates; real performance numbers.

**Deliverables:**
- `merkle/updater.py` — `update_block` (O(log n), returns `tree.height` op count)
- `benchmark.py` — 1 MB / 10 MB / 100 MB → `results.csv`

**Sizes tested:** 1 MB, 10 MB, 100 MB  
*(500 MB and 1 GB omitted — disk/time-constrained; documented in README)*

**Exit criteria:**
- `update_block` changes only leaf[n] and ancestors; other leaf hashes unchanged
- `update_block` return value == `tree.height`
- `benchmark.py` runs and produces `results.csv`

---

## Sprint 4 — Streamlit Visualizer ✅
**Goal:** A live, presentable demo app.

**Deliverables:**
- `app.py` — Streamlit app with Pyvis interactive tree

**Visualization (Pyvis):**
- Hierarchical layout: direction=UD, sortMethod=directed, physics=false
- Hover tooltip: full SHA-256 hash
- Color coding: blue (verify), red (tamper), green (update), purple (root)

**Exit criteria:**
- File upload → block table + Pyvis tree rendered
- Verify Block → proof path highlighted blue, result shown
- Tamper Block → tampered path highlighted red, exact block index shown
- Update Block → rehashed path highlighted green, op count shown
- All SHA-256 counts from real execution (never hardcoded)
- `streamlit run app.py` starts with no errors

---

## Git Log (one commit per sprint)
```
Sprint 1: Core data structures (chunker, node, tree + tests)
Sprint 2: Proof generation, verification, tamper localization + tests
Sprint 3: Dynamic updater, benchmarking + tests
Sprint 4: Streamlit visualizer (Pyvis, dark theme, all actions)
```
