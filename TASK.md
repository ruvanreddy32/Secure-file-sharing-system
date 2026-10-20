# Task Board — Merkle Tree File Integrity Verification

## Sprint 1 — Core Data Structures
- [x] `merkle/__init__.py`
- [x] `merkle/node.py` — MerkleNode class
- [x] `merkle/chunker.py` — chunk_file, chunk_bytes
- [x] `merkle/tree.py` — MerkleTree with bottom-up build + odd-leaf duplication
- [x] `tests/test_chunker.py`
- [x] `tests/test_tree.py`
- [x] Run pytest — Sprint 1 green
- [x] git commit Sprint 1

## Sprint 2 — Proof & Verification
- [x] `merkle/proof.py` — get_proof, verify_proof
- [x] `merkle/tamper.py` — find_tampered_blocks
- [x] `tests/test_proof.py`
- [x] `tests/test_tamper.py`
- [x] Run pytest — Sprint 2 green
- [x] git commit Sprint 2

## Sprint 3 — Dynamic Update & Benchmarking
- [x] `merkle/updater.py` — update_block O(log n)
- [x] `tests/test_updater.py`
- [x] `benchmark.py` — 1 MB / 10 MB / 100 MB → results.csv
- [x] Run pytest — Sprint 3 green
- [x] Run benchmark.py
- [x] git commit Sprint 3

## Sprint 4 — Streamlit Visualizer
- [x] `app.py` — full Pyvis + Streamlit app
- [x] `requirements.txt`
- [x] `README.md`
- [x] `SPRINT.md`
- [x] `TASK.md`
- [x] `backlog.md`
- [ ] Manual smoke test via `streamlit run app.py`
- [ ] git commit Sprint 4
