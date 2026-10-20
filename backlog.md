# Product Backlog — Merkle Tree File Integrity Verification

## Epic A — Core Data Structure & Tree Construction

| ID | Story | Status |
|----|-------|--------|
| A1 | As a developer, I want a `MerkleNode` class with `hash`, `left`, `right`, `parent`, `block_index`, `is_leaf` so the tree is a real, navigable data structure (not just a list of hashes). | ✅ Done |
| A2 | As a developer, I want a file chunker that splits a file into fixed-size blocks `(index, offset, length, data)` — no physical padding of the file. | ✅ Done |
| A3 | As a developer, I want `build_tree(blocks)` to hash each block (SHA-256), build leaf nodes, and pair them bottom-up into parent nodes until one root remains. | ✅ Done |
| A4 | As a developer, I want an explicit, documented odd-leaf-count strategy (duplicate the last node) applied consistently at every tree level. | ✅ Done |

## Epic B — Proof Generation & Verification

| ID | Story | Status |
|----|-------|--------|
| B1 | As a user, I want `get_proof(block_index)` to return the sibling hashes (and their left/right position) along the path from a leaf to the root. | ✅ Done |
| B2 | As a user, I want `verify_proof(block_data, proof, root_hash)` to recompute the candidate root from a block and its proof, and confirm it matches the trusted root — without touching any other block. | ✅ Done |

## Epic C — Tamper Detection & Localization

| ID | Story | Status |
|----|-------|--------|
| C1 | As a user, I want the system to detect when a file's recomputed root hash differs from the trusted stored root. | ✅ Done |
| C2 | As a user, I want `find_tampered_block(old_tree, new_tree)` to traverse the differing branch recursively and return the exact tampered block index. | ✅ Done |

## Epic D — Dynamic Block Update

| ID | Story | Status |
|----|-------|--------|
| D1 | As a developer, I want `update_block(tree, index, new_data)` to rehash only the modified leaf and its ancestors (O(log n)), not the whole tree. | ✅ Done |

## Epic E — Benchmarking

| ID | Story | Status |
|----|-------|--------|
| E1 | As a student, I want a benchmark script that measures real wall-clock time for full-file SHA-256 vs. Merkle proof verification across several file sizes, so my Results slide uses measured numbers, not invented ones. | ✅ Done |

## Epic F — Streamlit Visualizer

| ID | Story | Status |
|----|-------|--------|
| F1 | As a demo presenter, I want to upload/select a file and see it chunked into labeled blocks on screen. | ✅ Done |
| F2 | As a demo presenter, I want to see the Merkle tree rendered visually (level by level, leaves to root) with hashes truncated for readability. | ✅ Done |
| F3 | As a demo presenter, I want a "Verify Block" control that highlights the proof path (target leaf → siblings → root) live on the tree diagram. | ✅ Done |
| F4 | As a demo presenter, I want a "Tamper Block" control that mutates one block, re-verifies, and highlights the tampered path in red with the detected block index shown. | ✅ Done |
| F5 | As a demo presenter, I want a "Dynamic Update" control that legitimately updates a block and shows only the rehashed path highlighted in green, with an O(log n) operation counter. | ✅ Done |
| F6 | As a demo presenter, I want a live complexity/operation counter (number of hashes computed) shown for each action, to make the O(n) vs O(log n) claim visible, not just asserted. | ✅ Done |
