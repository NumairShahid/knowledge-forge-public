# P4-P1-P1-P3-P4 — Offline native integrity and dependency gap assessment

**STATUS: REVIEW-ONLY. Not a host runtime attestation, dependency closure, installation trust proof, or launch ticket.**

P3-P1/R1 (PR #28) captured a full-file Claude SHA-256 under the 256 MiB cap, but correctly refused Codex (`FILE_EXCEEDS_INVENTORY_LIMIT`; 292,309,256 bytes). P3-P2 (PR #29) observed bounded metadata and sample/ELF-loader hints without a complete oversized-file hash. P3-P3/R1 (PR #30) observed limited ELF dependency-name hints, parent directory mode bits and an intermediate Codex `current` symlink. It explicitly distinguishes symlink `0777` from actual directory permissions; directory `0775` mode bits do **not** prove effective write access. Claude's ELF string mapping refused `DYNSTR_BOUND_OR_ADDRESS_REFUSED`; Codex reported `NO_DT_NEEDED_OBSERVED`. Neither state proves a resolved runtime dependency tree.

## Exact offline operation

The `portable_native_integrity_gap_assessment` module invokes the three existing **read-only Python** evidence functions in-process. Those functions read a bounded executable file (for Claude, the prior P3-P1 bounded full hash may read up to 256 MiB), metadata and ELF header/dynamic sections. **No external native executable is launched**, nor is any loader, package manager, model, hook, credential, project, host setting, or network endpoint accessed. This module adds **no new executable-reading parser** and does not raise any old limit. The snapshots are sequential and cannot freeze the executable, PATH selection, directory links or trust state. The output is a compact assessment (not full source JSON) with a deterministic fingerprint of *source status labels only*, not an executable attestation.

The assessor requires exact host labels, known P1/P2/P3 evidence surfaces and state labels, and all required negative authority fields. It rejects changed file size or resolved path between successful readouts, missing P3-R1 non-attestation fields, unknown evidence states, and attempts to self-declare native permission. A refused source remains a refusal. It cannot turn a missing observation into a PASS.

The **nine proof gates** are imported directly from `portable_native_sandbox_contract.PROOF_GATES` (P4-P1-P1-P2), not reproduced under a new renamed policy. Every gate remains `UNVERIFIED_NATIVE_EVIDENCE_REQUIRED` for both hosts. Specifically, these are actual host executable identity/dependency closure, real process isolation, private file isolation, host trust and hook discovery, absence of extra hooks, model/tool nonexecution, native hook behavior, bounded lifecycle/receipt and **separate explicit test authorization**. None can be marked proven by passing a Python unit test or a static inventory. The earlier Python Bubblewrap namespace canary probe is useful supporting evidence **only for Python**, not for actual Claude/Codex.

Run without native launch:

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_integrity_gap_assessment
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_integrity_gap_assessment --host claude-code --mode ASSESS_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_integrity_gap_assessment --host codex-cli --mode ASSESS_ONLY
```

Raising `ASSESS_ONLY` to `ON`, `NATIVE_TEST`, registering a hook, mounting user HOME, calling Claude/Codex, inheriting credentials, granting tools, model context delivery or promotion is **strictly out of scope**. No native test authorization follows from merging this or any earlier PR. Next work must be separately bounded and human reviewed; complete Codex identity, install signer/provenance, link-target stability and verified runtime library closure remain open before any native session is considered.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
