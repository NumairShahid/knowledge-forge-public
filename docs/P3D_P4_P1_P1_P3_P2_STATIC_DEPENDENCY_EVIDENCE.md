# P3D-P4-P1-P1-P3-P2 — Passive oversized executable and runtime hint evidence

**STATUS: REVIEW-ONLY STATIC METADATA. DO NOT RUN CLAUDE, CODEX, HOOKS, MODELS OR NETWORK TESTS.**

## Purpose and verified upstream boundary

P3-P1/R1 (PR #28) proved the TNG `claude` candidate's bounded SHA-256, but refused the first PATH `codex` candidate as `FILE_EXCEEDS_INVENTORY_LIMIT`. The operator independently read Codex's size as **292,309,256 bytes**, larger than the unchanged **256 MiB = 268,435,456-byte** full-digest cap. This P2 does **not** hash all of Codex or raise the previous limit. It creates a separate, read-bounded, static-evidence surface and does not alter P3-P1's inventory contract.

## Exact passive procedure

For `claude-code` and `codex-cli`, locate only the first command on the existing PATH, resolve at most 16 direct executable symlinks using P3-P1's existing helper, and open the resolved regular executable **read-only**, without following a final symlink. Require nonempty and executable file, refuse world-writable mode, and compare device/inode/size/ownership/mode/ctime/mtime before and after reads. Report: size, owner UID/GID, permissions, symlink chain with `$HOME` redaction, whether the file exceeds the original 256 MiB bound, and a SHA-256 of **only the first 4,096 bytes** labelled `header_sample_sha256_not_full_file_hash`.

The existing bounded static interpreter parser may inspect a maximum of 128 ELF program headers (at most 256 bytes each) and a PT_INTERP string (at most 255 bytes). **Upper bound on executable contents read per run: 37,119 bytes.** For scripts, the interpreter basename is only a hint. For ELF, PT_INTERP is only a loader-path hint. This is not a verified dependency tree, not a package signature, not a complete ELF hash, not immutable executable identity, and not actual native process proof. This cut does not read runtime package manifests, configuration, credential files, home directories or plugin sources. A PATH candidate may be different from a later executed binary; directory chain permissions, trust and provenance remain unresolved.

Both hosts remain disabled for native sessions, hooks, model calls, tool grants, knowledge context injection and promotion. If the candidate is missing or a bounded metadata read fails, return `UNRESOLVED_NO_EXECUTION` or `BLOCKED_METADATA_NOT_PROVEN` with a generic category, never a fallback native invocation. No package manager, `ldd`, `readelf`, `--version`, interpreter, network command or execution subprocess is invoked by the module. This is a local operator diagnostic, not a public attestation.

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_dependency_evidence
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_dependency_evidence --host claude-code --mode EVIDENCE_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_dependency_evidence --host codex-cli --mode EVIDENCE_ONLY
```

## Remaining gates and authority

Future separately approved work must independently establish the complete executable digest for oversized files **under a new distinct bounded policy**, runtime interpreter and library closure, package provenance/signatures, precise mount requirements, and finally any real host sandbox isolation and hook dispatcher behavior. Nothing in this output authorizes launching a native host. All P2/P3 evidence gates remain unverified for native execution.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
