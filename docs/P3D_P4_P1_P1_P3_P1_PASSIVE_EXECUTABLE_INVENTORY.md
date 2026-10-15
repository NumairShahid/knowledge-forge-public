# P3D-P4-P1-P1-P3-P1 — Passive native executable inventory (no host launch)

**REVIEW ONLY. No native Claude/Codex execution, native hook activation, network calls, model requests, installed-host configuration changes, credential inspection, or permission promotion.**

This cut implements **stage 01 — executable inventory** from P4-P1-P1-P3-P0 (PR #27). The observed version strings `2.1.296` (Claude Code) and `0.161.0` (Codex CLI) were from an earlier passive `--version` probe and **are not reused as current binary attestations**.

## Exact bounded evidence

For each command name (`claude`, `codex`), locate **only the first executable on the existing PATH**, without executing it. Resolve at most 16 direct symlinks; require a regular executable file; hash at most 256 MiB with SHA-256, and reject a file that changes identity during reading. Collect uid, size, mode, and world-writable status. For scripts, report only a sanitized shebang interpreter **basename**; for ELF, report an optional bounded `PT_INTERP` path hint. No source file is imported, no package manager, `ldd`, native `--version`, `readelf`, executable interpreter, agent host, hook handler, or network command is run by the inventory module.

The module may report `PASSIVE_FILE_IDENTITY_ONLY`, `UNRESOLVED_NO_EXECUTION`, or `BLOCKED_CANDIDATE_NOT_PROVEN`. A positive result confirms only the file bytes and static hints *at the time of reading*. An unresolved or blocked candidate **does not** fall back to running the host. Paths within the local home are displayed as `$HOME/...` for limited disclosure; this is a private operator report, not a public security attestation. `PATH` could be mutable or attacker-controlled; the first-hit file may not be the binary that a later process actually executes. File hashes do not prove supply-chain trust, ownership of package provenance, signature verification, or whether contents/dependencies will change in the future.

**Critical missing evidence:** executable interpreter chain beyond the first shebang/ELF-loader hint, JavaScript imports, dynamically loaded native libraries, runtime package provenance, package files, symlink-parent directory permissions, and any transient host process identity remain **UNVERIFIED**. This is deliberately not a complete runtime dependency tree, and it does not authorize mounting a binary into Bubblewrap.

## R1: bounded refusal diagnosis for Codex

The first TNG run found a `codex` PATH candidate but refused its file proof as
`BLOCKED_CANDIDATE_NOT_PROVEN`. This is a **valid fail-closed result**, not a
runtime claim. The original code combined all symlink, size, permission and
identity problems under one state. R1 adds an allowlisted `refusal_category`
only when blocked. Stable possible categories include `FILE_EXCEEDS_INVENTORY_LIMIT`,
`EMPTY_FILE`, `NOT_REGULAR_FILE`, `NOT_EXECUTABLE_FILE`,
`IDENTITY_CHANGED_DURING_READ`, `FILE_OPEN_READ_OR_STAT_UNAVAILABLE`,
`SYMLINK_CYCLE`, `SYMLINK_DEPTH_LIMIT`, `EMPTY_SYMLINK_TARGET`,
`SYMLINK_METADATA_UNAVAILABLE`, and generic validation refusals.

These categories expose neither the raw exception message nor a refused
candidate path or content. R1 retains the **256 MiB cap**, read-only
`O_NOFOLLOW` file opening, same `PATH` first candidate, one final executable
read, 16-link limit, no native execution and no package inspection. A category
is diagnostic evidence only; it cannot certify a binary, dependency chain,
provenance or authorize a native host. A positive inventory remains
`PASSIVE_FILE_IDENTITY_ONLY` and is not elevated to runtime attestation.

## TNG execution (existing source checkout)

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_executable_inventory
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_executable_inventory --host claude-code --mode INVENTORY_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_executable_inventory --host codex-cli --mode INVENTORY_ONLY
```

The cut intentionally runs **only Python** to read passive filesystem metadata and candidate binary bytes. The wrapper also runs the existing regression suite and installer `--check-only`; the standard CI applies independently. No real native host dispatch tests in this cut. An OS sandbox is not claimed for these passive filesystem reads; `--version` is not invoked. If the host's binary exceeds the bound or lives outside PATH, record the block/unresolved status and design a separately approved follow-up; do **not** remove the bound.

## Authority / next gate

The earlier P2 contract retains nine future independently verifiable evidence gates. This inventory can provide **partial review evidence** for stage 01 only; it cannot mark any P2 gate as proven. A future P3-P2 must review runtime dependency and provenance gaps before even considering a separately approved native launch. Real Claude/Codex sessions, user/project/plugin/managed hooks, credentials, trust bypass, automatic knowledge delivery, operator promotion, and execution permissions remain forbidden.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
