# P3D-P4-P1-P1-P3-P3 — Passive installation-layout and ELF dependency-name hints

**STATUS: REVIEW-ONLY, STATIC EVIDENCE. DO NOT START CLAUDE, CODEX, HOOKS, MODELS, INTERPRETERS, PACKAGE MANAGERS, OR NETWORK TESTS.**

## Boundary and purpose

P3-P1/R1 (PR #28) found Claude's bounded complete executable digest but refused Codex's 292,309,256-byte file under the pre-existing 256 MiB full-hash limit. P3-P2 (PR #29) collected at most 37,119 bytes of static ELF metadata and proved neither binary's runtime dependency closure. **This P3-P3 cut retains that cap**, and adds a different, read-bounded surface to inspect ELF `DT_NEEDED` library-name strings and ancestor directory permissions, without launching a loader or reading package manifests.

The new module reads only the first executable on the existing PATH, up to 16 direct executable symlinks, then uses read-only `O_NOFOLLOW` file access. It reads at most **98,304 bytes of executable content**: a short ELF header, up to 128 bounded program headers, up to 32,768 bytes of `PT_DYNAMIC`, and up to 16,384 bytes of dynamic string table. It may report at most 32 sanitized `DT_NEEDED` basename-like hints. Out-of-range, truncated, ambiguous and unsupported structures are *not* repaired by full-file scans. It gathers metadata for up to seven parent directories under the user's home, without reading directory contents. Parent directories may include symlinks; this is recorded and **not** a trust attestation.

`DT_NEEDED` strings are labels in a binary, **not** evidence of which libraries the loader would select, whether transitive dependencies resolve, whether `dlopen` or bundled assets are needed, or whether a binary is statically linked. `NO_DYNAMIC_SEGMENT_OBSERVED` is not proof of a statically linked program. Layout descriptions for `$HOME/.local/share/claude/versions/…` and `$HOME/.codex/packages/standalone/…` are just path-pattern hints, **not proof of official package provenance, authenticity, signatures or update integrity**. A first-on-PATH candidate may differ from a future execution target. No package files, installer manifests, credentials or host settings are read.

## Reproduce without native execution

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_provenance_hints
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_provenance_hints --host claude-code --mode HINTS_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_provenance_hints --host codex-cli --mode HINTS_ONLY
```

The module starts **zero subprocesses**. Unsupported execution modes exit 2 without stdout. It refuses executable world-writable mode or moving identity and redacts paths outside the user's home. The wrapper may run Python tests, installer `--check-only` and the earlier Python-only Bubblewrap preflight; these are not native agent sessions.

## Outstanding evidence and authority

The dependency-name and parent-directory results are **review hints only**. They do not identify the complete linked runtime closure, exact mount set, official package provenance, package signatures or the actual sandboxed Claude/Codex process. Full executable hashing of Codex remains unverified under the original unchanged 256 MiB cap. No native launcher, hook activation, model call, automatic knowledge delivery, human attestation or promotion is introduced. A separately approved future cut must address the remaining P2 nine proof gates without inheriting user credentials, home, settings or networks. Failure to run a native host offline is a valid BLOCKED result, not permission to broaden authority.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
