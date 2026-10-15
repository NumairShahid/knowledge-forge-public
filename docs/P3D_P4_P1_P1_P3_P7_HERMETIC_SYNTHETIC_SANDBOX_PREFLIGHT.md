# P4-P1-P1-P3-P7 — Hermetic sandbox/mount preflight (synthetic Python only)

**REVIEW ONLY: NO CLAUDE/CODEX NATIVE HOST EXECUTION, HOOK INSTALLATION, MODEL CALLS, TOKENS, TOOL GRANTS OR PROMOTION.**

P6 (PR #33) captured separate 320 MiB-bounded full-file snapshots for TNG's Claude Code and Codex CLI. The hashes and same-descriptor ELF hints identify observed file bytes only; neither dependency closure nor signer/provenance or permanent path integrity is established. P7 does **not** use or mount those binaries. It prepares a strictly knowledge-free Linux Bubblewrap fixture for checking an intended minimal mount and scrubbed-environment pattern. P8 hook trust, P9 exact approval packet, and P10 separately authorized native tests still remain.

## Exact synthetic-only contract

The `portable_native_hermetic_preflight` module's **default `PLAN_ONLY`** is declarative and cannot execute subprocesses. `FIXTURE_ONLY` may invoke **only** `/usr/bin/bwrap` to launch `/usr/bin/python3 -I -S -c` with embedded static probe code. No shell, CLI host, project repository, hook source, package manager, credential reader or network client executes. It observes and compares **net, mount and PID** namespace inode identities against its unsandboxed parent, checks that only loopback interfaces are present, the parent-created **synthetic `/tmp` canary** and original home directory are absent, private `/work` and `/config` start empty, private `/work` is writable, `/usr` is read-only and the complete four-key environment equals an allowlist. It never sends a network packet; namespace/loopback evidence is not an end-to-end network policy attestation.

Sandbox plan: `--unshare-all --new-session --die-with-parent --cap-drop ALL --clearenv`, system `/usr` bound **read-only** and only known `/lib`, `/lib64`, `/bin`, `/sbin` symlinks or directories bound read-only if present, private `/tmp`/`/work`/`/config` tmpfs, newly created empty `/home/synthetic`, `/proc` in new PID namespace and minimal `/dev`. Environment is strictly `HOME=/home/synthetic`, `TMPDIR=/tmp`, `PATH=/usr/bin:/bin`, `LANG=C.UTF-8`; the Python probe starts from `/work`. The original user HOME, project, configuration, credentials and user-runtime binaries are **never explicitly bound**. **Caveat:** `/usr` is still a broad system runtime mount and may contain other executables; this is *not* a vetted minimum mount set for an untrusted native host. No private user's `HOME`/project/`/etc`/host `/tmp` is mounted, and host binary executables are never explicitly mounted from home.

The only persistent filesystem write is creation and cleanup of a **synthetic** `/tmp/kf-p7-synthetic-*/private-fixture-canary` under a new temporary directory, mode `0600`; it is never mounted in the child. The child writes a scratch marker only inside `/work` tmpfs. No actual credential/home/config file is opened. If Bubblewrap is missing, namespaces fail, the fixture exits abnormally, times out, the negative checks fail or the required read-only mount cannot be observed, the status is `BLOCKED_P7_SYNTHETIC_ISOLATION_NOT_PROVEN`. There is **no unsandboxed fallback**. The exact JSON receipt is redacted to Boolean synthetic assertions and contains no raw original HOME paths or canary contents.

A successful `PROBE_HERMETIC_PYTHON_FIXTURE_PASS_NOT_NATIVE_ATTESTATION` supports **only that transient Python fixture on TNG**, not actual Claude/Codex isolation, host hook behavior, complete dependency closure or all nine native proof gates. A pass does not establish system enforcement against a malicious native host or that any host could run without models or network. Every native gate remains UNVERIFIED; approvals remain separate, explicit and single-use.

Run on the TNG development checkout (does not install anything):

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_hermetic_preflight
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hermetic_preflight --host claude-code --mode PLAN_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hermetic_preflight --host codex-cli --mode FIXTURE_ONLY
```

**Security laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
