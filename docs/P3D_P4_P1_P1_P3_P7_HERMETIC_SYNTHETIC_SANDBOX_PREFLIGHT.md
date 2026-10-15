# P4-P1-P1-P3-P7 — Hermetic sandbox/mount preflight (synthetic Python only)

**REVIEW ONLY: NO CLAUDE/CODEX NATIVE HOST EXECUTION, HOOK INSTALLATION, MODEL CALLS, TOKENS, TOOL GRANTS OR PROMOTION.**

P6 (PR #33) captured separate 320 MiB-bounded full-file snapshots for TNG's Claude Code and Codex CLI. The hashes and same-descriptor ELF hints identify observed file bytes only; neither dependency closure nor signer/provenance or permanent path integrity is established. P7 does **not** use or mount those binaries. It prepares a strictly knowledge-free Linux Bubblewrap fixture for checking an intended minimal mount and scrubbed-environment pattern. P8 hook trust, P9 exact approval packet, and P10 separately authorized native tests still remain.

## P7-R1 — Bubblewrap preserved `PWD` diagnostic repair (2026-10-15)

TNG's original P7 report returned `BLOCKED_P7_SYNTHETIC_ISOLATION_NOT_PROVEN` even though an earlier Python namespace canary passed. The single-run follow-up diagnostic established that Bubblewrap executed with status `0`, produced valid JSON, and failed only `scrubbed_environment`. Per Bubblewrap's documented semantics, `--clearenv` **retains `PWD`** unless explicitly removed. P7-R1 adds **`--unsetenv PWD` immediately after `--clearenv`**, before all mount/fixture options. The existing exact four-key allowed environment (`HOME`, `TMPDIR`, `PATH`, `LANG`) is **unchanged**. The Python fixture still refuses *any* additional key or wrong value; neither `PWD` nor any other inherited field is permitted as an exception.

Two regression tests pin the command argument order and prove a fixture reporting extra environment state still fails closed. No other runtime capabilities are added. **Hypothesis, not TNG proof:** the native TNG fixture must still run under the repaired branch and produce the expected synthetic-only receipt for both host labels. If it does not, the repair script must not push. Even on PASS, no actual Claude/Codex process was launched or attested, and all nine native proof gates stay UNVERIFIED.


## P7-R4 — Verified R2/R3 blocker; re-exec isolation probe with exact allowlist

The TNG R2 differential found that all four intended variables (`HOME`, `TMPDIR`, `PATH`, `LANG`) were correct and that the *only* extra variable was `PWD=/work`. R3 tested option reordering and removal of Bubblewrap `--chdir`; all three variations still received `PWD` and remained BLOCKED. R1's simple `--unsetenv PWD` alone is **not** sufficient on this host. The working source remains uncommitted and PR #34 unchanged until the real TNG fixture proves a correction.

The R4 correction keeps Bubblewrap's unshare, read-only mounts, synthetic private scratch, and **all original strict receipt requirements**. The Bubblewrap child first runs *only* `/usr/bin/python3 -I -S -c` with a tiny static bootstrap. The bootstrap checks `cwd == /work` and accepts **only** one of two initial environments: the exact four-variable allowlist, or that same four-variable allowlist with the single observed `PWD=/work`. It refuses any changed allowed value, unexpected variable, mismatched `PWD`, or malformed probe arguments. It then replaces its own process with `os.execve('/usr/bin/python3', ..., {HOME, TMPDIR, PATH, LANG})`, passing **exactly four literal values**. The resulting Python fixture still checks `dict(os.environ) == allowed_env`, namespace identity, loopback-only network, private-home/canary exclusion, read-only `/usr`, private scratch and cleanup. No shell, `/usr/bin/env`, native Claude/Codex binary, extra host mount, hook, credential or user config is touched.

The bootstrap is a *synthetic-only* process-environment boundary; it is not a general proof of how native hosts would be initialized. In particular, this repair does **not** claim that Bubblewrap alone delivered a four-variable environment, and it does not count toward any of the nine unverified native-runtime gates. If the TNG fixture remains BLOCKED, do not commit or push. Even a passing Python fixture is supporting evidence only, never host launch approval.

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
