# P3D-P4-P1-P1-P1 — OS isolation preflight, no native host dispatch

**STATUS: PROBE / BLOCKED ONLY. NEVER START CLAUDE OR CODEX, NEVER INSTALL A HOOK, NEVER CALL A MODEL.**

This increment builds on the merged synthetic fixture and passive version probes. It tests whether the TNG Linux runtime can establish an actual restricted namespace **for a tiny knowledge-free Python test**, not for either agent. Its output cannot certify future CLI isolation or permit automatic knowledge retrieval.

The default CLI mode prints an inert plan and does not execute subprocesses. The explicit `--probe` runs `/usr/bin/bwrap` with `--unshare-all`, `--new-session`, `--clearenv`, read-only system libraries, private `/tmp`, private `/home`, and no bindings for original HOME, repository, or host `/tmp`. It compares the nested network namespace inode with its parent, examines only interface names, and proves an unmounted temporary private-file canary is not present. No network packet is sent. If `bwrap` is missing, user namespaces are prohibited, or the probe fails, status is `BLOCKED_ISOLATION_NOT_PROVEN`. **Never run the host unsandboxed as a fallback.** A successful probe is only `PROBE_NAMESPACE_PASS_NOT_HOST_ATTESTATION`.

Example, after test installation in a source checkout (no host sessions):

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_isolation_preflight
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_isolation_preflight --host claude-code
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_isolation_preflight --host codex-cli --probe
```

This is **not** a general-purpose untrusted-executable sandbox. Read-only `/usr` can contain code and shared libraries; `PATH` is fixed but bubblewrap and Linux namespaces may themselves be unavailable. The operating system's own namespace restrictions and the actual mount table would need further corroboration before executing any third-party host binary. The command is Linux-only. No user account settings are inspected or changed.

A future native host dispatch test requires a new human approval, a separate isolated home and project, verified no credential access, verified network isolation for the **real host process**, bounded runtime, no host-trust bypass, no tool grants, proof of configuration discovery, exit-code semantics, and teardown evidence. Even that test grants no promotion rights or automatic knowledge injection.

Official interface references checked 2026-10-15:
- https://code.claude.com/docs/en/hooks
- https://learn.chatgpt.com/docs/hooks

Security laws: `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
