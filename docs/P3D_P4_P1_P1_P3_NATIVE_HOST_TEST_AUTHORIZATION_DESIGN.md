# P3D-P4-P1-P1-P3-P0 — Native host test authorization and execution design (inert)

**STATUS: DESIGN AND REVIEW ONLY. This commit does not authorize or run Claude Code, Codex CLI, native hooks, model calls or network access.** No personal settings, host credentials, repository content or installed hooks are touched. It is not a launcher, a test authorization system or an OS attestation tool.

## Why this cut exists

P4-P1-P1-P1 demonstrated a small **knowledge-free Python** probe under Bubblewrap on TNG, including separation of the network namespace and an inaccessible private-file canary. P4-P1-P1-P2 defined an immutable, **non-executing** sandbox policy and nine missing proof gates. Neither proved the real Claude/Codex process or its hook dispatch. P3 now maps every P2 proof gate to one review stage and prevents claimed evidence from masquerading as authorization.

Two previously observed version strings are recorded only as historical references: Claude Code `2.1.296` and Codex CLI `0.161.0` on TNG on October 15, 2026. They are **not current binary identity, executable path, SHA-256 or dependency attestations**.

## Proposed future test procedure — not commands to execute

| Stage | Required independent proof / stop condition |
| --- | --- |
| 01 — Executable inventory | Independently identify exact native executable, symlinks, interpreter chain, version, content hash and dependency tree. Do not execute to discover it in this cut. Missing or mutable identity means STOP. |
| 02 — Sandbox attestation | In a **later separately approved cut**, prove the *actual host process* runs inside pinned Bubblewrap mount/PID/network boundaries; deny host HOME, credentials, external network and writable original paths. Python-only namespace proof is insufficient. |
| 03 — Configuration and trust | Use only one disposable synthetic `UserPromptSubmit` handler. Identify all effective user/project/plugin/managed hook sources; if any additional source may execute or trust requires bypass, STOP. |
| 04 — No model or tools | Prove no real prompt, API credentials, network requests, model invocation, tool grant, shell tools or knowledge delivery. If a host cannot dispatch a hook offline, STOP rather than relaxing isolation. |
| 05 — Hook behavior | Only a future approved execution could observe native event dispatch, stdin schema, exit `0`/`2`, stdout/stderr, duplicate delivery, and context injection. A direct handler replay is not native dispatch. The chosen test handler must emit zero model-context stdout. |
| 06 — Teardown receipt | Bound runtime, kill descendants on timeout, clean temporary directories, verify user settings unchanged, record signed/independently verifiable evidence without prompt/token contents. Failed cleanup means STOP. |
| 07 — Separate human authorization | Obtain explicit, fresh approval for the *exact future* command, host/version/digest, sandbox and test scope. Previous PR merge or an `APPROVE` string in source does not authenticate a human. No approval is inferred here. |

**Order of any eventual execution:** human approval must actually precede launch despite appearing as stage 07 in this review inventory. Code intentionally cannot reorder these stages into an executable workflow. An external authenticated human-host gate and fresh safety review must be designed separately.

## Static proof ledger

`portable_native_test_design.py` imports the existing P2 `contract` and `PROOF_GATES`. It provides deterministic, host-specific plans and hashes. Each of the nine gates is mapped exactly once. The optional in-memory status dictionary accepts only `NOT_OBSERVED` or `CLAIMED_UNVERIFIED`; even nine self-declared claims remain **missing independent attestations**. Unknown gates, status `PASS`, secret-bearing strings, runtime requests (`ON`, `EXECUTE`, `NATIVE_TEST`) and unknown hosts are refused. The design SHA-256 establishes only plan identity, **not** authorization or evidence authenticity.

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_test_design
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_test_design --host claude-code --mode PLAN_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_test_design --host codex-cli --mode PLAN_ONLY
```

Both commands report `native_launch_authorized=false`, `native_dispatch_verified=false`, `safe_to_activate_hooks=false`, `promotion_authorized=false`, and `DESIGN_ONLY_UNAUTHORIZED`. They **do not start a subprocess**.

Official hook references checked 2026-10-15: [Claude Code hooks](https://code.claude.com/docs/en/hooks) and [Codex hooks](https://learn.chatgpt.com/docs/hooks). These are interface references, not proof of behavior on the TNG host.

**Future P4-P1-P1-P3-P1 requires a new separately approved cut.** If offline auth-free native dispatch cannot be demonstrated under strict isolation, record BLOCKED and do not broaden privileges. No production bridge, token use, host settings writes, hook registration, operator promotion or deployment.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
