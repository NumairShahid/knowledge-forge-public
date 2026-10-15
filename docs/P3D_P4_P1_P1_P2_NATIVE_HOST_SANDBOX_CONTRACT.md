# P3D-P4-P1-P1-P2 — Native host sandbox contract (plan only)

**STATUS: REVIEW-ONLY POLICY CONTRACT. NO REAL HOST EXECUTION OR HOOK REGISTRATION.**

P4-P1-P1-P1 proved on TNG that a *small standard-library Python probe* could run inside a Bubblewrap network/mount namespace without seeing its private-file canary. It did **not** prove that Claude Code or Codex CLI can be run with that exact boundary. This P2 cut converts the gap into a fixed, machine-checked contract and a finite list of unverified evidence gates. Matching or printing this contract does not attest the OS, execute a native host, or approve a launch.

## Proposed future native-test boundary

The standalone Python contract (`portable_native_sandbox_contract.py`) requires the exact following characteristics of a **separately authorized future experiment**, without implementing execution:

- A real, independently observed Bubblewrap PID/mount/network boundary (`--unshare-all` or equivalent), not merely syntactic flags, and a host process with no external route or packet exchange.
- A pinned absolute-path native executable and dependencies whose identities and digests have been separately reviewed; only minimum explicitly enumerated read-only runtime mounts. This may require host-specific design: Claude and Codex packages are not assumed to reside under `/usr`.
- No mount of the user's HOME, config, private tokens, agent memories, project repositories, plugins, or credential files. Only a new private temporary home/project/config, exactly one synthetic knowledge-free `UserPromptSubmit` test hook, cleared inherited environment and no extra hook sources. Reject when managed/user/project/plugin hook sources cannot be ruled out; **do not bypass host trust**.
- No real user prompt, user API credentials, model request, tool grants, operator promotion, command injection, knowledge retrieval, or context delivery. A future hook handler would observe event metadata only, with no stdout to the model.
- Explicit human authorization **for the later test itself**, strict process runtime limits, fail-closed termination and auditable cleanup/reconciliation. Previous merge approval does not authorize native execution.

These are *requirements*, not proof they are achievable. In particular, host authentication, runtime dependencies, and host trust prompts may prevent an offline real-host test. Refuse rather than importing credentials, sharing a home or enabling network. Official hook interfaces: [Claude Code](https://code.claude.com/docs/en/hooks) and [Codex CLI](https://learn.chatgpt.com/docs/hooks).

## CLI and result law

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_sandbox_contract
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_sandbox_contract --host claude-code --mode PLAN_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_sandbox_contract --host codex-cli --mode PLAN_ONLY
```

Both plans include a deterministic SHA-256 of the host label, full fixed policy and future proof-gate names. The fingerprint protects **plan identity only**; it does not attest external evidence. `ON`, `NATIVE_TEST`, unknown hosts, missing/extra fields, unsafe mounts, shared network, inherited credentials or hook-trust bypass are refused. Even an exact policy match still produces `native_launch_authorized=false`, `native_dispatch_verified=false`, `safe_to_activate_hooks=false`, `promotion_authorized=false` and `UNVERIFIED_NO_RUNTIME_EVIDENCE`.

**P3D-P4-P1-P1-P3** must be a new scoped and explicitly approved task before any actual Claude/Codex CLI is called. P2 must not be installed as a hook, connected to the P4 bridge, or treated as automatic knowledge delivery. No systemd services, local host settings, shell profiles, credentials or existing worktrees change in this cut. GitHub PR is review-only.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
