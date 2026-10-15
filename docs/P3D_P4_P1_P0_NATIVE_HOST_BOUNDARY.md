# P3D-P4-P1-P0: passive installed-host boundary and refusal rehearsal

**STATUS: PASSIVE VERSION CHECK + SYNTHETIC REPLAY ONLY. NOT A NATIVE HOOK DISPATCH TEST. NO HOOK CONFIGURATION OR ACTIVATION.**

The installed Claude Code and Codex CLI each expose `UserPromptSubmit` hooks, but their behavior must not be inferred from synthetic inputs alone. The P4-P0 bridge has a critical property: it emits **zero stdout** even on errors, but returns exit code **2** for `ON` and malformed/missing-input `DRY_RUN`. Both official hosts document that exit 2 on `UserPromptSubmit` can **block the human prompt**. Therefore **do not install** `portable_hook_bridge.py` as a real hook. This is a documented host contract, not live runtime proof.

Official sources checked October 15, 2026:
- Claude Code: https://code.claude.com/docs/en/hooks (UserPromptSubmit; exit code 2 blocks prompt).
- Codex: https://learn.chatgpt.com/docs/hooks (UserPromptSubmit; exit code 2 with stderr blocks prompt; output may become developer context; trust review and layered configuration).

## Limited P4-P1-P0 probe

- `portable_native_host_probe.py --host <host>` launches only the resolved native executable's `--version`, using temporary HOME/XDG/CODEX_HOME/CLAUDE_CONFIG_DIR and no model-service credential environment variables. Version strings are diagnostic only and do **not** attest to live hook support, trust status, or setting-layer behavior.
- Replays the **Knowledge Forge** P4-P0 Python bridge as a subprocess twice for each synthetic `OFF`, missing-mapping `DRY_RUN`, and `ON` event; confirms output is empty, `OFF` succeeds, refusal returns 2, and no synthetic prompt canary leaks. No real host prompt is dispatched.
- Returns `safe_to_activate_hooks=false`, `native_dispatch_verified=false`, `host_configuration_modified=false`. No settings files opened, edited, created, or merged; no MCP installation or hook registration. This is deliberately incompatible with claiming automatic retrieval or host attestation.

## R1 environment and evidence precision

The native `--version` subprocess receives an **explicit environment allowlist**,
not the user's inherited shell environment. This excludes unrelated secrets such
as `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY`, user-specific Python/Node loader options,
and unknown future credential names. `PATH` remains inherited for interpreter
resolution, so this is **environment isolation, not an OS process sandbox**.
A native executable can still attempt other filesystem or network access;
`--version` is **not** proof that preexisting user settings were unread or
unmodified. The report now uses `native_host_settings_read_verified=false` and
`native_host_settings_write_protection_verified=false` instead of asserting
unobserved `read=false` and `written=false`. No hook, model, or registry activation.

## Guardrail before P4-P1-P1

A later **separately approved** isolated live-host test must verify configuration discovery and trust review, which hooks run on the current versions, exit-2 rejection, zero-output success, duplicate/replay behavior, stderr visibility, and whether project/user/plugin hooks combine. It needs temporary test HOME, temporary empty project, explicit knowledge-free synthetic prompt, no inherited user host config or secrets, and a cleanup/reconciliation receipt. Even that test will not authenticate promotion or permit automatic injection. Do not run a real Claude or Codex session or change user host configuration in this cut.

**Security laws:** `VALIDATED != PROMOTED`, `REVIEWED != AUTHENTICATED`, `KNOWLEDGE != AUTHORITY`.
