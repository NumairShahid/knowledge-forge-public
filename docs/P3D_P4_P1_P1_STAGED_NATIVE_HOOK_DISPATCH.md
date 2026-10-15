# P3D-P4-P1-P1-P0 — Staged, non-activated native-host hook dispatch fixture

**STATUS: TEST-FIXTURE PREPARATION ONLY. NO NATIVE CLAUDE/CODEX SESSIONS, NO HOOK ACTIVATION, NO MODEL CALLS.**

This stage produces disposable hook configuration fixtures matching the documented shapes of Claude Code `settings.json` and Codex CLI `hooks.json`. It deliberately **does not** point to the P4-P0 Knowledge Forge bridge: that bridge returns exit `2` when it refuses, which can block a human `UserPromptSubmit`. A separate test handler receives synthetic JSON, records only event metadata in a restricted temporary directory, emits zero stdout/stderr and exits `0`. It does not load or deliver knowledge.

Official interface references (reviewed 2026-10-15):
- Claude: https://code.claude.com/docs/en/hooks — configuration levels, lifecycle event, stdout and exit behavior.
- Codex: https://learn.chatgpt.com/docs/hooks — `hooks.json`, project trust, input fields, concurrent hook sources and stdout.

The fixture constructor requires an already-existing, *empty*, ordinary-user-owned `0700` directory named with the `kf-native-hook-fixture-` prefix. Tests create it through the standard library's `TemporaryDirectory`. The builder writes only under this root, including an empty project directory, a private config directory, and one self-contained event recorder. The CLI always deletes its temporary fixture on normal return. Temporary HOME, `CODEX_HOME`, and `CLAUDE_CONFIG_DIR` are supplied to the synthetic subprocess with an allowlisted environment. This is **not an OS sandbox** and not proof that a native executable cannot access other user files.

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_hook_fixture
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hook_fixture --host claude-code --mode PREPARE_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hook_fixture --host codex-cli --mode PREPARE_ONLY
```

## Separate approval gate for real native dispatch

Before running either actual installed CLI with any hook configuration, obtain explicit human authorization for a **new** cut with the exact host version, `bwrap`/equivalent isolation proof, zero inherited credentials, configured network restrictions, temporary workspace, expected hook-trust behavior, no tool grants, bounded runtime, clean teardown and auditable proof. Real native dispatch may require host authentication; do not supply personal credentials or bypass host trust. User/project/plugin/managed hooks can combine. Do not invoke `--dangerously-bypass-hook-trust` or allow model-generated tool use.

The results of this P0 phase must always report `native_dispatch_verified=false`. Synthetic event replay is not a substitute for observing a host's actual hook dispatcher. No automatic knowledge injection, authenticated approval or promotion is permitted.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
