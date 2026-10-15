# P3D-P4-P0 — Claude Code / Codex CLI host-event envelope, inactive

**STATUS: CODE-ONLY SYNTHETIC `OFF` / `DRY_RUN`. NO LIVE HOOKS CONFIGURED OR INSTALLED.**

The two upstream CLIs have a `UserPromptSubmit` hook that receives JSON on stdin, including `hook_event_name`, `session_id`, and `prompt`. Codex also provides a turn identifier. Output behavior is security-sensitive: plain stdout can become model-visible context. The new `portable_hook_bridge.py` therefore **always emits zero stdout bytes**, regardless of whether its metadata-only dry-run succeeds or refuses.

Official interface references (reviewed 2026-10-15):
- Claude Code: https://code.claude.com/docs/en/hooks (UserPromptSubmit and hook settings)
- Codex: https://learn.chatgpt.com/docs/hooks (hook discovery, UserPromptSubmit, trust and output fields)

## Design

- `OFF`: no event input, no registry/package callbacks, no filesystem writes, no knowledge bodies.
- `DRY_RUN`: accept one caller-supplied JSON `UserPromptSubmit` event, max 16,384 UTF-8 bytes, max 2,000 prompt characters. Reject malformed events, unsupported modes, unknown hosts, and missing Codex turn labels. Delegate **only** to P3D-P1 `portable_host_preflight.probe` metadata routing (`max_skills=1`). Return a redacted Python diagnostic value to local test harnesses, **never** serialize it into hook stdout.
- The CLI supports the two hosts but does not install `~/.claude/settings.json`, `~/.codex/hooks.json`, `.claude/`, `.codex/`, or any global/project hooks. It does not invoke the host, register an MCP server, or configure prompt/context injection.
- No prompt, package path, source content, personal session ID, or callback exception is included in the diagnostic value or error message. The caller controls the synthetic events, registry and mappings; output is not host-attested.
- A nonzero diagnostic refusal is not a protected authorization gate. **Do not register the CLI as a live hook**; its exit behavior has not been tested against actual installed host versions.

## Local syntax and synthetic test commands

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_hook_bridge
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_hook_bridge --host claude-code --mode OFF
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_hook_bridge --host codex-cli --mode OFF
```

Both `OFF` CLI commands emit no stdout or stderr and make no Forge/host calls.

## Next review gate — P4-P1

Record installed `claude --version` and `codex --version` on TNG (and later Windows) without writing their configuration. Verify version-specific schema, hook trust rules, duplicate dispatch, exit codes, and that *synthetic tests do not equal live host proof*. Design an explicitly human-approved opt-in test harness in a sandbox that cannot touch preexisting host configs or invoke knowledge-to-tool authority. No automatic delivery until true host protection and source trust can be demonstrated.

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
