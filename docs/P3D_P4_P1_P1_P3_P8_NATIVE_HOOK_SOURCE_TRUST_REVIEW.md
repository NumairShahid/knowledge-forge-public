# P4-P1-P1-P3-P8 — Native hook sources and trust (plan-only)

**REVIEW ONLY / NO NATIVE HOST DISPATCH.** P8 introduces no hooks, CLI executable launches, config reads, user/project scans, model calls, credential access, network requests, tool grants, or promotion. It does **not** make Claude Code or Codex CLI ready to run inside the P7 synthetic fixture.

## Evidence entering P8

P6 proved bounded full-file executable hashes at one TNG snapshot, not provenance, path immutability, version-specific capabilities or dynamic dependency closure. P7/R4 proved a separate **Python-only** Bubblewrap fixture with exact four-key process environment, private scratch and namespace checks, but *not* the actual Claude/Codex host. The nine native host proof gates in `portable_native_sandbox_contract.PROOF_GATES` remain UNVERIFIED. P8 specifically maps the original hook-source trust, absence-of-extra-hooks, and native hook behavior gates; it cannot close them without a real host process.

## Version-scoped candidate hook-source inventory (not observed on TNG)

| Host version label from P6 snapshot | Candidate source classes | Unverified risks |
| --- | --- | --- |
| Claude Code `2.1.296` | Managed/enterprise policy, user settings, project settings, project-local settings, enabled plugins, session/skill/agent hook sources, built-ins | Sources may **merge**; managed hooks or force-enabled plugins may resist ordinary disable switches. Effective sources cannot be assumed absent merely because the sandbox project is empty. |
| Codex CLI `0.161.0` | Managed/system layers, user `hooks.json`, user inline `config.toml` hooks, trusted project `hooks.json`, trusted project inline `config.toml` hooks, enabled plugin bundles, other version-specific layers | Multiple layers may contribute; actual hook loading, trust prompts, feature flags and `UserPromptSubmit` support are **not tested in the pinned binary**. A synthetic `hooks.json` file is not proof that Codex recognizes it. |

These are *candidate classes*, **not** the effective hook inventory of a running host. Neither a user configuration file nor a private managed policy file is opened by P8. Exact source order, trust policy, plugin/default behavior, and native hook schema must be observed by a separately authorized, bounded host test. Unknown or uninspectable sources cause a REFUSAL, not assumed absence.

Reference documentation for reviewers (not executable verification):
- Claude Code hook reference: <https://code.claude.com/docs/en/hooks>
- Codex CLI hooks reference: <https://developers.openai.com/codex/hooks> (documentation routing may move; re-confirm official, pinned version support before tests).

## P8 static review matrix

`portable_native_hook_trust_review.review(host)` imports the nine canonical proof gates; it returns exactly seven host-specific candidate source classes, all **NOT ACTUALLY DISCOVERED**. Caller-supplied synthetic observations can only say `UNINSPECTED`, `SYNTHETIC_ABSENT_NOT_HOST_VERIFIED`, or `POSSIBLE_OR_UNKNOWN`. The code **rejects** `TRUSTED`, `VERIFIED`, actual absence, extra source classes, and source substitutions between Claude and Codex. Its deterministic fingerprint is a hash of policy and *status labels*, not host attestation. `REVIEW_ONLY` is the only CLI mode.

A proposed future handler is `KNOWLEDGE_FREE_SYNTHETIC_METADATA_ONLY`: nominal `UserPromptSubmit` event, zero stdout/stderr, no prompt/token storage, no model, no tool, no Forge context. Event availability, host stdout/stderr meaning, timeout/duplicate behavior, trust dialogs and merged hooks must be independently attested by actual hosts *only after fresh, explicit human authorization*. **P8 executes none of them.**

P9 should assemble an approval *request*, pin exact binary digest and trust assumptions, require a single temporary config source with verified no extra hooks, verify all mount/dependency prerequisites, and record refusal paths for unknown managed/plugin hooks. If any necessary observation remains inaccessible, P10 must remain BLOCKED. Merging P8/P9 does not authorize native execution.

## Reproduce

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_hook_trust_review
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hook_trust_review --host claude-code --mode REVIEW_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_hook_trust_review --host codex-cli --mode REVIEW_ONLY
```

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
