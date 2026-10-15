# P3D-P3-P0 — Bounded knowledge delivery PREVIEW for Claude/Codex

**STATUS: EXPLICIT DATA PREVIEW ONLY. NO AUTOMATIC HOOKS, NO TRUSTED HOST, NO OPERATOR, NO HUMAN AUTHENTICATION, NO PROTECTED PROMOTION.**

This next additive cut follows P3D-P1 metadata-only `DRY_RUN` and P3D-P2 `VERIFY_ONLY` (which checks content but never returns it). `PREVIEW` delivers selected content **only as explicit data** on stdout; neither host's prompt or model context is automatically modified.

## One-account experience

An ordinary user with Claude Code or Codex under their existing account can inspect bounded, source-labeled knowledge. Example from a checkout:

```bash
PYTHONPATH=src python3 -m knowledge_forge.portable_delivery_preview --host claude-code --mode OFF
PYTHONPATH=src python3 -m knowledge_forge.portable_delivery_preview \
  --host codex-cli --mode PREVIEW --question 'What approval quorum is required?' \
  --registry /path/to/real-registry.json --packages-map /path/to/current-packages.json \
  --world-as-of 2026-10-15T12:00:00Z
```

`OFF` must invoke no registry or package callbacks. `ON` refuses. `PREVIEW` selects exactly one current `PROMOTED` skill from caller-supplied registry and package mapping using existing Forge discovery, rechecks selected package/registry/lifecycle bindings, current temporal status, tool ceiling and optional source status through `load_current_skill_context`, and delivers **1–3 untrusted knowledge units** with their exact source bindings. Output includes no executable grant or changed host configuration.

The envelope includes `trust_class=UNTRUSTED_KNOWLEDGE_DATA`, `instruction_authority=NONE`, `execution_authority=NONE`, `authority=KNOWLEDGE_ONLY`, `executable=false` per unit, `source_bindings`, `source_reverification`, `temporal_condition`, `world_as_of` and `content`. Since content might contain instructions, **hosts must treat it solely as quoted evidence/data**; it is never a system/developer instruction, tool call, or human approval.

Limits: at most one skill, three units, 6,000 characters per unit, and 32,768 serialized UTF-8 bytes total. Oversize fails closed; no silent truncation. Errors produce a generic refusal and do not disclose source text or paths. When sources are not reverified, `source_reverification_complete=false`; preview must never describe them as independently checked. Caller-supplied registry and time are not host truth; `registry_trust_attested=false` and `trusted_clock_verified=false` always. `model_context_injected=false`, `automatic_consumption_active=false` always.

## Security boundaries and acceptance gates

The user's CLI agent can alter data it owns under the same account, and can execute the preview or synthesize a registry. Therefore this cut **does not independently prove `PROMOTED` truth or authenticate human input**. The package path check is diagnostic-only and subject to TOCTOU. Unit content is emitted deliberately, so don't claim it stays secret from an agent that invokes the preview. Source IDs/sections are provenance references and not proof of an independently verified origin. Executable instructions embedded in knowledge are untrusted data, not authority. No runtime hooks or agent integrations are installed by the P0 script.

Before enabling actual automatic Claude/Codex delivery, require host-owned current registry and mapping, bounded prompt framing with instruction/data separation, tamper/stale/incident/refusal tests and native host-hook tests. Protected skill promotion remains independently blocked until host-controlled human authentication, fresh registry/candidate reread, code/state isolation, and durable one-use consumption with restart reconciliation are proven.

**Laws:** `VALIDATED != PROMOTED`, `REVIEWED != AUTHENTICATED`, `KNOWLEDGE != AUTHORITY`. Native Windows installer PR #18 is separate.
