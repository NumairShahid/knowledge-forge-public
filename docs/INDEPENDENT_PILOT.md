# Codex / Claude clean-environment pilot

**Status: proposed; not yet run against any public distribution.**

Use two separate environments. Neither may have access to the private engine repository, prior ToadAid configuration, or hidden test fixtures. Both must use the same independently verified, pinned public artifact once one exists.

Evidence to record separately for each host:

- Platform, agent app/version, artifact identifier and SHA-256
- Installation prerequisites and commands
- Consumer and authoring commands actually available
- Source-ingest and faithfulness-backed VALIDATED candidate proof
- Discovery and bounded unit loading, with traceable source evidence
- Unsupported-query refusal and tampered/stale/stopped-package refusals
- OFF and DRY_RUN behavior, and separately authorized isolated ON tests
- Privileged operator absent from model-facing tools; no promotion and no tool widening
- Complete test results and exact error codes

Separate verdicts: **INSTALL**, **AUTHOR**, **CONSUME**, **HOST ADAPTER**, **SECURITY** as PASS / PARTIAL / FAIL. Do not label a CLI smoke test as full native app integration.
