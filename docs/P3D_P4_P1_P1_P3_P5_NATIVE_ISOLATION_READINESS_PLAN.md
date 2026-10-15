# P4-P1-P1-P3-P5 — Offline native host isolation readiness and release plan

**REVIEW ONLY — NOT AUTHORIZATION FOR NATIVE CLAUDE/CODEX, HOOKS, MODEL CALLS, TOOLS, USER CONFIG, CREDENTIALS, OR DEPLOYMENT.**

## What has actually been observed

The merged P3-P1/R1, P3-P2, P3-P3/R1, and P3-P4 cuts established bounded passive TNG executable inventory, oversized-file metadata, installation-layout/ELF hints, and reconciliation against the **nine original native-runtime proof gates** in `portable_native_sandbox_contract.PROOF_GATES`. The latest TNG P3-P4 report found **nine unverified gates for each native host**. The non-atomic P3-P1/P2/P3 observations cannot freeze PATH, the candidate inode, symlink target, dependencies or package integrity. An earlier Bubblewrap network/private-file canary succeeded **only for a Python probe**, not native Claude or Codex.

- Claude Code: P3-P1 reported a complete file SHA-256 **at that snapshot only**; P3-P3 could not resolve the bounded dynamic string table (`DYNSTR_BOUND_OR_ADDRESS_REFUSED`).
- Codex CLI: the first candidate was **292,309,256 bytes**, above the original **256 MiB (268,435,456-byte)** full-file SHA-256 cap. P3-P2/P3-P3 recorded limited metadata, an intermediate `current` symlink, and `NO_DT_NEEDED_OBSERVED`; this is **not proof of static linkage, package authenticity, runtime dependency closure, or safety**. Linux symlink mode `0777` is not directory write permission; a directory's `0775` bits alone do not prove effective access.
- No native host test, native hook event delivery, actual host sandbox isolation, tool/model nonexecution, or crash-safe native lifecycle has yet been proven. No merge in this sequence is native-launch approval.

## Ordered proposed workstreams — *not* commitments to run

The `portable_native_readiness_plan` module is **declarative Python only**. It imports the original sandbox contract, outputs the exact nine gates **UNVERIFIED**, and sketches an order of work. It reads **no executable bytes, host configs, credentials, or network resources**. The optional `prior_assessment` parameter only accepts the P3-P4 *review-only* nine-unverified structure, and can never elevate it to proof.

| Cut | Scope | Exit checkpoint |
| --- | --- | --- |
| **P6** | Offline stable candidate/installer provenance, bounded oversized Codex hash under a **separate policy** (old limit unchanged), symlink/parent integrity, loader and transitive dependency evidence. | Evidence dossier or explicit BLOCKED. |
| **P7** | Minimal read-only mount manifest, isolated HOME-less temporary project/config/environment, Python/synthetic namespace and network negative controls. | Isolated fixture receipt; **not** native process proof. |
| **P8** | Version-scoped host hook-source discovery/trust plan, extra managed/user/project/plugin-hook refusals, knowledge-free hook contract. | Review-only trust evidence; no host hooks installed. |
| **P9** | Pinned command and sandbox test plan, no-token environment, no-network/no-model negative tests, timeout/cleanup/receipt specification, separate human approval request. | Single-use human review packet; **not** an approval. |
| **P10** | **Actual native Claude/Codex test only after a separate, explicit, narrowly scoped human authorization.** Actual namespace/private-files/hook/model/no-tool/lifecycle evidence. | Verified native test receipts or fail-closed BLOCKED. |
| **P11** | Cross-host/OS regressions, user install/uninstall/rollback, refusal paths, support documentation and independent review of Windows installer PR #18. | Versioned release candidate with limitations. |
| **P12** | Claim-by-claim public communication review, documentation and ToadAid announcement. | Public preview or verified-native launch claim, honestly labeled. |

A realistic *planning range* after P5: **3–5 additional preparation cuts before even requesting a native test**, **1–2 explicitly authorized native-test/repair cuts**, and **2–3 release/announcement cuts**. In practice, an unresolvable dynamic dependency, extra inherited hook, unavailable signed provenance or model call could add more cuts or block native testing entirely. A **public preview announcement** about existing passive/governed functionality is possible sooner if carefully scoped. A **native integration announcement** requires independent receipts for all nine gates and human acceptance.

## Guardrails and exclusions

- Retain original `portable_native_sandbox_contract.POLICY`: `BWRAP_UNSHARE_ALL_WITH_VERIFIED_NET_MOUNT_PID`, zero external network, strict minimum read-only mounts, no user HOME/project or credential files, private temporary config, no model/tool grants, bounded cleanup, and separate explicit human authorization.
- `PLAN_ONLY` CLI prints deterministic JSON with `native_launch_authorized=false`, `approval_can_be_inferred_from_pr_merge=false`, zero tool grants, and **all nine gates `UNVERIFIED_NATIVE_EVIDENCE_REQUIRED`**. All other modes refuse exit 2 with zero stdout.
- No call to Claude/Codex, `ldd`, package manager, ELF loader, hooks, native host CLI, network, system credential store, config reader or user project. No runtime activation, native test, secrets, or model tool actions.
- This is a plan and must not be mistaken for proof that P6–P12 passed, that their number is fixed, or that any future authority can be inferred from a PR merge.

## Reproduce without running an agent

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_readiness_plan
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_readiness_plan --host claude-code --mode PLAN_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_readiness_plan --host codex-cli --mode PLAN_ONLY
```

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
