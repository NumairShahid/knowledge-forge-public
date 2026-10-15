"""P4-P1-P1-P3-P5: purely declarative, offline native-host readiness plan.

Neither this module nor its CLI reads executable/host configuration files,
launches agents, resolves dependencies, modifies system state, or authenticates
human approval. All nine runtime proof gates remain unverified.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping, Sequence

from knowledge_forge.portable_native_sandbox_contract import POLICY, PROOF_GATES, contract

HOSTS = ('claude-code', 'codex-cli')
ASSESSMENT_SURFACE = 'P4_P1_P1_P3_P4_OFFLINE_GAP_ASSESSMENT'
REQUIRED_STATE = 'REVIEW_ONLY_ALL_NATIVE_GATES_UNVERIFIED'
UNVERIFIED_STATE = 'UNVERIFIED_NATIVE_EVIDENCE_REQUIRED'

# Workstream identifiers are *planning markers*, not branch/tag/PR claims.
# A stage requiring execution is explicitly ineligible until a fresh human
# authorization names the host, artifact, isolation, runtime and expiry.
STAGES: tuple[dict[str, Any], ...] = (
    {
        'cut': 'P4-P1-P1-P3-P6',
        'name': 'bounded_binary_identity_and_dependency_closure',
        'activity': 'OFFLINE_PREPARATION_ONLY',
        'deliverables': [
            'separate reviewed oversized-Codex full-file fingerprint policy (old 256 MiB cap unchanged)',
            'stable candidate path/symlink and parent mount/ACL identity review',
            'offline interpreter and declared-library closure with unresolved/dlopen cases explicit',
            'installer provenance/signature evidence or honest unverified refusal',
        ],
        'exit_evidence': 'reviewed non-executing identity and dependency dossier or BLOCKED',
    },
    {
        'cut': 'P4-P1-P1-P3-P7',
        'name': 'hermetic_sandbox_and_mount_preflight',
        'activity': 'SYNTHETIC_OR_PYTHON_ONLY',
        'deliverables': [
            'explicit minimal read-only mount manifest; HOME and credential paths excluded',
            'temporary empty project and isolated configuration source; zero inherited secrets',
            'network, mount and PID namespace fixture proofs independent of native agents',
            'dry-run plan receipt and refusal on unresolved dependencies',
        ],
        'exit_evidence': 'synthetic isolation proof only, not native process attestation',
    },
    {
        'cut': 'P4-P1-P1-P3-P8',
        'name': 'native_hook_sources_and_trust_review',
        'activity': 'OFFLINE_REVIEW_ONLY',
        'deliverables': [
            'version-scoped documented host hook surfaces and trust assumptions',
            'single metadata-only zero-stdout test hook specification',
            'extra managed/user/project/plugin hook source risk matrix',
            'refusal design for any uninspectable hook source; no installed hooks',
        ],
        'exit_evidence': 'reviewed hook trust plan or BLOCKED; no host dispatch claimed',
    },
    {
        'cut': 'P4-P1-P1-P3-P9',
        'name': 'single_use_native_test_approval_packet',
        'activity': 'PLAN_ONLY_NO_AUTHORIZATION',
        'deliverables': [
            'exact pinned binary, filesystem mount set, temp config, and zero-secret environment',
            'no-network/no-model/no-tool negative controls and crash-safe timeout',
            'single-use receipt schema with failure/cancellation and cleanup criteria',
            'separate explicit operator approval request; approval NOT collected by this module',
        ],
        'exit_evidence': 'a reviewable request, not approval or executable launch capability',
    },
    {
        'cut': 'P4-P1-P1-P3-P10',
        'name': 'controlled_actual_native_host_test',
        'activity': 'FORBIDDEN_UNTIL_SEPARATELY_AUTHORIZED',
        'deliverables': [
            'only after approved exact single-use scope: native namespace and network evidence',
            'actual private-file non-mount checks and extra-hook discovery',
            'no-model/no-tool negative evidence and native hook exit/stdout/duplicate behavior',
            'bounded lifecycle, cleanup and auditable receipt; refuse on any gap',
        ],
        'exit_evidence': 'real host test receipts; otherwise blocked, not silently retried',
    },
    {
        'cut': 'P4-P1-P1-P3-P11',
        'name': 'release_regressions_and_supportability',
        'activity': 'FUTURE_REVIEW_REQUIRED',
        'deliverables': [
            'cross-host/OS reproducibility and negative/refusal regression evidence',
            'operator install/uninstall/rollback with existing OFF-by-default behavior',
            'scope review for normal users and separate Windows installer PR',
        ],
        'exit_evidence': 'release candidate and audited limitations, not automatic promotion',
    },
    {
        'cut': 'P4-P1-P1-P3-P12',
        'name': 'public_preview_or_native_integrated_announcement',
        'activity': 'FUTURE_COMMUNICATION_REVIEW',
        'deliverables': [
            'distinguish public preview of passive/governed features from proven native integration',
            'publish only claims supported by versioned CI, receipts and manual review',
            'do not state hook/native test success while nine gates are unverified',
        ],
        'exit_evidence': 'accurate announcement copy approved by human maintainers',
    },
)

# Source truth: exact nine strings imported from the already merged native
# sandbox policy, no newly invented renamed authority gate.
EXPECTED_PROOF_GATES = (
    'actual_host_executable_identity_and_dependency_tree',
    'actual_host_process_namespace_and_network_attestation',
    'actual_host_process_unmounted_private_files_and_secrets',
    'host_hook_configuration_discovery_and_trust_review',
    'absence_of_extra_user_project_plugin_managed_hooks',
    'no_model_or_tool_execution_during_native_test',
    'hook_exit_status_stdout_stderr_and_duplicate_behavior',
    'bounded_test_runtime_cleanup_and_auditable_receipt',
    'separate_explicit_authorized_test_scope',
)

class ReadinessPlanError(ValueError):
    """Invalid host, source observation or policy drift; do not advance."""


def _validated_prior_report(host: str, assessment: Mapping[str, Any] | None) -> bool:
    """Accept *review context* only; never proof of runtime or human approval."""
    if assessment is None:
        return False
    if not isinstance(assessment, dict):
        raise ReadinessPlanError('assessment type refused')
    if (assessment.get('surface') != ASSESSMENT_SURFACE or
            assessment.get('host_label_only') != host or
            assessment.get('state') != REQUIRED_STATE or
            assessment.get('unverified_proof_gate_count') != 9):
        raise ReadinessPlanError('unrecognized or cross-host assessment')
    gates = assessment.get('native_proof_gates')
    if not isinstance(gates, list) or len(gates) != 9:
        raise ReadinessPlanError('nine-gate record missing')
    if [x.get('gate') if isinstance(x, dict) else None for x in gates] != list(PROOF_GATES):
        raise ReadinessPlanError('native contract gate mismatch')
    if any(x.get('status') != UNVERIFIED_STATE for x in gates):
        raise ReadinessPlanError('self-declared native proof refused')
    for field in ('native_host_sessions_started', 'native_dispatch_verified', 'hooks_installed',
                  'credentials_accessed', 'model_called', 'network_traffic_sent',
                  'native_launch_authorized', 'safe_to_activate_hooks', 'promotion_authorized'):
        if assessment.get(field) is not False:
            raise ReadinessPlanError('source declares forbidden native authority')
    if assessment.get('tool_grants') != []:
        raise ReadinessPlanError('tool grants refused')
    return True


def plan(host: str, *, prior_assessment: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return only a bounded, deterministic planning packet. No host I/O."""
    if type(host) is not str or host not in HOSTS:
        raise ReadinessPlanError('host refused')
    if tuple(PROOF_GATES) != EXPECTED_PROOF_GATES or len(PROOF_GATES) != 9:
        raise ReadinessPlanError('canonical nine-gate policy drift')
    if POLICY.get('approval') != 'SEPARATE_EXPLICIT_HUMAN_AUTHORIZATION':
        raise ReadinessPlanError('native test approval policy drift')
    if POLICY.get('user_home') != 'NOT_MOUNTED' or POLICY.get('credential_env') != 'EMPTY_ALLOWLIST_NO_USER_TOKENS':
        raise ReadinessPlanError('private-file or credential contract drift')
    if POLICY.get('network') != 'UNSHARED_NO_EXTERNAL_ROUTE_OR_PACKET':
        raise ReadinessPlanError('network isolation contract drift')
    parent = contract(host)
    if parent['required_future_evidence'] != list(PROOF_GATES) or parent['native_launch_authorized'] is not False:
        raise ReadinessPlanError('native sandbox contract drift')
    attached = _validated_prior_report(host, prior_assessment)
    gaps = [{'gate': g, 'status': UNVERIFIED_STATE} for g in PROOF_GATES]
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P5_NATIVE_ISOLATION_READINESS_PLAN',
        'host_label_only': host,
        'state': 'PLAN_ONLY_NATIVE_TEST_BLOCKED',
        'parent_contract_sha256': parent['contract_sha256'],
        'review_only_p4_report_attached': attached,
        'p4_report_does_not_establish_runtime_truth': True,
        'required_proof_gates': gaps,
        'unverified_proof_gate_count': 9,
        'stages': [dict(s, deliverables=list(s['deliverables'])) for s in STAGES],
        'candidate_execution_mode': 'NONE',
        'native_launch_authorized': False,
        'native_host_sessions_started': False,
        'native_dispatch_verified': False,
        'hooks_installed': False,
        'model_called': False,
        'network_traffic_sent': False,
        'credentials_accessed': False,
        'host_settings_modified': False,
        'model_context_injected': False,
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'separate_explicit_human_approval_received': False,
        'approval_can_be_inferred_from_pr_merge': False,
        'tool_grants': [],
        'release_claim': 'PLANNING_ONLY_NO_NATIVE_INTEGRATION_CLAIM',
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Native sandbox readiness plan only; no native host calls')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'PLAN_ONLY':
            raise ReadinessPlanError('execution mode forbidden')
        output = plan(args.host)
    except ReadinessPlanError:
        print('Native readiness plan refused; no host launched', file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
