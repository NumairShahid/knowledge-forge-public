"""P4-P1-P1-P3-P8: completely non-executing native hook-source trust plan.

No host command, config discovery, filesystem/network access, credential read,
hook dispatch, or launch authorization. Synthetic source labels are not proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Mapping, Sequence

from knowledge_forge.portable_native_sandbox_contract import POLICY, PROOF_GATES, contract

HOSTS = ('claude-code', 'codex-cli')
# Named candidate source classes only. Not tested effective load order or exact
# paths. Version-specific implementation and documentation must be reviewed at P9.
SOURCES: dict[str, tuple[tuple[str, str], ...]] = {
    'claude-code': (
        ('managed_policy', 'Potential organization/enterprise managed hooks; authority and bypass semantics unverified.'),
        ('user_settings', 'User-level settings and any inherited hooks uninspected.'),
        ('project_settings', 'Project settings may merge hooks; sandbox project must be empty.'),
        ('project_local_settings', 'Project-local settings may add hooks.'),
        ('enabled_plugin_hooks', 'Plugins, including managed-enabled plugins, may add hooks.'),
        ('session_skill_agent_hooks', 'Session or skill/agent-provided hook sources may exist.'),
        ('built_in_runtime_hooks', 'Built-in hooks, if any, require separate host-version review.'),
    ),
    'codex-cli': (
        ('managed_or_system_layers', 'Managed/system config layers and hook precedence unverified.'),
        ('user_hooks_json', 'User hooks.json candidate source; actual loading unverified.'),
        ('user_inline_config_toml', 'User config.toml inline hooks candidate source.'),
        ('project_hooks_json', 'Trusted project hooks.json candidate source.'),
        ('project_inline_config_toml', 'Trusted project config.toml inline hooks candidate source.'),
        ('enabled_plugin_hooks', 'Plugin-bundled or injected hooks may add sources.'),
        ('other_version_specific_layers', 'Additional host-version-specific layers not excluded.'),
    ),
}
ALLOWED_SYNTHETIC = frozenset({'UNINSPECTED', 'SYNTHETIC_ABSENT_NOT_HOST_VERIFIED', 'POSSIBLE_OR_UNKNOWN'})
GATES_TO_REVIEW = (
    'host_hook_configuration_discovery_and_trust_review',
    'absence_of_extra_user_project_plugin_managed_hooks',
    'hook_exit_status_stdout_stderr_and_duplicate_behavior',
)
KNOWN_VERSIONS_AT_PRIOR_SNAPSHOT = {'claude-code': '2.1.296', 'codex-cli': '0.161.0'}


class HookTrustReviewError(ValueError):
    """Invalid synthetic evidence or unauthorized native hook proof."""


def _synthetic_statuses(host: str, observations: Mapping[str, str] | None) -> dict[str, str]:
    names = tuple(n for n, _ in SOURCES[host])
    if observations is None:
        return {n: 'UNINSPECTED' for n in names}
    if type(observations) is not dict or set(observations) != set(names):
        raise HookTrustReviewError('missing, extra or unrecognized hook source')
    if any(type(observations[n]) is not str or observations[n] not in ALLOWED_SYNTHETIC for n in names):
        raise HookTrustReviewError('unverified host source cannot claim authentication or absence')
    return {n: observations[n] for n in names}


def review(host: str, *, observations: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return policy-linked review matrix; never read any host installation/config."""
    if type(host) is not str or host not in HOSTS:
        raise HookTrustReviewError('host refused')
    parent = contract(host)
    if (tuple(parent['required_future_evidence']) != tuple(PROOF_GATES) or
            parent.get('native_launch_authorized') is not False or
            len(PROOF_GATES) != 9 or
            POLICY.get('host_hook_trust') != 'OBSERVE_REVIEW_NO_BYPASS' or
            POLICY.get('extra_hook_sources') != 'ABSENT_OR_TEST_REFUSED' or
            POLICY.get('config') != 'PRIVATE_SINGLE_SOURCE_TEMPORARY_HOST_CONFIG' or
            POLICY.get('hook_handler') != 'KNOWLEDGE_FREE_METADATA_ONLY_ZERO_STDOUT' or
            POLICY.get('approval') != 'SEPARATE_EXPLICIT_HUMAN_AUTHORIZATION'):
        raise HookTrustReviewError('canonical native contract drift')
    if any(g not in PROOF_GATES for g in GATES_TO_REVIEW):
        raise HookTrustReviewError('hook proof gates drift')
    statuses = _synthetic_statuses(host, observations)
    candidates = [
        {'source_class': name, 'synthetic_status_not_host_observed': statuses[name],
         'risk_to_exclude': why, 'actual_effective_source_discovered': False,
         'absence_independently_verified': False, 'trust_decision_made': False}
        for name, why in SOURCES[host]
    ]
    fingerprint_input = {'host': host, 'policy_hash': parent['contract_sha256'],
                         'status_only': statuses}
    fingerprint = hashlib.sha256(json.dumps(fingerprint_input, sort_keys=True,
                              separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P8_HOOK_TRUST_SOURCE_REVIEW_ONLY',
        'host_label_only': host,
        'host_version_reference_from_prior_snapshot_only': KNOWN_VERSIONS_AT_PRIOR_SNAPSHOT[host],
        'parent_contract_sha256': parent['contract_sha256'],
        'source_state_fingerprint_not_host_attestation': fingerprint,
        'state': 'REVIEW_ONLY_HOOK_SOURCE_TRUST_UNVERIFIED',
        'candidate_sources_not_discovered': candidates,
        'source_classes_assessed': len(candidates),
        'actual_effective_hook_sources_identified': False,
        'extra_managed_user_project_plugin_hooks_excluded': False,
        'hook_source_precedence_or_merging_verified': False,
        'native_hook_event_supported_by_pinned_host_verified': False,
        'host_hook_configuration_trust_verified': False,
        'hook_behavior_in_native_runtime_verified': False,
        'proposed_synthetic_only_hook': {
            'event_name_reference_not_runtime_verified': 'UserPromptSubmit',
            'handler': 'KNOWLEDGE_FREE_SYNTHETIC_METADATA_ONLY',
            'stdout_bytes_allowed': 0, 'stderr_bytes_allowed': 0,
            'model_context_allowed': False, 'user_prompts_or_tokens_allowed': False,
            'tools_allowed': [], 'native_dispatch_verified': False,
        },
        'native_proof_gates': [{'gate': g, 'status': 'UNVERIFIED_NATIVE_EVIDENCE_REQUIRED'} for g in PROOF_GATES],
        'unverified_proof_gate_count': 9,
        'review_gates': list(GATES_TO_REVIEW),
        'uninspectable_hook_source_action': 'REFUSE_NATIVE_TEST_UNTIL_SEPARATE_REVIEW',
        'unknown_or_extra_hook_source_action': 'REFUSE_NATIVE_TEST_UNTIL_SEPARATE_REVIEW',
        'next_cut': 'P4-P1-P1-P3-P9',
        'native_host_started': False, 'native_hook_dispatched': False,
        'model_called': False, 'credentials_accessed': False,
        'network_traffic_sent': False, 'host_configurations_read_or_modified': False,
        'hooks_installed': False, 'actual_user_project_scanned': False,
        'native_launch_authorized': False, 'safe_to_activate_hooks': False,
        'promotion_authorized': False, 'tool_grants': [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline native hook-source trust plan; no host reads or dispatch')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'REVIEW_ONLY':
            raise HookTrustReviewError('native execution mode refused')
        out = review(args.host)
    except HookTrustReviewError:
        print('Hook-source review refused; no native agent or hook launched', file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
