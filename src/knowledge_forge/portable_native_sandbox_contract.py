"""P4-P1-P1-P2: non-executing native host sandbox contract.

This module never starts a process, reads host configuration, installs a hook,
invokes a model or treats policy assertions as OS or human attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Mapping, Sequence

HOST_CONFIGS = {'claude-code': 'settings.json', 'codex-cli': 'hooks.json'}

# Every future test must meet each constraint. Matching this document is NOT
# evidence that the OS enforces it and cannot authorize native host execution.
POLICY = {
    'sandbox': 'BWRAP_UNSHARE_ALL_WITH_VERIFIED_NET_MOUNT_PID',
    'network': 'UNSHARED_NO_EXTERNAL_ROUTE_OR_PACKET',
    'host_executable': 'PINNED_ABSOLUTE_PATH_HASH_AND_DEPENDENCIES_REVIEWED',
    'runtime_mounts': 'MINIMUM_EXPLICIT_READ_ONLY_SYSTEM_AND_HOST_BINARIES',
    'user_home': 'NOT_MOUNTED',
    'project': 'PRIVATE_EMPTY_TEMPORARY_PROJECT',
    'config': 'PRIVATE_SINGLE_SOURCE_TEMPORARY_HOST_CONFIG',
    'credential_env': 'EMPTY_ALLOWLIST_NO_USER_TOKENS',
    'credential_files': 'NOT_MOUNTED',
    'hook_handler': 'KNOWLEDGE_FREE_METADATA_ONLY_ZERO_STDOUT',
    'host_hook_trust': 'OBSERVE_REVIEW_NO_BYPASS',
    'extra_hook_sources': 'ABSENT_OR_TEST_REFUSED',
    'model_and_tool_grants': 'NONE',
    'lifetime': 'BOUNDED_TIMEOUT_AND_CRASH_SAFE_TEARDOWN',
    'host_settings': 'NO_READ_OR_WRITE',
    'operator_promotion': 'FORBIDDEN',
    'approval': 'SEPARATE_EXPLICIT_HUMAN_AUTHORIZATION',
}

PROOF_GATES = (
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

class NativeSandboxContractError(ValueError):
    """A proposed fixture diverges from a strictly inert sandbox contract."""


def validate_policy(candidate: Mapping[str, str]) -> None:
    """Inspect declared policy only. Never elevate policy claims to evidence."""
    if not isinstance(candidate, dict) or set(candidate) != set(POLICY):
        raise NativeSandboxContractError('contract keys refused')
    if any(type(candidate[k]) is not str or candidate[k] != v
           for k, v in POLICY.items()):
        raise NativeSandboxContractError('contract boundary refused')


def contract(host: str, *, candidate: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return a deterministic review-only contract, never a launch ticket."""
    if type(host) is not str or host not in HOST_CONFIGS:
        raise NativeSandboxContractError('unknown host')
    policy = dict(POLICY) if candidate is None else candidate
    validate_policy(policy)
    sealed = {'host': host, 'policy': dict(POLICY), 'proof_gates': list(PROOF_GATES)}
    digest = hashlib.sha256(json.dumps(sealed, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=True).encode('ascii')).hexdigest()
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P2_NATIVE_SANDBOX_CONTRACT_PLAN_ONLY',
        'host_label_only': host,
        'expected_temporary_config_file': HOST_CONFIGS[host],
        'policy': dict(POLICY),
        'required_future_evidence': list(PROOF_GATES),
        'contract_sha256': digest,
        'state': 'REVIEW_ONLY_NOT_EXECUTED',
        'evidence_status': 'UNVERIFIED_NO_RUNTIME_EVIDENCE',
        'native_host_sessions_started': False,
        'native_dispatch_verified': False,
        'host_configuration_modified': False,
        'hooks_installed': False,
        'model_calls_made': False,
        'network_traffic_sent': False,
        'credentials_accessed': False,
        'model_context_injected': False,
        'safe_to_activate_hooks': False,
        'native_launch_authorized': False,
        'promotion_authorized': False,
        'instruction_authority': 'NONE',
        'execution_authority': 'NONE',
        'tool_grants': [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Review an inert native-host sandbox policy only')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'PLAN_ONLY':
            raise NativeSandboxContractError('no host execution mode exists')
        result = contract(args.host)
    except NativeSandboxContractError:
        print('Native sandbox contract refused; no host launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
