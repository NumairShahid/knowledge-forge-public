"""P4-P1-P1-P3-P0: non-executing, non-authorizing native test design.

Only consumes the P2 review contract and optional synthetic status claims.
No host discovery, subprocess, filesystem inspection, hooks, credentials,
model calls, operator promotion, or approval issuance occurs here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Mapping, Sequence

from knowledge_forge.portable_native_sandbox_contract import (
    PROOF_GATES, NativeSandboxContractError, contract,
)

# Every P2 gate has exactly one future evidence owner in this ordered design.
STAGES = (
    ('01_EXECUTABLE_INVENTORY', (
        'actual_host_executable_identity_and_dependency_tree',),
     'pin exact native executable, interpreter chain, executable bytes and dependencies; no execution'),
    ('02_SANDBOX_ATTESTATION', (
        'actual_host_process_namespace_and_network_attestation',
        'actual_host_process_unmounted_private_files_and_secrets'),
     'separately approved test must prove mount, PID and net isolation of the real host process'),
    ('03_CONFIG_AND_TRUST', (
        'host_hook_configuration_discovery_and_trust_review',
        'absence_of_extra_user_project_plugin_managed_hooks'),
     'observe effective hook sources; refuse if any additional source or trust bypass'),
    ('04_NO_MODEL_TOOLS', (
        'no_model_or_tool_execution_during_native_test',),
     'prove no model call, tool invocation, credentials, network or user prompt'),
    ('05_HOOK_BEHAVIOR', (
        'hook_exit_status_stdout_stderr_and_duplicate_behavior',),
     'observe real dispatcher, synthetic-only event, zero context output, exit codes and replay'),
    ('06_TEARDOWN_RECEIPT', (
        'bounded_test_runtime_cleanup_and_auditable_receipt',),
     'record timeouts, termination, removed scratch artifacts and unchanged host settings'),
    ('07_AUTHORIZATION_GATE', (
        'separate_explicit_authorized_test_scope',),
     'obtain fresh explicitly scoped human consent before any native execution'),
)

HOST_VERSION_REFERENCES = {
    'claude-code': '2.1.296',
    'codex-cli': '0.161.0',
}

class NativeTestDesignError(ValueError):
    """A proposal attempts to treat unauthenticated claims as launch permission."""


def _validate_matrix() -> None:
    seen: list[str] = []
    for ident, names, instruction in STAGES:
        if not ident or type(instruction) is not str or not instruction:
            raise NativeTestDesignError('invalid stage')
        seen.extend(names)
    if len(seen) != len(set(seen)) or set(seen) != set(PROOF_GATES):
        raise NativeTestDesignError('evidence gates drifted from P2 contract')


def _claim_statuses(claims: Mapping[str, str] | None) -> dict[str, str]:
    """Return explicitly unauthenticated status; never accept a PASS or receipt."""
    if claims is None:
        return {g: 'NOT_OBSERVED' for g in PROOF_GATES}
    if type(claims) is not dict or not set(claims).issubset(set(PROOF_GATES)):
        raise NativeTestDesignError('claim scope refused')
    if any(type(v) is not str or v not in {'NOT_OBSERVED', 'CLAIMED_UNVERIFIED'}
           for v in claims.values()):
        raise NativeTestDesignError('positive or secret-bearing claim refused')
    return {g: claims.get(g, 'NOT_OBSERVED') for g in PROOF_GATES}


def design(host: str, *, claims: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Generate an inert review design. Claims can never become an attestation."""
    _validate_matrix()
    try:
        parent = contract(host)
    except NativeSandboxContractError as error:
        raise NativeTestDesignError('unknown host') from error
    statuses = _claim_statuses(claims)
    phases = [
        {'stage': ident,
         'required_gates': list(gates),
         'review_action_not_run': instruction,
         'status': 'DESIGNED_NOT_EXECUTED'}
        for ident, gates, instruction in STAGES
    ]
    fingerprint_input = {
        'host': host,
        'parent_contract_sha256': parent['contract_sha256'],
        'stages': phases,
        'evidence_gates': list(PROOF_GATES),
    }
    digest = hashlib.sha256(json.dumps(fingerprint_input, sort_keys=True,
                    ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_NATIVE_HOST_TEST_DESIGN_NO_LAUNCH',
        'host_label_only': host,
        'historic_host_version_reference_not_revalidated': HOST_VERSION_REFERENCES[host],
        'parent_contract_sha256': parent['contract_sha256'],
        'design_sha256': digest,
        'status': 'DESIGN_ONLY_UNAUTHORIZED',
        'phases': phases,
        'proof_gate_claims_unverified': statuses,
        'missing_independent_attestations': list(PROOF_GATES),
        'separate_explicit_human_test_authorization_received': False,
        'native_launch_authorized': False,
        'native_dispatch_verified': False,
        'host_session_started': False,
        'host_configuration_modified': False,
        'hook_installed': False,
        'model_called': False,
        'network_traffic_sent': False,
        'credentials_accessed': False,
        'model_context_injected': False,
        'tool_grants': [],
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'execution_authority': 'NONE',
        'instruction_authority': 'NONE',
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Review-only native host test design; no launch mode')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'PLAN_ONLY':
            raise NativeTestDesignError('native test cannot be launched by this module')
        result = design(args.host)
    except NativeTestDesignError:
        print('Native host test design refused; no host launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
