"""P4-P1-P1-P3-P4: read-only reconciliation of prior passive host evidence.

No process spawn, credential/config reading, host startup, package probing or
native execution approval. Nine historical native-proof gates always remain
unverified by these static observations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Mapping, Sequence

from knowledge_forge.portable_native_sandbox_contract import PROOF_GATES, contract
from knowledge_forge.portable_native_executable_inventory import inventory
from knowledge_forge.portable_native_dependency_evidence import evidence
from knowledge_forge.portable_native_provenance_hints import provenance_hints

HOSTS = ('claude-code', 'codex-cli')
EXPECTED_SURFACES = {
    'p1_inventory': 'P4_P1_P1_P3_P1_PASSIVE_NATIVE_EXECUTABLE_INVENTORY',
    'p2_bounded': 'P4_P1_P1_P3_P2_STATIC_OVERSIZE_AND_DEPENDENCY_HINTS',
    'p3_layout': 'P4_P1_P1_P3_P3_STATIC_LAYOUT_AND_NEEDED_NAMES',
}
ACCEPTED_STATES = {
    'p1_inventory': ('PASSIVE_FILE_IDENTITY_ONLY', 'BLOCKED_CANDIDATE_NOT_PROVEN', 'UNRESOLVED_NO_EXECUTION'),
    'p2_bounded': ('PASSIVE_BOUNDED_METADATA_ONLY', 'PASSIVE_OVERSIZED_METADATA_ONLY', 'BLOCKED_METADATA_NOT_PROVEN', 'UNRESOLVED_NO_EXECUTION'),
    'p3_layout': ('PASSIVE_STATIC_HINTS_NOT_ATTESTATION', 'BLOCKED_STATIC_EVIDENCE_NOT_PROVEN', 'UNRESOLVED_NO_EXECUTION'),
}
# Established by P4-P1-P1-P2: do not replace these with renamed or invented gates.
GATE_HINTS = {
    'actual_host_executable_identity_and_dependency_tree': 'Full Codex executable digest, loader/lib closure, package provenance and path integrity remain unresolved.',
    'actual_host_process_namespace_and_network_attestation': 'Python-only Bubblewrap checks do not attest a native host process or its network namespace.',
    'actual_host_process_unmounted_private_files_and_secrets': 'No native host process proved private HOME, credentials, settings and secrets absent.',
    'host_hook_configuration_discovery_and_trust_review': 'No native managed/user/project/plugin hook trust assessment has been performed.',
    'absence_of_extra_user_project_plugin_managed_hooks': 'Extra host hook sources have not been independently excluded.',
    'no_model_or_tool_execution_during_native_test': 'No permitted native test has occurred; static no-spawn code is not runtime proof.',
    'hook_exit_status_stdout_stderr_and_duplicate_behavior': 'Synthetic hooks cannot prove native host hook event delivery or behavior.',
    'bounded_test_runtime_cleanup_and_auditable_receipt': 'No native process lifecycle, bounded termination and cleanup receipt exists.',
    'separate_explicit_authorized_test_scope': 'Prior merge consent or design review is not explicit native-test authorization.',
}


class IntegrityGapAssessmentError(ValueError):
    """Invalid or contradictory passive evidence; stop without promotion."""


def _check_record(label: str, host: str, record: Mapping[str, Any]) -> None:
    if not isinstance(record, dict):
        raise IntegrityGapAssessmentError('passive record type refused')
    if record.get('surface') != EXPECTED_SURFACES[label] or record.get('host_label_only') != host:
        raise IntegrityGapAssessmentError('wrong host or evidence surface')
    if record.get('state') not in ACCEPTED_STATES[label]:
        raise IntegrityGapAssessmentError('unknown passive evidence state')
    common = ('native_launch_authorized', 'promotion_authorized', 'safe_to_activate_hooks')
    p1 = ('native_host_sessions_started', 'native_dispatch_verified', 'model_called', 'credentials_requested', 'hooks_installed', 'host_configuration_modified')
    p2 = ('host_session_started', 'native_hook_dispatched', 'model_or_tools_invoked', 'credentials_accessed', 'host_settings_modified', 'network_traffic_sent')
    p3 = ('native_host_started', 'hook_dispatched', 'model_called', 'credentials_accessed', 'host_settings_modified', 'network_traffic_sent')
    for field in common + {'p1_inventory': p1, 'p2_bounded': p2, 'p3_layout': p3}[label]:
        if record.get(field) is not False:
            raise IntegrityGapAssessmentError('native authority or side-effect declaration refused')
    if record.get('tool_grants') != []:
        raise IntegrityGapAssessmentError('tool grants refused')
    if label == 'p3_layout' and record['state'] == 'PASSIVE_STATIC_HINTS_NOT_ATTESTATION':
        for field in ('effective_directory_write_access_verified', 'installation_path_integrity_verified',
                      'intermediate_symlink_target_stability_verified', 'dependency_resolution_verified',
                      'transitive_dependency_tree_verified', 'package_provenance_verified'):
            if record.get(field) is not False:
                raise IntegrityGapAssessmentError('static evidence promoted to attestation')
    if label == 'p2_bounded' and record['state'].startswith('PASSIVE_'):
        for field in ('complete_executable_sha256_verified_by_this_cut', 'dependency_tree_verified',
                      'package_provenance_verified'):
            if record.get(field) is not False:
                raise IntegrityGapAssessmentError('bounded evidence promoted to attestation')
    if label == 'p1_inventory' and record['state'] == 'PASSIVE_FILE_IDENTITY_ONLY':
        if record.get('runtime_dependency_tree_verified') is not False:
            raise IntegrityGapAssessmentError('file evidence promoted to dependency attestation')


def _snapshot_consistency(records: Mapping[str, dict[str, Any]]) -> None:
    paths: list[str] = []
    sizes: list[int] = []
    for label, r in records.items():
        if r['state'].startswith('PASSIVE_'):
            path = r.get('resolved_executable_path')
            if not isinstance(path, str) or not path.startswith('$HOME/') or len(path) > 2048:
                raise IntegrityGapAssessmentError('unbounded or missing candidate path')
            paths.append(path)
            if label == 'p1_inventory':
                size = r.get('executable_file_identity', {}).get('bytes')
            elif label == 'p2_bounded':
                size = r.get('bounded_file_metadata', {}).get('file_size_bytes')
            else:
                size = r.get('file_size_bytes')
            if type(size) is not int or size <= 0:
                raise IntegrityGapAssessmentError('missing bounded file size')
            sizes.append(size)
    if len(set(paths)) > 1 or len(set(sizes)) > 1:
        raise IntegrityGapAssessmentError('passive snapshots conflict; re-evaluation required')


def assess(host: str, *, observations: Mapping[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Review observed static records; by default sample 3 existing passive paths.

    Sources are sequential non-atomic observations; comparisons only reject
    conflicts and never establish a trustworthy frozen executable identity.
    """
    if type(host) is not str or host not in HOSTS:
        raise IntegrityGapAssessmentError('unknown host')
    if observations is None:
        # These functions are passive filesystem readers: no subprocesses,
        # package managers, credential lookup, network, hook or native model.
        data = {
            'p1_inventory': inventory(host),
            'p2_bounded': evidence(host),
            'p3_layout': provenance_hints(host),
        }
    else:
        if not isinstance(observations, dict) or set(observations) != set(EXPECTED_SURFACES):
            raise IntegrityGapAssessmentError('incomplete or extra passive records')
        data = observations
    for label in EXPECTED_SURFACES:
        _check_record(label, host, data[label])
    _snapshot_consistency(data)
    native_contract = contract(host)
    if tuple(native_contract['required_future_evidence']) != tuple(PROOF_GATES):
        raise IntegrityGapAssessmentError('native policy gates drifted')
    if set(PROOF_GATES) != set(GATE_HINTS) or len(PROOF_GATES) != 9:
        raise IntegrityGapAssessmentError('nine native proof gates drifted')
    # Only carefully reduced, enumerated hints are copied into result. Full
    # source records, raw paths and arbitrary user input are never echoed.
    inv, bounded, layout = (data[k] for k in EXPECTED_SURFACES)
    p3ok = layout['state'] == 'PASSIVE_STATIC_HINTS_NOT_ATTESTATION'
    p2ok = bounded['state'].startswith('PASSIVE_')
    p1ok = inv['state'] == 'PASSIVE_FILE_IDENTITY_ONLY'
    elf = layout.get('static_elf_dependency_name_hints', {}) if p3ok else {}
    known_elf = {'DYNSTR_BOUND_OR_ADDRESS_REFUSED', 'NO_DT_NEEDED_OBSERVED',
                 'DT_NEEDED_NAMES_OBSERVED_NOT_RESOLVED', 'NO_DYNAMIC_SEGMENT_OBSERVED'}
    elf_status = elf.get('status') if elf.get('status') in known_elf else 'UNRESOLVED_OR_OTHER_STATIC_ELF_STATUS'
    summary = {
        'p1_inventory_state': inv['state'],
        'p1_refusal_category': inv.get('refusal_category') if inv['state'].startswith('BLOCKED_') else None,
        'p1_complete_digest_at_snapshot_only': bool(p1ok),
        'p2_bounded_state': bounded['state'],
        'p2_oversized_observed': (bounded['bounded_file_metadata']['exceeds_original_256_mib_digest_cap'] if p2ok else None),
        'p3_layout_state': layout['state'],
        'p3_elf_dependency_hint_status': elf_status,
        'p3_intermediate_symlink_observed': layout.get('intermediate_directory_symlink_observed') if p3ok else None,
        'p3_effective_write_access_verified': False,
        'source_snapshots_atomically_bound': False,
        'actual_executable_dependency_closure_verified': False,
        'package_provenance_verified': False,
    }
    # All proof gates remain unverified even if source records say PASSIVE_*.
    gaps = [{'gate': name, 'status': 'UNVERIFIED_NATIVE_EVIDENCE_REQUIRED',
             'reason': GATE_HINTS[name]} for name in PROOF_GATES]
    audit = {'host': host, 'contract_sha256': native_contract['contract_sha256'],
             'sources': {k: data[k]['surface'] for k in EXPECTED_SURFACES},
             'observed_states': {k: data[k]['state'] for k in EXPECTED_SURFACES}}
    digest = hashlib.sha256(json.dumps(audit, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
    return {
        'schema_version': '0.1', 'surface': 'P4_P1_P1_P3_P4_OFFLINE_GAP_ASSESSMENT',
        'host_label_only': host,
        'state': 'REVIEW_ONLY_ALL_NATIVE_GATES_UNVERIFIED',
        'passive_evidence_summary': summary,
        'assessment_fingerprint_not_host_attestation': digest,
        'native_policy_contract_sha256': native_contract['contract_sha256'],
        'unverified_proof_gate_count': 9, 'native_proof_gates': gaps,
        'native_host_sessions_started': False, 'native_dispatch_verified': False,
        'hooks_installed': False, 'credentials_accessed': False,
        'model_called': False, 'network_traffic_sent': False,
        'native_launch_authorized': False, 'safe_to_activate_hooks': False,
        'promotion_authorized': False, 'tool_grants': [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline static evidence gap assessment; never a host launch')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'ASSESS_ONLY':
            raise IntegrityGapAssessmentError('live modes refused')
        result = assess(args.host)
    except (IntegrityGapAssessmentError, OSError, ValueError):
        print('Offline integrity gap assessment refused; no host launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
