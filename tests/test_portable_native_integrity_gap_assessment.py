"""P4-P1-P1-P3-P4: nine fixed gaps, bounded source reconciliation, never run hosts."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_integrity_gap_assessment import (
    IntegrityGapAssessmentError, PROOF_GATES, assess, main,
)


def fixtures(host='codex-cli', *, over=True):
    """Synthetic source records with known static claims and no runtime proof."""
    path = '$HOME/.codex/packages/standalone/current/bin/codex' if over else '$HOME/.local/share/claude/versions/2.1.296'
    size = 292309256 if over else 257068216
    neg = dict(native_launch_authorized=False, promotion_authorized=False,
               safe_to_activate_hooks=False, tool_grants=[])
    inv = dict(neg, surface='P4_P1_P1_P3_P1_PASSIVE_NATIVE_EXECUTABLE_INVENTORY',
               host_label_only=host, state=('BLOCKED_CANDIDATE_NOT_PROVEN' if over else 'PASSIVE_FILE_IDENTITY_ONLY'),
               native_host_sessions_started=False, native_dispatch_verified=False,
               model_called=False, credentials_requested=False, hooks_installed=False,
               host_configuration_modified=False, runtime_dependency_tree_verified=False)
    if over:
        inv['refusal_category'] = 'FILE_EXCEEDS_INVENTORY_LIMIT'
    else:
        inv.update(resolved_executable_path=path, executable_file_identity={'bytes': size, 'sha256': 'a'*64})
    bounded = dict(neg, surface='P4_P1_P1_P3_P2_STATIC_OVERSIZE_AND_DEPENDENCY_HINTS',
                   host_label_only=host, state='PASSIVE_OVERSIZED_METADATA_ONLY' if over else 'PASSIVE_BOUNDED_METADATA_ONLY',
                   host_session_started=False, native_hook_dispatched=False, model_or_tools_invoked=False,
                   credentials_accessed=False, host_settings_modified=False, network_traffic_sent=False,
                   complete_executable_sha256_verified_by_this_cut=False,
                   dependency_tree_verified=False, package_provenance_verified=False,
                   resolved_executable_path=path, bounded_file_metadata={'file_size_bytes': size,
                                           'exceeds_original_256_mib_digest_cap': over})
    layout = dict(neg, surface='P4_P1_P1_P3_P3_STATIC_LAYOUT_AND_NEEDED_NAMES',
                  host_label_only=host, state='PASSIVE_STATIC_HINTS_NOT_ATTESTATION',
                  native_host_started=False, hook_dispatched=False, model_called=False,
                  credentials_accessed=False, host_settings_modified=False, network_traffic_sent=False,
                  effective_directory_write_access_verified=False, installation_path_integrity_verified=False,
                  intermediate_symlink_target_stability_verified=False, dependency_resolution_verified=False,
                  transitive_dependency_tree_verified=False, package_provenance_verified=False,
                  resolved_executable_path=path, file_size_bytes=size,
                  intermediate_directory_symlink_observed=over,
                  static_elf_dependency_name_hints={'status': 'NO_DT_NEEDED_OBSERVED' if over else 'DYNSTR_BOUND_OR_ADDRESS_REFUSED'})
    return {'p1_inventory': inv, 'p2_bounded': bounded, 'p3_layout': layout}


class IntegrityGapAssessmentTests(unittest.TestCase):
    def test_codex_blocked_fingerprint_stays_nine_unverified(self):
        result = assess('codex-cli', observations=fixtures())
        self.assertEqual(result['unverified_proof_gate_count'], 9)
        self.assertEqual([x['gate'] for x in result['native_proof_gates']], list(PROOF_GATES))
        self.assertTrue(all(g['status'] == 'UNVERIFIED_NATIVE_EVIDENCE_REQUIRED' for g in result['native_proof_gates']))
        self.assertEqual(result['passive_evidence_summary']['p1_refusal_category'], 'FILE_EXCEEDS_INVENTORY_LIMIT')
        self.assertTrue(result['passive_evidence_summary']['p2_oversized_observed'])
        self.assertFalse(result['native_launch_authorized'])
        self.assertFalse(result['safe_to_activate_hooks'])

    def test_claude_digest_only_at_snapshot_not_runtime_proof(self):
        result = assess('claude-code', observations=fixtures('claude-code', over=False))
        summary = result['passive_evidence_summary']
        self.assertTrue(summary['p1_complete_digest_at_snapshot_only'])
        self.assertEqual(summary['p3_elf_dependency_hint_status'], 'DYNSTR_BOUND_OR_ADDRESS_REFUSED')
        self.assertFalse(summary['source_snapshots_atomically_bound'])
        self.assertEqual(result['unverified_proof_gate_count'], 9)
        self.assertFalse(result['native_dispatch_verified'])

    def test_source_host_substitution_and_wrong_surface_refused(self):
        for label, key, value in [('p1_inventory','host_label_only','claude-code'),
                                  ('p2_bounded','surface','unreviewed'),
                                  ('p3_layout','host_label_only','claude-code')]:
            evidence = fixtures()
            evidence[label][key] = value
            with self.subTest(label=label), self.assertRaises(IntegrityGapAssessmentError):
                assess('codex-cli', observations=evidence)

    def test_invented_verified_attestation_and_grant_refused(self):
        for label, name in [('p1_inventory','native_launch_authorized'),
                            ('p2_bounded','complete_executable_sha256_verified_by_this_cut'),
                            ('p3_layout','installation_path_integrity_verified'),
                            ('p3_layout','effective_directory_write_access_verified')]:
            evidence = fixtures()
            evidence[label][name] = True
            with self.subTest(label=label, field=name), self.assertRaises(IntegrityGapAssessmentError):
                assess('codex-cli', observations=evidence)
        evidence=fixtures()
        evidence['p3_layout']['tool_grants']=['shell']
        with self.assertRaises(IntegrityGapAssessmentError): assess('codex-cli', observations=evidence)

    def test_changed_binary_path_or_size_refused(self):
        data = fixtures()
        data['p3_layout']['file_size_bytes'] += 1
        with self.assertRaises(IntegrityGapAssessmentError): assess('codex-cli', observations=data)
        data = fixtures()
        data['p2_bounded']['resolved_executable_path'] = '$HOME/other/codex'
        with self.assertRaises(IntegrityGapAssessmentError): assess('codex-cli', observations=data)

    def test_unresolved_p1_does_not_claim_digest(self):
        data=fixtures()
        data['p1_inventory']['state']='UNRESOLVED_NO_EXECUTION'
        data['p1_inventory'].pop('refusal_category')
        r=assess('codex-cli', observations=data)
        self.assertFalse(r['passive_evidence_summary']['p1_complete_digest_at_snapshot_only'])
        self.assertEqual(r['unverified_proof_gate_count'],9)

    def test_partial_or_extraneous_evidence_refused(self):
        for invalid in ({}, {'p1_inventory':fixtures()['p1_inventory']},
                        dict(fixtures(), extra={}), ['not a dict'], None):
            with self.subTest(kind=type(invalid).__name__):
                if invalid is None:
                    continue # None selects actual passive readers, not an explicit invalid record
                with self.assertRaises(IntegrityGapAssessmentError): assess('codex-cli',observations=invalid)

    def test_unexpected_state_refused(self):
        d=fixtures()
        d['p3_layout']['state']='NATIVE_VERIFIED'
        with self.assertRaises(IntegrityGapAssessmentError): assess('codex-cli', observations=d)

    def test_digest_deterministic_for_same_statuses_and_not_binary_hash(self):
        d=fixtures()
        x=assess('codex-cli',observations=d)
        y=assess('codex-cli',observations=copy.deepcopy(d))
        self.assertEqual(x['assessment_fingerprint_not_host_attestation'],y['assessment_fingerprint_not_host_attestation'])
        self.assertNotIn('sha256',x['passive_evidence_summary'])
        self.assertNotIn('resolved_executable_path',x['passive_evidence_summary'])

    def test_no_subprocess_host_in_assess_and_no_context_injection(self):
        d=fixtures()
        with patch('subprocess.run',side_effect=AssertionError('spawning forbidden')):
            out=assess('codex-cli',observations=d)
        self.assertFalse(out['model_called'])
        self.assertFalse(out['hooks_installed'])
        self.assertFalse(out['promotion_authorized'])
        self.assertEqual(out['tool_grants'],[])

    def test_cli_bad_host_or_native_modes_refused_without_stdout(self):
        for host,mode in [('codex-cli','ON'),('claude-code','NATIVE_TEST'),('unknown','ASSESS_ONLY')]:
            done=subprocess.run([sys.executable,'-m','knowledge_forge.portable_native_integrity_gap_assessment',
                                 '--host',host,'--mode',mode],capture_output=True,timeout=8)
            self.assertEqual(done.returncode,2)
            self.assertEqual(done.stdout,b'')

    def test_source_function_invocation_is_exact_three_passive_paths(self):
        data=fixtures()
        with patch('knowledge_forge.portable_native_integrity_gap_assessment.inventory', return_value=data['p1_inventory']) as p1, \
             patch('knowledge_forge.portable_native_integrity_gap_assessment.evidence', return_value=data['p2_bounded']) as p2, \
             patch('knowledge_forge.portable_native_integrity_gap_assessment.provenance_hints', return_value=data['p3_layout']) as p3, \
             patch('subprocess.run',side_effect=AssertionError('no native spawn')):
            with patch('builtins.print') as sink:
                self.assertEqual(main(['--host','codex-cli','--mode','ASSESS_ONLY']),0)
        for mock in (p1,p2,p3):mock.assert_called_once_with('codex-cli')
        result=json.loads(sink.call_args.args[0])
        self.assertEqual(result['state'],'REVIEW_ONLY_ALL_NATIVE_GATES_UNVERIFIED')

    def test_invalid_host_types_refused(self):
        for host in ('', None, True, 'claude --version'):
            with self.assertRaises(IntegrityGapAssessmentError):
                assess(host,observations=fixtures())


if __name__ == '__main__':
    unittest.main()
