"""P4-P1-P1-P3-P5 — nine-gate planning only, never native-test authority."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_readiness_plan import (
    ASSESSMENT_SURFACE, EXPECTED_PROOF_GATES, REQUIRED_STATE,
    STAGES, ReadinessPlanError, UNVERIFIED_STATE, main, plan,
)
from knowledge_forge.portable_native_sandbox_contract import PROOF_GATES, contract


def _p4(host='codex-cli'):
    result = {
        'surface': ASSESSMENT_SURFACE,
        'host_label_only': host,
        'state': REQUIRED_STATE,
        'unverified_proof_gate_count': 9,
        'native_proof_gates': [{'gate': g, 'status': UNVERIFIED_STATE} for g in PROOF_GATES],
        'native_host_sessions_started': False,
        'native_dispatch_verified': False,
        'hooks_installed': False,
        'credentials_accessed': False,
        'model_called': False,
        'network_traffic_sent': False,
        'native_launch_authorized': False,
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'tool_grants': [],
    }
    return result


class ReadinessPlanTests(unittest.TestCase):
    def test_both_hosts_exact_nine_gates_and_contract(self):
        self.assertEqual(tuple(PROOF_GATES), EXPECTED_PROOF_GATES)
        for host in ('claude-code', 'codex-cli'):
            with self.subTest(host=host):
                result = plan(host)
                self.assertEqual(result['unverified_proof_gate_count'], 9)
                self.assertEqual(result['state'], 'PLAN_ONLY_NATIVE_TEST_BLOCKED')
                self.assertEqual(result['parent_contract_sha256'], contract(host)['contract_sha256'])
                self.assertEqual([g['gate'] for g in result['required_proof_gates']], list(PROOF_GATES))
                self.assertTrue(all(g['status'] == UNVERIFIED_STATE for g in result['required_proof_gates']))

    def test_no_authority_from_passing_plan_or_pr(self):
        result = plan('codex-cli')
        for key in ('native_launch_authorized', 'native_host_sessions_started', 'native_dispatch_verified',
                    'hooks_installed', 'model_called', 'network_traffic_sent', 'credentials_accessed',
                    'host_settings_modified', 'model_context_injected', 'safe_to_activate_hooks',
                    'promotion_authorized', 'separate_explicit_human_approval_received',
                    'approval_can_be_inferred_from_pr_merge'):
            self.assertFalse(result[key], key)
        self.assertEqual(result['candidate_execution_mode'], 'NONE')
        self.assertEqual(result['tool_grants'], [])

    def test_stage_sequence_and_single_use_approval_boundary(self):
        r = plan('claude-code')
        self.assertEqual([s['cut'].split('-')[-1] for s in r['stages']],
                         ['P6', 'P7', 'P8', 'P9', 'P10', 'P11', 'P12'])
        self.assertTrue(all(s['activity'] != 'HOST_EXECUTION' for s in r['stages']))
        self.assertEqual(r['stages'][4]['activity'], 'FORBIDDEN_UNTIL_SEPARATELY_AUTHORIZED')
        self.assertIn('approval', r['stages'][3]['name'])
        self.assertTrue(all(s['exit_evidence'] and s['deliverables'] for s in r['stages']))

    def test_p4_context_is_never_proof_or_launch_ticket(self):
        for host in ('claude-code', 'codex-cli'):
            r = plan(host, prior_assessment=_p4(host))
            self.assertTrue(r['review_only_p4_report_attached'])
            self.assertTrue(r['p4_report_does_not_establish_runtime_truth'])
            self.assertEqual(r['unverified_proof_gate_count'], 9)
            self.assertFalse(r['native_launch_authorized'])
        self.assertFalse(plan('codex-cli')['review_only_p4_report_attached'])

    def test_cross_host_and_source_swap_refused(self):
        for field, bad in [('host_label_only', 'claude-code'), ('surface', 'fake-surface'),
                           ('state', 'NATIVE_VERIFIED'), ('unverified_proof_gate_count', 0)]:
            source = _p4()
            source[field] = bad
            with self.subTest(field=field), self.assertRaises(ReadinessPlanError):
                plan('codex-cli', prior_assessment=source)

    def test_self_declared_runtime_proofs_refused(self):
        for field in ('native_host_sessions_started', 'native_dispatch_verified', 'hooks_installed',
                      'credentials_accessed', 'model_called', 'network_traffic_sent',
                      'native_launch_authorized', 'safe_to_activate_hooks', 'promotion_authorized'):
            source = _p4()
            source[field] = True
            with self.subTest(field=field), self.assertRaises(ReadinessPlanError):
                plan('codex-cli', prior_assessment=source)

    def test_forged_gate_or_granted_tools_refused(self):
        d = _p4()
        d['native_proof_gates'][0]['status'] = 'PROVEN'
        with self.assertRaises(ReadinessPlanError): plan('codex-cli', prior_assessment=d)
        d = _p4()
        d['native_proof_gates'][0]['gate'] = 'fake_gate'
        with self.assertRaises(ReadinessPlanError): plan('codex-cli', prior_assessment=d)
        d = _p4()
        d['tool_grants'] = ['shell']
        with self.assertRaises(ReadinessPlanError): plan('codex-cli', prior_assessment=d)

    def test_bad_assessment_type_and_missing_fields_refused(self):
        for source in ([], True, {}, {'surface': ASSESSMENT_SURFACE}, 123):
            with self.subTest(kind=str(source)[:80]), self.assertRaises(ReadinessPlanError):
                plan('codex-cli', prior_assessment=source)
        for field in ('native_launch_authorized', 'tool_grants', 'native_proof_gates'):
            d = _p4()
            d.pop(field)
            with self.subTest(field=field), self.assertRaises(ReadinessPlanError):
                plan('codex-cli', prior_assessment=d)

    def test_reject_unknown_host_and_type(self):
        for host in ('', 'codex --version', 'unknown', None, 33, True):
            with self.subTest(host=str(host)), self.assertRaises(ReadinessPlanError):
                plan(host)

    def test_no_filesystem_host_or_network_reads_inside_plan(self):
        with patch('subprocess.run', side_effect=AssertionError('spawn forbidden')), \
             patch('builtins.open', side_effect=AssertionError('file read forbidden')):
            r = plan('claude-code', prior_assessment=_p4('claude-code'))
        self.assertEqual(r['state'], 'PLAN_ONLY_NATIVE_TEST_BLOCKED')

    def test_output_defensive_copy_and_repeatable(self):
        a = plan('codex-cli')
        b = plan('codex-cli')
        self.assertEqual(a, b)
        a['stages'][0]['deliverables'].append('bad')
        self.assertEqual(b, plan('codex-cli'))
        self.assertNotIn('bad', plan('codex-cli')['stages'][0]['deliverables'])

    def test_cli_live_modes_and_unknown_hosts_refuse_no_stdout(self):
        for host, mode in [('codex-cli', 'NATIVE_TEST'), ('claude-code', 'ON'),
                           ('unknown', 'PLAN_ONLY')]:
            p = subprocess.run([sys.executable, '-m', 'knowledge_forge.portable_native_readiness_plan',
                                '--host', host, '--mode', mode], capture_output=True, timeout=8)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(p.stdout, b'')

    def test_cli_plan_contains_no_authorization_or_extra_grants(self):
        with patch('subprocess.run', side_effect=AssertionError('spawn forbidden')):
            with patch('builtins.print') as sink:
                self.assertEqual(main(['--host', 'codex-cli', '--mode', 'PLAN_ONLY']), 0)
        j = json.loads(sink.call_args.args[0])
        self.assertFalse(j['native_launch_authorized'])
        self.assertEqual(j['tool_grants'], [])
        self.assertEqual(j['release_claim'], 'PLANNING_ONLY_NO_NATIVE_INTEGRATION_CLAIM')

    def test_stages_have_explicit_remaining_proof_pitfalls(self):
        text = json.dumps(STAGES).lower()
        for marker in ('256 mib', 'symlink', 'network', 'credential', 'extra', 'timeout',
                       'separate', 'receipt', 'rollback', 'announcement'):
            self.assertIn(marker, text, marker)
        self.assertEqual(len(STAGES), 7)


if __name__ == '__main__':
    unittest.main()
