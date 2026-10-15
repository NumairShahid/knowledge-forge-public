"""P4-P1-P1-P3-P0: finite proof-gate design and refusal to grant launch authority."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_sandbox_contract import PROOF_GATES, contract
from knowledge_forge.portable_native_test_design import (
    HOST_VERSION_REFERENCES, STAGES, NativeTestDesignError,
    _claim_statuses, _validate_matrix, design, main,
)


class NativeTestDesignTests(unittest.TestCase):
    def test_every_p2_proof_gate_covered_once(self):
        _validate_matrix()
        flattened = [g for _, gates, _ in STAGES for g in gates]
        self.assertEqual(set(flattened), set(PROOF_GATES))
        self.assertEqual(len(flattened), len(PROOF_GATES))
        self.assertEqual(len(STAGES), 7)

    def test_both_hosts_reference_exact_p2_contract(self):
        for host in HOST_VERSION_REFERENCES:
            result = design(host)
            self.assertEqual(result['parent_contract_sha256'], contract(host)['contract_sha256'])
            self.assertEqual(result['host_label_only'], host)
            self.assertEqual(result['status'], 'DESIGN_ONLY_UNAUTHORIZED')
            self.assertEqual(len(result['design_sha256']), 64)
            self.assertEqual(result, design(host))
            self.assertEqual(len(result['phases']), 7)

    def test_no_launch_even_if_all_claims_marked(self):
        fake = {g: 'CLAIMED_UNVERIFIED' for g in PROOF_GATES}
        for host in HOST_VERSION_REFERENCES:
            result = design(host, claims=fake)
            self.assertEqual(result['missing_independent_attestations'], list(PROOF_GATES))
            self.assertFalse(result['separate_explicit_human_test_authorization_received'])
            for key in ('native_launch_authorized', 'native_dispatch_verified',
                        'host_session_started', 'hook_installed', 'model_called',
                        'network_traffic_sent', 'credentials_accessed',
                        'model_context_injected', 'safe_to_activate_hooks',
                        'promotion_authorized'):
                self.assertIs(result[key], False, key)
            self.assertEqual(result['tool_grants'], [])
            self.assertEqual(result['execution_authority'], 'NONE')

    def test_positive_or_secret_bearing_status_refused(self):
        for value in ('PASS', 'VERIFIED', 'AUTHORIZED', 'secret-token', True, 1, [], None):
            with self.subTest(value=str(value)):
                with self.assertRaises(NativeTestDesignError):
                    design('claude-code', claims={PROOF_GATES[0]: value})

    def test_unknown_missing_or_extra_gates_refused(self):
        with self.assertRaises(NativeTestDesignError):
            design('codex-cli', claims={'unexpected_gate': 'NOT_OBSERVED'})
        for invalid in ([], 'not-dict', {PROOF_GATES[0]: 'CLAIMED_UNVERIFIED', 'bad': 'NOT_OBSERVED'}):
            with self.subTest(value=str(type(invalid))):
                with self.assertRaises(NativeTestDesignError):
                    design('codex-cli', claims=invalid)
        self.assertEqual(_claim_statuses({PROOF_GATES[0]: 'CLAIMED_UNVERIFIED'})[PROOF_GATES[1]],
                         'NOT_OBSERVED')

    def test_unknown_host_refused_without_fallback(self):
        for host in ('', 'codex-cli --trust-bypass', 'claude --dangerously-skip-permissions', None, True):
            with self.subTest(host=str(host)):
                with self.assertRaises(NativeTestDesignError):
                    design(host)

    def test_returned_plan_mutation_does_not_change_canonical_plan(self):
        canonical = design('codex-cli')
        mutated = design('codex-cli')
        mutated['phases'][0]['stage'] = 'RUN_HOST'
        mutated['proof_gate_claims_unverified'][PROOF_GATES[0]] = 'PASS'
        mutated['missing_independent_attestations'].clear()
        mutated['tool_grants'].append('ALL')
        self.assertEqual(design('codex-cli'), canonical)

    def test_plan_main_no_subprocess_execution(self):
        with patch('subprocess.run', side_effect=AssertionError('attempted process spawn')):
            with patch('builtins.print') as out:
                self.assertEqual(main(['--host','claude-code','--mode','PLAN_ONLY']), 0)
        result = json.loads(out.call_args.args[0])
        self.assertFalse(result['native_launch_authorized'])
        self.assertEqual(result['status'], 'DESIGN_ONLY_UNAUTHORIZED')

    def test_cli_refuses_execution_modes_without_stdout(self):
        for host, mode in (('claude-code','ON'), ('codex-cli','NATIVE_TEST'),
                           ('codex-cli','EXECUTE'), ('unknown','PLAN_ONLY')):
            done = subprocess.run([sys.executable, '-m',
                'knowledge_forge.portable_native_test_design',
                '--host',host,'--mode',mode], capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 2)
            self.assertEqual(done.stdout, b'')
        for host in HOST_VERSION_REFERENCES:
            done = subprocess.run([sys.executable, '-m',
                'knowledge_forge.portable_native_test_design',
                '--host',host,'--mode','PLAN_ONLY'], capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)['host_label_only'], host)


if __name__ == '__main__':
    unittest.main()
