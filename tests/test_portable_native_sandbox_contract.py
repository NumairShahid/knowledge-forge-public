"""P4-P1-P1-P2: contract integrity, negative cases, no execution authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_sandbox_contract import (
    HOST_CONFIGS, POLICY, PROOF_GATES, NativeSandboxContractError,
    contract, main, validate_policy,
)


class NativeSandboxContractTests(unittest.TestCase):
    def test_both_hosts_distinct_sealed_review_contracts(self):
        output = {h: contract(h) for h in HOST_CONFIGS}
        self.assertNotEqual(output['claude-code']['contract_sha256'],
                            output['codex-cli']['contract_sha256'])
        for host, result in output.items():
            self.assertEqual(result, contract(host))
            self.assertEqual(len(result['contract_sha256']), 64)
            self.assertEqual(result['expected_temporary_config_file'], HOST_CONFIGS[host])
            self.assertEqual(result['state'], 'REVIEW_ONLY_NOT_EXECUTED')
            self.assertEqual(result['policy'], POLICY)
            self.assertEqual(result['required_future_evidence'], list(PROOF_GATES))

    def test_no_host_launch_or_model_authority_even_for_matching_claims(self):
        for host in HOST_CONFIGS:
            result = contract(host, candidate=dict(POLICY))
            for field in ('native_host_sessions_started', 'native_dispatch_verified',
                          'host_configuration_modified', 'hooks_installed',
                          'model_calls_made', 'network_traffic_sent',
                          'credentials_accessed', 'model_context_injected',
                          'safe_to_activate_hooks', 'native_launch_authorized',
                          'promotion_authorized'):
                self.assertIs(result[field], False, field)
            self.assertEqual(result['execution_authority'], 'NONE')
            self.assertEqual(result['instruction_authority'], 'NONE')
            self.assertEqual(result['tool_grants'], [])
            self.assertEqual(result['evidence_status'], 'UNVERIFIED_NO_RUNTIME_EVIDENCE')

    def test_dangerous_network_mount_or_trust_changes_refused(self):
        cases = {
            'network': 'SHARE_HOST_NETWORK',
            'user_home': 'MOUNT_REAL_USER_HOME',
            'credential_env': 'INHERIT_USER_ENV',
            'credential_files': 'USER_KEYSTORE_READONLY',
            'host_hook_trust': 'DANGEROUS_BYPASS',
            'extra_hook_sources': 'ALLOW_PLUGIN_HOOKS',
            'hook_handler': 'KNOWLEDGE_BRIDGE_ON',
            'model_and_tool_grants': 'BROAD_TOOLS',
            'approval': 'IMPLICIT_FROM_PREVIOUS_MERGE',
            'lifetime': 'UNBOUNDED',
            'operator_promotion': 'ALLOW',
        }
        for key, unsafe in cases.items():
            with self.subTest(key=key):
                proposal = dict(POLICY)
                proposal[key] = unsafe
                with self.assertRaises(NativeSandboxContractError):
                    contract('claude-code', candidate=proposal)

    def test_unknown_and_extra_fields_refused(self):
        invalid = [dict(POLICY, allow_model='yes'),
                   {k: v for k, v in POLICY.items() if k != 'sandbox'},
                   dict(POLICY, approval=True),
                   [], None, 'not-a-policy']
        for proposal in invalid:
            with self.subTest(proposal=type(proposal).__name__):
                with self.assertRaises(NativeSandboxContractError):
                    validate_policy(proposal)
        for host in ('', 'unknown', 'codex-cli --launch', None, True):
            with self.assertRaises(NativeSandboxContractError):
                contract(host)

    def test_policy_fingerprint_immutable_from_caller_mutation(self):
        base = contract('codex-cli')
        returned = contract('codex-cli')
        returned['policy']['network'] = 'BAD'
        returned['required_future_evidence'].clear()
        returned['tool_grants'].append('BAD')
        self.assertEqual(contract('codex-cli'), base)
        self.assertEqual(POLICY['network'], 'UNSHARED_NO_EXTERNAL_ROUTE_OR_PACKET')

    def test_plan_cli_has_no_process_spawn_even_when_mocked(self):
        # The module's PLAN_ONLY path does not call subprocess or run the hosts.
        with patch('subprocess.run', side_effect=AssertionError('spawn attempted')):
            with patch('builtins.print') as sink:
                self.assertEqual(main(['--host', 'claude-code', '--mode', 'PLAN_ONLY']), 0)
        self.assertEqual(len(sink.call_args_list), 1)
        result = json.loads(sink.call_args[0][0])
        self.assertFalse(result['native_launch_authorized'])
        self.assertFalse(result['native_dispatch_verified'])

    def test_cli_rejects_on_and_unknown_without_stdout(self):
        for host, mode in [('claude-code','ON'), ('codex-cli','NATIVE_TEST'),
                           ('invalid','PLAN_ONLY')]:
            done = subprocess.run([sys.executable, '-m',
                                   'knowledge_forge.portable_native_sandbox_contract',
                                   '--host', host, '--mode', mode],
                                  capture_output=True, timeout=5, check=False)
            self.assertEqual(done.returncode, 2)
            self.assertEqual(done.stdout, b'')
        done = subprocess.run([sys.executable, '-m',
                               'knowledge_forge.portable_native_sandbox_contract',
                               '--host', 'codex-cli', '--mode', 'PLAN_ONLY'],
                              capture_output=True, timeout=5, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(json.loads(done.stdout)['safe_to_activate_hooks'])


if __name__ == '__main__':
    unittest.main()
