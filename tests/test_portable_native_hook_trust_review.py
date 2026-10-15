"""P8 negative controls: inert plans cannot substitute for actual host hook trust."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_hook_trust_review import (
    ALLOWED_SYNTHETIC, GATES_TO_REVIEW, SOURCES, HookTrustReviewError,
    main, review,
)
from knowledge_forge.portable_native_sandbox_contract import PROOF_GATES, contract


class HookTrustReviewTests(unittest.TestCase):
    def test_both_hosts_explicit_source_taxonomy_and_all_gates_unverified(self):
        for host in SOURCES:
            with self.subTest(host=host):
                result=review(host)
                self.assertEqual(result['unverified_proof_gate_count'],9)
                self.assertEqual([g['gate'] for g in result['native_proof_gates']],list(PROOF_GATES))
                self.assertTrue(all(g['status']=='UNVERIFIED_NATIVE_EVIDENCE_REQUIRED' for g in result['native_proof_gates']))
                self.assertEqual(result['parent_contract_sha256'],contract(host)['contract_sha256'])
                self.assertEqual(result['state'],'REVIEW_ONLY_HOOK_SOURCE_TRUST_UNVERIFIED')
                self.assertEqual(result['source_classes_assessed'],7)
                self.assertEqual(len(result['candidate_sources_not_discovered']),7)

    def test_scopes_include_managed_user_project_and_plugin(self):
        for host in SOURCES:
            names=' '.join(n for n,_ in SOURCES[host])
            for required in ('managed','user','project','plugin'):
                self.assertIn(required,names)

    def test_unknown_hosts_and_type_refused(self):
        for host in ('',None,True,'codex --help',3,'unknown'):
            with self.assertRaises(HookTrustReviewError):review(host)

    def test_default_never_claims_actual_hook_or_authorization(self):
        for host in SOURCES:
            r=review(host)
            for key in ('actual_effective_hook_sources_identified',
                        'extra_managed_user_project_plugin_hooks_excluded',
                        'hook_source_precedence_or_merging_verified',
                        'native_hook_event_supported_by_pinned_host_verified',
                        'host_hook_configuration_trust_verified',
                        'hook_behavior_in_native_runtime_verified',
                        'native_host_started','native_hook_dispatched','model_called',
                        'credentials_accessed','network_traffic_sent','hooks_installed',
                        'host_configurations_read_or_modified','actual_user_project_scanned',
                        'native_launch_authorized','safe_to_activate_hooks','promotion_authorized'):
                self.assertIs(r[key],False,key)
            self.assertEqual(r['tool_grants'],[])

    def test_synthetic_statuses_may_not_verify_absence(self):
        for host in SOURCES:
            d={n:'SYNTHETIC_ABSENT_NOT_HOST_VERIFIED' for n,_ in SOURCES[host]}
            r=review(host,observations=d)
            self.assertFalse(r['extra_managed_user_project_plugin_hooks_excluded'])
            self.assertFalse(r['actual_effective_hook_sources_identified'])
            self.assertTrue(all(not e['absence_independently_verified'] for e in r['candidate_sources_not_discovered']))

    def test_observed_extra_source_refused(self):
        d={n:'UNINSPECTED' for n,_ in SOURCES['codex-cli']}
        d['unlisted_hook_script']='POSSIBLE_OR_UNKNOWN'
        with self.assertRaises(HookTrustReviewError):review('codex-cli',observations=d)

    def test_missing_source_refused(self):
        d={n:'UNINSPECTED' for n,_ in SOURCES['claude-code']}
        d.pop('managed_policy')
        with self.assertRaises(HookTrustReviewError):review('claude-code',observations=d)

    def test_forged_positive_status_refused(self):
        for bogus in ('VERIFIED','ABSENT','TRUSTED','PASS','NATIVE_TEST_APPROVED','SIGNED',True,None,[],3):
            d={n:'UNINSPECTED' for n,_ in SOURCES['codex-cli']}
            d[next(iter(d))]=bogus
            with self.subTest(status=bogus),self.assertRaises(HookTrustReviewError):
                review('codex-cli',observations=d)

    def test_non_dict_sources_refused(self):
        for d in ([],True,'UNINSPECTED',(),3):
            with self.assertRaises(HookTrustReviewError):review('claude-code',observations=d)

    def test_cross_host_source_substitution_refused(self):
        d={n:'UNINSPECTED' for n,_ in SOURCES['claude-code']}
        with self.assertRaises(HookTrustReviewError):review('codex-cli',observations=d)

    def test_host_pins_are_snapshot_references_not_live_version_probe(self):
        self.assertEqual(review('claude-code')['host_version_reference_from_prior_snapshot_only'],'2.1.296')
        self.assertEqual(review('codex-cli')['host_version_reference_from_prior_snapshot_only'],'0.161.0')
        self.assertFalse(review('codex-cli')['native_hook_event_supported_by_pinned_host_verified'])

    def test_proposed_synthetic_hook_zero_stdout_no_model(self):
        for host in SOURCES:
            x=review(host)['proposed_synthetic_only_hook']
            self.assertEqual(x['stdout_bytes_allowed'],0)
            self.assertEqual(x['stderr_bytes_allowed'],0)
            self.assertFalse(x['model_context_allowed'])
            self.assertFalse(x['native_dispatch_verified'])
            self.assertEqual(x['tools_allowed'],[])

    def test_three_canonical_hook_gates_not_new_claims(self):
        self.assertEqual(len(GATES_TO_REVIEW),3)
        self.assertTrue(set(GATES_TO_REVIEW).issubset(set(PROOF_GATES)))
        self.assertEqual(review('codex-cli')['review_gates'],list(GATES_TO_REVIEW))

    def test_deterministic_audit_label_not_authentication(self):
        d={n:'POSSIBLE_OR_UNKNOWN' for n,_ in SOURCES['codex-cli']}
        a=review('codex-cli',observations=d)
        b=review('codex-cli',observations=copy.deepcopy(d))
        self.assertEqual(a,b)
        self.assertEqual(len(a['source_state_fingerprint_not_host_attestation']),64)
        self.assertNotIn('path',json.dumps(a['candidate_sources_not_discovered']).lower())

    def test_review_does_not_read_files_spawn_or_connect(self):
        with patch('builtins.open',side_effect=AssertionError('file reads forbidden')), \
             patch('subprocess.run',side_effect=AssertionError('spawn forbidden')):
            r=review('claude-code')
        self.assertEqual(r['state'],'REVIEW_ONLY_HOOK_SOURCE_TRUST_UNVERIFIED')

    def test_cli_live_and_unknown_modes_exit_two_without_stdout(self):
        for host,mode in [('codex-cli','NATIVE_TEST'),('claude-code','ON'),('unknown','REVIEW_ONLY')]:
            cp=subprocess.run([sys.executable,'-m','knowledge_forge.portable_native_hook_trust_review',
                               '--host',host,'--mode',mode],capture_output=True,timeout=8)
            self.assertEqual(cp.returncode,2)
            self.assertEqual(cp.stdout,b'')

    def test_cli_review_returns_bounded_synthetic_only_json(self):
        with patch('subprocess.run',side_effect=AssertionError('spawn forbidden')):
            with patch('builtins.print') as sink:
                self.assertEqual(main(['--host','claude-code','--mode','REVIEW_ONLY']),0)
        out=json.loads(sink.call_args.args[0])
        self.assertFalse(out['native_launch_authorized'])
        self.assertFalse(out['hooks_installed'])
        self.assertEqual(out['unverified_proof_gate_count'],9)


if __name__=='__main__':
    unittest.main()
