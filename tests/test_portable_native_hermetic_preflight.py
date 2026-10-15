"""P4-P1-P1-P3-P7: synthetic only, fail-closed isolation and no authority."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_hermetic_preflight import (
    BWRAP, PYTHON, PROBE_CODE, STATUS_BLOCKED, STATUS_PASS,
    HermeticPreflightError, _check_receipt, main, manifest, preflight,
)
from knowledge_forge.portable_native_sandbox_contract import PROOF_GATES


def good_fixture(parent):
    return {
        'namespaces': {k: v + 999 for k, v in parent.items()},
        'interfaces': ['lo'],
        'user_home_absent': True,
        'host_canary_absent': True,
        'empty_project_and_config': True,
        'private_scratch_writable': True,
        'read_only_usr_mount': True,
        'scrubbed_environment': True,
        'home_is_private': True,
    }


class P7HermeticTests(unittest.TestCase):
    def test_pure_plan_two_hosts_exact_nine_gates(self):
        for host in ('claude-code', 'codex-cli'):
            r = manifest(host)
            self.assertEqual(r['proof_gates_unverified'], list(PROOF_GATES))
            self.assertEqual(r['native_runtime_gates_proven'], 0)
            self.assertFalse(r['native_launch_authorized'])
            self.assertEqual(r['tool_grants'], [])
            self.assertFalse(r['native_host_binary_explicitly_bound'])
            self.assertEqual(r['state'], 'PLAN_ONLY_FIXTURE_NOT_EXECUTED')

    def test_plan_never_invokes_subprocess_or_reads_files(self):
        with patch('subprocess.run', side_effect=AssertionError('spawn denied')):
            with patch('builtins.open', side_effect=AssertionError('open denied')):
                r = preflight('claude-code')
        self.assertEqual(r['state'], 'PLAN_ONLY_FIXTURE_NOT_EXECUTED')

    def test_denies_unknown_hosts_and_non_boolean_mode(self):
        for host in ('', 'codex --version', None, True, 123):
            with self.assertRaises(HermeticPreflightError):
                manifest(host)
        for bad in (None, 'yes', 1, []):
            with self.assertRaises(HermeticPreflightError):
                preflight('codex-cli', execute_fixture=bad)

    def test_declared_mounts_no_host_home_config_or_external_network(self):
        r = manifest('codex-cli')
        modes = {x['target']: x['mode'] for x in r['mount_plan']}
        self.assertEqual(modes['/home'], 'PRIVATE_EMPTY')
        self.assertEqual(modes['/work'], 'PRIVATE_TMPFS_PROJECT')
        self.assertEqual(modes['/config'], 'PRIVATE_TMPFS_CONFIG')
        self.assertEqual(modes['/usr'], 'READ_ONLY_SYSTEM_RUNTIME')
        for k in ('original_home_mounted', 'real_project_mounted',
                  'original_config_mounted', 'credential_paths_mounted'):
            self.assertFalse(r[k])
        self.assertEqual(r['network_namespace_intended'], 'UNSHARED')

    def test_bwrap_command_never_contains_native_hosts_or_mutable_user_bind(self):
        from knowledge_forge import portable_native_hermetic_preflight as mod
        with patch.object(mod.Path, 'is_file', return_value=True), \
             patch.object(mod.Path, 'is_symlink', return_value=False), \
             patch.object(mod.Path, 'is_dir', return_value=False):
            cmd = mod._mounts()
        self.assertEqual(cmd[0], BWRAP)
        for flag in ('--unshare-all', '--clearenv', '--cap-drop', '--ro-bind',
                     '--tmpfs', '--new-session', '--die-with-parent'):
            self.assertIn(flag, cmd)
        self.assertNotIn('--bind', cmd)
        self.assertNotIn('--share-net', cmd)
        self.assertNotIn('/home/tommy', cmd)
        self.assertNotIn('codex', cmd)
        self.assertNotIn('claude', cmd)

    def test_unknown_system_link_is_refused_not_host_escape(self):
        from knowledge_forge import portable_native_hermetic_preflight as mod
        with patch.object(mod.Path, 'is_file', return_value=True), \
             patch.object(mod.Path, 'is_symlink', return_value=True), \
             patch('os.readlink', return_value='../../../home/tommy'):
            with self.assertRaises(HermeticPreflightError):
                mod._mounts()

    def test_valid_synthetic_fixture_receipt_is_only_fixture_proof(self):
        parent={'net': 101, 'mnt': 202, 'pid': 303}
        self.assertTrue(_check_receipt(good_fixture(parent), parent))
        self.assertEqual(manifest('codex-cli')['native_runtime_gates_proven'], 0)

    def test_fixture_refuses_same_namespace(self):
        parent={'net': 101, 'mnt': 202, 'pid': 303}
        data=good_fixture(parent)
        for ns in parent:
            d=copy.deepcopy(data)
            d['namespaces'][ns]=parent[ns]
            self.assertFalse(_check_receipt(d,parent))

    def test_fixture_refuses_nonloopback_or_host_canary(self):
        parent={'net': 1, 'mnt': 2, 'pid': 3}
        for key,value in [('interfaces',['lo','eth0']),('host_canary_absent',False),
                          ('user_home_absent',False),('empty_project_and_config',False)]:
            d=good_fixture(parent)
            d[key]=value
            self.assertFalse(_check_receipt(d,parent))

    def test_fixture_refuses_wrong_environment_or_writable_system(self):
        parent={'net': 1, 'mnt': 2, 'pid': 3}
        for key in ('scrubbed_environment','read_only_usr_mount',
                    'private_scratch_writable','home_is_private'):
            d=good_fixture(parent)
            d[key]=False
            self.assertFalse(_check_receipt(d,parent))

    def test_receipt_wrong_type_extra_key_not_accepted(self):
        parent={'net': 1, 'mnt': 2, 'pid': 3}
        self.assertFalse(_check_receipt('PASS',parent))
        d=good_fixture(parent)
        d['native_launch_authorized']=True
        self.assertFalse(_check_receipt(d,parent))
        d=good_fixture(parent)
        d['namespaces']['net']=True
        self.assertFalse(_check_receipt(d,parent))

    def test_missing_bwrap_fail_closed_no_native_fallback(self):
        from knowledge_forge import portable_native_hermetic_preflight as mod
        with patch.object(mod,'_mounts',side_effect=HermeticPreflightError('no bwrap')):
            result=preflight('codex-cli',execute_fixture=True)
            self.assertEqual(result['state'],STATUS_BLOCKED)
        with patch.object(mod,'_mounts',side_effect=FileNotFoundError('bwrap')):
            result=preflight('codex-cli',execute_fixture=True)
        self.assertEqual(result['state'], STATUS_BLOCKED)
        self.assertFalse(result['native_launch_authorized'])

    def test_synthetic_runner_scope_fixed_and_sanitized(self):
        from knowledge_forge import portable_native_hermetic_preflight as mod
        parent={k:os.stat('/proc/self/ns/'+k).st_ino for k in ('net','mnt','pid')}
        record=good_fixture(parent)
        completed=subprocess.CompletedProcess(['bwrap'],0,stdout=json.dumps(record).encode(),stderr=b'')
        with patch.object(mod,'_mounts',return_value=[BWRAP,'--unshare-all','--clearenv']), \
             patch.object(mod.subprocess,'run',return_value=completed) as runner:
            r=preflight('codex-cli',execute_fixture=True)
        self.assertEqual(r['state'],STATUS_PASS)
        self.assertEqual(r['native_runtime_gates_proven'],0)
        self.assertFalse(r['native_host_started'])
        command=runner.call_args.args[0]
        self.assertEqual(command[0],BWRAP)
        self.assertIn(PYTHON,command)
        self.assertIn(PROBE_CODE,command)
        self.assertNotIn('codex',command)
        self.assertNotIn('claude',command)
        self.assertEqual(runner.call_args.kwargs['env'],{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        self.assertEqual(runner.call_args.kwargs['timeout'],12)
        self.assertFalse(r['native_launch_authorized'])

    def test_synthetic_failure_or_malformed_json_stays_blocked(self):
        from knowledge_forge import portable_native_hermetic_preflight as mod
        for code,output,error in ((1,b'',b'error'),(0,b'not json',b''),(0,b'{}',b'')):
            completed=subprocess.CompletedProcess(['bwrap'],code,stdout=output,stderr=error)
            with patch.object(mod,'_mounts',return_value=[BWRAP]), \
                 patch.object(mod.subprocess,'run',return_value=completed):
                r=preflight('claude-code',execute_fixture=True)
            self.assertEqual(r['state'],STATUS_BLOCKED)
            self.assertNotIn('synthetic_receipt',r)

    def test_cli_live_modes_refused_no_stdout(self):
        for host,mode in (('claude-code','NATIVE_TEST'),('codex-cli','ON'),('invalid','PLAN_ONLY')):
            cp=subprocess.run([sys.executable,'-m','knowledge_forge.portable_native_hermetic_preflight',
                               '--host',host,'--mode',mode],capture_output=True,timeout=8)
            self.assertEqual(cp.returncode,2)
            self.assertEqual(cp.stdout,b'')


if __name__ == '__main__':
    unittest.main()
