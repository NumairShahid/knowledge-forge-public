"""P4-P1-P1-P3-P7: knowledge-free Python-only hermetic fixture.

May run /usr/bin/bwrap and /usr/bin/python3 only with explicit FIXTURE_ONLY.
Never launches native hosts, installs hooks, reads user configs or models.
Synthetic isolation is NOT native Claude/Codex process attestation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Any, Sequence

from knowledge_forge.portable_native_sandbox_contract import POLICY, PROOF_GATES, contract

HOSTS = ('claude-code', 'codex-cli')
BWRAP = '/usr/bin/bwrap'
PYTHON = '/usr/bin/python3'
FIXTURE_TIMEOUT_SECONDS = 12
STATUS_PASS = 'PROBE_HERMETIC_PYTHON_FIXTURE_PASS_NOT_NATIVE_ATTESTATION'
STATUS_BLOCKED = 'BLOCKED_P7_SYNTHETIC_ISOLATION_NOT_PROVEN'

# Bytecode is static: no shell, credentials, user project, native host or sockets.
PROBE_CODE = r'''import json, os, socket, sys
ns = {k: os.stat('/proc/self/ns/' + k).st_ino for k in ('net', 'mnt', 'pid')}
original_home = sys.argv[1]
canary = sys.argv[2]
before = (os.listdir('/work'), os.listdir('/config'))
# Write exclusively inside a sandbox tmpfs mount.
with open('/work/synthetic-check', 'x', encoding='ascii') as f: f.write('fixture')
scratch_ok = os.path.exists('/work/synthetic-check')
allowed_env = {'HOME': '/home/synthetic', 'TMPDIR': '/tmp', 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
print(json.dumps({'namespaces': ns,
 'interfaces': sorted(name for _, name in socket.if_nameindex()),
 'user_home_absent': not os.path.exists(original_home),
 'host_canary_absent': not os.path.exists(canary),
 'empty_project_and_config': before == ([], []),
 'private_scratch_writable': scratch_ok,
 'read_only_usr_mount': bool(os.statvfs('/usr').f_flag & os.ST_RDONLY),
 'scrubbed_environment': dict(os.environ) == allowed_env,
 'home_is_private': os.environ.get('HOME') == '/home/synthetic',
 }, sort_keys=True))'''


class HermeticPreflightError(ValueError):
    """Invalid plan, execution mode or synthetic bwrap contract."""


def manifest(host: str) -> dict[str, Any]:
    """Pure declaration only, never read host filesystem or launch a process."""
    if type(host) is not str or host not in HOSTS:
        raise HermeticPreflightError('unknown host')
    if tuple(PROOF_GATES) != tuple(contract(host)['required_future_evidence']):
        raise HermeticPreflightError('proof gate drift')
    if (POLICY.get('sandbox') != 'BWRAP_UNSHARE_ALL_WITH_VERIFIED_NET_MOUNT_PID' or
            POLICY.get('network') != 'UNSHARED_NO_EXTERNAL_ROUTE_OR_PACKET' or
            POLICY.get('user_home') != 'NOT_MOUNTED' or
            POLICY.get('credential_env') != 'EMPTY_ALLOWLIST_NO_USER_TOKENS' or
            POLICY.get('approval') != 'SEPARATE_EXPLICIT_HUMAN_AUTHORIZATION'):
        raise HermeticPreflightError('sandbox policy drift')
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P7_HERMETIC_SYNTHETIC_PREFLIGHT',
        'host_label_only': host,
        'state': 'PLAN_ONLY_FIXTURE_NOT_EXECUTED',
        'fixture_executable': 'PYTHON_ONLY_NOT_NATIVE_HOST',
        'mount_plan': [
            {'target': '/usr', 'mode': 'READ_ONLY_SYSTEM_RUNTIME'},
            {'target': '/lib;/lib64;/bin;/sbin', 'mode': 'READ_ONLY_IF_PRESENT_OR_SYMLINK'},
            {'target': '/home', 'mode': 'PRIVATE_EMPTY'},
            {'target': '/home/synthetic', 'mode': 'PRIVATE_EMPTY'},
            {'target': '/work', 'mode': 'PRIVATE_TMPFS_PROJECT'},
            {'target': '/config', 'mode': 'PRIVATE_TMPFS_CONFIG'},
            {'target': '/tmp', 'mode': 'PRIVATE_TMPFS'},
            {'target': '/proc', 'mode': 'NEW_PID_NAMESPACE_PROC'},
            {'target': '/dev', 'mode': 'MINIMAL_SANDBOX_DEVICE_NODES'},
        ],
        'original_home_mounted': False,
        'real_project_mounted': False,
        'original_config_mounted': False,
        'credential_paths_mounted': False,
        'native_host_binary_explicitly_bound': False,
        'network_namespace_intended': 'UNSHARED',
        'mount_namespace_intended': 'UNSHARED',
        'pid_namespace_intended': 'UNSHARED',
        'process_timeout_seconds': FIXTURE_TIMEOUT_SECONDS,
        'environment_keys_intended': ['HOME', 'TMPDIR', 'PATH', 'LANG'],
        'proof_gates_unverified': list(PROOF_GATES),
        'native_runtime_gates_proven': 0,
        'native_host_started': False,
        'native_host_process_isolation_verified': False,
        'native_hook_dispatched': False,
        'model_called': False,
        'credentials_accessed': False,
        'network_traffic_sent': False,
        'native_launch_authorized': False,
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'tool_grants': [],
    }


def _mounts() -> list[str]:
    """System mount recipe for Python fixture, never native host mounts."""
    if not Path(BWRAP).is_file() or not Path(PYTHON).is_file():
        raise HermeticPreflightError('synthetic dependencies unavailable')
    args = [BWRAP, '--unshare-all', '--die-with-parent', '--new-session',
            '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr']
    # Ubuntu may use /bin -> usr/bin, /lib -> usr/lib, etc. Only known paths.
    allowed = {'/bin': ('usr/bin',), '/sbin': ('usr/sbin',),
               '/lib': ('usr/lib',), '/lib64': ('usr/lib64',)}
    for label, targets in allowed.items():
        path = Path(label)
        if path.is_symlink():
            target = os.readlink(label)
            if target not in targets:
                raise HermeticPreflightError('system link target not allowlisted')
            args.extend(['--symlink', target, label])
        elif path.is_dir():
            args.extend(['--ro-bind', label, label])
    args.extend(['--proc', '/proc', '--dev', '/dev',
                 '--tmpfs', '/tmp', '--dir', '/home', '--dir', '/home/synthetic',
                 '--tmpfs', '/work', '--tmpfs', '/config',
                 '--chdir', '/work', '--setenv', 'HOME', '/home/synthetic',
                 '--setenv', 'TMPDIR', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
                 '--setenv', 'LANG', 'C.UTF-8'])
    return args


def _check_receipt(data: Any, parent_ns: dict[str, int]) -> bool:
    if not isinstance(data, dict) or set(data) != {
        'namespaces', 'interfaces', 'user_home_absent', 'host_canary_absent',
        'empty_project_and_config', 'private_scratch_writable',
        'read_only_usr_mount', 'scrubbed_environment', 'home_is_private'}:
        return False
    child = data['namespaces']
    if not isinstance(child, dict) or set(child) != set(parent_ns):
        return False
    if any(type(child[k]) is not int or child[k] == parent_ns[k] for k in parent_ns):
        return False
    if data['interfaces'] != ['lo']:
        return False
    return all(data[k] is True for k in (
        'user_home_absent', 'host_canary_absent', 'empty_project_and_config',
        'private_scratch_writable', 'read_only_usr_mount',
        'scrubbed_environment', 'home_is_private'))


def preflight(host: str, *, execute_fixture: bool = False) -> dict[str, Any]:
    """Only synthetic Python may execute, with explicit caller's FIXTURE_ONLY."""
    if type(execute_fixture) is not bool:
        raise HermeticPreflightError('fixture-mode type refused')
    result = manifest(host)
    if not execute_fixture:
        return result
    result['state'] = STATUS_BLOCKED
    # Never substitute an unsandboxed or real native-host run if bwrap is absent.
    try:
        args = _mounts()
        parent = {k: os.stat('/proc/self/ns/' + k).st_ino
                  for k in ('net', 'mnt', 'pid')}
        # Synthetic-only canary; no user's actual files are read.
        with TemporaryDirectory(prefix='kf-p7-synthetic-', dir='/tmp') as folder:
            canary = Path(folder) / 'private-fixture-canary'
            canary.write_text('P7_SYNTHETIC_ONLY', encoding='ascii')
            canary.chmod(0o600)
            original_home = str(Path.home())
            if original_home == '/home/synthetic':
                return result
            cmd = args + ['--', PYTHON, '-I', '-S', '-c', PROBE_CODE,
                          original_home, str(canary)]
            proc = subprocess.run(cmd, capture_output=True, timeout=FIXTURE_TIMEOUT_SECONDS,
                                  env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, check=False)
            if proc.returncode != 0 or proc.stderr or len(proc.stdout) > 4096:
                return result
            record = json.loads(proc.stdout.decode('ascii'))
            if not _check_receipt(record, parent):
                return result
        result['state'] = STATUS_PASS
        result['synthetic_receipt'] = {
            'net_mount_pid_namespaces_distinct_from_parent': True,
            'loopback_only_observed': True,
            'home_and_host_fixture_canary_absent': True,
            'empty_project_and_config_observed': True,
            'scratch_is_private_tmpfs': True,
            'usr_readonly_observed': True,
            'environment_exact_allowlist_observed': True,
            'temporary_fixture_cleaned': True,
        }
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return result
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Hermetic synthetic Python fixture only; no native hosts')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode not in ('PLAN_ONLY', 'FIXTURE_ONLY'):
            raise HermeticPreflightError('native mode forbidden')
        result = preflight(args.host, execute_fixture=args.mode == 'FIXTURE_ONLY')
    except HermeticPreflightError:
        print('Hermetic synthetic fixture refused; no native hosts launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
