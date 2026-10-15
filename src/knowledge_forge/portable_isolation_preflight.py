"""P3D-P4-P1-P1-P1: knowledge-free OS isolation preflight, NOT native dispatch.

This can invoke *only* bubblewrap and a short standard-library Python probe.
No Claude/Codex execution, network traffic, hook registration, credentials,
model queries, protected promotion, or automatic knowledge retrieval.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Sequence

PROBE_SCRIPT = r'''
import json, os, socket, sys
# No outbound sockets or host files are opened. Probe namespace identifiers.
ident = os.stat('/proc/self/ns/net').st_ino
names = [name for _, name in socket.if_nameindex()]
canary = sys.argv[1]
print(json.dumps({
  'net_namespace_inode': ident,
  'interfaces': sorted(names),
  'canary_visible': os.path.exists(canary),
  'home_is_tmp': os.environ.get('HOME') == '/tmp',
  'python_isolated_mode': bool(sys.flags.isolated),
}, sort_keys=True))
'''


class IsolationPreflightError(ValueError):
    """Fail closed with generic diagnostics and no file or credential disclosure."""


def sandbox_command(canary: str, *, bubblewrap: str = '/usr/bin/bwrap') -> list[str]:
    """Create a closed mount/net namespace command for a knowledge-free probe.

    Do not bind a user's HOME, project, runtime, /etc, or host /tmp.
    Actual enforcement requires real execution and namespace evidence.
    """
    if not isinstance(canary, str):
        raise IsolationPreflightError('canary boundary refused')
    canary_path = Path(canary)
    if (canary_path.name != 'private-user-canary'
            or not canary_path.parent.name.startswith('kf-native-isolation-')
            or canary_path.parent.parent != Path('/tmp')
            or '..' in canary_path.parts):
        raise IsolationPreflightError('canary boundary refused')
    if not isinstance(bubblewrap, str) or bubblewrap != '/usr/bin/bwrap':
        raise IsolationPreflightError('unexpected bubblewrap executable')
    cmd = [bubblewrap, '--unshare-all', '--die-with-parent', '--new-session',
           '--cap-drop', 'ALL', '--clearenv',
           '--ro-bind', '/usr', '/usr']
    for directory in ('/lib', '/lib64', '/bin', '/sbin'):
        path = Path(directory)
        if path.is_symlink():
            target = os.readlink(directory)
            if not isinstance(target, str) or not target or '..' in Path(target).parts:
                raise IsolationPreflightError('system symlink refused')
            cmd += ['--symlink', target, directory]
        elif path.is_dir():
            cmd += ['--ro-bind', directory, directory]
    cmd += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
            '--chdir', '/tmp', '--setenv', 'HOME', '/tmp',
            '--setenv', 'TMPDIR', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
            '/usr/bin/python3', '-I', '-S', '-c', PROBE_SCRIPT, canary]
    return cmd


def _base() -> dict[str, Any]:
    return {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P1_OS_ISOLATION_PREFLIGHT_NO_HOST_DISPATCH',
        'authority': 'KNOWLEDGE_ONLY', 'instruction_authority': 'NONE',
        'execution_authority': 'NONE', 'tool_grants': [],
        'native_dispatch_verified': False, 'host_session_started': False,
        'host_config_read_verified': False, 'host_config_write_protection_verified': False,
        'network_traffic_sent': False, 'hook_activated': False,
        'model_context_injected': False, 'promotion_authorized': False,
        'safe_to_activate_hooks': False,
    }


def preflight(*, execute_probe: bool = False) -> dict[str, Any]:
    """Default is a no-execution plan. Explicit probe uses bwrap, NEVER host CLI.

    On failure, report BLOCKED, never fall back to running unsandboxed. A PASS
    proves this tiny probe's namespace restrictions, not future host isolation.
    """
    result = _base()
    result['state'] = 'PLANNED_NOT_EXECUTED'
    result['bubblewrap_found'] = Path('/usr/bin/bwrap').is_file()
    result['system_python_found'] = Path('/usr/bin/python3').is_file()
    result['network_namespace_verified'] = False
    result['home_canary_inaccessible_verified'] = False
    if not execute_probe:
        return result
    result['state'] = 'BLOCKED_ISOLATION_NOT_PROVEN'
    if not result['bubblewrap_found'] or not result['system_python_found']:
        return result
    try:
        with TemporaryDirectory(prefix='kf-native-isolation-', dir='/tmp') as temp:
            canary = Path(temp) / 'private-user-canary'
            canary.write_text('PRIVATE_NOT_FOR_SANDBOX', encoding='utf-8')
            cmd = sandbox_command(str(canary))
            # An allowlist is not an OS sandbox. bwrap must itself enforce it.
            done = subprocess.run(cmd, cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=12, check=False)
            if done.returncode != 0 or len(done.stdout) > 2048:
                return result
            probe = json.loads(done.stdout.decode('utf-8'))
            if set(probe) != {'net_namespace_inode', 'interfaces', 'canary_visible',
                              'home_is_tmp', 'python_isolated_mode'}:
                return result
            if type(probe['net_namespace_inode']) is not int:
                return result
            host_ns = os.stat('/proc/self/ns/net').st_ino
            net_ok = (probe['net_namespace_inode'] != host_ns
                      and isinstance(probe['interfaces'], list)
                      and all(x == 'lo' for x in probe['interfaces']))
            private_ok = (probe['canary_visible'] is False
                          and probe['home_is_tmp'] is True
                          and probe['python_isolated_mode'] is True)
            result['network_namespace_verified'] = net_ok
            result['home_canary_inaccessible_verified'] = private_ok
            if net_ok and private_ok:
                result['state'] = 'PROBE_NAMESPACE_PASS_NOT_HOST_ATTESTATION'
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return result
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Knowledge-free namespace preflight; no host session')
    parser.add_argument('--probe', action='store_true', help='Run only a tiny bwrap namespace probe')
    parser.add_argument('--host', choices=('claude-code', 'codex-cli'), required=True)
    args = parser.parse_args(argv)
    result = preflight(execute_probe=args.probe)
    result['host_label_only'] = args.host
    print(json.dumps(result, sort_keys=True))
    # No positive native-host test is ever claimed by this command.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
