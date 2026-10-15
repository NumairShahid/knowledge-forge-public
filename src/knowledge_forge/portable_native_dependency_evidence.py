"""P4-P1-P1-P3-P2: bounded passive executable metadata and runtime-loader hints.

No full-file hashing, external commands, host sessions, native hooks, model calls,
credential reads, network access, or dependency-tree attestation. This is NOT
an execution/sandbox approval or an executable verification service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any, Sequence

from knowledge_forge.portable_native_executable_inventory import (
    HOST_COMMANDS, MAX_BYTES, NativeExecutableInventoryError,
    _display, _interpreter_hint, _links,
)

# The existing ELF parser can read at most 128 program headers x 256 bytes,
# one PT_INTERP <=255 bytes, in addition to this 4096-byte sample.
HEADER_SAMPLE_BYTES = 4096
MAX_STATIC_BYTES_READ = HEADER_SAMPLE_BYTES + 128 * 256 + 255


class NativeDependencyEvidenceError(ValueError):
    """An input or candidate violates the passive evidence boundary."""


def _sealed_stat(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


def _inspect(candidate: str) -> dict[str, Any]:
    """Read <= MAX_STATIC_BYTES_READ from one PATH candidate, never execute it."""
    resolved, chain = _links(candidate)
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(resolved, flags)
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size <= 0:
            raise NativeDependencyEvidenceError('CANDIDATE_NOT_REGULAR_NONEMPTY')
        if not (initial.st_mode & 0o111) or bool(initial.st_mode & 0o002):
            raise NativeDependencyEvidenceError('CANDIDATE_UNSAFE_MODE')
        head = os.pread(fd, min(initial.st_size, HEADER_SAMPLE_BYTES), 0)
        if len(head) != min(initial.st_size, HEADER_SAMPLE_BYTES):
            raise NativeDependencyEvidenceError('STATIC_READ_INCOMPLETE')
        kind = _interpreter_hint(head, fd, initial.st_size)
        final = os.fstat(fd)
        current = os.stat(resolved, follow_symlinks=False)
        if _sealed_stat(initial) != _sealed_stat(final) or _sealed_stat(final) != _sealed_stat(current):
            raise NativeDependencyEvidenceError('CANDIDATE_CHANGED_DURING_READ')
        return {
            '_resolved_path': resolved,
            '_symlink_chain': chain,
            'file_size_bytes': initial.st_size,
            'file_uid': initial.st_uid,
            'file_gid': initial.st_gid,
            'mode_octal': format(stat.S_IMODE(initial.st_mode), '04o'),
            'world_writable': bool(initial.st_mode & 0o002),
            'exceeds_original_256_mib_digest_cap': initial.st_size > MAX_BYTES,
            'header_sample_bytes_read': len(head),
            'header_sample_sha256_not_full_file_hash': hashlib.sha256(head).hexdigest(),
            'static_runtime_loader_hint': kind,
        }
    finally:
        os.close(fd)


def evidence(host: str, *, search_path: str | None = None,
             home: str | None = None) -> dict[str, Any]:
    """Collect bounded metadata for first PATH candidate, not runtime proof."""
    if type(host) is not str or host not in HOST_COMMANDS:
        raise NativeDependencyEvidenceError('host refused')
    if search_path is not None and type(search_path) is not str:
        raise NativeDependencyEvidenceError('search path refused')
    home = os.path.abspath(os.path.expanduser('~')) if home is None else home
    if type(home) is not str or not os.path.isabs(home):
        raise NativeDependencyEvidenceError('home label refused')
    out: dict[str, Any] = {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P2_STATIC_OVERSIZE_AND_DEPENDENCY_HINTS',
        'host_label_only': host,
        'command_name': HOST_COMMANDS[host],
        'state': 'UNRESOLVED_NO_EXECUTION',
        'original_full_file_sha256_limit_bytes': MAX_BYTES,
        'max_static_read_bytes': MAX_STATIC_BYTES_READ,
        'complete_executable_sha256_verified_by_this_cut': False,
        'dependency_tree_verified': False,
        'package_provenance_verified': False,
        'host_binary_identity_immutable': False,
        'host_session_started': False,
        'native_hook_dispatched': False,
        'native_launch_authorized': False,
        'model_or_tools_invoked': False,
        'credentials_accessed': False,
        'host_settings_modified': False,
        'network_traffic_sent': False,
        'knowledge_context_injected': False,
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'tool_grants': [],
        'missing_evidence': [
            'complete_executable_digest_for_oversized_binary',
            'interpreter_and_transitive_dependency_identity',
            'installation_provenance_and_signatures',
            'actual_sandboxed_host_process_and_hooks',
        ],
    }
    first = shutil.which(HOST_COMMANDS[host], path=search_path)
    if first is None:
        return out
    try:
        meta = _inspect(first)
    except NativeExecutableInventoryError:
        out['state'] = 'BLOCKED_METADATA_NOT_PROVEN'
        out['refusal_category'] = 'SYMLINK_OR_STATIC_VALIDATION_REFUSED'
        return out
    except NativeDependencyEvidenceError as exc:
        out['state'] = 'BLOCKED_METADATA_NOT_PROVEN'
        out['refusal_category'] = str(exc)
        return out
    except OSError:
        out['state'] = 'BLOCKED_METADATA_NOT_PROVEN'
        out['refusal_category'] = 'FILE_OR_LINK_METADATA_UNAVAILABLE'
        return out
    resolved = meta.pop('_resolved_path')
    chain = meta.pop('_symlink_chain')
    out['state'] = ('PASSIVE_OVERSIZED_METADATA_ONLY' if
                    meta['exceeds_original_256_mib_digest_cap'] else
                    'PASSIVE_BOUNDED_METADATA_ONLY')
    out['path_from_PATH'] = _display(first, home)
    out['resolved_executable_path'] = _display(resolved, home)
    out['symlink_chain'] = [
        {'at': _display(x['at'], home),
         'target': _display(x['target'], home) if x['target'].startswith('/') else x['target']}
        for x in chain
    ]
    out['bounded_file_metadata'] = meta
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Static, read-bounded file metadata only; never launch agents')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'EVIDENCE_ONLY':
            raise NativeDependencyEvidenceError('no execution mode exists')
        result = evidence(args.host)
    except NativeDependencyEvidenceError:
        print('Passive dependency evidence refused; no native host started', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
