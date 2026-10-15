"""P4-P1-P1-P3-P6: passive same-descriptor ELF + bounded full-hash snapshot.

This does not establish supply-chain provenance, unchanging path identity,
transitive dependency closure, isolation, or authority to launch a native host.
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

from knowledge_forge.portable_native_executable_inventory import MAX_BYTES as LEGACY_HASH_LIMIT
from knowledge_forge.portable_native_provenance_hints import (
    _elf_needed, MAX_EXECUTABLE_BYTES_READ, MAX_SYMLINKS,
)

HOSTS = {'claude-code': 'claude', 'codex-cli': 'codex'}
# DISTINCT P6 policy. P3-P1's historical 256 MiB cap is NEVER modified.
P6_MAX_HASH_BYTES = 320 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
MAX_PATH_PARTS = 48


class BinaryDossierError(ValueError):
    """Fail-closed invalid request, changed path, or bounded-file refusal."""


def _inside(path: str, home: str) -> bool:
    try:
        return os.path.commonpath((path, home)) == home
    except ValueError:
        return False


def _label(path: str, home: str) -> str:
    return '$HOME' + path[len(home):] if _inside(path, home) else 'OUTSIDE_HOME_REDACTED'


def _stat_key(s: os.stat_result) -> tuple[int, ...]:
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _path_sources(first: str, home: str) -> tuple[str, list[str]]:
    """Find only direct command link destinations and the final real path.

    This is a time-limited observation, not an atomic or race-free path walk.
    """
    current = os.path.abspath(first)
    paths = [current]
    seen: set[str] = set()
    for _ in range(MAX_SYMLINKS + 1):
        if not _inside(current, home):
            raise BinaryDossierError('PATH_OUTSIDE_ALLOWED_HOME')
        if current in seen:
            raise BinaryDossierError('DIRECT_SYMLINK_CYCLE')
        seen.add(current)
        info = os.lstat(current)
        if not stat.S_ISLNK(info.st_mode):
            break
        if len(paths) > MAX_SYMLINKS:
            raise BinaryDossierError('DIRECT_SYMLINK_LIMIT')
        target = os.readlink(current)
        if not target:
            raise BinaryDossierError('DIRECT_SYMLINK_EMPTY')
        current = os.path.abspath(target if os.path.isabs(target) else
                                  os.path.join(os.path.dirname(current), target))
        paths.append(current)
    else:
        raise BinaryDossierError('DIRECT_SYMLINK_LIMIT')
    real = os.path.realpath(current)
    if not _inside(real, home):
        raise BinaryDossierError('RESOLVED_PATH_OUTSIDE_HOME')
    if real not in paths:
        paths.append(real)
    return real, paths


def _path_snapshot(paths: list[str], home: str) -> dict[str, tuple[int, ...]]:
    """Only lstat bounded prefixes of already identified candidate paths."""
    snap: dict[str, tuple[int, ...]] = {}
    for path in paths:
        if not _inside(path, home):
            raise BinaryDossierError('PATH_OUTSIDE_ALLOWED_HOME')
        relative = os.path.relpath(path, home)
        pieces = [] if relative == '.' else relative.split(os.sep)
        current = home
        for piece in [''] + pieces:
            if piece:
                current = os.path.join(current, piece)
            if current not in snap:
                if len(snap) >= MAX_PATH_PARTS:
                    raise BinaryDossierError('PATH_COMPONENT_BOUND_REFUSED')
                snap[current] = _stat_key(os.lstat(current))
    return snap


def _full_hash(fd: int, file_bytes: int, limit: int) -> tuple[str, int]:
    if file_bytes > limit:
        raise BinaryDossierError('FILE_EXCEEDS_P6_SEPARATE_BOUND')
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    consumed = 0
    while consumed < file_bytes:
        part = os.read(fd, min(CHUNK_BYTES, file_bytes - consumed))
        if not part:
            raise BinaryDossierError('FILE_TRUNCATED_DURING_HASH')
        consumed += len(part)
        h.update(part)
    if consumed != file_bytes:
        raise BinaryDossierError('FULL_HASH_LENGTH_MISMATCH')
    return h.hexdigest(), consumed


def dossier(host: str, *, search_path: str | None = None,
            home: str | None = None, max_hash_bytes: int = P6_MAX_HASH_BYTES) -> dict[str, Any]:
    if type(host) is not str or host not in HOSTS:
        raise BinaryDossierError('host refused')
    if search_path is not None and type(search_path) is not str:
        raise BinaryDossierError('search path refused')
    if type(max_hash_bytes) is not int or not 0 < max_hash_bytes <= P6_MAX_HASH_BYTES:
        raise BinaryDossierError('new-policy cap refused')
    home = os.path.abspath(os.path.expanduser('~')) if home is None else home
    if type(home) is not str or not os.path.isabs(home):
        raise BinaryDossierError('home scope refused')
    home = os.path.normpath(home)
    out: dict[str, Any] = {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P6_BINARY_SNAPSHOT_DOSSIER',
        'host_label_only': host,
        'command_name': HOSTS[host],
        'state': 'UNRESOLVED_NO_EXECUTION',
        'legacy_p1_limit_bytes_unchanged': LEGACY_HASH_LIMIT,
        'distinct_p6_max_full_hash_bytes': P6_MAX_HASH_BYTES,
        'full_hash_policy_bytes_used': max_hash_bytes,
        'elf_parser_max_additional_bytes': MAX_EXECUTABLE_BYTES_READ,
        'full_file_hash_snapshot_only': False,
        'same_descriptor_elf_hints_snapshot_only': False,
        'path_components_stable_only_during_observation': False,
        'immutable_executable_or_path_identity_verified': False,
        'native_dependency_closure_verified': False,
        'installer_provenance_or_signature_verified': False,
        'effective_directory_write_access_verified': False,
        'native_process_isolation_verified': False,
        'credentials_accessed': False,
        'network_traffic_sent': False,
        'native_host_started': False,
        'native_hook_dispatched': False,
        'model_called': False,
        'native_launch_authorized': False,
        'safe_to_activate_hooks': False,
        'promotion_authorized': False,
        'tool_grants': [],
    }
    first = shutil.which(HOSTS[host], path=search_path)
    if first is None:
        return out
    fd = None
    try:
        resolved, observed_paths = _path_sources(first, home)
        before_paths = _path_snapshot(observed_paths, home)
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(resolved, flags)
        start = os.fstat(fd)
        if not stat.S_ISREG(start.st_mode) or start.st_size <= 0:
            raise BinaryDossierError('NOT_NONEMPTY_REGULAR_FILE')
        if not (start.st_mode & 0o111) or (start.st_mode & 0o002):
            raise BinaryDossierError('UNSAFE_EXECUTABLE_MODE')
        if start.st_size > max_hash_bytes:
            raise BinaryDossierError('FILE_EXCEEDS_P6_SEPARATE_BOUND')
        digest, read = _full_hash(fd, start.st_size, max_hash_bytes)
        usage = [0]
        static_elf = _elf_needed(fd, start.st_size, usage)
        end = os.fstat(fd)
        on_path = os.stat(resolved, follow_symlinks=False)
        if _stat_key(start) != _stat_key(end) or _stat_key(end) != _stat_key(on_path):
            raise BinaryDossierError('FILE_METADATA_CHANGED_DURING_OBSERVATION')
        after_real, after_observed_paths = _path_sources(first, home)
        after_paths = _path_snapshot(after_observed_paths, home)
        if (after_real != resolved or observed_paths != after_observed_paths or
                before_paths != after_paths):
            raise BinaryDossierError('PATH_METADATA_CHANGED_DURING_OBSERVATION')
        links = [p for p, v in before_paths.items() if stat.S_ISLNK(v[2])]
        dir_writes = [p for p, v in before_paths.items()
                      if stat.S_ISDIR(v[2]) and v[2] & 0o022]
        out.update({
            'state': 'PASSIVE_P6_DIGEST_AND_ELF_SNAPSHOT_NOT_ATTESTATION',
            'path_from_PATH': _label(os.path.abspath(first), home),
            'resolved_executable_path': _label(resolved, home),
            'file_size_bytes': start.st_size,
            'file_uid': start.st_uid,
            'file_gid': start.st_gid,
            'mode_octal': format(stat.S_IMODE(start.st_mode), '04o'),
            'full_file_sha256_at_snapshot_only': digest,
            'full_file_bytes_read': read,
            'full_file_hash_snapshot_only': True,
            'same_descriptor_elf_hints_snapshot_only': True,
            'static_elf_dependency_names_not_resolved': static_elf,
            'elf_parser_additional_bytes_read': usage[0],
            'path_components_observed': len(before_paths),
            'symlink_components_observed': [_label(p, home) for p in links],
            'directory_mode_group_or_world_write_bits_observed': [_label(p, home) for p in dir_writes],
            'path_components_stable_only_during_observation': True,
        })
    except (BinaryDossierError, OSError, ValueError) as error:
        out['state'] = 'BLOCKED_P6_IDENTITY_NOT_PROVEN'
        # No raw exception, executable bytes, or private path on refusal.
        allow = {
            'PATH_OUTSIDE_ALLOWED_HOME', 'DIRECT_SYMLINK_CYCLE', 'DIRECT_SYMLINK_LIMIT',
            'DIRECT_SYMLINK_EMPTY', 'RESOLVED_PATH_OUTSIDE_HOME',
            'PATH_COMPONENT_BOUND_REFUSED', 'FILE_EXCEEDS_P6_SEPARATE_BOUND',
            'FILE_TRUNCATED_DURING_HASH', 'FULL_HASH_LENGTH_MISMATCH',
            'NOT_NONEMPTY_REGULAR_FILE', 'UNSAFE_EXECUTABLE_MODE',
            'FILE_METADATA_CHANGED_DURING_OBSERVATION',
            'PATH_METADATA_CHANGED_DURING_OBSERVATION',
        }
        code = str(error)
        out['refusal_category'] = code if isinstance(error, BinaryDossierError) and code in allow else 'FILE_OR_PATH_INSPECTION_UNAVAILABLE'
    finally:
        if fd is not None:
            os.close(fd)
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='P6 offline executable fingerprint dossier; never host execution')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'DOSSIER_ONLY':
            raise BinaryDossierError('native test forbidden')
        result = dossier(args.host)
    except BinaryDossierError:
        print('P6 offline dossier refused; host not launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
