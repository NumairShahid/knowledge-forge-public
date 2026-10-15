"""P4-P1-P1-P3-P3: bounded passive ELF dependency-name and installation-layout hints.

Never launches a host, loader, interpreter, package manager, network program,
model, or hook. No package manifest, home configuration, or credential content
is opened. Results are NOT dependency resolution or provenance attestation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
from typing import Any, Sequence

HOST_COMMANDS = {'claude-code': 'claude', 'codex-cli': 'codex'}
MAX_SYMLINKS = 16
MAX_EXECUTABLE_BYTES_READ = 98_304
MAX_ELF_PROGRAM_HEADERS = 128
MAX_DYNAMIC_BYTES = 32_768
MAX_DYNSTR_BYTES = 16_384
MAX_NEEDED_NAMES = 32
MAX_ANCESTORS = 7


class ProvenanceHintError(ValueError):
    """Refused passive candidate or malformed bounded evidence."""


def _label(path: str, home: str) -> str:
    root = os.path.normpath(home)
    p = os.path.normpath(path)
    if p == root:
        return '$HOME'
    if p.startswith(root + os.sep):
        return '$HOME/' + p[len(root) + 1:]
    # Do not disclose unrelated absolute paths outside the caller's home.
    return 'OUTSIDE_HOME_REDACTED'


def _resolve(first: str) -> tuple[str, list[dict[str, str]]]:
    current = os.path.abspath(first)
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    for _ in range(MAX_SYMLINKS + 1):
        if current in seen:
            raise ProvenanceHintError('SYMLINK_CYCLE')
        seen.add(current)
        mode = os.lstat(current).st_mode
        if not stat.S_ISLNK(mode):
            return current, links
        if len(links) == MAX_SYMLINKS:
            raise ProvenanceHintError('SYMLINK_LIMIT')
        dest = os.readlink(current)
        if not dest:
            raise ProvenanceHintError('EMPTY_SYMLINK')
        links.append({'at': current, 'target': dest})
        current = os.path.normpath(dest if os.path.isabs(dest) else
                                   os.path.join(os.path.dirname(current), dest))
    raise ProvenanceHintError('SYMLINK_LIMIT')


def _read(fd: int, offset: int, count: int, file_size: int, usage: list[int]) -> bytes:
    if (type(offset) is not int or type(count) is not int or offset < 0 or
            count < 0 or offset > file_size or count > file_size - offset or
            usage[0] + count > MAX_EXECUTABLE_BYTES_READ):
        raise ProvenanceHintError('BOUNDED_ELF_READ_REFUSED')
    data = os.pread(fd, count, offset)
    usage[0] += len(data)
    if len(data) != count:
        raise ProvenanceHintError('BOUNDED_ELF_READ_INCOMPLETE')
    return data


def _elf_needed(fd: int, size: int, usage: list[int]) -> dict[str, Any]:
    """Return bounded DT_NEEDED *names*, not resolved libraries or a full tree."""
    head = _read(fd, 0, min(size, 64), size, usage)
    if len(head) < 16 or head[:4] != b'\x7fELF':
        return {'kind': 'NOT_ELF', 'status': 'NO_ELF_DEPENDENCY_HINT', 'needed_name_hints': []}
    klass, endianness = head[4], head[5]
    if klass not in (1, 2) or endianness not in (1, 2):
        return {'kind': 'ELF', 'status': 'UNSUPPORTED_ELF_HEADER', 'needed_name_hints': []}
    order = '<' if endianness == 1 else '>'
    is64 = klass == 2
    if len(head) < (64 if is64 else 52):
        return {'kind': 'ELF', 'status': 'TRUNCATED_ELF_HEADER', 'needed_name_hints': []}
    try:
        phoff, = struct.unpack_from(order + ('Q' if is64 else 'I'), head, 32 if is64 else 28)
        phentsize, phnum = struct.unpack_from(order + 'HH', head, 54 if is64 else 42)
    except struct.error:
        return {'kind': 'ELF', 'status': 'INVALID_HEADER', 'needed_name_hints': []}
    if phnum == 0 or phnum > MAX_ELF_PROGRAM_HEADERS or phentsize < (56 if is64 else 32) or phentsize > 256:
        return {'kind': 'ELF', 'status': 'PROGRAM_HEADER_BOUND_REFUSED', 'needed_name_hints': []}
    if phoff > size or phnum * phentsize > size - phoff:
        return {'kind': 'ELF', 'status': 'PROGRAM_HEADER_OUT_OF_FILE', 'needed_name_hints': []}
    load: list[tuple[int, int, int]] = []  # vaddr, file_offset, file_length
    dynamic: tuple[int, int] | None = None
    for i in range(phnum):
        block = _read(fd, phoff + i * phentsize, phentsize, size, usage)
        if is64:
            typ, flags, offset, va, pa, length, memlen, align = struct.unpack_from(order + 'IIQQQQQQ', block)
        else:
            typ, offset, va, pa, length, memlen, flags, align = struct.unpack_from(order + 'IIIIIIII', block)
        if offset > size or length > size - offset:
            return {'kind': 'ELF', 'status': 'SEGMENT_OUT_OF_FILE', 'needed_name_hints': []}
        if typ == 1:
            load.append((va, offset, length))
        elif typ == 2:
            if dynamic is not None:
                return {'kind': 'ELF', 'status': 'MULTIPLE_DYNAMIC_SEGMENTS', 'needed_name_hints': []}
            dynamic = (offset, length)
    if dynamic is None:
        return {'kind': 'ELF', 'status': 'NO_DYNAMIC_SEGMENT_OBSERVED', 'needed_name_hints': []}
    off, length = dynamic
    if length == 0 or length > MAX_DYNAMIC_BYTES:
        return {'kind': 'ELF', 'status': 'DYNAMIC_TABLE_BOUND_REFUSED', 'needed_name_hints': []}
    step = 16 if is64 else 8
    table = _read(fd, off, length, size, usage)
    needs: list[int] = []
    straddr: int | None = None
    strsize: int | None = None
    ended = False
    for idx in range(0, len(table) - step + 1, step):
        tag, value = struct.unpack_from(order + ('QQ' if is64 else 'II'), table, idx)
        if tag == 0:
            ended = True
            break
        if tag == 1:
            needs.append(value)
            if len(needs) > MAX_NEEDED_NAMES:
                return {'kind': 'ELF', 'status': 'NEEDED_NAME_COUNT_REFUSED', 'needed_name_hints': []}
        elif tag == 5:
            straddr = value
        elif tag == 10:
            strsize = value
    if not ended:
        return {'kind': 'ELF', 'status': 'UNTERMINATED_DYNAMIC_TABLE', 'needed_name_hints': []}
    if not needs:
        return {'kind': 'ELF', 'status': 'NO_DT_NEEDED_OBSERVED', 'needed_name_hints': []}
    if straddr is None or strsize is None or not 0 < strsize <= MAX_DYNSTR_BYTES:
        return {'kind': 'ELF', 'status': 'DYNSTR_BOUND_OR_ADDRESS_REFUSED', 'needed_name_hints': []}
    regions = [(off_ + straddr - va) for va, off_, length_ in load
               if va <= straddr and strsize <= length_ - (straddr - va)]
    if len(regions) != 1:
        return {'kind': 'ELF', 'status': 'DYNSTR_MAPPING_AMBIGUOUS', 'needed_name_hints': []}
    strings = _read(fd, regions[0], strsize, size, usage)
    labels: list[str] = []
    for offset in needs:
        if offset >= len(strings):
            return {'kind': 'ELF', 'status': 'NEEDED_OFFSET_INVALID', 'needed_name_hints': []}
        end = strings.find(b'\x00', offset)
        if end == -1 or end - offset > 96:
            return {'kind': 'ELF', 'status': 'NEEDED_NAME_BOUND_REFUSED', 'needed_name_hints': []}
        name = strings[offset:end].decode('ascii', errors='ignore')
        if not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,96}', name):
            return {'kind': 'ELF', 'status': 'NEEDED_NAME_UNSAFE', 'needed_name_hints': []}
        labels.append(name)
    return {'kind': 'ELF', 'status': 'DT_NEEDED_NAMES_OBSERVED_NOT_RESOLVED',
            'needed_name_hints': labels}


def _ancestor_metadata(path: str, home: str) -> list[dict[str, Any]]:
    current = Path(path).parent
    results: list[dict[str, Any]] = []
    for _ in range(MAX_ANCESTORS):
        label = _label(str(current), home)
        if label == 'OUTSIDE_HOME_REDACTED':
            break
        info = current.lstat()
        is_dir = stat.S_ISDIR(info.st_mode)
        is_link = stat.S_ISLNK(info.st_mode)
        # Linux symlink mode bits (commonly 0777) do not grant ordinary
        # directory write permission. Interpret write bits for directories only.
        # Even a 0775 directory is a mode hint, NOT proof of effective access:
        # group membership, ACLs, mount policy and races are unverified.
        results.append({'directory_label': label, 'owner_uid': info.st_uid,
                        'mode_octal': format(stat.S_IMODE(info.st_mode), '04o'),
                        'directory_mode_group_or_world_write_bits_set': (
                            bool(info.st_mode & 0o022) if is_dir else None),
                        'mode_interpretation': (
                            'DIRECTORY_BITS_HINT_NOT_EFFECTIVE_ACCESS' if is_dir else
                            'SYMLINK_MODE_NOT_WRITE_PERMISSION' if is_link else
                            'NON_DIRECTORY_NOT_ACCESS_ATTESTATION'),
                        'effective_write_access_verified': False,
                        'is_symlink': is_link,
                        'is_directory': is_dir})
        if label == '$HOME':
            break
        if current.parent == current:
            break
        current = current.parent
    return results


def _layout_hint(path: str, home: str, host: str) -> str:
    relative = _label(path, home)
    if host == 'claude-code' and relative.startswith('$HOME/.local/share/claude/versions/'):
        return 'CLAUDE_VERSIONED_HOME_LAYOUT_NOT_PROVENANCE'
    if host == 'codex-cli' and relative.startswith('$HOME/.codex/packages/standalone/'):
        return 'CODEX_STANDALONE_HOME_LAYOUT_NOT_PROVENANCE'
    return 'UNCLASSIFIED_LAYOUT_NO_PROVENANCE'


def provenance_hints(host: str, *, search_path: str | None = None,
                     home: str | None = None) -> dict[str, Any]:
    if type(host) is not str or host not in HOST_COMMANDS:
        raise ProvenanceHintError('host refused')
    if search_path is not None and type(search_path) is not str:
        raise ProvenanceHintError('search path refused')
    home = os.path.abspath(os.path.expanduser('~')) if home is None else home
    if type(home) is not str or not os.path.isabs(home):
        raise ProvenanceHintError('home label refused')
    out: dict[str, Any] = {
        'schema_version': '0.1', 'surface': 'P4_P1_P1_P3_P3_STATIC_LAYOUT_AND_NEEDED_NAMES',
        'host_label_only': host, 'command_name': HOST_COMMANDS[host],
        'state': 'UNRESOLVED_NO_EXECUTION',
        'max_executable_bytes_read': MAX_EXECUTABLE_BYTES_READ,
        'full_executable_hash_verified': False, 'dependency_resolution_verified': False,
        'transitive_dependency_tree_verified': False, 'package_provenance_verified': False,
        'native_host_started': False, 'hook_dispatched': False, 'model_called': False,
        'credentials_accessed': False, 'host_settings_modified': False,
        'network_traffic_sent': False, 'native_launch_authorized': False,
        'safe_to_activate_hooks': False, 'promotion_authorized': False,
        'tool_grants': [],
    }
    first = shutil.which(HOST_COMMANDS[host], path=search_path)
    if first is None:
        return out
    try:
        resolved, chain = _resolve(first)
        if _label(resolved, home) == 'OUTSIDE_HOME_REDACTED':
            raise ProvenanceHintError('OUTSIDE_HOME_REFUSED')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(resolved, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
                raise ProvenanceHintError('NOT_REGULAR_NONEMPTY_FILE')
            if not (before.st_mode & 0o111) or before.st_mode & 0o002:
                raise ProvenanceHintError('UNSAFE_EXECUTABLE_MODE')
            usage = [0]
            hint = _elf_needed(fd, before.st_size, usage)
            after = os.fstat(fd)
            current = os.stat(resolved, follow_symlinks=False)
            def seal(info: os.stat_result) -> tuple[int, ...]:
                return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
                        info.st_uid, info.st_gid, info.st_mtime_ns, info.st_ctime_ns)
            if seal(before) != seal(after) or seal(after) != seal(current):
                raise ProvenanceHintError('IDENTITY_CHANGED_DURING_READ')
        finally:
            os.close(fd)
        ancestors = _ancestor_metadata(resolved, home)
    except ProvenanceHintError as error:
        out['state'] = 'BLOCKED_STATIC_EVIDENCE_NOT_PROVEN'
        out['refusal_category'] = (str(error) if str(error) in {
            'SYMLINK_CYCLE', 'SYMLINK_LIMIT', 'EMPTY_SYMLINK', 'OUTSIDE_HOME_REFUSED',
            'NOT_REGULAR_NONEMPTY_FILE', 'UNSAFE_EXECUTABLE_MODE',
            'IDENTITY_CHANGED_DURING_READ', 'BOUNDED_ELF_READ_REFUSED',
            'BOUNDED_ELF_READ_INCOMPLETE'} else 'STATIC_VALIDATION_REFUSED')
        return out
    except OSError:
        out['state'] = 'BLOCKED_STATIC_EVIDENCE_NOT_PROVEN'
        out['refusal_category'] = 'FILESYSTEM_METADATA_UNAVAILABLE'
        return out
    out.update({
        'state': 'PASSIVE_STATIC_HINTS_NOT_ATTESTATION',
        'path_from_PATH': _label(first, home),
        'resolved_executable_path': _label(resolved, home),
        'symlink_chain': [
            {'at': _label(item['at'], home),
             'target': (_label(item['target'], home) if os.path.isabs(item['target'])
                        else item['target'][:100])}
            for item in chain[:MAX_SYMLINKS]],
        'installation_layout_hint': _layout_hint(resolved, home, host),
        'ancestor_directory_metadata': ancestors,
        'intermediate_directory_symlink_observed': any(x['is_symlink'] for x in ancestors),
        'intermediate_symlink_target_stability_verified': False,
        'effective_directory_write_access_verified': False,
        'installation_path_integrity_verified': False,
        'static_elf_dependency_name_hints': hint,
        'executable_bytes_read': usage[0],
        'file_size_bytes': before.st_size,
    })
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Static, bounded provenance hints only; no host execution')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'HINTS_ONLY':
            raise ProvenanceHintError('native mode denied')
        record = provenance_hints(args.host)
    except ProvenanceHintError:
        print('Passive host hints refused; no native host started', file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
