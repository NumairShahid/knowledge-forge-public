"""P4-P1-P1-P3-P1: passive, bounded executable identity inventory.

Never invokes Claude, Codex, a package manager, ldd, readelf, a model, or a hook.
Searches one PATH candidate per host and reads only that candidate's symlink
chain and resolved executable bytes. Provides hints, not dependency attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
from typing import Any, Sequence

HOST_COMMANDS = {'claude-code': 'claude', 'codex-cli': 'codex'}
MAX_LINKS = 16
MAX_BYTES = 256 * 1024 * 1024
CHUNK = 1 * 1024 * 1024


class NativeExecutableInventoryError(ValueError):
    """Inventory input or a candidate violates a bounded passive-read rule."""


def _display(path: str, home: str) -> str:
    """Show paths useful to operator without printing the username/home root."""
    root = os.path.normpath(home)
    normalized = os.path.normpath(path)
    if normalized == root:
        return '$HOME'
    if normalized.startswith(root + os.sep):
        return '$HOME/' + normalized[len(root) + 1:]
    return normalized


def _links(start: str) -> tuple[str, list[dict[str, str]]]:
    """Follow only the executable's symlinks; no directory/package tree walk."""
    current = os.path.abspath(start)
    seen: set[str] = set()
    chain: list[dict[str, str]] = []
    for _ in range(MAX_LINKS + 1):
        if current in seen:
            raise NativeExecutableInventoryError('symlink cycle')
        seen.add(current)
        mode = os.lstat(current).st_mode
        if not stat.S_ISLNK(mode):
            return current, chain
        if len(chain) == MAX_LINKS:
            raise NativeExecutableInventoryError('symlink depth limit')
        target = os.readlink(current)
        if not target:
            raise NativeExecutableInventoryError('empty symlink')
        chain.append({'at': current, 'target': target})
        current = os.path.normpath(target if os.path.isabs(target)
                                   else os.path.join(os.path.dirname(current), target))
    raise NativeExecutableInventoryError('symlink limit')


def _interpreter_hint(head: bytes, fd: int, file_size: int) -> dict[str, str]:
    """Parse a short shebang or bounded ELF PT_INTERP field only, never exec it."""
    if head.startswith(b'#!'):
        # The raw shebang could contain paths or arguments; never report it.
        first = head.split(b'\n', 1)[0][2:256].strip().split(b' ', 1)[0]
        name = first.rsplit(b'/', 1)[-1].decode('ascii', 'ignore')
        return {'kind': 'SCRIPT', 'interpreter_basename_hint': name[:64] or 'UNKNOWN',
                'dependency_tree_verified': 'false'}
    if not head.startswith(b'\x7fELF') or len(head) < 64:
        return {'kind': 'OTHER_OR_UNKNOWN', 'dependency_tree_verified': 'false'}
    answer = {'kind': 'ELF', 'dependency_tree_verified': 'false'}
    klass, endian = head[4], head[5]
    if klass not in (1, 2) or endian not in (1, 2):
        return answer
    order = '<' if endian == 1 else '>'
    try:
        if klass == 2:
            offset, = struct.unpack_from(order + 'Q', head, 32)
            step, count = struct.unpack_from(order + 'HH', head, 54)
            offset_location, size_location, min_header = 8, 32, 56
        else:
            offset, = struct.unpack_from(order + 'I', head, 28)
            step, count = struct.unpack_from(order + 'HH', head, 42)
            offset_location, size_location, min_header = 4, 16, 32
        if count == 0 or count > 128 or step < min_header or step > 256:
            return answer
        if offset > file_size or count * step > file_size - offset:
            return answer
        for index in range(count):
            os.lseek(fd, offset + index * step, os.SEEK_SET)
            header = os.read(fd, step)
            if len(header) != step:
                return answer
            type_, = struct.unpack_from(order + 'I', header)
            if type_ != 3:  # PT_INTERP
                continue
            code = 'Q' if klass == 2 else 'I'
            where, = struct.unpack_from(order + code, header, offset_location)
            length, = struct.unpack_from(order + code, header, size_location)
            if length < 2 or length > 255 or where > file_size or length > file_size - where:
                return answer
            os.lseek(fd, where, os.SEEK_SET)
            raw = os.read(fd, length)
            if len(raw) != length or not raw.endswith(b'\0'):
                return answer
            interp = raw[:-1].decode('ascii', 'ignore')
            if interp.startswith('/') and '\n' not in interp:
                answer['elf_pt_interp_path_hint'] = interp
            return answer
    except (OSError, struct.error, ValueError):
        return answer
    return answer


def _bounded_digest(filename: str, *, max_bytes: int) -> dict[str, Any]:
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
        raise NativeExecutableInventoryError('digest limit refused')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(filename, flags)
    try:
        start = os.fstat(fd)
        if not stat.S_ISREG(start.st_mode) or start.st_size <= 0 or start.st_size > max_bytes:
            raise NativeExecutableInventoryError('candidate not a bounded regular file')
        if not (start.st_mode & 0o111):
            raise NativeExecutableInventoryError('candidate not executable')
        h = hashlib.sha256()
        head = b''
        read = 0
        while True:
            buf = os.read(fd, min(CHUNK, max_bytes + 1 - read))
            if not buf:
                break
            read += len(buf)
            if read > max_bytes:
                raise NativeExecutableInventoryError('file grew beyond limit')
            if len(head) < 512:
                head += buf[:512-len(head)]
            h.update(buf)
        end = os.fstat(fd)
        statnow = os.stat(filename, follow_symlinks=False)
        seal = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode)
        if seal(start) != seal(end) or seal(end) != seal(statnow) or read != end.st_size:
            raise NativeExecutableInventoryError('candidate identity changed during read')
        hint = _interpreter_hint(head, fd, end.st_size)
        return {'sha256': h.hexdigest(), 'bytes': read, 'uid': end.st_uid,
                'mode_octal': format(stat.S_IMODE(end.st_mode), '04o'),
                'world_writable': bool(end.st_mode & stat.S_IWOTH),
                'runtime_dependency_hint': hint}
    finally:
        os.close(fd)


def inventory(host: str, *, search_path: str | None = None,
              home: str | None = None, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """Read at most one PATH-resolved candidate. Never launch native host."""
    if type(host) is not str or host not in HOST_COMMANDS:
        raise NativeExecutableInventoryError('unknown host')
    if search_path is not None and type(search_path) is not str:
        raise NativeExecutableInventoryError('PATH type refused')
    home = os.path.abspath(os.path.expanduser('~')) if home is None else home
    if type(home) is not str or not os.path.isabs(home):
        raise NativeExecutableInventoryError('HOME scope refused')
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
        raise NativeExecutableInventoryError('digest limit refused')
    result: dict[str, Any] = {
        'schema_version': '0.1',
        'surface': 'P4_P1_P1_P3_P1_PASSIVE_NATIVE_EXECUTABLE_INVENTORY',
        'host_label_only': host, 'command_name': HOST_COMMANDS[host],
        'state': 'UNRESOLVED_NO_EXECUTION',
        'candidate_fingerprint_immutable_after_inventory': False,
        'runtime_dependency_tree_verified': False,
        'native_host_version_verified': False,
        'native_host_sessions_started': False,
        'native_dispatch_verified': False,
        'hooks_installed': False,
        'host_configuration_modified': False,
        'model_called': False,
        'credentials_requested': False,
        'safe_to_activate_hooks': False,
        'native_launch_authorized': False,
        'promotion_authorized': False,
        'tool_grants': [],
    }
    candidate = shutil.which(HOST_COMMANDS[host], path=search_path)
    if candidate is None:
        return result
    try:
        resolved, chain = _links(candidate)
        identity = _bounded_digest(resolved, max_bytes=max_bytes)
    except (OSError, NativeExecutableInventoryError):
        result['state'] = 'BLOCKED_CANDIDATE_NOT_PROVEN'
        return result
    result['state'] = 'PASSIVE_FILE_IDENTITY_ONLY'
    result['path_from_PATH'] = _display(candidate, home)
    result['resolved_executable_path'] = _display(resolved, home)
    result['symlink_chain'] = [{'at': _display(x['at'], home),
                                'target': _display(x['target'], home) if x['target'].startswith('/') else x['target']}
                               for x in chain]
    result['executable_file_identity'] = identity
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Passive executable inventory only; never starts native hosts')
    parser.add_argument('--host', required=True)
    parser.add_argument('--mode', required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode != 'INVENTORY_ONLY':
            raise NativeExecutableInventoryError('execution mode forbidden')
        result = inventory(args.host)
    except NativeExecutableInventoryError:
        print('Native executable inventory refused; host not launched', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
