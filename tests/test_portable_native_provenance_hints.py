"""P4-P1-P1-P3-P3: bounded DT_NEEDED and layout evidence, no host launch."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from knowledge_forge.portable_native_provenance_hints import (
    MAX_EXECUTABLE_BYTES_READ, ProvenanceHintError, _elf_needed,
    _label, provenance_hints, main,
)


class ProvenanceHintTests(unittest.TestCase):
    @staticmethod
    def _file(root: Path, name: str, data: bytes = b'not-elf') -> Path:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(0o700)
        return p

    @staticmethod
    def _synthetic_elf() -> bytes:
        b = bytearray(1024)
        b[:4] = b'\x7fELF'
        b[4] = 2   # ELF64
        b[5] = 1   # little endian
        struct.pack_into('<Q', b, 32, 64)
        struct.pack_into('<HH', b, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', b, 64, 1, 5, 0, 0x400000, 0, len(b), len(b), 0x1000)
        struct.pack_into('<IIQQQQQQ', b, 120, 2, 4, 0x200, 0x400200, 0, 80, 80, 8)
        string_table = b'\x00libc.so.6\x00libm.so.6\x00'
        for offset, (tag, value) in enumerate([(5, 0x400300), (10, len(string_table)),
                                               (1, 1), (1, 11), (0, 0)]):
            struct.pack_into('<QQ', b, 0x200 + offset * 16, tag, value)
        b[0x300:0x300 + len(string_table)] = string_table
        return bytes(b)

    def test_synthetic_elf_needed_names_not_resolution(self):
        with TemporaryDirectory() as folder:
            self._file(Path(folder), 'codex', self._synthetic_elf())
            result = provenance_hints('codex-cli', search_path=folder, home=folder)
        self.assertEqual(result['state'], 'PASSIVE_STATIC_HINTS_NOT_ATTESTATION')
        self.assertEqual(result['static_elf_dependency_name_hints']['needed_name_hints'],
                         ['libc.so.6', 'libm.so.6'])
        self.assertEqual(result['static_elf_dependency_name_hints']['status'],
                         'DT_NEEDED_NAMES_OBSERVED_NOT_RESOLVED')
        self.assertLessEqual(result['executable_bytes_read'], MAX_EXECUTABLE_BYTES_READ)
        self.assertFalse(result['dependency_resolution_verified'])
        self.assertFalse(result['package_provenance_verified'])
        self.assertFalse(result['native_launch_authorized'])

    def test_oversized_file_is_never_fully_read(self):
        with TemporaryDirectory() as folder:
            p = self._file(Path(folder), 'codex', self._synthetic_elf())
            with p.open('r+b') as stream:
                stream.truncate(292_309_256)
            with patch('knowledge_forge.portable_native_provenance_hints.os.pread', wraps=os.pread) as calls:
                got = provenance_hints('codex-cli', search_path=folder, home=folder)
        self.assertEqual(got['state'], 'PASSIVE_STATIC_HINTS_NOT_ATTESTATION')
        self.assertEqual(got['file_size_bytes'], 292_309_256)
        self.assertLessEqual(sum(c.args[1] for c in calls.call_args_list), MAX_EXECUTABLE_BYTES_READ)
        self.assertFalse(got['full_executable_hash_verified'])

    def test_no_dynamic_segment_never_implies_static_binary(self):
        with TemporaryDirectory() as folder:
            p = self._file(Path(folder), 'claude', b'\x7fELF' + bytes(60))
            got = provenance_hints('claude-code', search_path=folder, home=folder)
        self.assertIn(got['static_elf_dependency_name_hints']['status'],
                      {'PROGRAM_HEADER_BOUND_REFUSED', 'NO_ELF_DEPENDENCY_HINT', 'UNSUPPORTED_ELF_HEADER'})
        self.assertFalse(got['transitive_dependency_tree_verified'])

    def test_installation_layout_and_parent_metadata_only(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            real = self._file(root, '.codex/packages/standalone/current/bin/codex')
            entry = root / 'codex'
            entry.symlink_to(real)
            got = provenance_hints('codex-cli', search_path=folder, home=folder)
            self.assertEqual(got['installation_layout_hint'], 'CODEX_STANDALONE_HOME_LAYOUT_NOT_PROVENANCE')
            self.assertEqual(got['resolved_executable_path'], '$HOME/.codex/packages/standalone/current/bin/codex')
            self.assertTrue(got['ancestor_directory_metadata'])
            self.assertEqual(got['ancestor_directory_metadata'][-1]['directory_label'], '$HOME')
            self.assertTrue(all('owner_uid' in x for x in got['ancestor_directory_metadata']))
            self.assertTrue(entry.is_symlink())

    def test_missing_and_unsafe_candidate_are_nonexecution(self):
        with TemporaryDirectory() as folder:
            self.assertEqual(provenance_hints('claude-code', search_path=folder)['state'],
                             'UNRESOLVED_NO_EXECUTION')
            p = self._file(Path(folder), 'codex')
            p.chmod(0o707)
            got = provenance_hints('codex-cli', search_path=folder, home=folder)
            self.assertEqual(got['state'], 'BLOCKED_STATIC_EVIDENCE_NOT_PROVEN')
            self.assertEqual(got['refusal_category'], 'UNSAFE_EXECUTABLE_MODE')
            self.assertNotIn('resolved_executable_path', got)
            self.assertFalse(got['native_host_started'])

    def test_malformed_elf_bounds_refuse_without_execution(self):
        blob = bytearray(self._synthetic_elf())
        struct.pack_into('<Q', blob, 32, 10**9)
        with TemporaryDirectory() as folder:
            self._file(Path(folder), 'codex', bytes(blob))
            got = provenance_hints('codex-cli', search_path=folder, home=folder)
        self.assertEqual(got['static_elf_dependency_name_hints']['status'],
                         'PROGRAM_HEADER_OUT_OF_FILE')
        self.assertFalse(got['dependency_resolution_verified'])

    def test_credentials_and_settings_not_read(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            self._file(root, 'codex')
            (root / 'credentials.json').write_text('PRIVATE_CANARY_SECRET', encoding='utf-8')
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                got = provenance_hints('codex-cli', search_path=folder, home=folder)
            self.assertNotIn('PRIVATE_CANARY_SECRET', json.dumps(got))
            self.assertEqual((root / 'credentials.json').read_text(encoding='utf-8'),
                             'PRIVATE_CANARY_SECRET')

    def test_file_change_fail_closed_no_paths(self):
        with TemporaryDirectory() as folder:
            self._file(Path(folder), 'codex')
            with patch('knowledge_forge.portable_native_provenance_hints._elf_needed',
                       side_effect=ProvenanceHintError('IDENTITY_CHANGED_DURING_READ')):
                got = provenance_hints('codex-cli', search_path=folder, home=folder)
            self.assertEqual(got['refusal_category'], 'IDENTITY_CHANGED_DURING_READ')
            self.assertNotIn(folder, json.dumps(got))

    def test_no_spawning_even_when_main_called(self):
        with patch('subprocess.run', side_effect=AssertionError('spawn')):
            with patch('builtins.print') as out:
                self.assertEqual(main(['--host', 'codex-cli', '--mode', 'HINTS_ONLY']), 0)
        j = json.loads(out.call_args.args[0])
        self.assertFalse(j['native_launch_authorized'])
        self.assertFalse(j['host_settings_modified'])

    def test_unknown_or_live_modes_refuse_silently(self):
        for host, mode in [('claude-code', 'ON'), ('codex-cli', 'NATIVE_TEST'),
                           ('unknown', 'HINTS_ONLY')]:
            result = subprocess.run([sys.executable, '-m',
                'knowledge_forge.portable_native_provenance_hints', '--host', host,
                '--mode', mode], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')

    def test_invalid_arguments_and_redaction(self):
        for host in ('', None, True, 'codex --version'):
            with self.assertRaises(ProvenanceHintError):
                provenance_hints(host)
        with self.assertRaises(ProvenanceHintError):
            provenance_hints('codex-cli', search_path=[])
        self.assertEqual(_label('/home/tommy2/secrets', '/home/tommy'), 'OUTSIDE_HOME_REDACTED')
        self.assertEqual(_label('/home/tommy/bin/a', '/home/tommy'), '$HOME/bin/a')


if __name__ == '__main__':
    unittest.main()
