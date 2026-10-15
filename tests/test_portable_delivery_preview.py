"""P3D-P3-P0: bounded knowledge DATA preview, with no automatic model injection."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import subprocess
import sys
import unittest

from knowledge_forge.portable_delivery_preview import (
    CONTEXT_FIELDS, MAX_TOTAL_JSON_BYTES, MAX_UNIT_CHARS,
    PortableDeliveryError, preview, main, _result, _serialize_stdout,
)
from knowledge_forge.registry import create_skill_registry
from tests.test_temporal_integration import _temporal_package

AS_OF = "2026-09-24T20:00:00Z"
QUESTION = "What approval quorum is required?"


class PortableDeliveryTests(unittest.TestCase):
    def _fixture(self, folder, *, validity=None):
        return _temporal_package(Path(folder), validity or {})

    def _preview(self, folder, *, host="claude-code", question=QUESTION,
                 validity=None, clock=AS_OF, registry_override=None,
                 source_reverification=None, tools=(), max_units=1):
        package, registry, manifest, source = self._fixture(folder, validity=validity)
        result = preview(
            mode="PREVIEW", host=host, question=question, world_as_of=clock,
            registry_supplier=lambda: registry if registry_override is None else registry_override,
            package_resolver=lambda _s, _v: str(package),
            runtime_tools=tools, max_units=max_units,
            source_reverification=source_reverification,
        )
        return result, package, registry, manifest, source

    def test_off_zero_callbacks_and_zero_knowledge(self):
        def forbidden(*_):
            raise AssertionError("OFF called a supplier")
        for host in ("claude-code", "codex-cli"):
            result = preview(mode="OFF", host=host, registry_supplier=forbidden, package_resolver=forbidden)
            self.assertEqual(result["knowledge_items"], [])
            self.assertEqual(result["state"], "NO_FORGE_CALLS")
            self.assertFalse(result["automatic_consumption_active"])
            self.assertFalse(result["model_context_injected"])

    def test_real_promoted_knowledge_delivered_as_inert_data_both_hosts(self):
        for host in ("claude-code", "codex-cli"):
            with self.subTest(host=host), TemporaryDirectory() as folder:
                result, *_ = self._preview(folder, host=host)
                self.assertEqual(result["knowledge_item_count"], 1)
                unit = result["knowledge_items"][0]
                self.assertEqual(set(unit), CONTEXT_FIELDS)
                self.assertIn("exactly 7 members", unit["content"])
                self.assertTrue(unit["source_bindings"])
                self.assertEqual(unit["trust_class"], "UNTRUSTED_KNOWLEDGE_DATA")
                self.assertFalse(unit["executable"])
                self.assertEqual(unit["instruction_authority"], "NONE")
                self.assertEqual(unit["execution_authority"], "NONE")
                self.assertEqual(unit["temporal_condition"], "CURRENT")
                self.assertFalse(result["registry_trust_attested"])
                self.assertFalse(result["trusted_clock_verified"])
                self.assertEqual(result["tool_grants"], [])
                self.assertFalse(result["model_context_injected"])
                self.assertFalse(result["promotion_authorized"])
                self.assertLessEqual(len(json.dumps(result).encode()), MAX_TOTAL_JSON_BYTES)

    def test_source_not_reverified_is_explicit(self):
        with TemporaryDirectory() as folder:
            r, *_ = self._preview(folder)
            self.assertIs(r["source_reverification_complete"], False)
            self.assertEqual(r["knowledge_items"][0]["source_reverification"][0]["status"], "NOT_REVERIFIED")

    def test_changed_source_refused(self):
        with TemporaryDirectory() as folder:
            package, registry, manifest, source = self._fixture(folder)
            with self.assertRaises(PortableDeliveryError):
                preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                        registry_supplier=lambda: registry, package_resolver=lambda *_: str(package),
                        source_reverification={source:{"status":"CHANGED", "checked_at":AS_OF, "evidence_ref":"test"}})

    def test_unavailable_source_refused(self):
        with TemporaryDirectory() as folder:
            package, registry, manifest, source = self._fixture(folder)
            with self.assertRaises(PortableDeliveryError):
                preview(mode="PREVIEW", host="codex-cli", question=QUESTION, world_as_of=AS_OF,
                        registry_supplier=lambda: registry, package_resolver=lambda *_: str(package),
                        source_reverification={source:{"status":"UNAVAILABLE", "checked_at":AS_OF, "evidence_ref":"test"}})

    def test_tampered_package_refused(self):
        with TemporaryDirectory() as folder:
            package, registry, _, _ = self._fixture(folder)
            (package / "manifest.json").write_text('{"tampered": true}')
            with self.assertRaises(PortableDeliveryError):
                preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                        registry_supplier=lambda: registry, package_resolver=lambda *_: str(package))

    def test_unpromoted_registry_refused(self):
        with TemporaryDirectory() as folder, self.assertRaises(PortableDeliveryError):
            self._preview(folder, registry_override=create_skill_registry(created_at="t0"))

    def test_expired_claim_refused(self):
        with TemporaryDirectory() as folder, self.assertRaises(PortableDeliveryError):
            self._preview(folder, clock="2030-01-01T00:00:00Z", validity={"valid_until":"2026-09-24T21:00:00Z"})

    def test_bad_clock_refused(self):
        for value in (None, "2026-09-24", "2026-09-24T20:00:00"):
            with self.subTest(value=value), TemporaryDirectory() as folder, self.assertRaises((PortableDeliveryError, ValueError)):
                self._preview(folder, clock=value)

    def test_oversize_unit_refused_without_truncating(self):
        with TemporaryDirectory() as folder:
            package, registry, *_ = self._fixture(folder)
            # Test output cap without tampering package: patch constant for a tiny valid unit limit.
            from unittest.mock import patch
            with patch("knowledge_forge.portable_delivery_preview.MAX_UNIT_CHARS", 8):
                with self.assertRaises(PortableDeliveryError):
                    preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                            registry_supplier=lambda: registry, package_resolver=lambda *_: str(package))

    def test_total_byte_cap_refused(self):
        with TemporaryDirectory() as folder:
            package, registry, *_ = self._fixture(folder)
            from unittest.mock import patch
            with patch("knowledge_forge.portable_delivery_preview.MAX_TOTAL_JSON_BYTES", 200):
                with self.assertRaises(PortableDeliveryError):
                    preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                            registry_supplier=lambda: registry, package_resolver=lambda *_: str(package))

    def test_tool_grants_never_widen(self):
        with TemporaryDirectory() as folder:
            r, *_ = self._preview(folder, tools=("quote_only",))
            self.assertEqual(r["tool_grants"], [])
            self.assertNotIn("quote_only", json.dumps(r))

    def test_invalid_tool_names_refused(self):
        for value in ("shell", [""], [4], ["a"] * 33):
            with self.subTest(value=value), self.assertRaises(PortableDeliveryError):
                preview(mode="PREVIEW", host="codex-cli", question=QUESTION, world_as_of=AS_OF,
                        registry_supplier=lambda: None, package_resolver=lambda *_: "/tmp", runtime_tools=value)

    def test_on_mode_refused(self):
        for host in ("claude-code", "codex-cli"):
            with self.subTest(host=host), self.assertRaises(PortableDeliveryError):
                preview(mode="ON", host=host)

    def test_bad_host_refused(self):
        with self.assertRaises(PortableDeliveryError):
            preview(mode="OFF", host="agent0")

    def test_empty_question_refused(self):
        with self.assertRaises(PortableDeliveryError):
            preview(mode="PREVIEW", host="codex-cli", question="", world_as_of=AS_OF)

    def test_invalid_max_units_refused(self):
        for value in (0, 4, True, 1.5):
            with self.subTest(value=value), self.assertRaises(PortableDeliveryError):
                preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                        max_units=value)

    def test_callback_failure_redacts_sensitive_data(self):
        with self.assertRaises(PortableDeliveryError) as ctx:
            preview(mode="PREVIEW", host="claude-code", question=QUESTION, world_as_of=AS_OF,
                    registry_supplier=lambda: (_ for _ in ()).throw(RuntimeError("secret source content")),
                    package_resolver=lambda *_: "/tmp")
        self.assertNotIn("secret source content", str(ctx.exception))

    def test_cli_off_does_not_access_missing_paths(self):
        run = subprocess.run([sys.executable, "-m", "knowledge_forge.portable_delivery_preview",
            "--mode", "OFF", "--host", "claude-code", "--registry", "/absent"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["knowledge_items"], [])

    def test_cli_on_is_blocked(self):
        run = subprocess.run([sys.executable, "-m", "knowledge_forge.portable_delivery_preview",
            "--mode", "ON", "--host", "codex-cli"], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertIn("BLOCKED", run.stderr)

    def test_cli_preview_missing_inputs_refused(self):
        run = subprocess.run([sys.executable, "-m", "knowledge_forge.portable_delivery_preview",
            "--mode", "PREVIEW", "--host", "claude-code", "--question", QUESTION],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertIn("delivery preview refused", run.stderr)


    def test_wire_serializer_canonical_utf8_and_final_lf(self):
        payload = {"message": "frogs 🐸", "nested": {"tag": "café"}}
        actual = _serialize_stdout(payload)
        expected = (json.dumps(payload, sort_keys=True, indent=2,
                               ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        self.assertEqual(actual, expected)
        self.assertTrue(actual.endswith(b"\n"))
        self.assertGreater(len(actual), len(actual.decode("utf-8")))

    def test_preview_refuses_if_compact_json_fits_but_actual_wire_does_not(self):
        from unittest.mock import patch
        with TemporaryDirectory() as folder:
            package, registry, *_ = self._fixture(folder)
            kwargs = dict(mode="PREVIEW", host="claude-code", question=QUESTION,
                          world_as_of=AS_OF, registry_supplier=lambda: registry,
                          package_resolver=lambda *_: str(package))
            actual = preview(**kwargs)
            compact = len(json.dumps(actual, ensure_ascii=False,
                                     sort_keys=True, allow_nan=False).encode("utf-8"))
            wire = len(_serialize_stdout(actual))
            self.assertGreater(wire, compact)
            with patch("knowledge_forge.portable_delivery_preview.MAX_TOTAL_JSON_BYTES", compact):
                with self.assertRaises(PortableDeliveryError):
                    preview(**kwargs)

    def test_cli_actual_bytes_bound_and_unicode_for_both_hosts(self):
        from unittest.mock import patch
        from io import BytesIO, StringIO
        from contextlib import redirect_stderr
        class StdoutBytes:
            def __init__(self):
                self.buffer = BytesIO()
        for host in ("claude-code", "codex-cli"):
            with self.subTest(host=host):
                payload = _result(host, "PREVIEW", "UNTRUSTED_DATA_PREVIEW_ONLY",
                                  "question 🐸", [{"content": "evidence 🐸"}])
                output = StdoutBytes()
                with patch("knowledge_forge.portable_delivery_preview.preview", return_value=payload):
                    with patch.object(sys, "stdout", output), redirect_stderr(StringIO()):
                        code = main(["--mode", "OFF", "--host", host])
                self.assertEqual(code, 0)
                self.assertEqual(output.buffer.getvalue(), _serialize_stdout(payload))
                self.assertLessEqual(len(output.buffer.getvalue()), MAX_TOTAL_JSON_BYTES)
                self.assertEqual(json.loads(output.buffer.getvalue())["tool_grants"], [])

    def test_compact_pass_pretty_oversize_refuses_atomically(self):
        from unittest.mock import patch
        from io import BytesIO, StringIO
        from contextlib import redirect_stderr
        class StdoutBytes:
            def __init__(self):
                self.buffer = BytesIO()
        item = {"content": "PRIVATE KNOWLEDGE MUST NOT LEAK 🐸",
                "source_bindings": [{"source_id": str(i), "status": "OK"}
                                    for i in range(550)]}
        payload = _result("claude-code", "PREVIEW", "UNTRUSTED_DATA_PREVIEW_ONLY",
                          QUESTION, [item])
        compact = len(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                 allow_nan=False).encode("utf-8"))
        wire = len(_serialize_stdout(payload))
        self.assertLessEqual(compact, MAX_TOTAL_JSON_BYTES)
        self.assertGreater(wire, MAX_TOTAL_JSON_BYTES)
        out = StdoutBytes()
        err = StringIO()
        with patch("knowledge_forge.portable_delivery_preview.preview", return_value=payload):
            with patch.object(sys, "stdout", out), redirect_stderr(err):
                code = main(["--mode", "OFF", "--host", "claude-code"])
        self.assertEqual(code, 2)
        self.assertEqual(out.buffer.getvalue(), b"")
        self.assertIn("BLOCKED", err.getvalue())
        self.assertNotIn("PRIVATE KNOWLEDGE", err.getvalue())

    def test_no_partial_bytes_on_exact_cap_boundary(self):
        from unittest.mock import patch
        from io import BytesIO, StringIO
        from contextlib import redirect_stderr
        class StdoutBytes:
            def __init__(self):
                self.buffer = BytesIO()
        payload = _result("codex-cli", "OFF", "NO_FORGE_CALLS", None, [])
        wire = _serialize_stdout(payload)
        with patch("knowledge_forge.portable_delivery_preview.preview", return_value=payload):
            output = StdoutBytes()
            with patch("knowledge_forge.portable_delivery_preview.MAX_TOTAL_JSON_BYTES", len(wire)):
                with patch.object(sys, "stdout", output), redirect_stderr(StringIO()):
                    self.assertEqual(main(["--host", "codex-cli", "--mode", "OFF"]), 0)
            self.assertEqual(output.buffer.getvalue(), wire)
            output = StdoutBytes()
            err = StringIO()
            with patch("knowledge_forge.portable_delivery_preview.MAX_TOTAL_JSON_BYTES", len(wire) - 1):
                with patch.object(sys, "stdout", output), redirect_stderr(err):
                    self.assertEqual(main(["--host", "codex-cli", "--mode", "OFF"]), 2)
            self.assertEqual(output.buffer.getvalue(), b"")
            self.assertIn("BLOCKED", err.getvalue())



if __name__ == "__main__":
    unittest.main()
