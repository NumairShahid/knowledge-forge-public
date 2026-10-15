"""P3D-P4-P1-P0: passive native version inventory and synthetic hook boundary replay.

NEVER installs hooks or calls a model; cannot independently attest to native
UserPromptSubmit dispatch. Exit-2 blocking semantics are documented assumptions,
not observations from a running host. This module is NOT a hook command.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Any, Sequence

_HOSTS = {"claude-code": "claude", "codex-cli": "codex"}
_VERSION = re.compile(r"\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?\b")
_MAX_VERSION_OUTPUT = 4096


class NativeHostProbeError(ValueError):
    """Fail closed without exposing prompts, paths, or host config."""


def native_version(host: str, *, binary: str | None = None) -> dict[str, Any]:
    """Invoke --version only, under an allowlisted environment and temporary dirs.

    Does not establish that lifecycle hooks are supported or dispatched. A
    binary may ignore isolation environment variables: no host sessions run.
    """
    if host not in _HOSTS:
        raise NativeHostProbeError("unknown host")
    candidate = binary if binary is not None else shutil.which(_HOSTS[host])
    if not isinstance(candidate, str) or not candidate:
        raise NativeHostProbeError("host CLI unavailable")
    command = Path(candidate)
    if not command.is_absolute() or not command.is_file():
        raise NativeHostProbeError("host executable path refused")
    with TemporaryDirectory(prefix="kf-native-version-") as scratch:
        import os
        # Construct an ALLOWLIST, never copy the caller's credential-bearing
        # process environment. PATH is retained only for shebang runtimes such
        # as /usr/bin/env node; it is not a filesystem or process sandbox.
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": scratch,
            "XDG_CONFIG_HOME": str(Path(scratch) / "config"),
            "XDG_DATA_HOME": str(Path(scratch) / "data"),
            "XDG_CACHE_HOME": str(Path(scratch) / "cache"),
            "CODEX_HOME": str(Path(scratch) / "codex"),
            "CLAUDE_CONFIG_DIR": str(Path(scratch) / "claude"),
            "TMPDIR": scratch,
            "CI": "1", "NO_COLOR": "1",
            "LANG": "C.UTF-8",
        }
        try:
            done = subprocess.run(
                [str(command), "--version"], cwd=scratch, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=7, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise NativeHostProbeError("native CLI version probe failed") from None
    if done.returncode != 0 or len(done.stdout) > _MAX_VERSION_OUTPUT or len(done.stderr) > _MAX_VERSION_OUTPUT:
        raise NativeHostProbeError("native CLI version probe refused")
    try:
        output = done.stdout.decode("utf-8")
    except UnicodeError:
        raise NativeHostProbeError("native CLI version encoding refused") from None
    match = _VERSION.search(output)
    if not match:
        raise NativeHostProbeError("native CLI version absent")
    return {
        "host": host,
        "version": match.group(0),
        "probe": "ISOLATED_ENV_VERSION_FLAG_ONLY",
        "native_hook_dispatched": False,
        "native_host_settings_read_verified": False,
        "native_host_settings_write_protection_verified": False,
        "version_is_hook_capability_attestation": False,
    }


def _invoke_bridge(host: str, mode: str, event: bytes) -> tuple[int, bytes, bytes]:
    """Launch our own Python bridge, NEVER claude/codex, with synthetic stdin."""
    if host not in _HOSTS or mode not in {"OFF", "DRY_RUN", "ON"}:
        raise NativeHostProbeError("invalid synthetic test parameters")
    try:
        done = subprocess.run(
            [sys.executable, "-m", "knowledge_forge.portable_hook_bridge",
             "--host", host, "--mode", mode],
            input=event, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise NativeHostProbeError("synthetic bridge subprocess failed") from None
    return done.returncode, done.stdout, done.stderr


def replay_synthetic(host: str) -> dict[str, Any]:
    """Probe inert OFF and two refusal branches with canary input.

    Does not run host CLI or prove how its actual hook dispatcher behaves.
    A failed invariant refuses; it never reports 'hook safe to install'.
    """
    if host not in _HOSTS:
        raise NativeHostProbeError("unknown host")
    canary = b'PRIVATE_SYNTHETIC_PROMPT_CANARY_P4P1'
    event = (b'{"hook_event_name":"UserPromptSubmit","session_id":"fake",'
             b'"turn_id":"fake","prompt":"' + canary + b'"}')
    modes = (("OFF", 0), ("DRY_RUN", 2), ("ON", 2))
    evidence: dict[str, int] = {}
    for mode, expected_rc in modes:
        first = _invoke_bridge(host, mode, event)
        second = _invoke_bridge(host, mode, event)
        if first != second or first[0] != expected_rc or first[1] != b"":
            raise NativeHostProbeError("synthetic bridge contract mismatch")
        if canary in first[2] or len(first[2]) > 512:
            raise NativeHostProbeError("synthetic bridge refusal disclosure")
        if mode == "OFF" and first[2]:
            raise NativeHostProbeError("OFF emits diagnostics")
        evidence[mode] = first[0]
    return {
        "host": host,
        "surface": "SYNTHETIC_BRIDGE_SUBPROCESS_NOT_HOST",
        "two_replays_per_mode": True,
        "off_rc": evidence["OFF"],
        "dry_run_missing_mapping_rc": evidence["DRY_RUN"],
        "on_refusal_rc": evidence["ON"],
        "all_stdout_bytes": 0,
        "exit_2_blocks_user_prompt_if_INSTALLED_as_hook": True,
        "exit_2_meaning_source": "DOCUMENTED_NOT_NATIVE_VERIFIED",
        "safe_to_install_bridge_as_hook": False,
        "model_context_injected": False,
        "automatic_consumption_active": False,
        "operator_invoked": False,
        "promotion_authorized": False,
        "tool_grants": [],
        "native_hook_dispatched": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive native host boundary probe; never installs hooks")
    parser.add_argument("--host", choices=sorted(_HOSTS), required=True)
    parser.add_argument("--version-only", action="store_true")
    parser.add_argument("--synthetic-only", action="store_true")
    args = parser.parse_args(argv)
    if args.version_only and args.synthetic_only:
        parser.error("choose at most one probe type")
    try:
        result = {"schema_version": "0.1", "host": args.host,
                  "safe_to_activate_hooks": False, "native_dispatch_verified": False,
                  "host_configuration_modified": False,
                  "trust_class": "UNTRUSTED_PROBE_EVIDENCE", "authority": "KNOWLEDGE_ONLY",
                  "instruction_authority": "NONE", "execution_authority": "NONE"}
        if not args.synthetic_only:
            result["version"] = native_version(args.host)
        if not args.version_only:
            result["synthetic"] = replay_synthetic(args.host)
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0
    except NativeHostProbeError:
        print("Native host P4-P1 probe refused; no hooks activated", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
