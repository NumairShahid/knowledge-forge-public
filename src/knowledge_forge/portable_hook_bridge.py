"""P3D-P4-P0: inert Claude/Codex UserPromptSubmit host-envelope seam.

Never installed as a live hook. OFF does no input or registry work.
DRY_RUN permits metadata-only P3D-P1 preflight; the CLI never writes stdout.
Host event bytes, registry, mapping, current time and identity are NOT attested.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Mapping, Sequence

from .portable_host_preflight import PortableHostPreflightError, _read_json, probe

HOSTS = frozenset({"claude-code", "codex-cli"})
MODES = frozenset({"OFF", "DRY_RUN"})
MAX_HOOK_INPUT_BYTES = 16_384
MAX_PROMPT_CHARS = 2_000


class PortableHookBridgeError(ValueError):
    """Generic refusal. Never forward host JSON, prompt, paths or diagnostics."""


def _result(host: str, mode: str, state: str, count: int = 0) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "surface": "P3D_P4_UNINSTALLED_HOST_EVENT_DRY_RUN",
        "host": host,
        "mode": mode,
        "state": state,
        "metadata_only_selected_count": count,
        "event_origin_authenticated": False,
        "host_isolation_verified": False,
        "registry_trust_attested": False,
        "human_authenticated": False,
        "knowledge_bodies_loaded": False,
        "source_reverification_complete": False,
        "model_context_injected": False,
        "automatic_consumption_active": False,
        "operator_invoked": False,
        "promotion_authorized": False,
        "registry_mutated": False,
        "authority": "KNOWLEDGE_ONLY",
        "instruction_authority": "NONE",
        "execution_authority": "NONE",
        "tool_grants": [],
    }


def evaluate(
    *, host: str, mode: str, event_bytes: bytes | None = None,
    registry_supplier: Callable[[], Mapping[str, Any]] | None = None,
    package_resolver: Callable[[str, int], str] | None = None,
) -> dict[str, Any]:
    """Offline bridge contract, not a trusted runtime hook or delivery path.

    OFF ignores event bytes and suppliers completely. DRY_RUN inspects only a
    bounded prompt from caller-controlled JSON and delegates to the existing
    metadata-only P3D-P1 probe. All details are discarded from its result.
    """
    if host not in HOSTS or mode not in MODES:
        raise PortableHookBridgeError("unsupported host or mode")
    if mode == "OFF":
        return _result(host, mode, "DISABLED_NO_HOST_IO")
    try:
        if type(event_bytes) is not bytes or not 0 < len(event_bytes) <= MAX_HOOK_INPUT_BYTES:
            raise PortableHookBridgeError("host input size refused")
        event = json.loads(event_bytes.decode("utf-8"))
        if not isinstance(event, dict) or event.get("hook_event_name") != "UserPromptSubmit":
            raise PortableHookBridgeError("host event refused")
        prompt = event.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
            raise PortableHookBridgeError("host prompt refused")
        # Common event fields are advisory labels, never authentication.
        session = event.get("session_id")
        if not isinstance(session, str) or not 1 <= len(session) <= 256:
            raise PortableHookBridgeError("host session label refused")
        if host == "codex-cli":
            turn = event.get("turn_id")
            if not isinstance(turn, str) or not 1 <= len(turn) <= 256:
                raise PortableHookBridgeError("Codex turn label refused")
        routed = probe(
            mode="DRY_RUN", host=host, question=prompt,
            registry_supplier=registry_supplier, package_resolver=package_resolver,
            max_skills=1,
        )
        selected = routed["selected"]
        if (routed.get("mode") != "DRY_RUN" or
                routed.get("model_context_injected") is not False or
                routed.get("knowledge_bodies_loaded") is not False or
                routed.get("tool_grants") != [] or
                not isinstance(selected, list) or len(selected) != 1):
            raise PortableHookBridgeError("metadata ceiling refused")
        return _result(host, mode, "CALLER_SUPPLIED_METADATA_DRY_RUN", len(selected))
    except Exception:
        raise PortableHookBridgeError("host bridge dry run refused") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m knowledge_forge.portable_hook_bridge",
        description="Uninstalled host envelope seam; OFF or DRY_RUN; stdout always empty",
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--registry")
    parser.add_argument("--packages-map")
    args = parser.parse_args(argv)
    try:
        if args.mode == "OFF":
            evaluate(host=args.host, mode="OFF")
            return 0
        if args.mode != "DRY_RUN" or args.host not in HOSTS:
            raise PortableHookBridgeError("host or mode refused")
        if not args.registry or not args.packages_map:
            raise PortableHookBridgeError("DRY_RUN mapping required")

        def resolver(skill_id: str, version: int) -> str:
            mapping = _read_json(args.packages_map)
            if (set(mapping) != {"schema_version", "packages"} or
                    mapping["schema_version"] != "0.1"):
                raise PortableHookBridgeError("invalid mapping")
            packages = mapping.get("packages")
            entry = packages.get(skill_id) if isinstance(packages, dict) else None
            if (not isinstance(entry, dict) or set(entry) != {"version", "path"} or
                    type(entry["version"]) is not int or entry["version"] != version):
                raise PortableHookBridgeError("invalid mapping identity")
            return entry["path"]

        evaluate(
            host=args.host, mode="DRY_RUN",
            event_bytes=sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1),
            registry_supplier=lambda: _read_json(args.registry),
            package_resolver=resolver,
        )
        # Deliberately emit ZERO stdout on success: both hosts can consume
        # hook stdout as injected model context. Never print a routing result.
        return 0
    except (PortableHookBridgeError, PortableHostPreflightError, ValueError):
        print("Knowledge Forge host bridge refused; no context emitted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
