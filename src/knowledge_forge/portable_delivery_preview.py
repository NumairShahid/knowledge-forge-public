"""P3D-P3-P0: bounded untrusted data delivery PREVIEW for Claude and Codex.

Explicit CLI preview only. No automatic hooks, trusted host claim, human approval,
operator access, registry writes, executable instructions, or live ON mode.
Caller controls registry, package mapping, source checks and apparent world time.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import sys
from typing import Any, Callable, Mapping, Sequence

from .consumer_discovery import (
    ConsumerBinding, build_consumer_discovery_catalog, route_consumer_knowledge,
)
from .portable_host_preflight import _local_directory, _read_json
from .portable_verify_only import _utc_time
from .temporal_integration import load_current_skill_context

HOSTS = {
    "claude-code": ("ClaudeCode/cli", "terminal-session"),
    "codex-cli": ("OpenAI/CodexCLI", "terminal-session"),
}
MAX_UNIT_CHARS = 6000
MAX_TOTAL_JSON_BYTES = 32768
MAX_UNITS = 3
# Closed projection: no arbitrary fields from a package may become a host instruction.
CONTEXT_FIELDS = frozenset({
    "trust_class", "authority", "instruction_authority", "execution_authority",
    "executable", "skill_id", "skill_version", "unit_id", "claim_key",
    "kind", "source_bindings", "content", "temporal_condition", "world_as_of",
    "source_reverification",
})


class PortableDeliveryError(ValueError):
    """Refusal without source text, filenames, secrets or exception details."""


def _serialize_stdout(out: dict[str, Any]) -> bytes:
    """Canonical CLI UTF-8 wire bytes, including indentation and final LF."""
    return (json.dumps(
        out, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False,
    ) + "\n").encode("utf-8")


def _result(host: str, mode: str, state: str, question: str | None,
            items: list[dict[str, Any]], *, source_reverification_complete: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "surface": "PORTABLE_UNTRUSTED_KNOWLEDGE_PREVIEW_NOT_AGENT_HOOK",
        "host": host, "mode": mode, "state": state,
        "question_sha256": "sha256:" + sha256(question.encode("utf-8")).hexdigest() if question else None,
        "knowledge_items": items,
        "knowledge_item_count": len(items),
        "source_reverification_complete": source_reverification_complete,
        "verification_scope": "CALLER_SUPPLIED_INPUTS_NOT_HOST_ATTESTED",
        "trust_class": "UNTRUSTED_KNOWLEDGE_DATA",
        "authority": "KNOWLEDGE_ONLY",
        "instruction_authority": "NONE",
        "execution_authority": "NONE",
        "tool_grants": [],
        "model_context_injected": False,
        "automatic_consumption_active": False,
        "human_authenticated": False,
        "host_isolation_verified": False,
        "registry_trust_attested": False,
        "trusted_clock_verified": False,
        "promotion_authorized": False,
        "operator_invoked": False,
        "registry_mutated": False,
    }


def preview(
    *, mode: str, host: str, question: str | None = None,
    registry_supplier: Callable[[], Mapping[str, Any]] | None = None,
    package_resolver: Callable[[str, int], str] | None = None,
    world_as_of: str | None = None,
    runtime_tools: Sequence[str] = (),
    source_reverification: Mapping[str, Any] | None = None,
    max_units: int = 1,
) -> dict[str, Any]:
    """OFF: zero callbacks; PREVIEW: return bounded *untrusted data* explicitly.

    No implicit agent delivery. The caller supplies all inputs and can forge
    their apparent trust; this is not a protected promotion or authenticated host.
    """
    if host not in HOSTS or mode not in {"OFF", "PREVIEW"}:
        raise PortableDeliveryError("host or mode refused: ON is unavailable")
    if mode == "OFF":
        return _result(host, mode, "NO_FORGE_CALLS", None, [])
    if not isinstance(question, str) or not question.strip() or len(question) > 2000:
        raise PortableDeliveryError("PREVIEW requires a bounded question")
    _utc_time(world_as_of)
    if type(max_units) is not int or not 1 <= max_units <= MAX_UNITS:
        raise PortableDeliveryError("max_units outside supported range")
    if not isinstance(runtime_tools, (tuple, list)) or len(runtime_tools) > 32 or any(
        not isinstance(t, str) or not t or len(t) > 128 for t in runtime_tools
    ):
        raise PortableDeliveryError("invalid runtime_tools")
    if not callable(registry_supplier) or not callable(package_resolver):
        raise PortableDeliveryError("registry and package suppliers required")

    try:
        registry = registry_supplier()
        repo, entry = HOSTS[host]
        binding = ConsumerBinding(
            consumer_id=host, runtime_repo=repo, runtime_entrypoint=entry,
            integration_boundary="UNTRUSTED_EXPLICIT_DELIVERY_PREVIEW_NOT_HOOK",
            hard_max_skills_per_query=1,
        )
        selected = route_consumer_knowledge(
            build_consumer_discovery_catalog(registry, binding),
            binding, question, max_skills=1,
        )["selected_skills"]
        if len(selected) != 1:
            raise PortableDeliveryError("unexpected selected skill count")
        selected_id = selected[0]["skill_id"]
        selected_version = selected[0]["skill_version"]
        package_path = package_resolver(selected_id, selected_version)
        _local_directory(package_path)  # Diagnostic only; not filesystem ownership attestation.
        loaded = load_current_skill_context(
            package_path, registry, skill_id=selected_id, question=question,
            runtime_tools=list(runtime_tools), world_as_of=world_as_of,
            source_reverification=source_reverification, max_units=max_units,
        )
        if any(loaded.get(key) != val for key, val in (
            ("trust_class", "UNTRUSTED_KNOWLEDGE_DATA"),
            ("authority", "KNOWLEDGE_ONLY"),
            ("instruction_authority", "NONE"),
            ("execution_authority", "NONE"),
        )):
            raise PortableDeliveryError("load authority label mismatch")
        if not set(loaded.get("effective_tools", [])) <= set(runtime_tools):
            raise PortableDeliveryError("tool ceiling widened")
        temporal = loaded.get("temporal_evidence")
        evidence = loaded.get("load_evidence")
        contexts = loaded.get("reasoning_context")
        if not isinstance(temporal, dict) or temporal.get("current_use_allowed") is not True:
            raise PortableDeliveryError("temporal gate rejected")
        if not isinstance(evidence, dict) or evidence.get("skill_id") != selected_id or evidence.get("skill_version") != selected_version:
            raise PortableDeliveryError("load identity mismatch")
        if not isinstance(contexts, list) or not 1 <= len(contexts) <= max_units:
            raise PortableDeliveryError("invalid knowledge selection")
        if evidence.get("loaded_unit_ids") != [unit.get("unit_id") for unit in contexts if isinstance(unit, dict)]:
            raise PortableDeliveryError("selected unit binding mismatch")
        items = []
        for unit in contexts:
            if not isinstance(unit, dict) or not CONTEXT_FIELDS.issubset(unit):
                raise PortableDeliveryError("missing bounded context fields")
            if any(unit.get(key) != value for key, value in (
                ("trust_class", "UNTRUSTED_KNOWLEDGE_DATA"),
                ("authority", "KNOWLEDGE_ONLY"),
                ("instruction_authority", "NONE"),
                ("execution_authority", "NONE"),
                ("executable", False),
                ("skill_id", selected_id),
                ("skill_version", selected_version),
                ("temporal_condition", "CURRENT"),
            )):
                raise PortableDeliveryError("untrusted data boundary mismatch")
            content = unit.get("content")
            if not isinstance(content, str) or not content or len(content) > MAX_UNIT_CHARS:
                raise PortableDeliveryError("knowledge unit exceeds delivery cap")
            if not isinstance(unit.get("source_bindings"), list) or not unit["source_bindings"]:
                raise PortableDeliveryError("source binding missing")
            # COPY ONLY the 14 known context fields; never transport arbitrary fields.
            items.append({key: unit[key] for key in sorted(CONTEXT_FIELDS)})
        out = _result(
            host, mode, "UNTRUSTED_DATA_PREVIEW_ONLY", question, items,
            source_reverification_complete=temporal.get("source_reverification_complete") is True,
        )
        if len(_serialize_stdout(out)) > MAX_TOTAL_JSON_BYTES:
            raise PortableDeliveryError("delivery byte cap exceeded")
        return out
    except Exception as exc:
        # Refuse without printing inner errors, source content, OS paths or local secrets.
        raise PortableDeliveryError("delivery preview refused") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m knowledge_forge.portable_delivery_preview",
        description="Explicit bounded untrusted-data preview; no automatic Claude/Codex hook, no promotion",
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--question")
    parser.add_argument("--world-as-of")
    parser.add_argument("--registry")
    parser.add_argument("--packages-map")
    parser.add_argument("--max-units", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        if args.mode == "OFF":
            out = preview(mode="OFF", host=args.host)
        else:
            if not args.registry or not args.packages_map:
                raise PortableDeliveryError("missing registry and package mapping")
            def resolver(skill_id: str, version: int) -> str:
                mapping = _read_json(args.packages_map)
                if set(mapping) != {"schema_version", "packages"} or mapping["schema_version"] != "0.1":
                    raise PortableDeliveryError("mapping schema mismatch")
                packages = mapping.get("packages")
                node = packages.get(skill_id) if isinstance(packages, dict) else None
                if not isinstance(node, dict) or set(node) != {"version", "path"} or type(node["version"]) is not int or node["version"] != version:
                    raise PortableDeliveryError("package mapping identity mismatch")
                return node["path"]
            out = preview(
                mode=args.mode, host=args.host, question=args.question,
                world_as_of=args.world_as_of,
                registry_supplier=lambda: _read_json(args.registry),
                package_resolver=resolver, max_units=args.max_units,
            )
        wire = _serialize_stdout(out)
        if len(wire) > MAX_TOTAL_JSON_BYTES:
            raise PortableDeliveryError("delivery byte cap exceeded")
        # Perform exactly one complete write only after the full bound check.
        sys.stdout.buffer.write(wire)
        return 0
    except (PortableDeliveryError, ValueError):
        print(json.dumps({"ok": False, "activation": "BLOCKED", "error": "delivery preview refused",
            "promotion_authorized": False, "execution_authority": "NONE"}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
