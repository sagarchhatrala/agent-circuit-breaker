"""MCP catalog, result, and taint helpers for the stdio proxy."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from agent_circuit_breaker.taint import TaintLedger


DEFAULT_PIN_DIR = ".agent-circuit-breaker/mcp-pins"
PROMPT_INJECTION_PATTERNS = (
    re.compile(r"ignore (?:all )?(?:previous|prior|above) instructions", re.IGNORECASE),
    re.compile(r"reveal (?:the )?(?:system|developer) prompt", re.IGNORECASE),
    re.compile(r"exfiltrat(?:e|ion)", re.IGNORECASE),
    re.compile(r"send (?:all )?(?:secrets|credentials|tokens)", re.IGNORECASE),
)


@dataclass
class MCPProxySecurity:
    """State shared by client-frame and upstream-frame inspection."""

    upstream_label: str = "stdio-upstream"
    pin_dir: Optional[Path] = None
    taint_ledger: TaintLedger = field(default_factory=TaintLedger)
    pending: Dict[str, Dict[str, str]] = field(default_factory=dict)
    quarantined_tools: set[str] = field(default_factory=set)

    def record_client_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        message_id = message.get("id")
        if message_id is None:
            return None
        if method == "tools/list":
            self.pending[_canonical_id(message_id)] = {"kind": "tools/list"}
        elif method == "tools/call":
            tool_name = str((message.get("params") or {}).get("name") or "")
            if tool_name in self.quarantined_tools:
                return _jsonrpc_error(
                    message_id,
                    -32081,
                    "Agent Circuit Breaker blocked quarantined MCP tool",
                    {
                        "rule": "mcp_catalog_quarantine",
                        "tool": tool_name,
                        "reason": "tool catalog definition changed or description was unsafe",
                    },
                )
            self.pending[_canonical_id(message_id)] = {"kind": "tools/call", "tool": tool_name}
        return None

    def inspect_upstream_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        message_id = message.get("id")
        if message_id is None or "result" not in message:
            return {"allowed": True, "message": message, "checks": []}
        pending = self.pending.pop(_canonical_id(message_id), None)
        if not pending:
            return {"allowed": True, "message": message, "checks": []}
        if pending["kind"] == "tools/list":
            return self._inspect_tools_list(message)
        if pending["kind"] == "tools/call":
            return self._inspect_tool_result(message, pending.get("tool"))
        return {"allowed": True, "message": message, "checks": []}

    def _inspect_tools_list(self, message: Dict[str, Any]) -> Dict[str, Any]:
        catalog = extract_tool_catalog((message.get("result") or {}).get("tools"))
        check = CatalogPinStore(self.upstream_label, self.pin_dir).check(catalog)
        checks: List[Dict[str, Any]] = [{"type": "catalog_pin", **check}]
        poisoned = []
        for tool in catalog:
            surface = f"{tool['description']}\n{json.dumps(tool.get('inputSchema', {}), sort_keys=True)}"
            if _has_prompt_injection(surface):
                poisoned.append(tool["name"])
        if poisoned:
            self.quarantined_tools.update(poisoned)
            checks.append({"type": "tool_description", "poisoned_tools": poisoned})
        changed = [item["name"] for item in check.get("changed", [])]
        if changed:
            self.quarantined_tools.update(changed)
        if changed or poisoned:
            return {
                "allowed": False,
                "message": _jsonrpc_error(
                    message.get("id"),
                    -32082,
                    "Agent Circuit Breaker blocked MCP tool catalog",
                    {
                        "rule": "mcp_catalog_integrity",
                        "changed_tools": changed,
                        "poisoned_tools": poisoned,
                    },
                ),
                "checks": checks,
            }
        return {"allowed": True, "message": message, "checks": checks}

    def _inspect_tool_result(self, message: Dict[str, Any], tool: Optional[str]) -> Dict[str, Any]:
        texts = list(result_texts(message.get("result")))
        tagged = sum(self.taint_ledger.tag_text(text, source="mcp_tool_result", tool=tool) for text in texts)
        unsafe = [text[:160] for text in texts if _has_prompt_injection(text)]
        checks = [{"type": "tool_result", "texts": len(texts), "tainted_values_tagged": tagged}]
        if unsafe:
            checks[0]["unsafe_snippets"] = unsafe
            return {
                "allowed": False,
                "message": _jsonrpc_error(
                    message.get("id"),
                    -32083,
                    "Agent Circuit Breaker blocked MCP tool result",
                    {
                        "rule": "mcp_tool_result_prompt_injection",
                        "tool": tool,
                        "snippet": unsafe[0],
                    },
                ),
                "checks": checks,
            }
        return {"allowed": True, "message": message, "checks": checks}


class CatalogPinStore:
    """TOFU pin store for MCP tool catalogs."""

    def __init__(self, upstream_label: str, pin_dir: Optional[Path] = None):
        self.upstream_label = upstream_label
        self.pin_dir = pin_dir or default_pin_dir()

    @property
    def path(self) -> Path:
        digest = hashlib.sha256(self.upstream_label.encode("utf-8")).hexdigest()[:16]
        return self.pin_dir / f"{digest}.json"

    def check(self, catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
        live = {tool["name"]: tool_fingerprint(tool) for tool in catalog}
        stored = self._load()
        if stored is None:
            self._save(live)
            return {
                "first_contact": True,
                "changed": [],
                "new": [],
                "removed": [],
                "pin_path": str(self.path),
            }

        changed = [
            {"name": name, "pinned": pinned, "live": live[name]}
            for name, pinned in stored.items()
            if name in live and live[name] != pinned
        ]
        new = [name for name in live if name not in stored]
        removed = [name for name in stored if name not in live]
        if new:
            merged = dict(stored)
            for name in new:
                merged[name] = live[name]
            self._save(merged)
        return {
            "first_contact": False,
            "changed": changed,
            "new": new,
            "removed": removed,
            "pin_path": str(self.path),
        }

    def _load(self) -> Optional[Dict[str, str]]:
        if not self.path.exists():
            return None
        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        tools = payload.get("tools")
        return tools if isinstance(tools, dict) else None

    def _save(self, tools: Dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": 1, "upstream": self.upstream_label, "tools": tools}
        self.path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")


def default_pin_dir() -> Path:
    configured = os.environ.get("ACB_MCP_PIN_DIR")
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_PIN_DIR


def extract_tool_catalog(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    catalog = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        catalog.append(
            {
                "name": name,
                "description": item.get("description") if isinstance(item.get("description"), str) else "",
                "inputSchema": item.get("inputSchema") if isinstance(item.get("inputSchema"), dict) else {},
            }
        )
    return catalog


def tool_fingerprint(tool: Dict[str, Any]) -> str:
    material = {
        "name": tool.get("name"),
        "description": tool.get("description") or "",
        "inputSchema": tool.get("inputSchema") or {},
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def result_texts(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    yield item["text"]
        for child in value.values():
            if child is not content:
                yield from result_texts(child)
    elif isinstance(value, list):
        for child in value:
            yield from result_texts(child)


def _has_prompt_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in PROMPT_INJECTION_PATTERNS)


def _canonical_id(message_id: Any) -> str:
    return json.dumps(message_id, sort_keys=True, separators=(",", ":"))


def _jsonrpc_error(message_id: Any, code: int, message: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message, "data": data}}
