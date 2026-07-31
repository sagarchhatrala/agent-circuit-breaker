"""Central resource limits for parsers and policy inputs."""

from pathlib import Path
from typing import Any


MAX_COMMAND_BYTES = 256 * 1024
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_POLICY_FILE_BYTES = 1024 * 1024
MAX_TRAJECTORY_FILE_BYTES = 1024 * 1024
MAX_TRAJECTORY_ACTIONS = 512
MAX_APPROVAL_PAYLOAD_BYTES = 512 * 1024
MAX_MCP_MESSAGE_BYTES = 1024 * 1024
MAX_MCP_RECURSION_DEPTH = 32


def utf8_size(value: str) -> int:
    """Return the UTF-8 encoded size for a string."""
    return len(value.encode("utf-8"))


def ensure_text_within_limit(value: Any, limit: int, label: str) -> None:
    """Raise ValueError when a string input exceeds a byte limit."""
    if isinstance(value, str) and utf8_size(value) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")


def ensure_file_within_limit(path: Path, limit: int, label: str) -> None:
    """Raise ValueError when a file exceeds a byte limit."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"Could not stat {label}: {exc}") from exc
    if size > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
