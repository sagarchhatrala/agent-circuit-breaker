"""Static scanning helpers for files and directories."""

import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List


DEFAULT_SUFFIXES = {
    ".bash",
    ".cmd",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".sql",
    ".txt",
    ".yaml",
    ".yml",
}


def scan_paths(
    paths: List[str],
    evaluator: Callable[[str], Dict[str, Any]],
    *,
    suffixes: Iterable[str] = DEFAULT_SUFFIXES,
) -> Dict[str, Any]:
    """Scan text files line-by-line using the supplied evaluator."""
    findings: List[Dict[str, Any]] = []
    files_scanned = 0
    suffix_set = {suffix.lower() for suffix in suffixes}

    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            findings.append(
                {
                    "path": str(path),
                    "line": 0,
                    "text": "",
                    "verdict": "error",
                    "risk_score": 100,
                    "matched_rule": None,
                    "error": f"path not found: {path}",
                }
            )
            continue
        for file_path in _iter_files(path, suffix_set):
            files_scanned += 1
            findings.extend(_scan_file(file_path, evaluator))

    blocked = sum(1 for finding in findings if finding["verdict"] == "block")
    pending = sum(1 for finding in findings if finding["verdict"] == "pending_approval")
    errors = sum(1 for finding in findings if finding["verdict"] == "error")
    return {
        "files_scanned": files_scanned,
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "blocked": blocked,
            "pending_approval": pending,
            "errors": errors,
        },
    }


def format_scan_result(result: Dict[str, Any]) -> str:
    """Format scan output for humans."""
    summary = result["summary"]
    lines = [
        f"Files Scanned: {result['files_scanned']}",
        f"Findings: {summary['findings']}",
        f"Blocked: {summary['blocked']}",
        f"Pending Approval: {summary['pending_approval']}",
        f"Errors: {summary['errors']}",
    ]
    for finding in result["findings"]:
        lines.append(
            f"{finding['path']}:{finding['line']}: "
            f"{finding['verdict'].upper()} risk={finding['risk_score']} "
            f"rule={finding.get('matched_rule') or '-'}"
        )
    return "\n".join(lines)


def _iter_files(path: Path, suffixes: set[str]) -> Iterable[Path]:
    if path.is_file():
        if _is_text_candidate(path, suffixes):
            yield path
        return

    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_file() and _is_text_candidate(child, suffixes):
                yield child


def _is_text_candidate(path: Path, suffixes: set[str]) -> bool:
    return path.suffix.lower() in suffixes or path.name in {"Dockerfile", "Makefile"}


def _scan_file(path: Path, evaluator: Callable[[str], Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [
            {
                "path": str(path),
                "line": 0,
                "text": "",
                "verdict": "error",
                "risk_score": 100,
                "matched_rule": None,
                "error": str(exc),
            }
        ]

    for line_number, line in enumerate(lines, start=1):
        candidate = _extract_candidate(line)
        if not candidate:
            continue
        result = evaluator(candidate)
        if result.get("verdict") in {"block", "pending_approval", "error"}:
            findings.append(
                {
                    "path": str(path),
                    "line": line_number,
                    "text": candidate,
                    "verdict": result.get("verdict"),
                    "risk_score": result.get("risk_score"),
                    "matched_rule": result.get("matched_rule"),
                    "error": result.get("error"),
                }
            )
    return findings


def _extract_candidate(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    for marker in ("$", ">"):
        if stripped.startswith(marker):
            return stripped[len(marker) :].strip()
    marker_match = re.match(r"^(?:[-*]\s*)?(?:run|command|cmd|shell|sql)\s*:\s*(.+)$", stripped, re.IGNORECASE)
    if marker_match:
        return marker_match.group(1).strip()
    return stripped
