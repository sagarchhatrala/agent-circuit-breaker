"""Fixture-based tests for external rule files."""

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from agent_circuit_breaker.limits import MAX_RULE_FILE_BYTES, ensure_file_within_limit


def discover_rule_test_files(path: str) -> List[Path]:
    """Return deterministic rule-test files from a file or directory."""
    candidate = Path(path)
    if candidate.is_dir():
        return sorted(candidate.glob("*.test.json"))
    return [candidate]


def run_rule_tests(path: str) -> Dict[str, Any]:
    """Run rule tests from a JSON file or directory of *.test.json files."""
    files = discover_rule_test_files(path)
    results = [_run_rule_test_file(test_file) for test_file in files]
    total = sum(item["summary"]["total"] for item in results)
    passed = sum(item["summary"]["passed"] for item in results)
    failed = sum(item["summary"]["failed"] for item in results)
    return {
        "path": path,
        "is_valid": failed == 0,
        "summary": {"files": len(files), "total": total, "passed": passed, "failed": failed},
        "files": results,
    }


def _run_rule_test_file(path: Path) -> Dict[str, Any]:
    errors: List[str] = []
    cases: List[Dict[str, Any]] = []
    try:
        ensure_file_within_limit(path, MAX_RULE_FILE_BYTES, "rule test file")
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases = list(_validate_test_payload(payload, path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))

    case_results = []
    if not errors:
        from agent_circuit_breaker.cli import CircuitBreakerCLI

        rule_file = _resolve_rule_file(path, payload["rule_file"])
        cli = CircuitBreakerCLI()
        loaded = cli.load_custom_rules(str(rule_file))
        if not loaded["is_valid"]:
            errors.extend(loaded["errors"])
        else:
            for case in cases:
                result = cli.evaluate_command(case["action"], loaded["rules"])
                passed, failure = _case_matches(case, result)
                case_results.append(
                    {
                        "name": case["name"],
                        "passed": passed,
                        "expected": _expected_summary(case),
                        "actual": {
                            "verdict": result.get("verdict"),
                            "decision": result.get("decision"),
                            "matched_rule": result.get("matched_rule"),
                        },
                        "failure": failure,
                    }
                )

    failed = len(errors) + sum(1 for case in case_results if not case["passed"])
    return {
        "path": str(path),
        "is_valid": failed == 0,
        "errors": errors,
        "summary": {
            "total": len(case_results),
            "passed": sum(1 for case in case_results if case["passed"]),
            "failed": failed,
        },
        "cases": case_results,
    }


def _validate_test_payload(payload: Any, path: Path) -> Iterable[Dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    if not isinstance(payload.get("rule_file"), str) or not payload["rule_file"]:
        raise ValueError(f"{path}.rule_file must be a non-empty string")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"{path}.cases must be a non-empty list")
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"{path}.cases[{index}] must be an object")
        if not isinstance(case.get("action"), str):
            raise ValueError(f"{path}.cases[{index}].action must be a string")
        expected_verdict = case.get("expect") or case.get("verdict")
        if expected_verdict not in {"allow", "block", "error", "unknown", "pending_approval"}:
            raise ValueError(f"{path}.cases[{index}].expect must be a verdict string")
        yield {
            "name": str(case.get("name") or f"case_{index}"),
            "action": case["action"],
            "expect": expected_verdict,
            "matched_rule": case.get("matched_rule"),
        }


def _resolve_rule_file(test_path: Path, rule_file: str) -> Path:
    candidate = Path(rule_file)
    if candidate.is_absolute():
        return candidate
    return (test_path.parent / candidate).resolve()


def _case_matches(case: Dict[str, Any], result: Dict[str, Any]) -> tuple[bool, str | None]:
    if result.get("verdict") != case["expect"]:
        return False, f"expected verdict {case['expect']}, got {result.get('verdict')}"
    if case.get("matched_rule") is not None and result.get("matched_rule") != case["matched_rule"]:
        return False, f"expected matched_rule {case['matched_rule']}, got {result.get('matched_rule')}"
    return True, None


def _expected_summary(case: Dict[str, Any]) -> Dict[str, Any]:
    return {"verdict": case["expect"], "matched_rule": case.get("matched_rule")}
