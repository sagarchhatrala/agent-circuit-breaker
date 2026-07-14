# v0.4 Rule Loading And Validation Plan

The v0.4 milestone adds safe validation for external rule definitions. The goal is to let users describe rules in data files without allowing arbitrary code execution.

## Goals

- Define a minimal JSON rule format.
- Validate external rule files with clear errors.
- Add a CLI validation command.
- Keep rule loading separate from enforcement until validation behavior is stable.
- Document supported fields and intentionally unsupported behavior.
- Add fixture-based examples for valid and invalid rule files.

## Non-Goals

- YAML support.
- Arbitrary Python matchers in rule files.
- Remote rule fetching.
- Rule signing.
- Runtime policy downloads.
- Replacing built-in rules.

## Proposed Rule File Shape

Start with one JSON object containing a top-level `rules` list:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "custom_block_rm_tmp",
      "title": "Block tmp deletion",
      "severity": "HIGH",
      "response": "block",
      "matcher": {
        "type": "contains",
        "value": "rm -rf /tmp"
      },
      "metadata": {
        "category": "custom"
      }
    }
  ]
}
```

## Supported Matcher Types For v0.4

Keep the first matcher set small and deterministic:

- `contains`: action contains an exact substring.
- `equals`: action exactly equals a configured string.
- `prefix`: action starts with a configured string.

All matcher values must be strings. Matching should be case-sensitive initially unless a later slice adds an explicit `case_sensitive` option.

## Validation Rules

Each rule must include:

- `id`: non-empty string.
- `title`: non-empty string.
- `severity`: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- `response`: one of `allow`, `block`.
- `matcher`: object with supported `type` and string `value`.

Optional fields:

- `metadata`: object.

Reject:

- unknown top-level fields that imply behavior.
- unknown matcher types.
- non-string matcher values.
- duplicate rule IDs.
- empty rule lists.
- malformed JSON.

## Scope Slice 1: Validator Foundation

Add a validator module that reads parsed JSON-like dictionaries and returns deterministic validation results.

Initial tests:

- valid rule file returns valid.
- missing `rules` returns invalid.
- malformed rule fields return invalid.
- duplicate IDs return invalid.
- unknown matcher type returns invalid.
- non-object metadata returns invalid.

## Scope Slice 2: File Loading

Load JSON from disk with explicit errors:

- file not found.
- invalid JSON.
- top-level value is not an object.
- valid file returns parsed rule definitions.

## Scope Slice 3: CLI Validation

Add:

```bash
circuit-breaker validate-rules path/to/rules.json
```

Expected behavior:

- exit `0` for valid files.
- exit `1` for invalid files.
- text output with concise validation errors.
- JSON output when `--format json` is used.

## Scope Slice 4: Rule Construction

Convert validated rule definitions into `Rule` objects using only built-in deterministic matcher factories.

Do not include these custom rules in normal `check` evaluation until tests prove the full path.

## Scope Slice 5: Optional Enforcement Wiring

After validation and construction are stable, add an explicit option:

```bash
circuit-breaker check "action" --rules path/to/rules.json
```

This should append validated custom rules after built-in rules unless the docs explicitly define another order.

## Testing Plan

Add tests for:

- validator result shape.
- all required fields.
- duplicate IDs.
- matcher type validation.
- malformed JSON file loading.
- CLI text output.
- CLI JSON output.
- deterministic repeated validation.

## Acceptance Criteria

- `python -m unittest discover` passes.
- No runtime dependencies are added.
- Invalid rule files fail closed.
- CLI validation errors are actionable.
- Custom rule files cannot execute arbitrary code.
- Documentation clearly states the v0.4 rule format limitations.

## Release Target

Recommended prerelease tag:

```text
v0.4.0-alpha.1
```
