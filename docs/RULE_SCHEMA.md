# External Rule Schema

This document defines the external JSON rule format supported by Agent Circuit Breaker.

Schema version: `1`

## Top-Level Object

Rule files must be JSON objects with these fields:

- `version`: optional integer. When present, it must be `1`.
- `rules`: required non-empty list of rule objects.

Unknown top-level fields are rejected.

## Rule Object

Each rule object must include:

- `id`: non-empty string.
- `title`: non-empty string.
- `severity`: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- `response`: one of `allow`, `block`, `approval`.
- `matcher`: matcher object.

Optional fields:

- `metadata`: object.

Unknown rule fields are rejected. Duplicate rule IDs are rejected.

## Matcher Object

Scalar matcher objects include:

- `type`: one of `contains`, `equals`, `prefix`, `regex`.
- `value`: non-empty string.

Unknown matcher fields are rejected.

Matcher values are normalized with the same command normalization used by the core engine.

### `contains`

Matches when the action contains the configured substring.

### `equals`

Matches when the action exactly equals the configured value.

### `prefix`

Matches when the action starts with the configured value.

### `regex`

Matches when the configured regular expression matches the normalized action. Regex patterns are bounded and compiled during validation.

### `all_of`

Matches when every child matcher matches.

```json
{
  "type": "all_of",
  "matchers": [
    {"type": "contains", "value": "deploy"},
    {"type": "contains", "value": "production"}
  ]
}
```

### `any_of`

Matches when at least one child matcher matches.

### `not`

Matches when the child matcher does not match.

## Security Properties

External rule files are data only. They cannot execute Python code, import modules, fetch remote content, or define arbitrary functions.

Invalid rule files fail closed. When passed to `--rules`, an invalid file stops command evaluation and returns exit code `1`.

Built-in rules are evaluated before custom rules. A custom `allow` rule cannot override a built-in block rule.

## Valid Example

```json
{
  "version": 1,
  "rules": [
    {
      "id": "custom_deploy_guard",
      "title": "Block production deployment phrase",
      "severity": "HIGH",
      "response": "block",
      "matcher": {
        "type": "contains",
        "value": "deploy production"
      },
      "metadata": {
        "category": "custom"
      }
    }
  ]
}
```

## Unsupported

- YAML files.
- Arbitrary Python matchers.
- Dynamic expressions.
- Unbounded regular expressions.
