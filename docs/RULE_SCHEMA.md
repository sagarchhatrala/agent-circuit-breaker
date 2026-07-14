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
- `response`: one of `allow`, `block`.
- `matcher`: matcher object.

Optional fields:

- `metadata`: object.

Unknown rule fields are rejected. Duplicate rule IDs are rejected.

## Matcher Object

Each matcher object must include:

- `type`: one of `contains`, `equals`, `prefix`.
- `value`: non-empty string.

Unknown matcher fields are rejected.

Matcher behavior is case-sensitive.

### `contains`

Matches when the action contains the configured substring.

### `equals`

Matches when the action exactly equals the configured value.

### `prefix`

Matches when the action starts with the configured value.

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
- Regex matchers.
- Remote rule fetching.
- Rule signing.
- Arbitrary Python matchers.
- Dynamic expressions.
