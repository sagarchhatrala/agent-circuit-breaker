# Local Allowlist Pattern

Agent Circuit Breaker supports a local allowlist pattern through external JSON rules with `response` set to `allow`.

Use this pattern only for deterministic, known-safe workflows. Built-in block rules are evaluated before custom rules, so an allowlist rule cannot override built-in destructive filesystem, command, or SQL blocks.

## Constraints

- Keep allowlist files local.
- Validate allowlist files before use.
- Use only schema version `1`.
- Use only supported matcher types: `contains`, `equals`, and `prefix`.
- Do not fetch allowlists from remote locations.
- Do not treat `UNKNOWN` as safe.

## Example Rule

```json
{
  "version": 1,
  "rules": [
    {
      "id": "allow_repo_status_checks",
      "title": "Allow local repository status checks",
      "severity": "LOW",
      "response": "allow",
      "matcher": {
        "type": "equals",
        "value": "git status --short"
      },
      "metadata": {
        "category": "allowlist",
        "owner": "release-engineering"
      }
    }
  ]
}
```

Validate it:

```bash
circuit-breaker validate-rules examples/allowlist_rules.json
```

Use it:

```bash
circuit-breaker check "git status --short" --rules examples/allowlist_rules.json
```

Expected verdict:

```text
Verdict: ALLOW
Matched Rule: allow_repo_status_checks
```

Built-in blocks still win:

```bash
circuit-breaker check "rm -rf /" --rules examples/allowlist_rules.json
```

Expected verdict:

```text
Verdict: BLOCK
Matched Rule: fs_recursive_delete
```
