# Policy Assurance

Agent Circuit Breaker v1.5.2 adds local policy assurance tools for teams that treat safety policy as code.

These tools do not add telemetry, collectors, dashboards, or agent analytics. They strengthen the pre-execution enforcement contract.

## Rule Tests

Use `rules test` to validate custom rule packs against positive and negative fixtures before deployment.

```bash
circuit-breaker rules test ./policy-tests
circuit-breaker rules test ./policy-tests/deploy.test.json --format json
```

Rule test files use `*.test.json`:

```json
{
  "rule_file": "../rules.json",
  "cases": [
    {
      "name": "blocks production deploy",
      "action": "deploy production now",
      "expect": "block",
      "matched_rule": "custom_block_prod"
    }
  ]
}
```

Invalid rule files, malformed test fixtures, and failed cases return exit code `1`.

## Schema Export

Export versioned public JSON schema artifacts:

```bash
circuit-breaker schemas
circuit-breaker schemas rule-file
circuit-breaker schemas policy-file
circuit-breaker schemas decision-output
circuit-breaker schemas trajectory-output
circuit-breaker schemas audit-event
```

The schemas are documentation and integration contracts. Runtime validation remains dependency-free.

## Built-in Rule Catalog

Generate the built-in rule catalog from the shipped rule objects:

```bash
circuit-breaker catalog
circuit-breaker catalog --format json
```

The catalog is generated from code so docs can stay aligned with actual enforcement coverage.

## Resource Limits

v1.5.2 defines explicit limits for:

- command/action byte size.
- rule file byte size.
- policy file byte size.
- trajectory file size and action count.
- approval payload size.
- MCP message size and argument recursion depth.

Oversized inputs fail closed with an error verdict or validation error.

## Persisted Record Redaction

Audit events, approval records, and run-ledger entries redact common secret-like values by default.

Set `ACB_RETAIN_RAW_RECORDS=1` only in controlled environments that explicitly require raw local retention.

Redaction is not DLP. It is a deterministic safety guard against common accidental credential persistence.
