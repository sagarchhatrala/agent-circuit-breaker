# v0.3 SQL Inspector Plan

The v0.3 milestone adds deterministic SQL statement inspection. The goal is to detect a small set of high-risk destructive SQL patterns before execution. The goal is not to build a full SQL parser or understand every dialect.

## Goals

- Add `agent_circuit_breaker/inspectors/sql.py`.
- Add `tests/test_sql_inspector.py`.
- Tokenize and split common SQL statements deterministically.
- Detect high-risk destructive statements.
- Avoid false positives in quoted strings and comments where practical.
- Expose SQL analysis in CLI output before enforcement.
- Add built-in SQL rules only after inspector behavior is tested.

## Non-Goals

- Full SQL grammar parsing.
- Dialect-perfect behavior for PostgreSQL, MySQL, SQLite, SQL Server, Oracle, or BigQuery.
- Database connection inspection.
- Production database detection.
- Migration framework integration.
- Query execution.
- SQL injection detection.

## v0.3 Detection Scope

Start with these destructive patterns:

- `DROP TABLE`
- `DROP DATABASE`
- `TRUNCATE`
- unqualified `DELETE`
- unqualified `UPDATE`

Definitions for v0.3:

- A `DELETE` is unqualified when it has no `WHERE` clause.
- An `UPDATE` is unqualified when it has no `WHERE` clause.
- A `TRUNCATE` statement is always destructive.
- `DROP TABLE` and `DROP DATABASE` are always destructive.

## Proposed Data Model

The SQL inspector should return a dictionary or dataclass with fields like:

```python
{
    "raw": "DELETE FROM users",
    "statements": [
        {
            "raw": "DELETE FROM users",
            "tokens": ["DELETE", "FROM", "users"],
            "statement_type": "delete",
            "risk_flags": ["sql_unqualified_delete"],
            "is_dangerous": True,
            "danger_reason": "Unqualified DELETE detected",
        }
    ],
    "is_valid": True,
    "error": None,
    "risk_flags": ["sql_unqualified_delete"],
    "is_dangerous": True,
    "danger_reason": "Unqualified DELETE detected",
}
```

Keep the model close to the command inspector's shape so CLI integration stays predictable.

## Scope Slice 1: SQL Tokenizer Foundation

Implement a small tokenizer that handles:

- whitespace-separated tokens
- punctuation needed for statement detection
- single-quoted strings
- double-quoted identifiers where practical
- line comments with `--`
- block comments with `/* ... */`
- malformed quotes/comments as explicit invalid analysis

Initial tests:

- `SELECT * FROM users`
- `DELETE FROM users`
- `UPDATE users SET active = false`
- `SELECT 'DROP TABLE users'`
- malformed single quote
- malformed block comment
- deterministic repeated parsing

## Scope Slice 2: Statement Splitting

Split SQL text on semicolons outside strings and comments.

Examples:

- `SELECT 1; SELECT 2`
- `DELETE FROM users; SELECT * FROM users`
- `SELECT ';'`
- `SELECT 1; -- comment`

The output should preserve ordered statements.

## Scope Slice 3: Destructive Statement Detection

Detect:

- `DROP TABLE <name>`
- `DROP DATABASE <name>`
- `TRUNCATE <name>`
- `TRUNCATE TABLE <name>`
- `DELETE FROM <table>` without `WHERE`
- `UPDATE <table> SET ...` without `WHERE`

False-positive tests:

- `SELECT 'DROP TABLE users'`
- `SELECT '-- DELETE FROM users'`
- `DELETE FROM users WHERE id = 1`
- `UPDATE users SET active = false WHERE id = 1`
- `SELECT * FROM truncate_log`

## Built-In Rule IDs

Candidate built-in SQL rule IDs:

- `sql_drop_table`
- `sql_drop_database`
- `sql_truncate`
- `sql_unqualified_delete`
- `sql_unqualified_update`

Rules should use SQL inspector output instead of duplicating parsing logic.

## CLI Integration

Add SQL analysis as a separate field:

```json
{
  "sql_analysis": {
    "statements": [],
    "risk_flags": [],
    "is_dangerous": false
  }
}
```

Implementation order:

1. Expose SQL analysis in CLI output as analysis-only.
2. Add tests for JSON and text output.
3. Add built-in SQL rules.
4. Enforce SQL rules as `BLOCK`.

## Testing Plan

Add `tests/test_sql_inspector.py`.

Test categories:

- tokenizer behavior
- quoted strings
- comments
- statement splitting
- destructive statement detection
- qualified `DELETE` and `UPDATE`
- malformed input
- deterministic repeated analysis
- false positives

Add CLI tests only after inspector tests are stable.

## Acceptance Criteria

- `python -m unittest discover` passes.
- SQL inspector has focused tests for every supported SQL risk pattern.
- Existing filesystem and command behavior is unchanged.
- CLI JSON output includes SQL analysis when applicable.
- SQL rules block only the scoped destructive patterns.
- No runtime dependencies are added.
- Documentation clearly states that v0.3 is heuristic SQL inspection, not full SQL parsing.

## Release Target

Recommended prerelease tag:

```text
v0.3.0-alpha.1
```
