# Phase 1 Bug Log

This log tracks sandbox findings for the v2 Phase 1 hardening batch. All reproduction inputs are evaluated through the library API/CLI only; none are executed by a shell, filesystem, cloud CLI, or database.

| Input | Expected | Actual Before Fix | Severity | Module | Status |
|---|---|---|---|---|---|
| `r''m -r''f /etc` | `BLOCK fs_recursive_delete` | parser-dependent; covered by old custom tokenizer but not guaranteed POSIX-equivalent | High | `CommandInspector` | Fixed with stdlib POSIX `shlex` tokenization regression |
| `g'it' push --for''ce origin main` | `BLOCK cmd_git_force_push` | parser-dependent; quote-normalization class not explicitly tested | High | `CommandInspector` | Fixed with POSIX quote concatenation regression |
| `r\u200bm -rf /etc` | `BLOCK fs_recursive_delete` | likely `UNKNOWN` because zero-width character hid command token | Critical | normalization / filesystem rules | Fixed with zero-width stripping before matching |
| `rм -rf /etc` | `BLOCK fs_recursive_delete` | likely `UNKNOWN` because Cyrillic homoglyph hid command token | Critical | normalization / filesystem rules | Fixed with narrow homoglyph normalization before matching |
| `DRОP TABLE users` | `BLOCK sql_drop_table` | likely `UNKNOWN` because Cyrillic homoglyph hid SQL keyword | Critical | normalization / SQL rules | Fixed with narrow homoglyph normalization before matching |
| `DRO\u200bP TABLE users` | `BLOCK sql_drop_table` | likely `UNKNOWN` because zero-width character split SQL keyword | Critical | normalization / SQL rules | Fixed with zero-width stripping before matching |
| randomized shell-like and SQL-like strings | valid `ALLOW/BLOCK/ERROR/UNKNOWN`, no crash | not covered by existing tests | Medium | public API | Fixed with deterministic fuzz-style regression |
| very large benign input | no catastrophic parser/regex latency | not covered by existing tests | Medium | public API / parsers | Fixed with bounded-latency regression |
| fresh-venv example subprocess tests | examples import checkout deterministically | failed with `ModuleNotFoundError` because subprocesses inherited no package path in a clean venv | Medium | tests / examples | Fixed by passing repo-root `PYTHONPATH` to example subprocess tests |
