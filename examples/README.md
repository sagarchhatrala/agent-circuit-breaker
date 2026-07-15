# Examples

These examples show safe integration patterns for Agent Circuit Breaker.

Run from the repository root after installing the package locally:

```bash
python -m pip install -e .
python examples/cli_gate.py
python examples/python_api_integration.py
python examples/custom_rules_example.py
python examples/allowlist_example.py
```

The examples do not execute risky commands. They evaluate proposed actions and print the decision.
