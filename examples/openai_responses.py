"""Run with python examples/openai_responses.py (offline by default).

Installed-wheel equivalent: python -m agent_circuit_breaker.responses_example
See docs/integrations/openai-api.md for the opt-in bounded live example.
"""
from agent_circuit_breaker.responses_example import main

if __name__ == "__main__":
    raise SystemExit(main())
