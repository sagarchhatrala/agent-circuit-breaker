"""Example CLI gate wrapper.

This wrapper evaluates an action with the Agent Circuit Breaker CLI before an
integration would execute it. The example prints the decision and never executes
the proposed action.
"""

import subprocess
import sys


def check_action(action: str) -> int:
    """Run the CLI check command and return its exit code."""
    completed = subprocess.run(
        [sys.executable, "-m", "agent_circuit_breaker.cli", "check", action],
        check=False,
        text=True,
        capture_output=True,
    )
    print(completed.stdout.strip())
    return completed.returncode


if __name__ == "__main__":
    action = "rm -rf /"
    exit_code = check_action(action)
    print(f"gate_exit_code={exit_code}")
