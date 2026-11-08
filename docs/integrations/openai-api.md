# OpenAI Responses API

This integrates the **OpenAI API**, separately from Codex. It wraps application-side
function execution with `RuntimeGate`. A prompt, tool description, tracing callback
or optional guardrail cannot authorize execution. Hosted tools execute outside this
wrapper and are not protected by it.

Prerequisites: Python 3.11+, ACB 1.7.0. Offline mode has no SDK/API requirement:

```bash
python -m pip install agent-circuit-breaker==1.7.0
python -I -m agent_circuit_breaker.responses_example
```

The complete runnable implementation is
[responses_example.py](../../agent_circuit_breaker/responses_example.py). It creates
a fresh synthetic workspace and uses the same dispatcher in both modes. Expect a
real report, two `ALLOW` results, an approved-destination `PENDING_APPROVAL`, and an
alternate-destination `BLOCK`. No publisher starts for either export proposal.

Minimal application binding:

```python
import json
from agent_circuit_breaker.responses_example import Dispatcher

# workflow is an owner-configured, already-started Workflow instance.
dispatcher = Dispatcher(workflow)
for item in response.output:
    if item.type == "function_call":
        result = await dispatcher.dispatch(item.call_id, item.name, item.arguments)
        input_messages.append(result)
```

Use the complete example for client construction and loop handling. Preserve all
response output items, including reasoning, before appending `function_call_output`
items keyed by `call_id`. Multiple calls are dispatched individually, malformed
arguments produce `ERROR`, denied/pending results return to the model, and duplicate
call IDs reuse the prior result without repeating execution. The example permits
at most eight calls. Model-supplied principal, capability and labels are rejected.

Optional live mode:

```bash
python -m pip install 'agent-circuit-breaker[openai]==1.7.0'
# Supply OPENAI_API_KEY through your secure environment/secrets mechanism.
python -I -m agent_circuit_breaker.responses_example --live --model YOUR_AVAILABLE_MODEL
```

Live mode is opt-in, uses at most three requests with 512 output tokens each,
20-second client timeouts, no SDK retries, and `store=False`. It sends only synthetic
fixtures. No keys belong in code, terminal recordings or configuration files.
Local checks used OpenAI SDK **3.46.0**; live paid API requests were not run. The
Agents SDK is not included or claimed as verified.

Troubleshooting: install the extra only for live mode, ensure your account supports
the explicit model, and use the SDK's environment-based credentials. A provider
error is not tool authorization. Offline output is not a live-model trace.

Removal: uninstall the package/extra or remove the isolated virtual environment.
The example's temporary workspace is removed on exit; it changes no host settings.
Source: [official function calling guide](https://developers.openai.com/api/docs/guides/function-calling), checked November 8, 2026.
