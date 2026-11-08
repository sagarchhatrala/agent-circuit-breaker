# Local demonstration

```bash
python -m pip install agent-circuit-breaker==1.7.0
agent-circuit-breaker demo
```

Open the printed private loopback URL. Assets are packaged in the wheel; no CDN,
model, SDK, browser extension or source checkout is needed. `Ctrl-C` or **Stop demo**
shuts it down and removes its synthetic temporary data. **Run again** resets the
selected scenario into fresh state; no suspended run is secretly resumed.

```bash
agent-circuit-breaker demo --doctor
agent-circuit-breaker demo --replay --output /tmp/acb-replay.json
```

The replay executes the backend afresh. Proposal scripts are visibly labeled offline;
the resulting report, collector requests and durable decisions are fresh observations.
No live model or agent-generated trace is claimed. Only fixed safe fixture operations
run; this is a constrained executor, not an OS sandbox.

## Six-minute walkthrough

Talk: “Circuit-Breaking AI Agents: A Pre-execution Safety Gate for Shells, MCP.”
Intended date: Tuesday, November 10, 2026. Time of day is not established here.

| Time | Scene | Evidence to point out |
|---|---|---|
| 0:00–0:45 | Useful work | Explicit permissions, actual incident report, started/outcome events |
| 0:45–2:15 | Injection | Poisoned handoff; identical export proposal; one baseline receipt, protected executor did not start; encoded sensitivity preserved |
| 2:15–3:45 | Exact approval | Pending outcome; owner/artifact/destination scope; substitution refused; one receipt; replay denied after runtime reconstruction |
| 3:45–5:15 | Interruption | Collector received data before simulated response loss; uncertain state survives restart; no second request |
| 5:15–6:00 | Catalog | Optional definition diff, quarantine, visible first-use trust and implementation-attestation limitation |

The first scene is useful without any injection detector. The attack wording is an
intentional detector miss. Approval scenes identify the owner; the scripted owner
approval is a demonstration action, not a model making its own approval decision.

## Regenerate recordings

From a checkout, install development-only tools in an isolated environment:

```bash
python -m pip install playwright imageio-ffmpeg
python -m playwright install chromium ffmpeg
python scripts/record_demo.py --output /tmp/acb-recording --mode all
python scripts/record_demo.py --output /tmp/acb-poster --mode poster
```

The script creates new empty browser profiles, records only the 1440×1000 viewport (the standalone poster uses 1440×1200),
executes the backend, verifies key observations, and produces a 75-second overview,
a six-minute walkthrough, WebVTT captions, screenshots and JSON observations. Pass
`--browser /absolute/path/to/chrome` to use an installed browser with a fresh profile.
The MP4 encoder burns captions into a band beneath the viewport and strips
source metadata and audio. Raw WebM stays outside tracked/package paths.

Review frames and screenshots before publication. Allowlisted exports are
`overview.mp4`, `full.mp4`, matching `.vtt`, `poster.png`, and reviewed evidence JSON.
Never export browser profiles, arbitrary logs, launch URLs, environment dumps, or
whole temporary directories. A text/regex scan is not proof that a video is safe.

## Limits

The collector is an actual authenticated loopback HTTP receiver, not an external
internet service. Two logical destinations map to that one fixture endpoint. The
unprotected baseline uses a separate fixture copy and skips ACB for that same fixed
publication. No arbitrary hostile commands are executed on the host.

The UI displays known executor start/completion and explicitly uncertain outcomes.
Remote acknowledgments are not automatically proof of independent completion or
absence of side effects. See [security boundaries](WORKFLOW_SECURITY.md), the
[enforcement matrix](ADAPTER_ENFORCEMENT_MATRIX.md), and
[independent scenarios](validation/v1.7.0-independent-review.md).
