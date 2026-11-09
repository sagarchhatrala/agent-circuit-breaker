# Separate owner and agent on Linux

This recipe uses Docker to keep owner resources out of the agent container. ACB
provides the application gate; Linux identities, mounts and network policy provide
the containment boundary. Do not mount a Docker socket or owner resources into
the agent. Use a non-root owner in the container. Root/host administrator compromise
is outside this boundary.

First run the reproducible acceptance script from the repository:

```bash
python -m pip install build
python -m build
python scripts/verify_owner_isolation.py \
  --wheel dist/agent_circuit_breaker-1.7.2-py3-none-any.whl \
  --output /tmp/acb-isolation.json
```

It builds this Dockerfile from that wheel in a minimal context, creates uniquely
named fixture volumes/containers, runs actual reads/copies/approved SQL under
separate UIDs, observes effects independently, tests forbidden access and restart,
then removes its fixture resources. It uses no cloud account or production data.

For an interactive synthetic deployment, build the image with the supplied
`.dockerignore` (only the wheel and Dockerfile are sent):

```bash
docker build -f examples/owner/Dockerfile -t acb-owner:1.7.2 .
docker volume create acb-owner-data
docker volume create acb-owner-socket
docker run --rm --network none --user 0:0 \
  -v acb-owner-data:/owner -v acb-owner-socket:/run/acb acb-owner:1.7.2 \
  -c "import os; os.chown('/owner',10001,10001); os.chmod('/owner',0o700); os.chown('/run/acb',10001,10001); os.chmod('/run/acb',0o755)"
docker run --rm --network none \
  -v acb-owner-data:/owner acb-owner:1.7.2 \
  -m agent_circuit_breaker.owner init /owner/project
docker run -d --name acb-owner --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v acb-owner-data:/owner -v acb-owner-socket:/run/acb acb-owner:1.7.2 \
  -m agent_circuit_breaker.owner serve \
  --workspace /owner/project/workspace --state /owner/project/state \
  --config /owner/project/owner.json --socket /run/acb/agent.sock --agent-uid 10002
```

The agent gets **only** the public socket volume, read-only, and no external network:

```bash
docker run --rm -i --user 10002:10002 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 256m \
  -v acb-owner-socket:/run/acb:ro acb-owner:1.7.2 \
  -m agent_circuit_breaker_mcp.owner_client --socket /run/acb/agent.sock
```

Run that command as an MCP stdio server from the host client, or test a CLI call by
replacing the final module/arguments with `-m agent_circuit_breaker.owner status
--socket /run/acb/agent.sock`. A host process outside the container still has its
own host permissions; this recipe confines the containerized client, not every
tool the host agent may invoke. Run the complete agent workload within your chosen
sandbox and remove alternate access to protected resources.

The owner reviews through its private socket from its own container:

```bash
docker exec acb-owner python -I -m agent_circuit_breaker.owner inspect REVIEW_ID \
  --socket /owner/project/state/control.sock
```

Use the [owner guide](../../docs/OWNER_SERVICE.md) for approve/reject/export. Do not
put the control socket on the agent volume. Socket filesystem mode permits public
connections, but peer UID validation admits only UID 10002; the private socket
also has mode 0600 under the owner's 0700 state directory.

This offline recipe intentionally has no S3 connectivity. To publish, configure a
least-privilege S3 destination and credentials inside the owner only, and grant
the owner narrowly controlled egress using your deployment network policy. Keep
the agent without that route. The separate CI MinIO rehearsal tests SigV4 and
real remote effects; it does not claim cloud network-policy certification.

The base Python image is a maintained tag; pin a reviewed digest in your deployment
and rebuild on security updates. The acceptance report records the built image ID.
Persist the owner volume across restarts; deleting it grants a fresh authority
budget and discards local history, so retain/export evidence before deliberate
rotation. Stop with `docker stop acb-owner`; do not remove its volumes as a recovery
shortcut after an uncertain operation.
