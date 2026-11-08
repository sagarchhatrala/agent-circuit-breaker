"""Real stdio interoperability with optional MCP SDK 2.3.0; no model or network."""
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_circuit_breaker.demo import initialize_fixture


def check(result, decision):
    value = json.loads(result.content[0].text)
    assert value['decision'] == decision, value
    assert result.is_error == (decision != 'ALLOW')
    if decision == 'BLOCK':
        assert value['executor_started'] is False
    return value


async def main():
    with tempfile.TemporaryDirectory(prefix='acb-sdk-') as directory:
        root = Path(directory)
        policy = initialize_fixture(root / 'workspace')
        (root / 'policy.json').write_text(json.dumps(policy))
        params = StdioServerParameters(command=sys.executable, args=[
            '-I', '-m', 'agent_circuit_breaker_mcp.workflow_server',
            '--workspace', str(root / 'workspace'), '--state', str(root / 'state'),
            '--policy', str(root / 'policy.json')])
        async with Client(params, mode='2026-07-28') as client:
            assert len((await client.list_tools()).tools) == 6
            read = check(await client.call_tool('read_file', {'path': 'incident.txt'}), 'ALLOW')
            check(await client.call_tool('write_report', {
                'sources': [read['result']['artifact']['id']], 'path': 'reports/sdk.md'}), 'ALLOW')
            assert (root / 'workspace/reports/sdk.md').is_file()
            check(await client.call_tool('read_file', {'path': '../outside'}), 'BLOCK')
        first_run = (root / 'state/current-run').read_text()
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                assert (await session.initialize()).protocol_version == '2025-11-25'
                assert len((await session.list_tools()).tools) == 6
                check(await session.call_tool('read_file', {'path': 'incident.txt'}), 'ALLOW')
                check(await session.call_tool('read_file', {'path': '../outside'}), 'BLOCK')
        assert first_run == (root / 'state/current-run').read_text()
        print(json.dumps({'sdk': 'mcp 2.3.0', 'protocols': ['2026-07-28', '2025-11-25'],
                          'real_report': True, 'denied_without_start': True,
                          'restart_reused_run': True, 'status': 'passed'}))


if __name__ == '__main__':
    asyncio.run(main())
