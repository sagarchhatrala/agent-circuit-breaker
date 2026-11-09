"""Real stdio interoperability with optional MCP SDK 2.3.0; no model or network."""
import asyncio
import json
import os
import select
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_circuit_breaker.demo import initialize_fixture
from agent_circuit_breaker.owner_setup import initialize
from agent_circuit_breaker.owner import request
from agent_circuit_breaker.integrations import integrate


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
    await owner_route()


async def owner_route():
    with tempfile.TemporaryDirectory(prefix='acb-mcp-', dir='/tmp') as temporary:
        root = Path(temporary).resolve()
        info = initialize(root / 'project')
        agent = root / 'agent.sock'
        process = subprocess.Popen([sys.executable, '-I', '-m', 'agent_circuit_breaker.owner', 'serve',
            '--workspace', info['workspace'], '--state', info['state'], '--config', info['config'],
            '--socket', str(agent), '--agent-uid', str(os.getuid()), '--development'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([process.stdout], [], [], 15)[0] and process.stdout.readline(), 'owner startup failed'
            for host in ('claude', 'cursor', 'codex'):
                integrate(host, root, mode='mcp', operation='install', owner_socket=agent)
                assert integrate(host, root, mode='mcp', operation='verify')['status'] == 'verified'
                integrate(host, root, mode='mcp', operation='uninstall')
            params = StdioServerParameters(command=sys.executable, args=[
                '-I', '-m', 'agent_circuit_breaker_mcp.owner_client', '--socket', str(agent)])
            async with Client(params, mode='2026-07-28') as client:
                names = {tool.name for tool in (await client.list_tools()).tools}
                assert len(names) == 11 and 'database_change' in names and 'declassify' not in names
                read = check(await client.call_tool('read_file', {'path': 'incident.json'}), 'ALLOW')
                check(await client.call_tool('json_artifact', {'artifact_id': read['result']['artifact']['id'], 'path': 'reports/mcp.json'}), 'ALLOW')
                assert json.loads((Path(info['workspace']) / 'reports/mcp.json').read_bytes())['count'] == 3
                pending = check(await client.call_tool('database_change', {'operation': 'close_ticket', 'parameters': {'id': 2, 'status': 'closed'}}), 'PENDING_APPROVAL')
                check(await client.call_tool('execute_review', {'review_id': pending['review_id']}), 'BLOCK')
                approved = request(info['control_socket'], {'method': 'approve', 'review_id': pending['review_id'], 'fingerprint': pending['review']['action_fingerprint']})
                assert approved['status'] == 'approved'
                check(await client.call_tool('execute_review', {'review_id': pending['review_id']}), 'ALLOW')
                with sqlite3.connect(root / 'project/tickets.sqlite3') as db:
                    assert db.execute('SELECT status FROM tickets WHERE id=2').fetchone()[0] == 'closed'
                check(await client.call_tool('execute_review', {'review_id': pending['review_id']}), 'BLOCK')
            async with stdio_client(params) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    assert len((await session.list_tools()).tools) == 11
                    check(await session.call_tool('read_file', {'path': 'incident.json'}), 'ALLOW')
                    check(await session.call_tool('read_file', {'path': '../outside'}), 'BLOCK')
            print(json.dumps({'owner_mcp': 'passed', 'real_file_and_sql': True, 'protocols': ['2026-07-28', '2025-11-25'], 'integration_config_lifecycle': ['claude', 'cursor', 'codex']}))
        finally:
            process.terminate()
            process.communicate(timeout=10)


if __name__ == '__main__':
    asyncio.run(main())
