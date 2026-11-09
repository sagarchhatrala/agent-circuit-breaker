"""Execute installed owner CLI with real temporary files and SQLite (stdlib only)."""
import json
import os
import select
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_circuit_breaker.owner import request, verify_bundle


def cli(*args):
    result = subprocess.run([sys.executable, '-I', '-m', 'agent_circuit_breaker.cli', 'owner', *map(str, args)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode in (0, 3), result.stderr or result.stdout
    value = json.loads(result.stdout)
    assert result.returncode == (3 if value.get('decision') == 'PENDING_APPROVAL' else 0)
    return value


def main():
    with tempfile.TemporaryDirectory(prefix='acb-own-', dir='/tmp') as temporary:
        root = Path(temporary).resolve()
        info = cli('init', root / 'project')
        process = subprocess.Popen([sys.executable, '-I', '-m', 'agent_circuit_breaker.owner', 'serve',
            '--workspace', info['workspace'], '--state', info['state'], '--config', info['config'],
            '--socket', str(root / 'agent.sock'), '--agent-uid', str(os.getuid()), '--development'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([process.stdout], [], [], 15)[0], 'owner did not start'
            assert process.stdout.readline(), 'owner failed at startup'
            agent, owner = root / 'agent.sock', info['control_socket']
            result = cli('verify', '--socket', agent, '--control-socket', owner, '--report', 'reports/smoke.json')
            assert result['verified']
            pending = cli('call', 'database_change', '--socket', agent, '--arguments',
                          json.dumps({'operation': 'close_ticket', 'parameters': {'id': 1, 'status': 'closed'}}))
            assert pending['decision'] == 'PENDING_APPROVAL'
            inspected = cli('inspect', pending['review_id'], '--socket', owner)
            assert inspected['database_preview']['rows_affected'] == 1
            cli('approve', pending['review_id'], '--socket', owner, '--fingerprint', inspected['action_fingerprint'])
            executed = cli('commit', pending['review_id'], '--socket', agent)
            assert executed['outcome'] == 'executed'
            with sqlite3.connect(root / 'project/tickets.sqlite3') as db:
                assert db.execute('SELECT id,status FROM tickets ORDER BY id').fetchall() == [(1, 'closed'), (2, 'open'), (3, 'closed')]
            assert request(agent, {'method': 'commit', 'review_id': pending['review_id'], 'request_id': 'replay'})['decision'] == 'BLOCK'
            exported = cli('export', '--socket', owner, '--output', root / 'evidence.json', '--limit', '1')
            assert exported['next_sequence'] == 1
            key_path = Path(info['state']) / 'provenance.key'
            assert cli('verify-evidence', root / 'evidence.json', '--key-file', key_path)['verified']
            # Every event can be independently retained even when the ledger grows.
            position, sequences = 0, []
            while position is not None:
                bundle = request(owner, {'method': 'export', 'from_sequence': position, 'limit': 2})
                assert verify_bundle(bundle, key_path.read_bytes())['verified']
                sequences.extend(e['sequence'] for e in bundle['payload']['events'])
                position = bundle['payload']['next_sequence']
            assert sequences == list(range(bundle['payload']['total_events']))
            assert request(agent, {'method': 'status'})['effects'] == {'database_rows': 1, 'files_written': 1}
            print(json.dumps({'owner_cli': 'passed', 'real_file_copy': True, 'real_sql_update': True,
                              'single_use_approval': True, 'paginated_evidence': True}))
        finally:
            process.terminate()
            process.communicate(timeout=10)


if __name__ == '__main__':
    main()
