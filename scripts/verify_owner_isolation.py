"""Real Linux container isolation acceptance. Requires Docker; no production data.

Builds from the supplied wheel in a minimal temporary context. Only uniquely
named fixture containers/volumes are removed. Agent has no network or data mount.
"""
import argparse
import json
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def docker(*args, input=None, check=True):
    result = subprocess.run(['docker', *map(str, args)], input=input, capture_output=True, text=True, timeout=240)
    if check and result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    name = 'acb-isolation-' + uuid.uuid4().hex[:12]
    image, data, sockets = name + ':test', name + '-data', name + '-sockets'
    records = []
    def verify(label, condition):
        records.append({'name': label, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(label)
    try:
        with tempfile.TemporaryDirectory(prefix='acb-container-') as directory:
            root = Path(directory)
            (root / 'dist').mkdir()
            shutil.copyfile(args.wheel, root / 'dist' / args.wheel.name)
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'examples/owner/Dockerfile', root / 'Dockerfile')
            docker('build', '-t', image, root)
        for volume in (data, sockets):
            docker('volume', 'create', volume)
        mounts = ['--mount', f'type=volume,src={data},dst=/owner', '--mount', f'type=volume,src={sockets},dst=/run/acb']
        docker('run', '--rm', '--network', 'none', '--user', '0:0', *mounts, image, '-c',
               "import os; os.chown('/owner',10001,10001); os.chmod('/owner',0o700); os.chown('/run/acb',10001,10001); os.chmod('/run/acb',0o755)")
        docker('run', '--rm', '--network', 'none', *mounts, image, '-c',
               "from agent_circuit_breaker.owner_setup import initialize; initialize('/owner/project')")
        restrictions = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--network', 'none', '--pids-limit', '64', '--memory', '256m']
        docker('run', '-d', '--name', name, *restrictions, *mounts, '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', image,
               '-m', 'agent_circuit_breaker.owner', 'serve', '--workspace', '/owner/project/workspace',
               '--state', '/owner/project/state', '--config', '/owner/project/owner.json',
               '--socket', '/run/acb/agent.sock', '--agent-uid', '10002')
        for _ in range(100):
            if '"ready":true' in docker('logs', name).stdout:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('owner startup failed: ' + docker('logs', name).stderr)
        agent = ['run', '--rm', '-i', '--user', '10002:10002', *restrictions,
                 '--mount', f'type=volume,src={sockets},dst=/run/acb,readonly', image, '-']
        probe = '''
import json, os, socket
from pathlib import Path
from agent_circuit_breaker.owner import request
assert os.getuid() == 10002
assert not Path('/owner').exists()
assert not Path('/var/run/docker.sock').exists()
assert not any(k.startswith('AWS_') or k.startswith('ACB_REHEARSAL_') for k in os.environ)
assert [p.name for p in Path('/sys/class/net').iterdir()] == ['lo']
s='/run/acb/agent.sock'
status=request(s, {'method':'status'})
assert status['owner_uid'] == 10001 and status['agent_uid'] == 10002
assert 'separate UID' in status['isolation']
read=request(s, {'method':'call','name':'read_file','arguments':{'path':'incident.json'},'request_id':'read'})
artifact=read['result']['artifact']['id']
copy=request(s, {'method':'call','name':'copy_artifact','arguments':{'artifact_id':artifact,'path':'reports/container.json'},'request_id':'copy'})
assert copy['outcome'] == 'executed'
for method in ('approve','declassify','export','reconcile'):
    assert request(s, {'method':method})['decision'] == 'ERROR'
denied=request(s, {'method':'call','name':'copy_artifact','arguments':{'artifact_id':artifact,'path':'../escape'},'request_id':'escape'})
assert denied['decision'] == 'BLOCK' and denied['executor_started'] is False
try:
    Path(s).unlink()
    raise AssertionError('agent removed socket')
except OSError:
    pass
pending=request(s, {'method':'call','name':'database_change','arguments':{'operation':'close_ticket','parameters':{'id':1,'status':'closed'}},'request_id':'sql'})
assert pending['decision'] == 'PENDING_APPROVAL'
print(json.dumps(pending))
'''
        pending = json.loads(docker(*agent, input=probe).stdout)
        verify('agent has only read-only public socket mount and loopback network', True)
        verify('peer identity enforced and owner administrative methods refused', True)
        verify('permitted read/copy execute; traversal and socket removal refused', True)
        owner_code = '''
import json, sqlite3
from pathlib import Path
from agent_circuit_breaker.owner import request
assert Path('/owner/project/workspace/reports/container.json').read_bytes() == Path('/owner/project/workspace/incident.json').read_bytes()
assert not Path('/owner/project/escape').exists()
with sqlite3.connect('/owner/project/tickets.sqlite3') as db:
    assert db.execute('SELECT status FROM tickets WHERE id=1').fetchone()[0] == 'open'
p=json.loads(input())
answer=request('/owner/project/state/control.sock',{'method':'approve','review_id':p['review_id'],'fingerprint':p['review']['action_fingerprint']})
assert answer['status']=='approved'
'''
        docker('exec', '-i', name, 'python', '-I', '-c', owner_code, input=json.dumps(pending))
        verify('independent owner observes exact file bytes and unchanged unapproved SQL', True)
        commit_code = "from agent_circuit_breaker.owner import request; import json; p=json.loads(input()); r=request('/run/acb/agent.sock',{'method':'commit','review_id':p['review_id'],'request_id':'commit'}); assert r['outcome']=='executed',r"
        # stdin contains the program for python -, so embed the synthetic review ID as data.
        docker(*agent, input=commit_code.replace('json.loads(input())', repr(pending)))
        docker('exec', name, 'python', '-I', '-c', "import sqlite3; db=sqlite3.connect('/owner/project/tickets.sqlite3'); assert db.execute('SELECT id,status FROM tickets ORDER BY id').fetchall()==[(1,'closed'),(2,'open'),(3,'closed')]")
        verify('owner approval permits exactly one actual database row change', True)
        stranger = list(agent)
        stranger[stranger.index('10002:10002')] = '10003:10003'
        docker(*stranger, input="from agent_circuit_breaker.owner import request; r=request('/run/acb/agent.sock',{'method':'status'}); assert r['decision']=='ERROR' and r['executor_started'] is False")
        verify('different unregistered UID cannot use public socket', True)
        docker('restart', name)
        for _ in range(100):
            attempt = docker(*agent, input="from agent_circuit_breaker.owner import request; r=request('/run/acb/agent.sock',{'method':'status'}); assert r['effects']['database_rows']==1", check=False)
            if not attempt.returncode:
                break
            time.sleep(.1)
        verify('container restart retains consumed row budget', attempt.returncode == 0)
        replay = "from agent_circuit_breaker.owner import request; r=request('/run/acb/agent.sock',{'method':'commit','review_id':%r,'request_id':'replay'}); assert r['decision']=='BLOCK'" % pending['review_id']
        docker(*agent, input=replay)
        verify('restarted service rejects approval replay', True)
        report = {'status': 'passed', 'checks': records, 'image': json.loads(docker('image', 'inspect', image).stdout)[0]['Id'],
                  'scope': 'disposable Linux Docker containers, UID 10001 owner / 10002 agent, no agent network or resource mounts'}
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        docker('rm', '-f', name, check=False)
        for volume in (data, sockets):
            docker('volume', 'rm', volume, check=False)
        docker('image', 'rm', image, check=False)


if __name__ == '__main__':
    main()
