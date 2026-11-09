"""Release-critical checks against the installed wheel. Run Python with -I."""
import asyncio
import importlib.metadata
import json
import subprocess
import sys
import tempfile
from importlib.resources import files
from pathlib import Path

import agent_circuit_breaker
from agent_circuit_breaker.demo import Demo
from agent_circuit_breaker.hooks_native import decide
from agent_circuit_breaker.integrations import integrate


def main():
    expected=sys.argv[1] if len(sys.argv)>1 else agent_circuit_breaker.__version__
    assert agent_circuit_breaker.__version__ == importlib.metadata.version('agent-circuit-breaker') == expected
    for asset in ('index.html','app.js','style.css'):
        assert files('agent_circuit_breaker').joinpath('demo_assets',asset).read_bytes()
    demo=Demo()
    try:
        async def check():
            work=await demo.run('work'); assert work['files']['reports/incident.md']; assert all(s['decision']=='ALLOW' for s in work['steps'])
            injection=await demo.run('injection'); assert len(injection['receipts'])==1
            protected=[s for s in injection['steps'] if s['label'].startswith('Protected')][0]
            assert protected['decision']=='BLOCK' and not protected['executor_started']
            approval=await demo.run('approval'); assert len(approval['receipts'])==1
            assert approval['steps'][-1]['decision']=='BLOCK' and not approval['steps'][-1]['executor_started']
            interruption=await demo.run('interruption'); assert len(interruption['receipts'])==1
            assert interruption['steps'][-2]['outcome']=='unknown_execution_status'
            assert not interruption['steps'][-1]['executor_started']
            catalog=await demo.run('catalog'); assert catalog['steps'][-1]['decision']=='BLOCK'
        asyncio.run(check())
    finally:
        demo.close()
    assert decide('cursor','beforeShellExecution',{'command':'rm -rf /'})['decision']=='BLOCK'
    with tempfile.TemporaryDirectory() as directory:
        project=Path(directory).resolve()
        for host in ('claude','cursor','codex'):
            integrate(host,project,mode='mcp',operation='install',state=project/'state',policy=project/'policy.json')
            assert integrate(host,project,mode='mcp',operation='verify')['status']=='verified'
            integrate(host,project,mode='mcp',operation='uninstall')
    subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('owner_smoke.py'))], check=True, timeout=45)
    print(json.dumps({'version':expected,'installed_from':str(Path(agent_circuit_breaker.__file__).parent),'critical_scenarios':5,'owner_workflow':'passed','status':'passed'}))

if __name__=='__main__':
    main()
