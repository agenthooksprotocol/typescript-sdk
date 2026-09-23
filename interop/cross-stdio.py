"""Run the shared corpus in both TS/Rust stdio directions; no source edits."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

sdk = Path(__file__).resolve().parents[1]
rust = sdk.parent / 'rust-sdk'
scenarios = sdk.parent / 'agent-hooks-protocol/interop/scenarios.json'
adapters = {p.name: json.loads((p / 'interop/adapter.json').read_text()) for p in [sdk, rust]}
failed = False
for client, server in [(sdk, rust), (rust, sdk)]:
    with tempfile.TemporaryDirectory(prefix='ahp-ts-rust-') as tmp:
        directory = Path(tmp)
        ready, report = directory / 'ready.json', directory / 'report.json'
        server_config, client_config = directory / 'server.json', directory / 'client.json'
        common = dict(transport='stdio', scenarioFile=str(scenarios), auth=dict(mode='none'),
                      schemaDir=str(sdk.parent / 'agent-hooks-protocol/schema/draft'))
        server_config.write_text(json.dumps(dict(common, readinessFile=str(ready))))
        client_config.write_text(json.dumps(dict(common, reportFile=str(report),
            serverCommand=adapters[server.name]['server'], serverCwd=str(server), serverConfig=str(server_config))))
        try:
            result = subprocess.run(adapters[client.name]['client'] + ['--config', str(client_config)],
                                    cwd=client, capture_output=True, timeout=90)
            rows = json.loads(report.read_text())['results'] if report.exists() else []
            bad = [dict(id=r['id'], status=r['status']) for r in rows if r['status'] != 'passed']
            print(json.dumps(dict(pair=client.name + ' -> ' + server.name, exit=result.returncode,
                                  passed=len(rows)-len(bad), total=len(rows), failed=bad[:8])))
            failed |= result.returncode != 0 or bool(bad) or not rows
        finally:
            if ready.exists():
                pid = json.loads(ready.read_text()).get('pid')
                if pid:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        os.kill(pid, signal.SIGKILL)
                        print('Cleaned residual server process')
                        failed = True
if failed:
    raise SystemExit(1)
