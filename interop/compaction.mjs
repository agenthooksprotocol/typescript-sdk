// Offline host fixture, not a new AHP method. Semantics live in the public SDK.
import { runCompaction } from '../packages/sdk/dist/src/compaction.js';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
function receive(request) {
  try {
    if (request.jsonrpc !== '2.0' || request.method !== 'compaction/run') throw Error('invalid request');
    const p = request.params;
    const hooks = boundary => (p[boundary] ?? []).map(row => ({ supplier: row.supplier, failurePolicy: row.failurePolicy ?? 'fail-closed', run: () => { if (row.throw) throw Error('hook failed'); return row.effects; } }));
    const result = runCompaction(p.instructions, hooks('before'), hooks('after'), { itemId: p.itemId, observeOnly: p.observeOnly });
    return { jsonrpc: '2.0', id: request.id ?? null, result };
  } catch { return { jsonrpc: '2.0', id: request.id ?? null, error: { code: -32602, message: 'invalid request' } }; }
}
const mode = process.argv[2];
if (mode === 'stdio') {
  for await (const line of createInterface({ input: process.stdin })) console.log(JSON.stringify(receive(JSON.parse(line))));
} else if (mode === 'server') {
  const server = createServer(async (req, res) => {
    if (req.headers.authorization !== 'Bearer ' + process.env.AHP_COMPACTION_TOKEN) { res.writeHead(401); res.end(); return; }
    let raw = ''; for await (const chunk of req) raw += chunk;
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(receive(JSON.parse(raw))));
  });
  server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({ endpoint: 'http://127.0.0.1:' + server.address().port })));
} else if (mode === 'client') {
  let raw = ''; for await (const chunk of process.stdin) raw += chunk;
  const plan = JSON.parse(raw); let replies;
  if (plan.transport === 'stdio') {
    const out = spawnSync(plan.command[0], [...plan.command.slice(1), 'stdio'], { input: plan.requests.map(r => JSON.stringify(r)+'\n').join(''), encoding: 'utf8', timeout: 60000, maxBuffer: 16*1024*1024 });
    if (out.status !== 0) throw Error(out.stderr || String(out.error));
    replies = out.stdout.trim().split('\n').map(line => JSON.parse(line));
  } else {
    replies = [];
    for (const request of plan.requests) {
      const res = await fetch(plan.endpoint, { method: 'POST', headers: { Authorization: 'Bearer '+plan.token, 'Content-Type': 'application/json' }, body: JSON.stringify(request), signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw Error('HTTP '+res.status);
      replies.push(await res.json());
    }
  }
  console.log(JSON.stringify(replies));
} else throw Error('unknown mode');
