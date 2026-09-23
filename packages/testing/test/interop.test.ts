import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import process from 'node:process';
import { createAuth } from '../src/interop/auth.js';
import { atomicScenarios } from '../src/interop/atomic-client.js';
import { runInterop, resolveCredential, request } from '../src/interop/client.js';

test('synthetic interop: real concurrent stdio, HTTP, TLS and explicit auth matrix', async () => {
  const report = await runInterop();
  assert.equal(report.ok, true, JSON.stringify(report.results.filter(row => row.status === 'failed')));
  assert.equal(report.results.length, 34);
  assert.equal(report.results.filter(row => row.status === 'inapplicable').length, 4);
  assert.ok(report.results.some(row => row.id === 'stdio-repeat' && row.actual === 'no-effect'));
  // The report is language neutral, with no wire bodies, tokens or authorization headers.
  for (const row of report.results) assert.deepEqual(Object.keys(row).sort(), ['actual', 'auth', 'expected', 'id', 'status', 'transport']);
});
test('credential references fail closed and resolve outside protocol payloads', () => {
  assert.equal(resolveCredential('env:TEST', { TEST: 'fixture' }, {}), 'fixture');
  assert.equal(resolveCredential('credential:TEST', {}, { TEST: 'fixture' }), 'fixture');
  for (const reference of ['env:MISSING', 'credential:MISSING', 'literal:secret', 'malformed']) {
    let rejected = false;
    try { resolveCredential(reference, {}, {}); } catch { rejected = true; }
    assert.equal(rejected, true);
  }
});

test('HTTP authorization is independent of JSON-RPC correlation and event identifiers', async () => {
 const child=spawn(process.execPath,[new URL('../src/interop/server.js',import.meta.url).pathname],{stdio:['pipe','pipe','pipe','ipc'],shell:false});
 child.stdout.resume();child.stderr.resume();
 const exited=new Promise<void>(resolve=>child.once('exit',()=>resolve()));
 const deadline=setTimeout(()=>child.kill(),15000);
 try {
  const ready=await new Promise<{httpPort:number}>((resolve,reject)=>{
   child.once('message',(message:any)=>message.type==='ready'?resolve(message):reject(Error('Missing readiness')));
   child.once('error',reject);child.once('exit',()=>reject(Error('Server exited')));
  });
  const auth=createAuth();
  for(const id of ['unrelated-correlation','another-event']) {
   const wire=structuredClone(atomicScenarios()[0]!.expected.requests[0]) as any;
   wire.id=id;wire.params.event.id=id;
   const body=JSON.stringify(wire);
   const accepted=await request(ready.httpPort,'/bearer',body,`Bearer ${auth.credentials.bearer}`);
   assert.equal(accepted.status,200);assert.equal(JSON.parse(accepted.body).id,id);
   assert.equal((await request(ready.httpPort,'/bearer',body,`Bearer ${id}`)).status,401);
   assert.equal((await request(ready.httpPort,'/bearer',body)).status,401);
  }
  // Authentication happens before JSON-RPC decoding, even for malformed input.
  assert.equal((await request(ready.httpPort,'/bearer','{')).status,401);
 } finally {clearTimeout(deadline);child.kill();await exited;}
});
