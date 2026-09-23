import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {createAuth} from '../packages/testing/dist/src/interop/auth.js';
import {rawExchange} from './test-http.mjs';

test('legacy auth server rejects noncanonical state and raw duplicate credentials across HTTP, TLS and stdio',{timeout:15000},async()=>{
 const child=spawn('node',['packages/testing/dist/src/interop/server.js'],{stdio:['pipe','pipe','pipe','ipc']});
 child.stderr.resume();const lines=createInterface({input:child.stdout});
 const deadline=setTimeout(()=>child.kill('SIGKILL'),12000);
 try {
  const [ready]=await once(child,'message');assert.equal(ready.type,'ready');
  const auth=createAuth(),request=JSON.parse(await readFile('packages/testing/interop/scenarios.json','utf8')).request;
  const tokenForm=new URLSearchParams({grant_type:'client_credentials',client_id:auth.credentials.clientId,client_secret:auth.credentials.clientSecret});
  const oauth=auth.token(tokenForm).body.access_token;
  const directory=resolve('packages/testing/interop/fixtures');
  const tls={mode:'mtls',caFile:resolve(directory,'ca.pem'),certFile:resolve(directory,'client.pem'),keyFile:resolve(directory,'client-key.pem')};
  for(const [mode,token] of [['none',undefined],['bearer',auth.credentials.bearer],['oauth',oauth],['workload',auth.assertion()],['mtls',undefined]]) {
   const endpoint=mode==='mtls'?`https://127.0.0.1:${ready.httpsPort}`:`http://127.0.0.1:${ready.httpPort}`,transport=mode==='mtls'?tls:{};
   const fields=token?['Authorization',`Bearer ${token}`]:[];
   const valid=await rawExchange(endpoint,'/'+mode,request,transport,fields);assert.equal(valid.status,200);assert.deepEqual(valid.body.result.effects,[]);
   const invalid=structuredClone(request);invalid.params.state={candidate:null,permission:'garbage'};
   const rejected=await rawExchange(endpoint,'/'+mode,invalid,transport,fields);
   assert.equal(rejected.body.error?.code,-32600,mode);assert.equal(rejected.body.result,undefined,mode);
   const header=`Bearer ${token ?? 'unused'}`;
   for(const values of [[header,'Bearer invalid'],['Bearer invalid',header],[header,header]]) {
    const duplicate=await rawExchange(endpoint,'/'+mode,request,transport,['Authorization',values[0],'authorization',values[1]]);
    assert.equal(duplicate.status,401,`${mode}: duplicate credentials`);
   }
  }
  const invalid=structuredClone(request);invalid.params.state={candidate:null,permission:'garbage'};
  for(const wire of [request,invalid]) {const response=once(lines,'line');child.stdin.write(JSON.stringify(wire)+'\n');const [line]=await response;const value=JSON.parse(line);if(wire===invalid)assert.equal(value.error?.code,-32600);else assert.deepEqual(value.result.effects,[]);}
 } finally {
  clearTimeout(deadline);lines.close();const ended=child.exitCode===null && child.signalCode===null?once(child,'exit'):Promise.resolve();child.kill('SIGKILL');await ended;
 }
});
