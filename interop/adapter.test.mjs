import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {watch} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
import {send} from './security.mjs';
import {rawExchange} from './test-http.mjs';
import {listen,body,reply} from './common.mjs';
const clock=1893456000, issuer='urn:ahp:interop:local-issuer', audience='urn:ahp:interop:local-server';
function jwt(purpose,overrides={}) {const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url'), message=encode({alg:'HS256',typ:'JWT'})+'.'+encode({iss:issuer,aud:audience,purpose,iat:clock,exp:clock+3600,...overrides});return message+'.'+createHmac('sha256',`TEST-ONLY-ahp-interop-${purpose}-signing-key`).update(message).digest('base64url');}
function auth(mode,role) {const cfg={mode};if(mode==='bearer')cfg.token='TEST-ONLY-ahp-interop-static-bearer';if(['oauth','workload'].includes(mode))Object.assign(cfg,{issuer,audience,purpose:mode,clock,signingKey:`TEST-ONLY-ahp-interop-${mode}-signing-key`,assertion:jwt(mode)});if(mode==='mtls'){const fixtures=resolve('../agent-hooks-protocol/interop/fixtures');Object.assign(cfg,{caFile:join(fixtures,'ca.pem'),certFile:join(fixtures,`${role}.pem`),keyFile:join(fixtures,`${role}-key.pem`)});}return cfg;}
const request=id=>({jsonrpc:'2.0',id,method:'hooks/intercept',params:{protocolVersion:'draft',event:{id,source:'urn:ahp:matrix',type:'tool.before',time:'2030-01-01T00:00:00Z',session:{id:'session'},call:{id:'call'},path:'native',tool:{origin:'native',name:'task',kind:'task',input:{task:1}}},capabilities:{effects:['modify','return','deny','message','ask','allow'],modify:{input:{merge:true,replace:true}}},state:{permission:'none',candidate:null}}});
const row=(id,effects,expected)=>({id,request:request(id),response:{jsonrpc:'2.0',id,result:{protocolVersion:'draft',effects}},expected});
const smokeFixtures=[row('rewrite-return',[{type:'return',value:{ok:true}},{type:'modify',target:'input',operation:'merge',value:{task:2}}],{decision:'allow',executed:false,input:{task:2},result:{ok:true},messages:[]}),row('denial',[{type:'deny',reason:'policy'}],{decision:'deny',executed:false}),{...row('unknown',[{type:'future'}],{}),expectError:true}];
const fixtures=process.env.AHP_CENTRAL_MATRIX === '1' ? JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8')).scenarios : smokeFixtures;
function child(command,args) {const proc=spawn(command,args,{stdio:['ignore','pipe','pipe']});proc.stdout.resume();proc.stderr.resume();return proc;}
function exited(proc) {return new Promise((resolve,reject)=>{if(proc.exitCode!==null)return resolve(proc.exitCode);proc.once('error',reject);proc.once('exit',resolve);});}
async function readiness(path,dir) {return new Promise((resolve,reject)=>{const watcher=watch(dir,check),timer=setTimeout(()=>{watcher.close();reject(Error('Readiness watchdog'));},10000);async function check(){try{const value=JSON.parse(await readFile(path,'utf8'));clearTimeout(timer);watcher.close();resolve(value);}catch{}}void check();});}
for(const mode of ['none','bearer','oauth','workload','mtls'])test(`matrix HTTP ${mode}: separate control, actual auth, canonical local effects`,{timeout:20000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-ts-matrix-'));let server,tokenServer;
 try {
 const scenarioFile=join(dir,'scenarios.json'),readinessFile=join(dir,'ready.json'),reportFile=join(dir,'report.json');await writeFile(scenarioFile,JSON.stringify({version:1,scenarios:fixtures}));
 const serverConfig=join(dir,'server.json');await writeFile(serverConfig,JSON.stringify({transport:'http',scenarioFile,readinessFile,auth:auth(mode,'server')}));
 server=child('node',['interop/server.mjs','--config',serverConfig]);const ready=await readiness(readinessFile,dir);assert.notEqual(ready.endpoint,ready.controlEndpoint);
 assert.equal((await (await fetch(ready.controlEndpoint+'/health')).json()).ready,true);
 const clientAuth=auth(mode,'client');let issued=0;
 if(mode==='oauth') {tokenServer=createServer(async(req,res)=>{let text='';for await(const chunk of req)text+=chunk;const form=new URLSearchParams(text);if(form.get('client_id')!=='ahp-interop-client' || form.get('client_secret')!=='TEST-ONLY-ahp-interop-client-secret')return reply(res,401,{});issued++;reply(res,200,{access_token:jwt('oauth'),token_type:'Bearer'});});clientAuth.tokenEndpoint=(await listen(tokenServer))+'/token';clientAuth.clientId='ahp-interop-client';clientAuth.clientSecret='TEST-ONLY-ahp-interop-client-secret';}
 const token=mode==='bearer'?clientAuth.token:['oauth','workload'].includes(mode)?jwt(mode):undefined;
 const capabilities=await send(ready.endpoint,'/capabilities',undefined,clientAuth,token);assert.ok(capabilities.effects.includes('modify'));assert.equal(capabilities.effects.includes('future'),false);
 if(mode!=='none') {
  const badAuth=mode==='mtls'?{mode:'none'}:clientAuth;
  await assert.rejects(()=>send(ready.endpoint,'/capabilities',undefined,badAuth,'invalid'));
  await assert.rejects(()=>send(ready.endpoint,'/intercept',fixtures[0].request,badAuth,'invalid'));
  if(['oauth','workload'].includes(mode))for(const bad of [jwt(mode,{exp:clock}),jwt(mode,{aud:'wrong'}),jwt(mode,{iss:'wrong'}),jwt(mode,{purpose:'wrong'}),jwt(mode==='oauth'?'workload':'oauth')])await assert.rejects(()=>send(ready.endpoint,'/intercept',fixtures[0].request,clientAuth,bad));
  assert.deepEqual(await (await fetch(ready.controlEndpoint+'/receipts')).json(),{requests:[]});
 }
 // Repeated fields must be rejected before Node's normalized headers hide them.
 const validHeader=`Bearer ${token ?? 'unused'}`;
 for(const values of [[validHeader,'Bearer invalid'],['Bearer invalid',validHeader],[validHeader,validHeader]]) {
  const fields=['Authorization',values[0],'aUtHoRiZaTiOn',values[1]];
  for(const [path,payload] of [['/capabilities',undefined],['/intercept',fixtures[0].request]]) {
   const response=await rawExchange(ready.endpoint,path,payload,clientAuth,fields);
   assert.equal(response.status,401,`${mode} ${path}: duplicate Authorization`);
  }
 }
 const invalid=structuredClone(fixtures[0].request);invalid.params.state.permission='garbage';
 const rejected=await rawExchange(ready.endpoint,'/intercept',invalid,clientAuth,token?['Authorization',validHeader]:[]);
 assert.equal(rejected.status,400,`${mode}: invalid canonical pending permission`);
 assert.deepEqual(await (await fetch(ready.controlEndpoint+'/receipts')).json(),{requests:[]});
 if(mode==='mtls') {
  const before=(await (await fetch(ready.controlEndpoint+'/health')).json()).tlsRejections;
  const fixtures=resolve('../agent-hooks-protocol/interop/fixtures');
  const untrusted={...clientAuth,certFile:join(fixtures,'untrusted-client.pem'),keyFile:join(fixtures,'untrusted-client-key.pem')};
  await assert.rejects(()=>send(ready.endpoint,'/intercept',invalid,untrusted));
  const health=await (await fetch(ready.controlEndpoint+'/health')).json();
  assert.ok(health.tlsRejections>before,JSON.stringify(health));
  assert.ok(Object.keys(health.tlsRejectionCodes).every(code=>/^[A-Z0-9_]+$/.test(code)));
  assert.deepEqual(await (await fetch(ready.controlEndpoint+'/receipts')).json(),{requests:[]});
 }
 const clientConfig=join(dir,'client.json');await writeFile(clientConfig,JSON.stringify({transport:'http',endpoint:ready.endpoint,scenarioFile,reportFile,auth:clientAuth}));
 const client=child('node',['interop/client.mjs','--config',clientConfig]);assert.equal(await exited(client),0);const report=JSON.parse(await readFile(reportFile,'utf8'));assert.deepEqual(report.results.map(r=>r.status),fixtures.map(()=> 'passed'));for(const row of fixtures.filter(row=>row.expectError))assert.deepEqual(report.results.find(result=>result.id===row.id).actual,{rejected:true});if(mode==='oauth')assert.equal(issued,1);
 const receipts=await (await fetch(ready.controlEndpoint+'/receipts')).json();assert.deepEqual(receipts.requests,fixtures.map(row=>row.request));
 const health=await (await fetch(ready.controlEndpoint+'/health')).json();assert.deepEqual(health.requests,receipts.requests);
 assert.equal(receipts.requests.length,fixtures.length);assert.equal(JSON.stringify(receipts).includes('TEST-ONLY'),false);
 await fetch(ready.controlEndpoint+'/shutdown',{method:'POST'});await exited(server);
 } finally {server?.kill('SIGKILL');await new Promise(resolve=>tokenServer?tokenServer.close(resolve):resolve());await rm(dir,{recursive:true,force:true});}
});
test('matrix stdio sends canonical envelopes directly and cleans child process',{timeout:20000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-ts-stdio-'));
 try {const scenarioFile=join(dir,'scenarios.json'),serverConfig=join(dir,'server.json'),clientConfig=join(dir,'client.json'),reportFile=join(dir,'report.json'),readinessFile=join(dir,'ready.json');await writeFile(scenarioFile,JSON.stringify({version:1,scenarios:fixtures}));await writeFile(serverConfig,JSON.stringify({transport:'stdio',scenarioFile,readinessFile,auth:{mode:'none'}}));await writeFile(clientConfig,JSON.stringify({transport:'stdio',serverCommand:['node','interop/server.mjs'],serverCwd:process.cwd(),serverConfig,scenarioFile,reportFile,auth:{mode:'none'}}));const proc=child('node',['interop/client.mjs','--config',clientConfig]);assert.equal(await exited(proc),0);const report=JSON.parse(await readFile(reportFile,'utf8'));assert.deepEqual(report.results.map(r=>r.status),fixtures.map(()=> 'passed'));for(const row of fixtures.filter(row=>row.expectError))assert.deepEqual(report.results.find(result=>result.id===row.id).actual,{rejected:true});const ready=JSON.parse(await readFile(readinessFile,'utf8'));assert.throws(()=>process.kill(ready.pid,0));}finally{await rm(dir,{recursive:true,force:true});}
});
