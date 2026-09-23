import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
import {listen,reply} from './common.mjs';
import {rawExchange} from './test-http.mjs';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {digest} from './content-upload.mjs';
import {validateObserve} from './lifecycle-common.mjs';
const cwd=fileURLToPath(new URL('..',import.meta.url));
async function stop(child){if(child&&child.exitCode===null){child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));}}
const clock=1893456000,issuer='urn:ahp:interop:local-issuer',audience='urn:ahp:interop:local-server';
function auth(mode,role){
 const cfg={mode};if(mode==='bearer')cfg.token='TEST-ONLY-event-token';
 if(['oauth','workload'].includes(mode)){const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url'),value=encode({alg:'HS256',typ:'JWT'})+'.'+encode({iss:issuer,aud:audience,purpose:mode,exp:clock+3600});const signingKey=`TEST-ONLY-ahp-interop-${mode}-signing-key`;Object.assign(cfg,{issuer,audience,purpose:mode,clock,signingKey,assertion:value+'.'+createHmac('sha256',signingKey).update(value).digest('base64url')});}
 if(mode==='mtls'){const path=resolve(cwd,'../agent-hooks-protocol/interop/fixtures');Object.assign(cfg,{caFile:join(path,'ca.pem'),certFile:join(path,role+'.pem'),keyFile:join(path,role+'-key.pem')});}return cfg;
}
for(const [transport,mode] of [...['none','bearer','oauth','workload','mtls'].map(mode=>['http',mode]),['stdio','none']])test(`actual ${transport} ${mode} settled observations retain binary content and effective input`,async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-wire-'));let server,client,tokenServer;
 try{
  const bytes=Buffer.from([0,255,128,10]);
  const rows=['normal','denied','stopped','interrupted'].map(status=>{
   const event={id:status,source:'urn:typescript:wire',type:'tool.before',time:'2026-01-01T00:00:00Z',session:{id:'s'},call:{id:status},path:'native',tool:{origin:'native',name:'task',kind:'task',input:{task:1}}};
   const request={jsonrpc:'2.0',id:status,method:'hooks/intercept',params:{protocolVersion:'draft',event,capabilities:{effects:['modify','allow','deny','flow'],modify:{input:{replace:true,merge:true}},flow:{operations:['stop']}}}};
   const effects=[{type:'modify',target:'input',operation:'merge',value:{task:2}},...(status==='denied'?[{type:'deny',reason:'policy'}]:status==='stopped'?[{type:'flow',operation:'stop',reason:'done'}]:[])];
   const steps=[{op:'send',key:'a',slot:'a'},{op:'wait',key:'a'},{op:'release',key:'a'},{op:'receive',slot:'a'},{op:'accept',key:'a'},...(status==='interrupted'?[{op:'cancel',key:'a'}]:[]),{op:'upload',subscription:'body',ref:status,bodyBase64:bytes.toString('base64')},{op:'observe',key:'a',subscription:'body',items:[{id:'item-'+status,kind:'image',mediaType:'application/octet-stream',selection:'body',body:{ref:status,size:bytes.length,sha256:digest(bytes)}}]}];
   return {id:status,requests:{a:request},responses:{a:{jsonrpc:'2.0',id:status,result:{protocolVersion:'draft',effects}}},steps};
  });
  const scenarioFile=join(dir,'rows.json');await writeFile(scenarioFile,JSON.stringify({version:1,scenarios:rows}));
  const cfg={transport,scenarioFile,auth:auth(mode,'client'),upload:{auth:{type:'bearer',tokenEnv:'AHP_TEST_UPLOAD_TOKEN'},timeoutMs:5000,maxBytes:1048576},serverConfig:{uploadAuth:{token:'TEST-ONLY-upload-token',subscriptions:['body']}},reportFile:join(dir,'report.json'),serverCommand:['node','interop/lifecycle-server.mjs'],serverCwd:cwd};
  if(mode==='oauth'){tokenServer=createServer((req,res)=>{req.resume();reply(res,200,{access_token:cfg.auth.assertion});});cfg.auth.tokenEndpoint=await listen(tokenServer);cfg.auth.clientId='test-client';cfg.auth.clientSecret='TEST-ONLY-client-secret';}
  if(transport==='http'){
   const readinessFile=join(dir,'ready.json'),path=join(dir,'server.json');await writeFile(path,JSON.stringify({...cfg,auth:auth(mode,'server'),uploadAuth:{token:'TEST-ONLY-upload-token',subscriptions:['body']},readinessFile}));
   server=spawn(process.execPath,['interop/lifecycle-server.mjs','--config',path],{cwd,stdio:['ignore','ignore','pipe']});
   let error='';server.stderr.on('data',chunk=>error+=chunk);
   const deadline=Date.now()+10000;
   for(;;){try{Object.assign(cfg,JSON.parse(await readFile(readinessFile,'utf8')));break;}catch{if(Date.now()>deadline||server.exitCode!==null)throw Error(error||'Readiness timeout');await delay(10);}}
  }
  if(transport==='http'){cfg.upload.endpoint=cfg.uploadEndpoint;if(mode!=='none'&&mode!=='mtls'){const rejected=await rawExchange(cfg.endpoint,'/observe',{},cfg.auth);assert.equal(rejected.status,401);}}
  const path=join(dir,'client.json');await writeFile(path,JSON.stringify(cfg));
  client=spawn(process.execPath,['interop/lifecycle-client.mjs','--config',path],{cwd,env:{...process.env,AHP_TEST_UPLOAD_TOKEN:'TEST-ONLY-upload-token'},stdio:['ignore','ignore','pipe']});let error='';client.stderr.on('data',chunk=>error+=chunk);
  const code=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{client.kill();reject(Error('Client timeout'));},20000);client.once('exit',code=>{clearTimeout(timer);resolve(code);});});assert.equal(code,0,error);
  const report=JSON.parse(await readFile(cfg.reportFile,'utf8'));
  assert.equal(report.receipts.entries.some(entry=>entry.kind==='view'),false);
  for(const row of rows){const receipt=report.receipts.entries.find(entry=>entry.kind==='received'&&entry.id===row.id);assert.deepEqual(receipt.message,row.requests.a);}
  for(const status of ['normal','denied','stopped','interrupted']){
   const observed=report.receipts.entries.find(entry=>entry.kind==='observed'&&entry.eventId===status);validateObserve(observed.message);
   assert.equal(Object.hasOwn(observed.message.params,'disposition'),false);assert.equal(observed.message.params.event.tool.input.task,2);
   assert.ok(report.receipts.entries.findIndex(entry=>entry.kind==='upload'&&entry.ref===status)<report.receipts.entries.indexOf(observed));
  }
 }finally{await stop(client);await stop(server);if(tokenServer)await new Promise(resolve=>tokenServer.close(resolve));await rm(dir,{recursive:true,force:true});}
});
