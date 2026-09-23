import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {validateInterceptResponse} from '../packages/sdk/dist/src/draft/index.js';
const uploadSubscriptions={body:{scope:'default',auth:{type:'bearer',tokenEnv:'AHP_TEST_BODY'}},metadata:{authorized:false,auth:{type:'bearer',tokenEnv:'AHP_TEST_METADATA'}}};
const uploadPolicies=Object.fromEntries(Object.entries(uploadSubscriptions).map(([name,policy])=>[name,{auth:policy.auth}]));
const env={...process.env,AHP_TEST_BODY:'TEST-ONLY-body',AHP_TEST_METADATA:'TEST-ONLY-metadata'};
const cwd=fileURLToPath(new URL('..',import.meta.url));
const central=JSON.parse(await readFile(cwd+'/../agent-hooks-protocol/interop/lifecycle-scenarios.json','utf8')).scenarios;
// This positive lifecycle case exercises ask settlement, not malformed effects.
// Own the canonical response locally; never repair responses in either adapter.
const askBoundary=central.find(row=>row.id==='ask-boundary-observed');
askBoundary.responses.a.result.effects=[{type:'ask'}];
test('ask lifecycle fixture uses strict canonical fields and rejects added reason',()=>{
 const response=askBoundary.responses.a;
 assert.equal(validateInterceptResponse(response).ok,true);
 const malformed=structuredClone(response);malformed.result.effects[0].reason='confirm';
 assert.equal(validateInterceptResponse(malformed).ok,false);
});
function validateFixtureResponses(rows){
 for(const row of rows){
  const responses=[...Object.entries(row.responses),...Object.entries(row.responseSequences ?? {}).flatMap(([key,values])=>values.map((value,index)=>[`${key}[${index}]`,value]))];
  for(const [key,response] of responses){
   const checked=validateInterceptResponse(response);
   assert.equal(checked.ok,true,`Invalid canonical lifecycle response: scenario=${row.id}, response=${key}`);
  }
 }
}
async function stop(child){
 if(!child || child.exitCode!==null || child.signalCode!==null)return;
 child.kill('SIGTERM');
 await new Promise(resolve=>{const timer=setTimeout(()=>child.kill('SIGKILL'),1000);child.once('exit',()=>{clearTimeout(timer);resolve();});});
}
async function run(rows,transport,reverse=false){
 const dir=await mkdtemp('/tmp/ts-lifecycle-check-');let server,client;
 try{
  const scenarioFile=dir+'/fixture.json', selected=rows.filter(row=>!row.transports || row.transports.includes(transport));
  validateFixtureResponses(selected);
  await writeFile(scenarioFile,JSON.stringify({version:1,scenarios:selected}));
  const config={uploadPolicies,uploadSubscriptions,serverConfig:{uploadSubscriptions},transport,scenarioFile,auth:{mode:'none'},reportFile:dir+'/report.json',childPidFile:dir+'/pid.json',serverCommand:['node','interop/lifecycle-server.mjs'],serverCwd:cwd};
  if(reverse){
   // Proxy deliberately reverses the first two actual protocol replies after
   // both releases. It does not alter IDs/payloads or the real control server.
   const proxy=dir+'/proxy.mjs';
   await writeFile(proxy,`import {spawn} from 'node:child_process';import {createInterface} from 'node:readline';
const child=spawn(process.execPath,['interop/lifecycle-server.mjs',...process.argv.slice(2)],{stdio:['pipe','pipe','inherit']});
process.stdin.pipe(child.stdin);let held=[];
createInterface({input:child.stdout}).on('line',line=>{held.push(line);if(held.length===2){process.stdout.write(held.reverse().join('\\n')+'\\n');held=[];}});
process.on('SIGTERM',()=>child.kill('SIGTERM'));child.on('exit',code=>process.exit(code ?? 0));`);
   config.serverCommand=['node',proxy];
  }
  if(transport==='http'){
   const ready=dir+'/ready.json';await writeFile(dir+'/server.json',JSON.stringify({...config,readinessFile:ready}));
   server=spawn('node',['interop/lifecycle-server.mjs','--config',dir+'/server.json'],{cwd,env,stdio:'inherit'});
   const deadline=Date.now()+10000;
   for(;;){try{Object.assign(config,JSON.parse(await readFile(ready,'utf8')));break;}catch(error){if(error.code!=='ENOENT')throw error;if(Date.now()>deadline || server.exitCode!==null)throw Error('Readiness');await delay(10);}}
  }
  await writeFile(dir+'/client.json',JSON.stringify(config));
  client=spawn('node',['interop/lifecycle-client.mjs','--config',dir+'/client.json'],{cwd,env,stdio:'inherit'});
  const code=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{client.kill('SIGTERM');reject(Error('Client watchdog'));},25000);client.on('error',error=>{clearTimeout(timer);reject(error);});client.on('exit',code=>{clearTimeout(timer);resolve(code);});});
  if(code!==0){
   let failures='report unavailable';
   try{const report=JSON.parse(await readFile(config.reportFile,'utf8'));failures=JSON.stringify((report.results ?? []).filter(result=>result.status==='failed').map(result=>result.id));}catch{}
   assert.equal(code,0,`Lifecycle client failed (${transport}); failed scenario IDs: ${failures}`);
  }
  if(transport==='stdio')assert.ok(JSON.parse(await readFile(config.childPidFile,'utf8')).pid>0);
  const report=JSON.parse(await readFile(config.reportFile,'utf8'));
  assert.equal(report.results.length,selected.length);
  for(const result of report.results)assert.deepEqual(result.actual,selected.find(row=>row.id===result.id).expected,result.id);
  return report;
 }finally{await stop(client);await stop(server);await rm(dir,{recursive:true,force:true});}
}
function fixture(id,keys=['a']){
 const requests={},responses={};
 for(const key of keys){const request=structuredClone(central[0].requests.a);request.id=`local-${id}:${key}`;request.params.event.id=request.id;request.params.event.call={id:request.id};requests[key]=request;
 responses[key]={jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',effects:[{type:'modify',target:'input',operation:'replace',value:{value:key}},{type:'message',text:key}]}};}
 return {id:`local-${id}`,requests,responses,steps:[],expected:{published:[],cancelled:[],ignored:[],states:{},observations:[],uploadStatuses:[]}};
}
const send=key=>[{op:'send',key,slot:key},{op:'wait',key}];
const receive=key=>[{op:'receive',slot:key},{op:'accept',key}];
function accepted(row,key){const id=row.requests[key].id;row.expected.published.push(id);row.expected.states[id]={decision:'allow',executed:true,input:{value:key},messages:[key]};}
const reverse=fixture('reverse',['a','b']);
reverse.steps=[...send('a'),...send('b'),{op:'release',key:'a'},{op:'release',key:'b'},...receive('a'),...receive('b')];accepted(reverse,'a');accepted(reverse,'b');
const duplicate=fixture('first');
duplicate.responseSequences={a:[duplicate.responses.a,{...duplicate.responses.a,result:{protocolVersion:'draft',effects:[{type:'deny',reason:'must not replace first'}]}}]};
duplicate.steps=[...send('a'),{op:'release',key:'a'},{op:'receive',slot:'a'},{op:'send',key:'a',slot:'retry'},{op:'wait',key:'a',count:2},{op:'receive',slot:'retry'},{op:'accept',key:'a'}];accepted(duplicate,'a');duplicate.expected.ignored=['retry'];
const interrupted=fixture('interrupted');
interrupted.steps=[...send('a'),{op:'release',key:'a'},...receive('a'),{op:'cancel',key:'a'},{op:'failOpen',key:'a'},{op:'accept',key:'a'},{op:'observe',key:'a',subscription:'metadata'}];accepted(interrupted,'a');interrupted.expected.cancelled=[interrupted.requests.a.id];interrupted.expected.observations=[{eventId:interrupted.requests.a.id,subscription:'metadata',input:{value:'a'}}];
const unmatched=fixture('unmatched');unmatched.transports=['stdio'];
const stray={jsonrpc:'2.0',id:'local-unknown',result:{protocolVersion:'draft',effects:[{type:'deny',reason:'stray'}]}};
unmatched.steps=[...send('a'),{op:'emit',response:stray},{op:'release',key:'a'},...receive('a')];accepted(unmatched,'a');unmatched.expected.ignored=['unsolicited:local-unknown'];
const empty=fixture('empty',[]);empty.steps=[{op:'upload',subscription:'body',ref:'',size:0,sha256:createHash('sha256').update('').digest('hex'),text:''}];empty.expected.uploadStatuses=[201];
for(const transport of ['stdio','http'])test(`central exact reports and focused lifecycle regressions: ${transport}`,async()=>{
 const report=await run([...central,duplicate,interrupted,unmatched,empty],transport);
 const entries=report.receipts.entries;
 const acquired=entries.filter(e=>e.kind==='acquired' && e.id===duplicate.requests.a.id);assert.equal(acquired.length,1);
 const observed=entries.find(e=>e.kind==='observed' && e.eventId===interrupted.requests.a.params.event.id);
 assert.equal(Object.hasOwn(observed.message.params,'disposition'),false);
 assert.equal(entries.some(e=>e.kind==='view'),false);
 if(transport==='stdio')assert.ok(entries.findIndex(e=>e.kind==='discarded' && e.id==='local-unknown')<entries.findIndex(e=>e.kind==='acquired' && e.id===unmatched.requests.a.id));
});
test('stdio demultiplexes reverse replies despite A-then-B release order',async()=>{await run([reverse],'stdio',true);});
