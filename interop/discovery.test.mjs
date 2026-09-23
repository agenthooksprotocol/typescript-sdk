import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {createServer} from 'node:http';
import {validateCapabilitiesRequest,validateCapabilitiesResponse} from '../packages/sdk/dist/src/draft/index.js';
import {discovery,manifest,listen,body,reply} from './common.mjs';
const discoveryRequest={jsonrpc:'2.0',id:'discovery',method:'hooks/capabilities',params:{protocolVersion:'draft'}};
const discoveryResponse={jsonrpc:'2.0',id:'discovery',result:{protocolVersion:'draft',manifest}};
async function fixture(dir) {
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const row=structuredClone(scenarios[0]);delete row.request.params.state;
 const path=join(dir,'scenarios.json');await writeFile(path,JSON.stringify({version:1,scenarios:[row]}));return {row,path};
}
async function runClient(path) {
 const child=spawn('node',['interop/client.mjs','--config',path],{stdio:['ignore','ignore','ignore']});
 const timer=setTimeout(()=>child.kill('SIGKILL'),10000);
 try {const [code]=await once(child,'exit');return code;} finally {clearTimeout(timer);}
}
test('canonical discovery validates versioned requests and manifest responses',()=>{
 assert.equal(validateCapabilitiesRequest(discoveryRequest).ok,true);
 assert.equal(validateCapabilitiesResponse(discoveryResponse).ok,true);
 for(const request of [{...discoveryRequest,method:'capabilities'},{...discoveryRequest,params:{}},{...discoveryRequest,params:{protocolVersion:'other'}},{...discoveryRequest,jsonrpc:'1.0'}])assert.equal(validateCapabilitiesRequest(request).ok,false);
 for(const response of [{...discoveryResponse,result:discovery},{...discoveryResponse,result:{protocolVersion:'draft',manifest:{events:[]}}},{...discoveryResponse,result:{protocolVersion:'draft',manifest:{events:[{event:'tool.before',modes:[]}],gaps:[]}}}])assert.equal(validateCapabilitiesResponse(response).ok,false);
});
test('real stdio server accepts only canonical discovery envelopes without a session',{timeout:15000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-discovery-'));let child;
 try {
  const {path}=await fixture(dir), config=join(dir,'server.json');await writeFile(config,JSON.stringify({transport:'stdio',scenarioFile:path,readinessFile:join(dir,'ready.json'),auth:{mode:'none'}}));
  child=spawn('node',['interop/server.mjs','--config',config],{stdio:['pipe','pipe','ignore']});
  const lines=createInterface({input:child.stdout});
  for(const request of [discoveryRequest,{...discoveryRequest,params:{}},{...discoveryRequest,method:'capabilities'},{...discoveryRequest,params:{protocolVersion:'other'}}]) {
   const next=once(lines,'line');child.stdin.write(JSON.stringify(request)+'\n');const [line]=await next;const response=JSON.parse(line);
   if(request===discoveryRequest){assert.equal(validateCapabilitiesResponse(response).ok,true);assert.equal(response.id,request.id);assert.ok(response.result.manifest.events.some(e=>e.event==='tool.before'));}
   else {assert.equal(response.error?.code,-32600);assert.equal('result' in response,false);}
  }
  lines.close();const exited=once(child,'exit');child.stdin.end();await exited;
 } finally {child?.kill('SIGKILL');await rm(dir,{recursive:true,force:true});}
});
for(const transport of ['http','stdio'])test(`client ${transport} discovers and validates before intercepting`,{timeout:20000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-client-discovery-'));let server;
 try {
  const {path:scenarioFile,row}=await fixture(dir),traceFile=join(dir,'trace.jsonl');
  for(const valid of [true,false]) {
   const reportFile=join(dir,`report-${valid}.json`),configFile=join(dir,'client.json'),calls=[];
   const cfg={transport,scenarioFile,reportFile,auth:{mode:'none'}};
   if(transport==='http') {
    server=createServer(async(req,res)=>{calls.push(req.url);if(req.url==='/capabilities')return reply(res,200,valid?discovery:{});await body(req);reply(res,200,row.response);});cfg.endpoint=await listen(server);
   } else {
    const peer=join(dir,'peer.mjs'),serverConfig=join(dir,'peer.json');await writeFile(traceFile,'');
    await writeFile(peer,`import {readFileSync,appendFileSync} from 'node:fs';import {createInterface} from 'node:readline';const cfg=JSON.parse(readFileSync(process.argv[process.argv.indexOf('--config')+1]));createInterface({input:process.stdin}).on('line',line=>{const request=JSON.parse(line);appendFileSync(cfg.traceFile,line+'\\n');process.stdout.write(JSON.stringify(request.method==='hooks/capabilities'?cfg.discoveryResponse:cfg.response)+'\\n');});`);
    await writeFile(serverConfig,JSON.stringify({traceFile,discoveryResponse:valid?discoveryResponse:{...discoveryResponse,result:discovery},response:row.response}));
    Object.assign(cfg,{serverCommand:['node',peer],serverConfig});
   }
   await writeFile(configFile,JSON.stringify(cfg));assert.equal(await runClient(configFile),valid?0:1);
   const report=JSON.parse(await readFile(reportFile,'utf8'));assert.equal(report.results[0].status,valid?'passed':'failed');
   if(transport==='http'){assert.deepEqual(calls,valid?['/capabilities','/intercept']:['/capabilities']);await new Promise(r=>server.close(r));server=undefined;}
   else {const requests=(await readFile(traceFile,'utf8')).trim().split('\n').map(JSON.parse);assert.deepEqual(requests[0],discoveryRequest);assert.equal(requests.length,valid?2:1);}
  }
 } finally {if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}await rm(dir,{recursive:true,force:true});}
});
