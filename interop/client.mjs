import {waitForStdioReady} from './stdio-startup.mjs';
import {prepareRequestContent} from './content-upload.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {config,scenarios,atomic} from './common.mjs';
import {accessToken,send} from './security.mjs';
import {validateInterceptRequest,validateCapabilities,validateCapabilitiesRequest,validateCapabilitiesResponse} from '../packages/sdk/dist/src/draft/index.js';
import {evaluate,matches} from './evaluator.mjs';
const cfg=await config(), rows=await scenarios(cfg.scenarioFile), results=[];
let child; const pending=new Map();
function stdioCall(request) {
 return new Promise((resolve,reject)=>{
  const id=request.id;
  const timer=setTimeout(()=>{pending.delete(id);reject(Error('Response watchdog'));},15000);
  pending.set(id,{resolve:value=>{clearTimeout(timer);pending.delete(id);resolve(value);},reject:error=>{clearTimeout(timer);pending.delete(id);reject(error);}});
  child.stdin.write(JSON.stringify(request)+'\n');
 });
}
const auth=cfg.auth ?? {mode:'none'}, unsupported=!['none','bearer','oauth','workload','mtls'].includes(auth.mode), inapplicable=cfg.transport==='stdio' && auth.mode!=='none';
try {
 const token=cfg.transport==='http' && !unsupported?await accessToken(auth):undefined;
 if(cfg.transport==='stdio' && !inapplicable) {
  if(!cfg.serverCommand?.length || !cfg.serverConfig) throw Error('Missing stdio configuration');
  child=spawn(cfg.serverCommand[0],[...cfg.serverCommand.slice(1),'--config',cfg.serverConfig],{cwd:cfg.serverCwd,stdio:['pipe','pipe','pipe']});
  createInterface({input:child.stdout}).on('line',line=>{try{const value=JSON.parse(line);(pending.get(value?.id) ?? pending.values().next().value)?.resolve(value);}catch{for(const item of pending.values()) item.reject(Error('Invalid JSON'));}});
  child.stderr.resume();const fail=()=>{for(const item of pending.values())item.reject(Error('Server exited'));};child.on('error',fail);child.on('exit',fail);
  await waitForStdioReady(child,cfg.serverConfig);
 }
 let discoveredEvents;
 if(!unsupported && !inapplicable) {
  if(child) {
   const request={jsonrpc:'2.0',id:'discovery',method:'hooks/capabilities',params:{protocolVersion:'draft'}};
   if(!validateCapabilitiesRequest(request).ok) throw Error('Invalid discovery request');
   const response=await stdioCall(request);
   if(!validateCapabilitiesResponse(response).ok || response.id!==request.id) throw Error('Invalid discovery response');
   discoveredEvents=response.result.manifest.events;
  } else {
   const response=await send(cfg.endpoint,'/capabilities',undefined,auth,token);
   if(!validateCapabilities(response).ok) throw Error('Invalid discovery capabilities');
  }
 }
 for(const row of rows) {
  if(unsupported || inapplicable){results.push({id:row.id,status:unsupported?'unsupported':'inapplicable',actual:null});continue;}
  let received=false;
  try {
   if(!validateInterceptRequest(row.request).ok) throw Error('Invalid canonical request');
   if(discoveredEvents && !discoveredEvents.some(entry=>entry.event===row.request.params.event.type && entry.modes.includes('intercept'))) throw Error('Unsupported event');
   await prepareRequestContent(row.request,row.contentBodies,cfg,row.subscription);
   let response;
   if(child) response=await stdioCall(row.request);
   else response=await send(cfg.endpoint,'/intercept',row.request,auth,token);
   received=true;
   const actual=evaluate(row.request,response);
   results.push({id:row.id,status:!row.expectError && matches(actual,row.expected ?? {})?'passed':'failed',actual});
  } catch {results.push({id:row.id,status:row.expectError && received?'passed':'failed',actual:row.expectError && received?{rejected:true}:null,...(row.expectError && received?{}:{error:'Validation, transport, or effect application failed'})});}
 }
} catch {for(const row of rows)if(!results.some(r=>r.id===row.id))results.push({id:row.id,status:'failed',actual:null,error:'Adapter setup failed'});}
finally {
 if(child) {child.stdin.end();child.kill('SIGTERM');await new Promise(resolve=>{if(child.exitCode!==null || child.signalCode!==null)return resolve();const timer=setTimeout(()=>child.kill('SIGKILL'),1000);child.once('exit',()=>{clearTimeout(timer);resolve();});});}
 await atomic(cfg.reportFile,{language:'typescript',results});
}
if(results.some(r=>r.status==='failed'))process.exitCode=1;
