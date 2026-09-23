#!/usr/bin/env node
import {runChain} from './observation-chain.mjs';
import {evaluateRegistration} from './catalogue.mjs';
import {TaskLineage} from './task-lineage.mjs';
import {effectiveEvent} from './settlement.mjs';
import {uploadBytes} from './content-upload.mjs';
import {accessToken,send,sendStatus} from './security.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {config,scenarios,atomic} from './common.mjs';
import {validateInterceptRequest,validateInterceptResponse,validateCapabilitiesRequest,validateCapabilitiesResponse} from '../packages/sdk/dist/src/draft/index.js';
import {evaluate} from './lifecycle-evaluator.mjs';
import {validateObserve,http,control} from './lifecycle-common.mjs';
const cfg=await config(), rows=await scenarios(cfg.scenarioFile), results=[];
if(cfg.suite!==undefined&&!['lifecycle','catalogue'].includes(cfg.suite))throw Error('Unknown suite');
const auth=cfg.auth ?? {mode:'none'};
if(!['none','bearer','oauth','workload','mtls'].includes(auth.mode) || (cfg.transport==='stdio'&&auth.mode!=='none'))throw Error('Unsupported lifecycle authentication');
const token=cfg.transport==='http'?await accessToken(auth):undefined;
let child,temp,lines,transportError;
const confirmed=new Map();
function ready(event,subscription){for(const item of event.items ?? [])if(item.body){const matches=[...confirmed.entries()].filter(([key])=>JSON.parse(key)[1]===item.body.ref);const body=subscription===undefined?(matches.length===1?matches[0][1]:undefined):confirmed.get(JSON.stringify([subscription,item.body.ref]));if(!body || body.size!==item.body.size || body.sha256!==item.body.sha256)throw Error('Content not confirmed before event dispatch');item.body=structuredClone(body);}}
const pending=new Map(), discarded=new Map(), discardWaits=new Set();
function waitDiscard(id,count){return new Promise((resolve,reject)=>{
 const timer=setTimeout(()=>done(Error('Unsolicited drain watchdog')),15000);
 function done(error){clearTimeout(timer);discardWaits.delete(check);error?reject(error):resolve();}
 function check(){if(transportError)done(transportError);else if((discarded.get(id) ?? 0)>=count)done();}
 discardWaits.add(check);check();
});}
function fail(error){transportError=error;for(const queue of pending.values())for(const item of queue)item.reject(error);pending.clear();for(const check of [...discardWaits])check();}
function stdioCall(request){
 if(transportError) return Promise.reject(transportError);
 return new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(Error('Response watchdog')),15000);
  const queue=pending.get(request.id) ?? [];
  const attempt={id:request.id,resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}};
  queue.push(attempt);pending.set(request.id,queue);
  child.stdin.write(JSON.stringify(request)+'\n');
 });
}
try{
 if(cfg.transport==='stdio'){
  temp=await mkdtemp(join(tmpdir(),'ahp-ts-lifecycle-'));
  const serverConfig=typeof cfg.serverConfig==='string'?JSON.parse(await readFile(cfg.serverConfig,'utf8')):(cfg.serverConfig ?? {});
  const readinessFile=join(temp,'ready.json'), path=join(temp,'server.json');
  await atomic(path,{...serverConfig,suite:cfg.suite,transport:'stdio',scenarioFile:cfg.scenarioFile,auth:cfg.auth,readinessFile});
  child=spawn(cfg.serverCommand[0],[...cfg.serverCommand.slice(1),'--config',path],{cwd:cfg.serverCwd,stdio:['pipe','pipe','pipe']});
  child.stderr.on('data',data=>process.stderr.write(data));
  child.on('error',fail);child.on('exit',()=>fail(Error('Server exited')));child.stdin.on('error',fail);
  lines=createInterface({input:child.stdout});
  lines.on('line',line=>{try{
   const response=JSON.parse(line);
   // Unsolicited observer effects never enter the pending boundary pipeline.
   if(response.id==='unsolicited-observer') return;
   if(!(cfg.suite==='catalogue'&&response.id==='catalogue-discovery'?validateCapabilitiesResponse(response):validateInterceptResponse(response)).ok)throw Error('Invalid canonical response');
   const queue=pending.get(response.id);
   if(queue?.length){const attempt=queue.shift();if(!queue.length)pending.delete(response.id);attempt.resolve(response);}
   else {discarded.set(response.id,(discarded.get(response.id) ?? 0)+1);for(const check of [...discardWaits])check();}
  }catch(error){fail(error);}});
  if(cfg.childPidFile && child.pid)await atomic(cfg.childPidFile,{pid:child.pid});
  const deadline=Date.now()+15000;
  for(;;){
   if(transportError) throw transportError;
   try{const ready=JSON.parse(await readFile(readinessFile,'utf8'));cfg.controlEndpoint=ready.controlEndpoint;cfg.upload={...cfg.upload,endpoint:cfg.upload?.endpoint ?? ready.uploadEndpoint};break;}catch(error){if(error.code!=='ENOENT')throw error;}
   if(Date.now()>deadline)throw Error('Readiness watchdog');await delay(10);
  }
 }
 if(cfg.suite==='catalogue'){
  const request={jsonrpc:'2.0',id:'catalogue-discovery',method:'hooks/capabilities',params:{protocolVersion:'draft'}};
  if(!validateCapabilitiesRequest(request).ok)throw Error('Invalid discovery request');
  const discovery=child?await stdioCall(request):await send(cfg.endpoint,'/capabilities',request,auth,token);
  if(!validateCapabilitiesResponse(discovery).ok || discovery.id!==request.id)throw Error('Invalid correlated discovery');
  const lineage=new TaskLineage(),counts=new Map();
  for(const row of rows){
   const actual={sent:[],registrations:[]};
   for(const step of row.steps){
    if(transportError)throw transportError;
    if(step.op==='register'){
     actual.registrations.push(evaluateRegistration(step.registration,discovery.result.manifest,step.requirements,step.context));
    }else if(step.op==='notify'||step.op==='rawNotify'){
     const message=structuredClone(step.message);
     if(step.op==='notify'){validateObserve(message);ready(message.params.event,step.subscription);lineage.accept(message);}
     if(child)child.stdin.write(JSON.stringify(message)+'\n');
     else{
      const response=await sendStatus(cfg.endpoint,'/observe',message,auth,token);
      if(step.op==='notify'?response.status!==200:![200,400,409].includes(response.status))throw Error(`Catalogue event transport failed: ${response.status}`);
     }
     actual.sent.push(message);
     const eventId=message.params.event.id,count=(counts.get(eventId) ?? 0)+1;counts.set(eventId,count);
     await control(cfg.controlEndpoint,'/wait-observed',{eventId,count});
    }else throw Error(`Unknown catalogue operation ${step.op}`);
   }
   results.push({id:row.id,status:'passed',actual});
  }
  const receipts=await control(cfg.controlEndpoint,'/receipts');
  await atomic(cfg.reportFile,{language:'typescript',discovery,results,receipts});
 }else{
 const observedCounts=new Map();
 for(const row of rows){
  if(row.chain){
   const actual=await runChain(row,{send:request=>child?stdioCall(request):send(cfg.endpoint,'/intercept',request,auth,token),control:(path,value)=>control(cfg.controlEndpoint,path,value),observe:note=>child?child.stdin.write(JSON.stringify(note)+'\n'):send(cfg.endpoint,'/observe',note,auth,token),validate:request=>{if(!validateInterceptRequest(request).ok)throw Error('Invalid canonical request')}});
   results.push({id:row.id,actual});continue;
  }
  const actual={published:[],cancelled:[],ignored:[],states:{},observations:[],uploadStatuses:[]};
  const states=new Map(), slots=new Map();
  const state=request=>{if(!states.has(request.id))states.set(request.id,{status:'pending',staged:null});return states.get(request.id);};
  async function publish(request,response){
   const local=state(request);if(local.status!=='pending')return;
   const value=evaluate(request,response);local.status='accepted';local.staged=null;
   actual.states[request.id]=value;actual.published.push(request.id);
   await control(cfg.controlEndpoint,'/mark',{scenario:row.id,kind:'accepted',id:request.id});
  }
  for(const step of row.steps){
   if(transportError)throw transportError;
   const request=row.requests[step.key], id=request?.id;
   switch(step.op){
    case 'send':{
     if(!validateInterceptRequest(request).ok)throw Error('Invalid canonical request');
     ready(request.params.event,step.subscription);
     if(slots.has(step.slot))throw Error('Duplicate slot');state(request);
     const promise=(child?stdioCall(request):send(cfg.endpoint,'/intercept',request,auth,token)).then(value=>({value}),error=>({error}));
     slots.set(step.slot,{request,promise});break;
    }
    case 'wait':await control(cfg.controlEndpoint,'/wait',{id,count:step.count ?? 1});break;
    case 'release':await control(cfg.controlEndpoint,'/release',{id});break;
    case 'receive':{
     const attempt=slots.get(step.slot);if(!attempt)throw Error('Unknown slot');
     const {value:response,error}=await attempt.promise;if(error)throw error;
     if(!(cfg.suite==='catalogue'&&response.id==='catalogue-discovery'?validateCapabilitiesResponse(response):validateInterceptResponse(response)).ok)throw Error('Invalid canonical response');
     const local=state(attempt.request);
     if(response.id!==attempt.request.id || local.status!=='pending' || local.staged!==null || attempt.received){actual.ignored.push(step.slot);break;}
     attempt.received=true;local.staged=response;
     await control(cfg.controlEndpoint,'/mark',{scenario:row.id,kind:'acquired',id:attempt.request.id});break;
    }
    case 'cancel':{
     const local=state(request);local.status='cancelled';local.staged=null;
     actual.cancelled.push(id);await control(cfg.controlEndpoint,'/mark',{scenario:row.id,kind:'cancelled',id});break;
    }
    case 'accept':if(state(request).staged)await publish(request,state(request).staged);break;
    case 'failOpen':await publish(request,{jsonrpc:'2.0',id,result:{protocolVersion:'draft',effects:[]}});break;
    case 'emit':{
     if(!child)throw Error('emit requires stdio');
     const id=step.response.id, count=(discarded.get(id) ?? 0)+1;
     await control(cfg.controlEndpoint,'/emit',{response:step.response});
     await waitDiscard(id,count);
     actual.ignored.push(`unsolicited:${id}`);
     await control(cfg.controlEndpoint,'/mark',{scenario:row.id,kind:'discarded',id});break;
    }
    case 'upload':{
     const bytes=step.bodyBase64!==undefined?Buffer.from(step.bodyBase64,'base64'):Buffer.from(step.text ?? '', 'utf8');
     const upload={endpoint:new URL('/upload',cfg.controlEndpoint).href,...cfg.upload,...cfg.uploadPolicies?.[step.subscription],...step.upload};
     const result=await uploadBytes(upload,bytes,{allowLoopback:true,declaredSize:step.size,declaredHash:step.sha256});
     actual.uploadStatuses.push(result.status);if(result.body){confirmed.set(JSON.stringify([step.subscription,step.ref]),result.body);confirmed.set(JSON.stringify([step.subscription,result.body.ref]),result.body);}break;
    }
    case 'observe':{
     const local=state(request);if(local.status==='pending')throw Error('Observe before settlement');
     const event=effectiveEvent(request.params.event,actual.states[id]);
     const input=structuredClone(Object.hasOwn(actual.states,id)?actual.states[id].input:(event.tool?.input ?? event.input ?? {}));
     if(event.tool)event.tool.input=input;
     if(Object.hasOwn(step,'items'))event.items=structuredClone(step.items);
     const notification={jsonrpc:'2.0',method:'hooks/observe',params:{protocolVersion:'draft',event}};
     validateObserve(notification);ready(event,step.subscription);
     if(child)child.stdin.write(JSON.stringify(notification)+'\n');
     else await send(cfg.endpoint,'/observe',notification,auth,token); // Discard all observer response effects.
     const count=(observedCounts.get(event.id) ?? 0)+1;observedCounts.set(event.id,count);
     await control(cfg.controlEndpoint,'/wait-observed',{eventId:event.id,count});
     actual.observations.push({eventId:event.id,subscription:step.subscription,input});break;
    }
    default:throw Error(`Unknown lifecycle op ${step.op}`);
   }
  }
  results.push({id:row.id,actual});
 }
 const receipts=await control(cfg.controlEndpoint,'/receipts');
 await atomic(cfg.reportFile,{language:'typescript',results,receipts});
 }
}finally{
 if(child){
  child.stdin.end();child.kill('SIGTERM');
  await new Promise(resolve=>{if(child.exitCode!==null || child.signalCode!==null)return resolve();const timer=setTimeout(()=>child.kill('SIGKILL'),1000);child.once('exit',()=>{clearTimeout(timer);resolve();});});
  lines?.close();
 }
 if(temp)await rm(temp,{recursive:true,force:true});
}
