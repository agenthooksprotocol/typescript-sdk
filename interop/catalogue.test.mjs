import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {catalogueManifest,evaluateRegistration,catalogueEvents} from './catalogue.mjs';
import {validateCapabilitiesResponse,draftCodecs} from '../packages/sdk/dist/src/draft/index.js';
import {validateObserve} from './lifecycle-common.mjs';
import {TaskLineage} from './task-lineage.mjs';
const registration=(overrides={})=>({protocolVersion:'draft',hooks:[{id:'com.example.test',transport:{type:'http',url:'https://policy.invalid/hooks'},subscriptions:[{events:['tool.before'],mode:'intercept',timeoutMs:500,failurePolicy:'fail-closed',content:{default:'metadata'}}],...overrides}]});
test('catalogue manifest advertises typed observations without invented managed enforcement',()=>{
 assert.equal(catalogueEvents.length,22);
 assert.equal(validateCapabilitiesResponse({jsonrpc:'2.0',id:'discovery',result:{protocolVersion:'draft',manifest:catalogueManifest}}).ok,true);
 assert.equal(catalogueManifest.events.some(e=>e.event==='hook.failure'),false);
 assert.deepEqual(catalogueManifest.managedPolicy,{scopes:['user','project'],disableable:true});
});
test('registration uses discovered capabilities and trusted credential resolution',()=>{
 const evaluate=(r,requirements=[],context={interactive:true,environment:{}})=>evaluateRegistration(r,catalogueManifest,requirements,context).accepted;
 assert.equal(evaluate(registration()),true);
 const requirement={event:'tool.before',mode:'intercept',effects:['modify'],modify:{input:{merge:true}}};
 assert.equal(evaluate(registration(),[requirement]),true);
 assert.equal(evaluate(registration(),[{...requirement,modify:{workspace:{replace:true}}}]),false);
 assert.equal(evaluate(registration(),[{event:'tool.before',mode:'intercept',effects:['ask']}],{interactive:false,environment:{}}),false);
 assert.equal(evaluate(registration({authentication:{type:'bearer',tokenEnv:'TOKEN'}})),false);
 assert.equal(evaluate(registration({authentication:{type:'bearer',tokenEnv:'TOKEN'}}),[],{interactive:true,environment:{TOKEN:'TEST-ONLY'}}),true);
 const duplicate=registration();duplicate.hooks.push(structuredClone(duplicate.hooks[0]));assert.equal(evaluate(duplicate),false);
 const managed=registration();managed.hooks[0].subscriptions[0].scope='managed';managed.hooks[0].subscriptions[0].disableable=false;assert.equal(evaluate(managed),false);
 const observed=registration();observed.hooks[0].subscriptions[0].mode='observe';assert.equal(evaluate(observed),false);
});
test('catalogue native payloads and lineage negatives run through language validation',async()=>{
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/catalogue-scenarios.json','utf8'));
 const lineage=new TaskLineage();
 for(const row of scenarios)for(const step of row.steps){
  if(step.op==='notify'){
   assert.equal(draftCodecs.parseObserveNotification(step.message).ok,true,row.id);validateObserve(step.message);lineage.accept(step.message);
  }else if(step.op==='rawNotify'){
   assert.throws(()=>{validateObserve(step.message);lineage.accept(step.message);},row.id);
  }
 }
});

test('unknown configuration/auth/upload fields are tolerated, recognized fields still validate',()=>{
 const r=registration({futureBackend:{enabled:true},authentication:{type:'bearer',tokenEnv:'EVENT_TOKEN',futureAuth:true}});
 r.futureConfig=true;
 const sub=r.hooks[0].subscriptions[0];sub.futureSubscription={version:2};
 sub.upload={endpoint:'https://uploads.example.test/bytes',timeoutMs:500,maxBytes:0,auth:{type:'bearer',tokenEnv:'UPLOAD_TOKEN',futureAuth:true},futureUpload:true};
 const context={interactive:true,environment:{EVENT_TOKEN:'event',UPLOAD_TOKEN:'upload'}};
 assert.equal(evaluateRegistration(r,catalogueManifest,[],context).accepted,true);
 for(const mutate of [r=>{r.hooks[0].authentication.tokenEnv='bad-name'},r=>{r.hooks[0].subscriptions[0].upload.maxBytes=-1},r=>{r.hooks[0].subscriptions[0].upload.timeoutMs='500'},r=>{r.hooks[0].subscriptions[0].upload.auth.tokenEnv='bad-name'}]){
  const bad=structuredClone(r);mutate(bad);assert.equal(evaluateRegistration(bad,catalogueManifest,[],context).accepted,false);
 }
});
