import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {evaluate,matches} from './evaluator.mjs';
test('central canonical scenarios are independently evaluated with strict expected-key comparison',async()=>{
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 for(const scenario of scenarios){
  if(scenario.expectError)assert.throws(()=>evaluate(scenario.request,scenario.response),scenario.id);
  else {const actual=evaluate(scenario.request,scenario.response);assert.equal(matches(actual,scenario.expected),true,scenario.id);}
 }
});

test('valid requests without optional pending state use native permission and no candidate',async()=>{
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const request=structuredClone(scenarios[0].request);delete request.params.state;
 const response={jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',effects:[]}};
 const actual=evaluate(request,response);assert.equal(actual.decision,'allow');assert.equal(actual.executed,true);assert.equal('result' in actual,false);
});
test('continuation output is accumulated staged state, coalesces allowance, and stop consumes none',async()=>{
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const base=scenarios.find(s=>s.id==='flow-continue-at-finish');
 const response=effects=>({jsonrpc:'2.0',id:base.request.id,result:{protocolVersion:'draft',effects}});
 const again={type:'flow',operation:'continue',instruction:'first'}, second={...again,instruction:'second'}, stop={type:'flow',operation:'stop',reason:'done'};
 const continued=evaluate(base.request,response([again,second]));assert.deepEqual(continued.continuationInstructions,['first','second']);assert.equal(continued.continuationRemaining,1);
 for(const effects of [[stop],[again,stop],[stop,again]]){const actual=evaluate(base.request,response(effects));assert.equal(actual.flow,'stop');assert.equal(actual.continuationRemaining,2);assert.deepEqual(actual.continuationInstructions,effects.length===1?[]:['first']);}
});

test('serial responses retain accepted stop, instructions and injections in both evaluators',async()=>{
 const {evaluate:lifecycle}=await import('./lifecycle-evaluator.mjs');
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const seed=scenarios.find(row=>!row.expectError&&row.request.params.event.type==='tool.before').request;
 for(const evaluate of [lifecycle,(await import('./evaluator.mjs')).evaluate]){
  const first=structuredClone(seed);first.params.capabilities={...first.params.capabilities,effects:[...new Set([...first.params.capabilities.effects,'flow'])],flow:{operations:['stop']}};
  const accepted=evaluate(first,{jsonrpc:'2.0',id:first.id,result:{protocolVersion:'draft',effects:[{type:'flow',operation:'stop',reason:'accepted stop'}]}});
  assert.equal(accepted.flow,'stop');assert.equal(accepted.executed,false);
  const next=structuredClone(first),injection={target:'context',operation:'append',deliverAt:'next_turn',value:{text:'accepted context'}};
  next.params.state={permission:'none',candidate:null,flow:accepted.flow,instructions:['accepted instruction'],injections:[injection]};
  const original=structuredClone(next),response={jsonrpc:'2.0',id:next.id,result:{protocolVersion:'draft',effects:[]}};
  const settled=evaluate(next,response);assert.equal(settled.flow,'stop');assert.equal(settled.executed,false);assert.equal(Object.hasOwn(settled,'result'),false);
  assert.deepEqual(settled.continuationInstructions,['accepted instruction']);assert.deepEqual(settled.injections,[injection]);assert.deepEqual(next,original);
 }
});
test('semantic matcher rejects unauthorized result and scheduling extras',()=>{
 for(const decision of ['deny','ask']){
  const expected={decision,executed:false};assert.equal(matches({...expected,result:'unauthorized'},expected),false);
  assert.equal(matches({...expected,injections:[{value:'hidden'}]},expected),false);
  assert.equal(matches({...expected,continuationInstructions:['hidden']},expected),false);
 }
});

test('serial continuation preserves remaining allowance without consuming it twice',async()=>{
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const seed=scenarios.find(row=>row.id==='flow-continue-at-finish');
 for(const evaluate of [(await import('./evaluator.mjs')).evaluate,(await import('./lifecycle-evaluator.mjs')).evaluate]){
  const request=structuredClone(seed.request);request.params.state={permission:'none',candidate:null,flow:'continue',instructions:['previous'],injections:[]};request.params.capabilities.flow.remainingContinuations=1;
  const response=effects=>({jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',effects}});
  const retained=evaluate(request,response([]));assert.equal(retained.flow,'continue');assert.equal(retained.continuationRemaining,1);assert.deepEqual(retained.continuationInstructions,['previous']);
  const coalesced=evaluate(request,response([{type:'flow',operation:'continue',instruction:'additional'}]));assert.equal(coalesced.continuationRemaining,1);assert.deepEqual(coalesced.continuationInstructions,['previous','additional']);
 }
});

test('unknown capabilities and controls are extensible, unsupported effects remain atomic failures',async()=>{
 const {validateCapabilities}=await import('../packages/sdk/dist/src/draft/index.js');
 const {scenarios}=JSON.parse(await readFile('../agent-hooks-protocol/interop/scenarios.json','utf8'));
 const request=structuredClone(scenarios.find(row=>!row.expectError&&row.request.params.event.type==='tool.before').request);
 request.params.capabilities={effects:['modify','message'],modify:{input:{replace:true,merge:true,futureControl:{enabled:true}}},futureCapability:{version:2}};
 assert.equal(validateCapabilities(request.params.capabilities).ok,true);
 assert.equal(validateCapabilities({...request.params.capabilities,modify:{input:{replace:'yes'}}}).ok,false);
 const before=structuredClone(request),reply=effects=>({jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',effects}});
 for(const effect of [{type:'future-effect'},{type:'modify',target:'input',operation:'future-operation',value:{}},{type:'modify',target:'future-target',operation:'replace',value:{}}]){
  assert.throws(()=>evaluate(request,reply([{type:'message',text:'must not publish'},effect])));
  assert.deepEqual(request,before);
 }
 assert.equal(evaluate(request,reply([])).decision,'allow');
});
