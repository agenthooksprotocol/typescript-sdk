import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInterceptResponse, validateInterceptResponse, validateInterceptRequest, draftCodecs, stageResponse } from '@agenthooksprotocol/sdk/draft';
import { parseInterceptResponse as parseRootResponse, validateElicitationMode } from '@agenthooksprotocol/sdk';
import { atomicScenarios } from '../src/interop/atomic-client.js';

const response = (effects: unknown[]) => ({ jsonrpc: '2.0', id: 'first', result: { protocolVersion: 'draft', effects } });
test('canonical and generated draft validation reject unknown effects', () => {
  const wire = response([{ type: 'future-effect', value: 42 }]);
  assert.equal(draftCodecs.parseInterceptResponse(wire).ok, false);
  assert.equal(validateInterceptResponse(wire).ok, false);
  assert.equal(validateInterceptResponse(response([{ type: 'deny' }])).ok, false);
  assert.equal(validateInterceptResponse(response([{ type: 'modify', target: 'input', value: {} }])).ok, false);
  assert.equal(validateInterceptResponse({ ...response([]), extra: 'forward-compatible draft field' }).ok, true);
  assert.equal(parseInterceptResponse('{').ok, false);
});
test('generated codec and canonical validation preserve arbitrary JSON without substitution', () => {
  const value = JSON.parse('{"__proto__":{"polluted":true},"constructor":null,"nested":[null,false,0,"",{"x":1}]}');
  const wire = response([{ type: 'return', value }]);
  const parsed = validateInterceptResponse(wire);
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.deepEqual(JSON.parse(draftCodecs.encodeInterceptResponse(parsed.value)), wire);
  for (const value of [undefined, NaN, Infinity, new Date(), () => 1]) {
    assert.equal(validateInterceptResponse(response([{ type: 'return', value }])).ok, false);
  }
  const cycle: Record<string, unknown> = {}; cycle.self = cycle;
  assert.equal(validateInterceptResponse(response([{ type: 'return', value: cycle }])).ok, false);
});
test('canonical request checks explicit capabilities and current pending state', () => {
  const scenario = atomicScenarios()[0]!;
  const request = scenario.expected.requests[0] as { params: Record<string, unknown> };
  assert.equal(validateInterceptRequest(request).ok, true);
  assert.equal(validateInterceptRequest({ ...request, params: { ...request.params, state: undefined } }).ok, false);
  assert.equal(validateInterceptRequest({ ...request, params: { ...request.params, capabilities: {} } }).ok, false);
});
test('failed atomic staging never mutates the caller-owned pending state', () => {
  const scenario = atomicScenarios().find(s => s.id === 'failed-rewrite-preserves-candidate-approval')!;
  const before = JSON.stringify(scenario.initial);
  const decoded = validateInterceptResponse(scenario.subscribers[0]!.response);
  assert.equal(decoded.ok, true);
  let rejected = false;
  if (decoded.ok) try {
    stageResponse(scenario.initial, decoded.value.result.effects, scenario.subscribers[0]!.capabilities, 'first');
  } catch { rejected = true; }
  assert.equal(rejected, true);
  assert.equal(JSON.stringify(scenario.initial), before);
});

test('draft validation retains event identity and checks full-envelope formats', () => {
  const request = structuredClone(atomicScenarios()[0]!.expected.requests[0]) as any;
  assert.equal(validateInterceptRequest(request).ok, true);
  request.params.event.id = 'wrong-id';
  assert.equal(validateInterceptRequest(request).ok, false);
  request.params.event.id = request.id;
  request.params.event.time = '2026-02-30T00:00:00Z';
  assert.equal(validateInterceptRequest(request).ok, false);
  request.params.event.time = '2026-01-01T00:00:00Z';
  request.params.event.source = 'relative';
  assert.equal(validateInterceptRequest(request).ok, false);
  request.params.event = 'tool.before';
  assert.equal(validateInterceptRequest(request).ok, false);
});

test('unknown effects and operations reject whole compound responses without state mutation', () => {
 const scenario=atomicScenarios()[0]!;
 const before=structuredClone(scenario.initial);
 for (const unknown of [{type:'future-effect'}, {type:'modify',target:'input',operation:'future-operation',value:{task:2}}]) {
  const effects=[{type:'message',text:'must not escape'},{type:'return',value:'must not escape'},unknown];
  assert.equal(validateInterceptResponse(response(effects)).ok,false);
  let rejected=false;
  try {stageResponse(before,effects as Parameters<typeof stageResponse>[1],scenario.subscribers[0]!.capabilities,'local');}catch{rejected=true;}
  assert.equal(rejected,true);assert.deepEqual(before,scenario.initial);
 }
});

test('extensible registration, authentication, upload and capabilities preserve unknown fields', () => {
 const extension={future:{nested:[1,true,null]}};
 const upload={endpoint:'https://upload.example.test/bytes',timeoutMs:100,maxBytes:1024,auth:{type:'bearer',tokenEnv:'UPLOAD_TOKEN',...extension},...extension};
 const registration={protocolVersion:'draft',hooks:[{id:'test.backend',transport:{type:'http',url:'https://event.example.test/hooks',...extension},authentication:{type:'bearer',tokenEnv:'EVENT_TOKEN',...extension},subscriptions:[{events:['tool.before'],mode:'intercept',timeoutMs:100,failurePolicy:'fail-closed',content:{default:'metadata'},upload,...extension}],...extension}],...extension};
 const parsed=draftCodecs.parseRegistration(registration);
 assert.equal(parsed.ok,true);
 if(parsed.ok)assert.deepEqual(JSON.parse(draftCodecs.encodeRegistration(parsed.value)),registration);
 assert.equal(draftCodecs.parseContentUpload(upload).ok,true);
 for(const bad of [{...upload,maxBytes:"invalid"},{...upload,timeoutMs:"invalid"},{...upload,auth:{...upload.auth,type:'future-auth'}}])assert.equal(draftCodecs.parseContentUpload(bad).ok,false);
 const bad=structuredClone(registration);(bad.hooks[0]!.authentication as Record<string,unknown>).tokenEnv=42;
 assert.equal(draftCodecs.parseRegistration(bad).ok,false);
 const caps={effects:['modify'],modify:{input:{replace:false,merge:true,...extension}},...extension};
 assert.equal(draftCodecs.parseCapabilities(caps).ok,true);
 assert.equal(draftCodecs.parseCapabilities({...caps,modify:{input:{replace:false,merge:'yes',...extension}}}).ok,false);
 // The control envelope is extensible, but recognized protocol fields remain validated.
 const control={jsonrpc:'2.0',id:'control',method:'hooks/capabilities',params:{protocolVersion:'draft'},...extension};
 assert.equal(draftCodecs.parseCapabilitiesRequest(control).ok,true);
 assert.equal(draftCodecs.parseCapabilitiesRequest({...control,method:'future-control'}).ok,false);
});

test('root response parser accepts envelope and extension data but rejects unknown deny fields', () => {
 const deny={type:'deny',reason:'policy',code:'com.example.denied',extensions:{'com.example.detail':{future:true}}};
 const wire={...response([deny]),futureEnvelope:true,result:{...response([deny]).result,futureResult:{enabled:true}}};
 assert.deepEqual(parseRootResponse(JSON.stringify(wire),'first'),{protocolVersion:'draft',effects:[deny]});
 const invalid={...wire,result:{...wire.result,effects:[{...deny,ignoredEffect:true}]}};
 let rejected=false;
 try{parseRootResponse(JSON.stringify(invalid),'first');}catch{rejected=true;}
 assert.equal(rejected,true);
});
test('elicitation capabilities accept unknown fields while validating recognized modes', () => {
 const capabilities={form:{futureOption:true},url:{},futureMode:{enabled:true},futureFlag:true};
 assert.deepEqual(validateElicitationMode('form',capabilities),capabilities);
 assert.deepEqual(validateElicitationMode('url',capabilities),capabilities);
 assert.deepEqual(validateElicitationMode('form',{},'mcp'),{form:{}});
 for(const recognized of ['form','url'])for(const value of [null,[],true,'enabled',42]) {
  let rejected=false;
  try{validateElicitationMode('form',{...capabilities,[recognized]:value});}catch{rejected=true;}
  assert.equal(rejected,true,recognized);
 }
 for(const [mode,caps] of [['futureMode',capabilities],['form',{futureMode:{}}]] as const) {
  let rejected=false;
  try{validateElicitationMode(mode,caps);}catch{rejected=true;}
  assert.equal(rejected,true);
 }
});
