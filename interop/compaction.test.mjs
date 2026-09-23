import { spawnSync } from 'node:child_process';
import { MessageChannel } from 'node:worker_threads';
import test from 'node:test';
import assert from 'node:assert/strict';
import { runCompaction, compactionCapabilities } from '../packages/sdk/dist/src/compaction.js';
const modify = (target,value) => ({type:'modify',target,operation:'replace',value});
const hook = (supplier,run,failurePolicy='fail-closed') => ({supplier,run,failurePolicy});
test('compaction callbacks and generator see accepted inputs and results', () => {
  const generated=[];
  const r=runCompaction('old',[hook('edit',snapshot=>{snapshot.instructions='leak';return [modify('instructions','new')];})], [
    hook('redact',snapshot=>[modify('summary',snapshot.bodies[snapshot.summary.ref]+':redacted')]),
    hook('watch',snapshot=>{assert.equal(snapshot.bodies[snapshot.summary.ref],'generated:new:redacted');return [];})
  ],{generate:instructions=>{generated.push(instructions);return 'generated:'+instructions;}});
  assert.deepEqual(generated,['new']); assert.deepEqual(r.failures,[]);assert.equal(r.applied,true);
  assert.equal(r.seen[1].summary.id,r.summary.id); assert.notEqual(r.seen[1].summary.ref,r.summary.ref);
  assert.equal(Object.keys(r.bodies).length,2);
});
test('failed compound preserves candidate, messages and input; supplied summary still redacted',()=>{
  const r=runCompaction('old',[
    hook('cache',()=>[{type:'return',value:'cached'}]),
    hook('bad',()=>[modify('instructions','leak'),{type:'message',text:'leak'},modify('summary','wrong')],'fail-open')
  ],[hook('redact',()=>[modify('summary','safe')])],{generate:()=>{throw Error('generator must not run');}});
  assert.equal(r.instructions,'old');assert.deepEqual(r.messages,[]);assert.equal(r.bodies[r.summary.ref],'safe');
  assert.deepEqual(r.provenance,{kind:'supplied',supplier:'cache'});assert.equal(r.applied,true);
});
test('after failure prevents delivery; observation does not advertise control',()=>{
  const r=runCompaction('old',[],[hook('bad',()=>[modify('summary','leak'),modify('instructions','wrong')])]);
  assert.equal(r.applied,false);assert.equal(Object.values(r.bodies).includes('leak'),false);
  assert.deepEqual(compactionCapabilities('after',true),{effects:[],modify:{}});
});

test('blocked observer promises do not gate settlement or downstream', { timeout: 5000 }, async () => {
  // A live port keeps Node running while unref'd best-effort tasks execute.
  const keepalive = new MessageChannel(); keepalive.port1.on('message', () => {});
  let start, release, finish, failed;
  const entered = new Promise(resolve => { start = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const finished = new Promise(resolve => { finish = resolve; });
  const rejected = new Promise(resolve => { failed = resolve; });
  let snapshot;
  try {
    const r = runCompaction('base', [], [], { observeOnly: true, observers: [
      { supplier: 'slow', run: async s => { snapshot = s; start(); await gate; s.bodies = {}; s.instructions = 'mutation'; finish(); return [modify('summary','forbidden')]; } },
      { supplier: 'throw', run: async () => { failed(); throw Error('observer rejected'); } },
    ] });
    const downstream = r.applied ? [r.bodies[r.summary.ref]] : [];
    await entered; await rejected;
    assert.deepEqual(downstream, ['summary:base']);
    assert.equal(snapshot.applied, true);
    assert.deepEqual(snapshot.capabilities, { effects: [], modify: {} });
    const saved = structuredClone(r);
    release(); await finished;
    assert.deepEqual(r, saved); assert.deepEqual(r.failures, []);
  } finally { release(); keepalive.port1.close(); keepalive.port2.close(); }
});

test('observe-only legacy after callbacks are never invoked inline', { timeout: 5000 }, async () => {
  const keepalive = new MessageChannel(); keepalive.port1.on('message', () => {});
  let returned = false, sawReturn = false, notify;
  const entered = new Promise(resolve => { notify = resolve; });
  try {
    const r = runCompaction('base', [], [hook('legacy', () => {
      sawReturn = returned; notify(); return [modify('summary', 'forbidden')];
    })], { observeOnly: true });
    returned = true;
    const downstream = r.applied ? [r.bodies[r.summary.ref]] : [];
    await entered;
    assert.equal(sawReturn, true, 'callback ran inside settlement');
    assert.deepEqual(downstream, ['summary:base']);
    assert.deepEqual(r.failures, []);
    assert.equal(r.bodies[r.summary.ref], 'summary:base');
  } finally { keepalive.port1.close(); keepalive.port2.close(); }
});

test('wire receiver scopes uploads and events by independent credentials, never correlation IDs', {timeout:15000}, async () => {
  const {spawn}=await import('node:child_process');
  const {mkdtempSync,writeFileSync,rmSync}=await import('node:fs');
  const {tmpdir}=await import('node:os');
  const {join}=await import('node:path');
  const {createInterface}=await import('node:readline');
  const {createHash}=await import('node:crypto');
  const directory=mkdtempSync(join(tmpdir(),'ahp-compaction-test-'));
  const configPath=join(directory,'subscriptions.json');
  writeFileSync(configPath,JSON.stringify({one:{kind:'append',target:'instructions',suffix:':one'},two:{kind:'append',target:'instructions',suffix:':two'}}));
  const child=spawn(process.execPath,[new URL('./compaction-wire.mjs',import.meta.url).pathname,'server','unused-schema',directory,configPath],{
    stdio:['ignore','pipe','pipe'],env:{...process.env,
      AHP_COMPACTION_TOKENS:JSON.stringify({'event-one':'one','event-two':'two'}),
      AHP_COMPACTION_UPLOAD_TOKENS:JSON.stringify({'upload-one':'one','upload-two':'two'}),
    },
  });
  child.stderr.resume();
  const exited=new Promise(resolve=>child.once('exit',resolve));
  const lines=createInterface({input:child.stdout});
  try {
    const {endpoint}=await new Promise((resolve,reject)=>{
      lines.once('line',line=>{try{resolve(JSON.parse(line));}catch(error){reject(error);}});
      child.once('error',reject);child.once('exit',()=>reject(Error('Receiver exited before readiness')));
    });
    const bytes=Buffer.from('base'),sha256=createHash('sha256').update(bytes).digest('hex');
    const upload=token=>fetch(endpoint+'/upload',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/octet-stream','content-length':String(bytes.length),'ahp-content-sha256':sha256},body:bytes});
    for(const token of ['event-one','unknown']){const denied=await upload(token);assert.equal(denied.status,401);await denied.arrayBuffer();}
    const uploaded=await upload('upload-one');assert.equal(uploaded.status,201);const descriptor=await uploaded.json();
    assert.deepEqual(Object.keys(descriptor).sort(),['ref','sha256','size']);assert.equal(descriptor.sha256,sha256);
    const event={id:'same-correlation',source:'urn:ahp:compaction-test',time:'2026-09-15T12:00:00Z',session:{id:'test'},type:'context.compact.before',trigger:'manual',items:[],instructions:{id:'instructions',kind:'instructions',mediaType:'text/plain',role:'system',selection:'body',body:descriptor}};
    const request={jsonrpc:'2.0',id:event.id,method:'hooks/intercept',params:{protocolVersion:'draft',event,capabilities:compactionCapabilities('before')}};
    const send=(token,wire=request)=>fetch(endpoint+'/hooks/intercept',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(wire)});
    for(const token of ['upload-one','same-correlation']){const denied=await send(token);assert.equal(denied.status,401);await denied.arrayBuffer();}
    const accepted=await (await send('event-one')).json();assert.equal(accepted.result.effects[0].value,'base:one');
    const crossScope=await (await send('event-two')).json();assert.equal(crossScope.error.code,-32602);
    const second=await upload('upload-two');assert.equal(second.status,201);const secondDescriptor=await second.json();
    assert.notEqual(secondDescriptor.ref,descriptor.ref);
    const other=structuredClone(request);other.params.event.instructions.body=secondDescriptor;
    const scoped=await (await send('event-two',other)).json();assert.equal(scoped.result.effects[0].value,'base:two');
    other.id='unrelated-id';other.params.event.id=other.id;
    const correlated=await (await send('event-two',other)).json();assert.equal(correlated.id,other.id);assert.equal(correlated.result.effects[0].value,'base:two');
  }finally{lines.close();child.kill();await exited;rmSync(directory,{recursive:true,force:true});}
});

test('wire sender refuses plans missing independent upload credentials', () => {
  const result=spawnSync(process.execPath,[new URL('./compaction-wire.mjs',import.meta.url).pathname,'call'],{
    input:JSON.stringify({plan:{credentials:{one:{token:'event-only'}}},sub:'one',name:'case',snapshot:{}}),encoding:'utf8',timeout:5000,
  });
  assert.notEqual(result.status,0);assert.match(result.stderr,/Missing independent compaction credentials/);
});
