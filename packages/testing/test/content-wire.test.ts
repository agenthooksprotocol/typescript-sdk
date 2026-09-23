import test from 'node:test';
import assert from 'node:assert/strict';
import {uploadContent, prepareWireContent, draftCodecs, stageBoundary} from '@agenthooksprotocol/sdk/draft';
test('normalized content selection uses category, confirms binary bytes and emits no fallback body',async()=>{
 const bytes=new Uint8Array([0,255,128]);let uploads=0;
 const item={id:'item',kind:'image',category:'text',mediaType:'application/octet-stream',ref:'ref',bytes};
 const options={selection:{text:'body' as const},authorized:()=>true,mode:'observe' as const,failClosed:false,upload:async(value:Uint8Array)=>{uploads++;assert.deepEqual(value,bytes);const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array(value)));return {ref:"receiver-ref",size:value.length,sha256:Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('')};}};
 const views=await prepareWireContent([item],options);assert.equal(uploads,1);assert.equal(views[0]?.body?.size,3);assert.equal(views[0]?.body?.ref,'receiver-ref');assert.equal(draftCodecs.parseContentItem(views[0]).ok,true);
 const withheld=await prepareWireContent([item],{...options,authorized:()=>false});assert.equal(withheld[0]?.gap?.reason,'permission_withheld');assert.equal(withheld[0]?.body,undefined);assert.equal(uploads,1);
 const omitted=await prepareWireContent([item],{...options,selection:{text:'omit'}});assert.equal(omitted[0]?.gap,undefined);assert.equal(omitted[0]?.body,undefined);assert.equal(uploads,1);
 const failed=await prepareWireContent([item],{...options,upload:async()=>{throw Error('offline');}});assert.equal(failed[0]?.gap?.reason,'transfer_failed');assert.equal(failed[0]?.body,undefined);
});
test('effective operation invalidates cached allowance; fresh ask wins over allow atomically',()=>{
 const before={input:{task:1},values:{output:{status:'open'}},candidate:null,permission:'allow' as const,approval:'approved' as const,denied:false,messages:[]};
 const caps={effects:['modify','allow','ask','deny'],modify:{output:{replace:true}}};
 const modified=stageBoundary(before,[{type:'modify',target:'output',operation:'replace',value:{status:'done'}}],caps,'s');assert.equal(modified.permission,'native');assert.equal(modified.approval,'pending');assert.equal(before.permission,'allow');
 const state=stageBoundary(before,[{type:'modify',target:'output',operation:'replace',value:{status:'done'}},{type:'allow'},{type:'ask'},{type:'deny',reason:'policy'}],caps,'s');assert.equal(state.denied,true);assert.equal(state.permission,'ask');
});

test('unconfirmed or mismatched receiver descriptors never publish a body', async () => {
 const bytes=new TextEncoder().encode('abc');
 const valid={ref:'receiver-allocated',size:3,sha256:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'};
 const item={id:'item',kind:'text',category:'text',mediaType:'text/plain',bytes};
 for (const descriptor of [undefined,{}, {...valid,ref:''},{...valid,size:2},{...valid,sha256:'0'.repeat(64)}]) {
  const options={selection:{text:'body' as const},authorized:()=>true,mode:'observe' as const,failClosed:false,upload:async()=>descriptor as typeof valid};
  const views=await prepareWireContent([item],options);
  assert.equal(views[0]?.gap?.reason,'transfer_failed');assert.equal(views[0]?.body,undefined);
  let rejected=false;
  try {await prepareWireContent([item],{...options,mode:'intercept',failClosed:true});}catch{rejected=true;}
  assert.equal(rejected,true);
 }
});

test('HTTP upload confirms receiver descriptors, isolates credentials and snapshots exact bytes', async () => {
 const originalFetch=globalThis.fetch;
 const descriptor={ref:'opaque/receiver-chosen',size:3,sha256:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'};
 const config={endpoint:'https://upload.example.test/exact?route=1',auth:{type:'bearer' as const,tokenEnv:'UPLOAD_TOKEN',future:true},future:{enabled:true}};
 const seen:RequestInit[]=[];
 try {
  globalThis.fetch=async(input,init)=>{
   assert.equal(String(input),config.endpoint);seen.push(init!);
   assert.deepEqual(Array.from(init!.body as Uint8Array),[97,98,99]);
   assert.equal(init!.method,'POST');assert.equal(init!.redirect,'error');
   const headers=new Headers(init!.headers);
   assert.equal(headers.get('content-type'),'application/octet-stream');
   assert.equal(headers.get('content-length'),'3');assert.equal(headers.get('ahp-content-sha256'),descriptor.sha256);
   assert.equal(headers.has('ahp-subscription'),false);assert.equal(headers.has('ahp-content-ref'),false);
   return new Response(JSON.stringify(descriptor),{status:201,headers:{'content-type':'application/json; charset=utf-8'}});
  };
  const bytes=new TextEncoder().encode('abc');
  const pending=uploadContent(config,bytes,{resolveToken:name=>{assert.equal(name,'UPLOAD_TOKEN');return 'upload-only-token';}});
  bytes.fill(0);
  assert.deepEqual(await pending,descriptor);
  assert.equal(new Headers(seen[0]!.headers).get('authorization'),'Bearer upload-only-token');
  await uploadContent({endpoint:config.endpoint},new TextEncoder().encode('abc'),{resolveToken:()=>{throw Error('Must not inherit event authentication');}});
  assert.equal(new Headers(seen[1]!.headers).has('authorization'),false);
  for(const invalid of [{...config,timeoutMs:0},{...config,maxBytes:-1},{...config,auth:{...config.auth,tokenEnv:''}},{...config,auth:{...config.auth,tokenEnv:'invalid-name'}},{...config,auth:{...config.auth,type:'future-auth'}}]) {
   let rejected=false;
   try{await uploadContent(invalid as typeof config,new TextEncoder().encode('abc'),{resolveToken:()=> 'token'});}catch{rejected=true;}
   assert.equal(rejected,true);
  }
  assert.equal(seen.length,2);
 } finally {globalThis.fetch=originalFetch;}
});
test('HTTP upload rejects unconfirmed status, media type and malformed or mismatched descriptors', async () => {
 const originalFetch=globalThis.fetch;
 const descriptor={ref:'allocated',size:3,sha256:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'};
 const cases=[
  {status:202,body:descriptor},{status:204,body:null},
  ...[{}, {...descriptor,ref:''},{...descriptor,ref:42},{...descriptor,size:2},{...descriptor,sha256:'0'.repeat(64)},{...descriptor,sha256:descriptor.sha256.toUpperCase()},{...descriptor,extra:true}].map(body=>({status:201,body})),
  {status:201,body:descriptor,mediaType:'text/plain'},
  {status:201,body:descriptor,mediaType:''},
  {status:201,body:'malformed-json'},
 ];
 try {
  for(const entry of cases) {
   globalThis.fetch=async()=>new Response(entry.body===null?null:typeof entry.body==='string'?entry.body:JSON.stringify(entry.body),{status:entry.status,headers:{'content-type':'mediaType' in entry ? String(entry.mediaType) : 'application/json'}});
   let rejected=false;
   try{await uploadContent({endpoint:'https://upload.example.test'},new TextEncoder().encode('abc'));}catch{rejected=true;}
   assert.equal(rejected,true,JSON.stringify(entry));
  }
 }finally{globalThis.fetch=originalFetch;}
});

test('zero-byte uploads are valid with a zero-byte transfer bound', async () => {
 const originalFetch=globalThis.fetch;
 const descriptor={ref:'empty-object',size:0,sha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'};
 try {
  globalThis.fetch=async(_input,init)=>{
   assert.equal((init!.body as Uint8Array).length,0);
   assert.equal(new Headers(init!.headers).get('content-length'),'0');
   return new Response(JSON.stringify(descriptor),{status:201,headers:{'content-type':'application/json'}});
  };
  assert.deepEqual(await uploadContent({endpoint:'https://upload.example.test',maxBytes:0},new Uint8Array()),descriptor);
 }finally{globalThis.fetch=originalFetch;}
});
