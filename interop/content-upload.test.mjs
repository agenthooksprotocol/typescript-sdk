import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {uploadBytes,UploadStore,uploadURL,digest} from './content-upload.mjs';
import {reply,listen} from './common.mjs';
test('raw upload authenticates independently, preserves octets, allocates immutable scoped references',async()=>{
 const store=new UploadStore(a=>a==='Bearer upload-secret'?'sub':a==='Bearer forbidden'?403:401,10);
 const captures=[];
 const server=createServer(async(req,res)=>{captures.push(req.headers);if(req.url!=='/bytes?version=1'){req.resume();res.writeHead(404).end();return;}const result=await store.receive(req);reply(res,result.status,result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{});});
 const endpoint=await listen(server);
 try{
  const upload={endpoint:endpoint+'/bytes?version=1',auth:{type:'bearer',tokenEnv:'UPLOAD',future:true},future:true};
  const opts={allowLoopback:true,env:{UPLOAD:'upload-secret',EVENT:'event-secret'}}, bytes=new Uint8Array([0,255,128,13,10]);
  const result=await uploadBytes(upload,bytes,opts);assert.equal(result.status,201);assert.deepEqual(store.resolve('sub',result.body),Buffer.from(bytes));
  const retry=await uploadBytes(upload,bytes,opts);assert.equal(retry.status,201);assert.notEqual(retry.body.ref,result.body.ref);
  const changed=await uploadBytes(upload,new Uint8Array([1]),opts);assert.equal(changed.status,201);assert.notEqual(changed.body.ref,result.body.ref);assert.deepEqual(store.resolve('sub',result.body),Buffer.from(bytes));
  assert.equal((await uploadBytes(upload,bytes,{...opts,env:{UPLOAD:'forbidden'}})).status,403);
  assert.equal((await uploadBytes({...upload,auth:undefined},bytes,opts)).status,401);
  assert.equal((await uploadBytes(upload,bytes,{...opts,env:{UPLOAD:'event-secret'}})).status,401);
  assert.throws(()=>store.resolve('other',result.body));
  assert.throws(()=>store.resolve('sub',{...result.body,sha256:'0'.repeat(64)}));
  assert.equal((await uploadBytes(upload,new Uint8Array(),opts)).body.size,0);
  assert.equal((await uploadBytes(upload,new Uint8Array(11),opts)).status,413);
  assert.equal((await uploadBytes(upload,bytes,{...opts,declaredHash:'0'.repeat(64)})).status,400);
  assert.equal((await uploadBytes(upload,bytes,{...opts,declaredSize:bytes.length+1})).status,400);
  await assert.rejects(uploadBytes(upload,bytes,{...opts,declaredHash:'bad\r\nInjected: true'}));
  assert.ok(captures.every(headers=>Object.keys(headers).every(key=>!['ahp-subscription','ahp-content-ref'].includes(key))));
  assert.throws(()=>uploadURL(upload.endpoint));
  for(const invalid of [{maxBytes:'10'},{maxBytes:-1},{timeoutMs:0},{auth:{type:'bearer',tokenEnv:'bad-name'}}])await assert.rejects(uploadBytes({...upload,...invalid},bytes,opts));
  assert.equal((await uploadBytes({...upload,maxBytes:0},new Uint8Array(),opts)).status,201);
  await assert.rejects(uploadBytes({...upload,maxBytes:0},bytes,opts));
 }finally{await new Promise(resolve=>server.close(resolve));}
});
test('only a validated synchronous descriptor confirms a body; redirects never follow',async()=>{
 const bytes=Buffer.from('abc');
 const cases=[{status:202},{status:204},{status:201,body:{}},{status:201,body:{ref:'',size:3,sha256:digest(bytes)}},{status:201,body:{ref:'r',size:4,sha256:digest(bytes)}},{status:201,body:{ref:'r',size:3,sha256:'0'.repeat(64)}},{status:201,body:{ref:'r',size:3,sha256:digest(bytes)},media:'text/plain'},{status:201,body:{ref:'r',size:3,sha256:digest(bytes),future:true}}];
 const server=createServer((req,res)=>{req.resume();if(req.url==='/redirect')res.writeHead(307,{location:'/0'}).end();else{const row=cases[Number(req.url.slice(1))];res.writeHead(row.status,{'content-type':row.media ?? 'application/json'}).end(JSON.stringify(row.body));}});
 const endpoint=await listen(server);
 try{
  for(let i=0;i<cases.length;i++){
   const task=uploadBytes({endpoint:endpoint+'/'+i},bytes,{allowLoopback:true});
   if(i<2)assert.equal((await task).body,undefined);else if(i===cases.length-1)assert.equal((await task).body.ref,'r');else await assert.rejects(task);
  }
  await assert.rejects(uploadBytes({endpoint:endpoint+'/redirect'},bytes,{allowLoopback:true}));
 }finally{await new Promise(resolve=>server.close(resolve));}
});
