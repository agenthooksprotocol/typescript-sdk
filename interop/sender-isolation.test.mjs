import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {UploadStore,digest} from './content-upload.mjs';
import {discovery,listen,body,reply} from './common.mjs';
const cwd=fileURLToPath(new URL('..',import.meta.url));
test('actual sender never inherits event Authorization when upload auth is omitted',async()=>{
 const captures=[],events=[],store=new UploadStore(authorization=>authorization===undefined?'isolation':403);
 const uploadServer=createServer(async(req,res)=>{
  const capture={authorization:req.headers.authorization,rawHeaders:[...req.rawHeaders],bytes:[]};captures.push(capture);
  req.on('data',chunk=>capture.bytes.push(Buffer.from(chunk)));
  const result=await store.receive(req);reply(res,result.status,result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{});
 });
 const eventServer=createServer(async(req,res)=>{
  events.push({authorization:req.headers.authorization,path:req.url});
  if(req.headers.authorization!=='Bearer TEST-ONLY-event-credential')return reply(res,401,{});
  if(req.url==='/capabilities')return reply(res,200,discovery);
  const message=await body(req);events.at(-1).message=message;
  store.resolve('isolation',message.params.event.items[0].body);
  reply(res,200,{jsonrpc:'2.0',id:message.id,result:{protocolVersion:'draft',effects:[]}});
 });
 const dir=await mkdtemp(join(tmpdir(),'ahp-isolation-'));let child;
 try{
  const uploadEndpoint=await listen(uploadServer),endpoint=await listen(eventServer),bytes=Buffer.from([0,255,128,13,10]);
  const event={id:'unrelated-correlation',source:'urn:typescript:isolation',type:'tool.before',time:'2026-01-01T00:00:00Z',call:{id:'call'},path:'native',tool:{name:'task',origin:'native',input:{task:1}},items:[{id:'body-item',kind:'text',role:'user',mediaType:'application/octet-stream',selection:'body',body:{ref:'binary',size:bytes.length,sha256:digest(bytes)}}]};
  const request={jsonrpc:'2.0',id:'unrelated-correlation',method:'hooks/intercept',params:{protocolVersion:'draft',event,capabilities:{effects:[]}}};
  const scenarioFile=join(dir,'rows.json'),reportFile=join(dir,'report.json'),configFile=join(dir,'client.json');
  await writeFile(scenarioFile,JSON.stringify({version:1,scenarios:[{id:'isolation',request,contentBodies:[{ref:'binary',bodyBase64:bytes.toString('base64')}],expected:{decision:'allow',executed:true,input:{task:1},messages:[]}}]}));
  await writeFile(configFile,JSON.stringify({transport:'http',endpoint,scenarioFile,reportFile,auth:{mode:'bearer',token:'TEST-ONLY-event-credential'},allowLoopbackUploads:true,subscriptions:[{id:'isolation',content:{default:'body'},authorizedContent:['text'],upload:{endpoint:uploadEndpoint,timeoutMs:5000,maxBytes:1024}}]}));
  child=spawn(process.execPath,['interop/client.mjs','--config',configFile],{cwd,stdio:['ignore','ignore','pipe']});let error='';child.stderr.on('data',chunk=>error+=chunk);
  const code=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill();reject(Error('Client watchdog'));},10000);child.once('exit',code=>{clearTimeout(timer);resolve(code);});});
  assert.equal(code,0,error);assert.equal(JSON.parse(await readFile(reportFile,'utf8')).results[0].status,'passed');
  assert.equal(captures.length,1);assert.equal(captures[0].authorization,undefined);
  assert.equal(captures[0].rawHeaders.some((value,index)=>index%2===0&&value.toLowerCase()==='authorization'),false);
  assert.deepEqual(Buffer.concat(captures[0].bytes),bytes);
  assert.equal(events.length,2);assert.ok(events.every(event=>event.authorization==='Bearer TEST-ONLY-event-credential'));
  assert.notEqual(events[1].message.params.event.items[0].body.ref,'binary');
  request.params.event.items[0].body.ref=events[1].message.params.event.items[0].body.ref;assert.deepEqual(events[1].message,request);
 }finally{if(child?.exitCode===null)child.kill();await Promise.all([new Promise(resolve=>eventServer.close(resolve)),new Promise(resolve=>uploadServer.close(resolve))]);await rm(dir,{recursive:true,force:true});}
});
