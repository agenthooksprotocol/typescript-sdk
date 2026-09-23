// Offline HTTP adapter. Inputs describe bytes to send, never expected semantics.
import {authorize} from './security.mjs';
import {UploadStore} from './content-upload.mjs';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {createRequire} from 'node:module';
import {validateElicitationExchange,readSelectedElicitation,applyElicitationEffects,validateElicitationMode} from '../packages/sdk/dist/src/elicitation.js';
const require=createRequire(new URL('../packages/sdk/package.json',import.meta.url));
const {Ajv2020}=require('ajv/dist/2020.js'); const addFormats=require('ajv-formats');
const input=async()=>{let data='';for await(const b of process.stdin)data+=b;return JSON.parse(data)};
if(process.argv[2]==='client') {
 const plan=await input(), results=[];
 for(const step of plan.steps){
  const bytes=Buffer.from(step.bytes,'base64'),upload=step.path==='/upload';
  const headers=upload?{...(plan.uploadToken?{Authorization:'Bearer '+plan.uploadToken}:{}),...step.headers}:{Authorization:'Bearer '+plan.token,...step.headers};
  const r=await fetch(plan.endpoint+step.path,{method:'POST',headers,body:bytes,redirect:'error',signal:AbortSignal.timeout(10000)}),body=await r.text();
  if(upload&&r.status===201){const descriptor=JSON.parse(body);if(r.headers.get('content-type')?.split(';')[0].trim()!=='application/json'||!descriptor||typeof descriptor.ref!=='string'||!descriptor.ref||descriptor.size!==bytes.length||descriptor.sha256!==createHash('sha256').update(bytes).digest('hex'))throw Error('Invalid upload confirmation');}
  results.push({status:r.status,body});
 }
 console.log(JSON.stringify(results));
} else {
 const ajv=new Ajv2020({strict:false,allErrors:true});addFormats(ajv);
 for(const name of readdirSync(process.argv[3]).filter(x=>x.endsWith('.schema.json')))ajv.addSchema(JSON.parse(readFileSync(process.argv[3]+'/'+name,'utf8')));
 const validate=(name,value)=>{if(name==='form-answer'){if(!ajv.compile(value.schema)(value.value))throw Error('Submitted form rejected');return}const [file,def]=name.split('#');const fn=ajv.getSchema('https://agenthooksprotocol.org/schemas/draft/'+file+'.schema.json'+(def?'#/$defs/'+def:''));if(!fn||!fn(value))throw Error('Schema rejected')};
 const token=process.env.AHP_ELICITATION_TOKEN, principal=process.argv[4];if(!token||!principal)throw Error('Missing auth');
 const store=new Map(),pending=new Map(),receipts=[];
 const hash=b=>createHash('sha256').update(b).digest('hex');
 const resolve=ref=>{validate('content-reference',ref);const b=store.get(ref.ref);if(!b||b.length!==ref.size||hash(b)!==ref.sha256)throw Error('Upload integrity');return b};
 if(process.argv[2]==='check') {
  const outputs=[];
  for(const c of await input()) {
   const snapshot=JSON.stringify(c);
   store.clear();for(const u of c.uploads??[])store.set(u.ref,Buffer.from(u.bytes,'base64'));
   try{const before=JSON.stringify(c);let summary;try{summary=c.op==='capability'?validateElicitationMode(c.mode,c.capabilities,c.origin??'ahp'):c.op==='apply'?applyElicitationEffects(c.request,c.result??null,resolve,validate,principal,c.effects):validateElicitationExchange(c.request,c.result,resolve,validate,principal,c.effect)}finally{if(JSON.stringify(c)!==before)throw Error('Input mutated')}outputs.push({accepted:true,summary})}catch{outputs.push({accepted:false})}
   if(c.op==='apply')outputs[outputs.length-1].inputUnchanged=JSON.stringify(c)===snapshot;
  }console.log(JSON.stringify(outputs));
 } else {
 const uploads=new UploadStore(authorization=>process.env.AHP_ELICITATION_UPLOAD_TOKEN && authorization===`Bearer ${process.env.AHP_ELICITATION_UPLOAD_TOKEN}`?principal:401);
 const server=createServer(async(req,res)=>{
  if(req.url==='/upload'){
   const result=await uploads.receive(req);
   if(result.status===201)store.set(result.ref,uploads.resolve(principal,result));
   res.writeHead(result.status,{'content-type':'application/json'});res.end(JSON.stringify(result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{}));return;
  }
  if(!authorize(req,{mode:'bearer',token})){res.writeHead(401);res.end();return}
  try {
   const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>4194304)throw Error('Size limit');chunks.push(b)}const raw=Buffer.concat(chunks);
   if(req.url==='/receipts'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(receipts));return}
   if(req.url!=='/hooks/intercept')throw Error('Unknown endpoint');
   const message=JSON.parse(raw);validate('intercept-request',message);
   const event=message.params.event,meta=event.elicitation;const parent=event.type==='user.elicitation.request'?event.id:event.parentEventId;if(typeof parent!=='string')throw Error('Missing parent');const key=JSON.stringify([event.source,parent]);if(message.id!==event.id)throw Error('ID mismatch');
   let body,summary;
   if(event.type==='user.elicitation.request'){
    if(pending.has(key))throw Error('Duplicate pending request identity');
    validateElicitationMode(meta.mode,{form:{},url:{}});const payload=readSelectedElicitation(meta,'request',resolve,validate);
    body=payload===null?Buffer.alloc(0):resolve(meta.request.body);pending.set(key,message);summary=payload===null?{selection:meta.request?.selection??'omit'}:{request:payload};
   }else if(event.type==='user.elicitation.result'){
    summary=validateElicitationExchange(pending.get(key),message,resolve,validate,principal);body=meta.result?.body?resolve(meta.result.body):Buffer.alloc(0);pending.delete(key);
   }else throw Error('Not elicitation');
   receipts.push({message,bytes:body.toString('base64'),summary});res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:message.id,result:{protocolVersion:'draft',effects:[]}}));
  }catch{res.writeHead(400,{'content-type':'application/json'});res.end(JSON.stringify({error:'rejected'}))}
 });server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({endpoint:'http://127.0.0.1:'+server.address().port})));
}
}
