import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {uploadBytes} from './content-upload.mjs';

for(const name of ['compaction','elicitation'])test(`${name} receiver allocates refs using separate upload credentials`,{timeout:15000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ahp-upload-adapter-'));let child,lines;
 try{
  const schema=resolve('../agent-hooks-protocol/schema/draft'),config=join(dir,'config.json');
  await writeFile(config,JSON.stringify({hook:{effects:[]}}));
  const command=name==='compaction'?['interop/compaction-wire.mjs','server',schema,dir,config]:['interop/elicitation.mjs','server',schema,'trusted-principal'];
  const prefix=name==='compaction'?'AHP_COMPACTION':'AHP_ELICITATION';
  const credentials=name==='compaction'?{AHP_COMPACTION_TOKENS:JSON.stringify({'TEST-event':'hook'}),AHP_COMPACTION_UPLOAD_TOKENS:JSON.stringify({'TEST-upload':'hook'})}:{[prefix+'_TOKEN']:'TEST-event',[prefix+'_UPLOAD_TOKEN']:'TEST-upload'};
  child=spawn(process.execPath,command,{env:{...process.env,...credentials},stdio:['ignore','pipe','pipe']});
  let errors='';child.stderr.on('data',chunk=>errors+=chunk);
  lines=createInterface({input:child.stdout});
  const timer=setTimeout(()=>child.kill('SIGKILL'),10000);
  try{
   const [line]=await Promise.race([once(lines,'line'),once(child,'exit').then(()=>{throw Error(errors||'Receiver exited');})]);
   const {endpoint}=JSON.parse(line),bytes=Buffer.from([0,255,13,10]);
   const upload={endpoint:endpoint+'/upload',auth:{type:'bearer',tokenEnv:'UPLOAD'}},options={allowLoopback:true,env:{UPLOAD:'TEST-upload'}};
   const first=await uploadBytes(upload,bytes,options),second=await uploadBytes(upload,Buffer.from('changed'),options);
   assert.equal(first.status,201);assert.equal(second.status,201);assert.notEqual(first.body.ref,second.body.ref);
   assert.equal((await uploadBytes(upload,bytes,{...options,env:{UPLOAD:'TEST-event'}})).status,401);
   assert.equal((await uploadBytes({...upload,auth:undefined},bytes,options)).status,401);
   const response=await fetch(endpoint+(name==='compaction'?'/hooks/intercept':'/receipts'),{headers:{Authorization:'Bearer TEST-upload'}});
   assert.equal(response.status,401);
   if(name==='compaction'){
    const event={id:'unrelated-event',source:'urn:test',time:'2026-01-01T00:00:00Z',type:'context.compact.before',trigger:'manual',items:[],instructions:{id:'instructions',kind:'instructions',role:'system',mediaType:'text/plain',selection:'body',body:second.body}};
    const request={jsonrpc:'2.0',id:event.id,method:'hooks/intercept',params:{protocolVersion:'draft',event,capabilities:{effects:[]}}};
    const accepted=await fetch(endpoint+'/hooks/intercept',{method:'POST',headers:{Authorization:'Bearer TEST-event','Content-Type':'application/json'},body:JSON.stringify(request)});
    assert.deepEqual((await accepted.json()).result,{protocolVersion:'draft',effects:[]});
   }
  }finally{clearTimeout(timer);}
 }finally{
  lines?.close();if(child&&child.exitCode===null&&child.signalCode===null){const ended=once(child,'exit');child.kill('SIGKILL');await ended;}
  await rm(dir,{recursive:true,force:true});
 }
});
