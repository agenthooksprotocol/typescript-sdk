// Actual canonical AHP request/response traffic; scheduling stays local.
import {authorize} from './security.mjs';
import {uploadBytes,UploadStore} from './content-upload.mjs';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { runCompaction } from '../packages/sdk/dist/src/compaction.js';
import { validateInterceptRequest, validateInterceptResponse } from '../packages/sdk/dist/src/draft/index.js';
const digest=b=>createHash('sha256').update(b).digest('hex');
const location=(store,sub,ref)=>store+'/'+digest(Buffer.from(sub+'\0'+ref));
function validate(kind,value) { const r=(kind==='request'?validateInterceptRequest:validateInterceptResponse)(value);if(!r.ok)throw Error(JSON.stringify(r.errors)); }
function receive(request,sub,config,store) {
  try {
    validate('request',request);const event=request.params.event,bodies={};
    const items=[...(event.items??[]),...['instructions','summary'].filter(k=>k in event).map(k=>event[k])];
    for(const item of items){const ref=item.body,raw=readFileSync(location(store,sub,ref.ref));if(raw.length!==ref.size||digest(raw)!==ref.sha256)throw Error('integrity');bodies[item.id]=new TextDecoder('utf-8',{fatal:true}).decode(raw);}
    const action=config[sub];
    const effects=action.kind==='append'?[{type:'modify',target:action.target,operation:'replace',value:bodies[event[action.target].id]+action.suffix}]:action.effects;
    const response={jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',effects}};validate('response',response);
    appendFileSync(store+'/receipts.jsonl',JSON.stringify({subscription:sub,request,response,bodies})+'\n');return response;
  } catch { return {jsonrpc:'2.0',id:request.id??null,error:{code:-32602,message:'Invalid compaction request'}}; }
}
async function exchange(plan,sub,name,snapshot){
  const credentials=Object.hasOwn(plan.credentials ?? {},sub)?plan.credentials[sub]:undefined;
  if(!credentials || typeof credentials.token!=='string' || !credentials.token || typeof credentials.uploadToken!=='string' || !credentials.uploadToken)throw Error('Missing independent compaction credentials');
  const event={id:name+':'+snapshot.boundary,source:'urn:ahp:compaction-host',time:'2026-09-15T12:00:00Z',session:{id:name},type:'context.compact.'+snapshot.boundary};
  async function item(id,kind,text,role){
    const raw=Buffer.from(text);
    const result=await uploadBytes({endpoint:plan.endpoint+'/upload',auth:{type:'bearer',tokenEnv:'UPLOAD'}},raw,{allowLoopback:true,env:{UPLOAD:credentials.uploadToken}});
    if(result.status!==201)throw Error('upload unavailable '+result.status);
    return {id,kind,mediaType:'text/plain',role,selection:'body',body:result.body};
  }
  if(snapshot.boundary==='before'){
    event.trigger='manual';event.items=[await item(name+':context','user','conversation','user')];event.instructions=await item(name+':instructions','instructions',snapshot.instructions,'system');
  }else{
    event.parentEventId=name+':before';event.summary=await item(snapshot.summary.id,'summary',snapshot.bodies[snapshot.summary.ref],'assistant');event.removed=[{id:name+':context'}];
    event.execution=snapshot.candidate===null?{status:'executed'}:{status:'skipped',reason:'supplied_result'};
  }
  const request={jsonrpc:'2.0',id:event.id,method:'hooks/intercept',params:{protocolVersion:'draft',event,capabilities:snapshot.capabilities}};validate('request',request);
  let response;
  if(plan.transport==='http'){
    const r=await fetch(plan.endpoint+'/hooks/intercept',{method:'POST',headers:{Authorization:'Bearer '+credentials.token,'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(15000)});
    if(!r.ok)throw Error('HTTP '+r.status);response=await r.json();
  }else{
    const child=spawnSync(plan.receiverCommand[0],[...plan.receiverCommand.slice(1),'stdio',sub],{input:JSON.stringify(request)+'\n',encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
    if(child.status!==0)throw Error(child.stderr);response=JSON.parse(child.stdout);
  }
  validate('response',response);if(response.id!==request.id)throw Error('correlation');
  return {effects:response.result.effects,wire:{subscription:sub,request,response}};
}
let args=process.argv.slice(2);if(!['host','server','stdio','call'].includes(args[0]))args=[args[3],...args.slice(0,3),...args.slice(4)];
const mode=args[0];
if(mode==='host'||mode==='call'){
  let raw='';for await(const chunk of process.stdin)raw+=chunk;const input=JSON.parse(raw);
  if(mode==='call'){console.log(JSON.stringify(await exchange(input.plan,input.sub,input.name,input.snapshot)));}
  else{
    const plan=input,out=[];
    for(const row of plan.cases){
      const trace=[];
      const hooks=boundary=>row[boundary].map(h=>({supplier:h.supplier,failurePolicy:h.failurePolicy,run:snapshot=>{
        const child=spawnSync(process.execPath,[process.argv[1],'call'],{input:JSON.stringify({plan,sub:h.supplier,name:row.name,snapshot}),encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024});
        if(child.status!==0)throw Error(child.stderr);const r=JSON.parse(child.stdout);trace.push(r.wire);return r.effects;
      }}));
      const result=runCompaction('base',hooks('before'),hooks('after'),{itemId:row.name+':summary'}),downstream=[];
      if(result.applied)downstream.push(result.bodies[result.summary.ref]);out.push({name:row.name,result,trace,downstream});
    }
    console.log(JSON.stringify(out));
  }
}else{
  const [,schema,store,configPath,sub]=args,config=JSON.parse(readFileSync(configPath,'utf8'));
  if(mode==='stdio')for await(const line of createInterface({input:process.stdin}))console.log(JSON.stringify(receive(JSON.parse(line),sub,config,store)));
  else if(mode==='server'){
    const eventTokens=JSON.parse(process.env.AHP_COMPACTION_TOKENS ?? '{}');
    const uploadTokens=JSON.parse(process.env.AHP_COMPACTION_UPLOAD_TOKENS ?? '{}');
    const scopeFor=(tokens,authorization)=>{
      if(typeof authorization!=='string' || !authorization.startsWith('Bearer '))return undefined;
      const token=authorization.slice(7),scope=Object.hasOwn(tokens,token)?tokens[token]:undefined;
      return typeof scope==='string' && Object.hasOwn(config,scope)?scope:undefined;
    };
    const uploads=new UploadStore(authorization=>scopeFor(uploadTokens,authorization) ?? 401);
    const server=createServer(async(req,res)=>{
      try{
        if(req.url==='/upload'){
          const result=await uploads.receive(req);
          if(result.status===201){const scope=scopeFor(uploadTokens,req.headers.authorization);writeFileSync(location(store,scope,result.ref),uploads.resolve(scope,result));}
          res.writeHead(result.status,{'Content-Type':'application/json'});res.end(JSON.stringify(result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{}));return;
        }
        const sub=scopeFor(eventTokens,req.headers.authorization);
        if(sub===undefined || !authorize(req,{mode:'bearer',token:req.headers.authorization.slice(7)})){res.writeHead(401);res.end();return;}
        if(req.method!=='POST'||req.url!=='/hooks/intercept'){res.writeHead(404);res.end();return;}
        const chunks=[];for await(const c of req)chunks.push(c);const raw=Buffer.concat(chunks);
        res.setHeader('Content-Type','application/json');res.end(JSON.stringify(receive(JSON.parse(raw),sub,config,store)));
      }catch{res.writeHead(400);res.end();}
    });server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({endpoint:'http://127.0.0.1:'+server.address().port})));
  }else throw Error('unknown mode');
}
