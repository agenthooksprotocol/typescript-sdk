import {connect as tcpConnect} from 'node:net';
import {connect as tlsConnect} from 'node:tls';
import {createHash,randomUUID} from 'node:crypto';
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function uploadURL(endpoint, allowLoopback = false) {
 const url = new URL(endpoint);
 if(url.username || url.password || url.hash || (url.protocol !== 'https:' && !(allowLoopback && url.protocol === 'http:' && (['localhost','[::1]'].includes(url.hostname)||/^127(?:\.[0-9]{1,3}){3}$/.test(url.hostname))))) throw Error('Unsafe upload endpoint');
 return url;
}
/** Raw binary binding; upload credentials never inherit event authentication. */
export async function uploadBytes(upload, bytes, {allowLoopback=false, env=process.env,declaredSize,declaredHash}={}) {
 if(upload.timeoutMs!==undefined&&(!Number.isSafeInteger(upload.timeoutMs)||upload.timeoutMs<1))throw Error('Invalid upload timeout');
 if(upload.maxBytes!==undefined&&(!Number.isSafeInteger(upload.maxBytes)||upload.maxBytes<0))throw Error('Invalid upload limit');
 if(upload.auth!==undefined&&(!upload.auth||upload.auth.type!=='bearer'||typeof upload.auth.tokenEnv!=='string'||! /^[A-Za-z_][A-Za-z0-9_]*$/.test(upload.auth.tokenEnv)))throw Error('Invalid upload authentication');
 if(!(bytes instanceof Uint8Array)) throw Error('Invalid upload input');
 const snapshot=Buffer.from(bytes), headers={'content-type':'application/octet-stream','content-length':String(snapshot.length),'ahp-content-sha256':digest(snapshot)};
 if(declaredSize!==undefined)headers['content-length']=String(declaredSize);
 if(declaredHash!==undefined)headers['ahp-content-sha256']=declaredHash;
 if(upload.auth){if(upload.auth.type!=='bearer' || !env[upload.auth.tokenEnv])throw Error('Missing upload credential');headers.authorization=`Bearer ${env[upload.auth.tokenEnv]}`;}
 if(snapshot.length > (upload.maxBytes ?? 52428800))throw Error('Upload limit');
 if(Object.values(headers).some(value=>/[\r\n]/.test(value)))throw Error('Invalid upload framing');
 const url=uploadURL(upload.endpoint,allowLoopback);
 if(declaredSize!==undefined && declaredSize!==snapshot.length){
  const status=await new Promise((resolve,reject)=>{
   const socket=(url.protocol==='https:'?tlsConnect:tcpConnect)({host:url.hostname,port:Number(url.port)||(url.protocol==='https:'?443:80),allowHalfOpen:true},()=>{
    socket.end(Buffer.concat([Buffer.from(`POST ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n${Object.entries(headers).map(([k,v])=>`${k}: ${v}`).join('\r\n')}\r\n\r\n`),snapshot]));
   });
   let response='';socket.setTimeout(upload.timeoutMs ?? 15000,()=>socket.destroy(Error('Upload watchdog')));socket.on('error',reject);socket.on('data',chunk=>response+=chunk.toString());socket.on('end',()=>{const match=/^HTTP\/1\.[01] ([0-9]{3})/.exec(response);socket.destroy();match?resolve(Number(match[1])):reject(Error('No HTTP upload response'));});
  });return {status};
 }
 const response=await fetch(url,{method:'POST',headers,body:snapshot,redirect:'error',signal:AbortSignal.timeout(upload.timeoutMs ?? 15000)});
 if(response.status!==201){await response.arrayBuffer();return {status:response.status};}
 if(response.headers.get('content-type')?.split(';')[0].trim()!=='application/json')throw Error('Invalid upload confirmation media type');
 const body=await response.json();
 if(!body || typeof body.ref!=='string' || !body.ref || !Number.isSafeInteger(body.size) || body.size!==snapshot.length || !/^[a-f0-9]{64}$/.test(body.sha256 ?? '') || body.sha256!==digest(snapshot))throw Error('Invalid upload confirmation');
 return {status:201,body:{ref:body.ref,size:body.size,sha256:body.sha256}};
}
export class UploadStore {
 constructor(authorize, maxBytes=52428800){this.authorize=authorize;this.maxBytes=maxBytes;this.values=new Map();}
 async receive(req){
  const metadata={size:Number(req.headers['content-length']),sha256:req.headers['ahp-content-sha256']};
  const names=(req.rawHeaders ?? []).filter((_,i)=>i%2===0).map(name=>name.toLowerCase());
  if(['authorization','content-type','content-length','ahp-content-sha256'].some(name=>names.filter(value=>value===name).length>1)){req.resume();return {...metadata,status:400};}
  const scope=this.authorize(req.headers.authorization);
  if(typeof scope!=='string' || !scope){req.resume();return {...metadata,status:typeof scope==='number'?scope:403};}
  const length=req.headers['content-length'], sha256=req.headers['ahp-content-sha256'];
  if(req.method!=='POST'||req.headers['content-type']!=='application/octet-stream'||req.headers['content-encoding']||req.headers['transfer-encoding']||!/^\d+$/.test(length ?? '')||!Number.isSafeInteger(Number(length))||!/^[a-f0-9]{64}$/.test(sha256 ?? '')){req.resume();return {...metadata,status:400};}
  if(Number(length)>this.maxBytes){req.resume();return {...metadata,status:413};}
  const chunks=[];let size=0;
  try{for await(const chunk of req){size+=chunk.length;if(size>this.maxBytes)return {...metadata,status:413};chunks.push(chunk);}}catch{return {...metadata,status:400};}
  const bytes=Buffer.concat(chunks),ref=randomUUID(),key=JSON.stringify([scope,ref]);
  if(size!==Number(length)||digest(bytes)!==sha256)return {...metadata,status:400};
  this.values.set(key,{bytes,size,sha256});return {ref,size,sha256,status:201};
 }
 resolve(scope,body){const stored=this.values.get(JSON.stringify([scope,body.ref]));if(!stored||stored.size!==body.size||stored.sha256!==body.sha256)throw Object.assign(Error('Unavailable scoped content'),{status:409});return Buffer.from(stored.bytes);}
}
/** Only authenticated upload policy selects a scope; message IDs never do. */
export function authorizeUpload(config, authorization){
 if(config.uploadAuth){const policy=config.uploadAuth;return typeof policy.token==='string'&&policy.token.length>0&&authorization===`Bearer ${policy.token}`?(policy.scope ?? 'default'):401;}
 const matches=Object.entries(config.uploadSubscriptions ?? {}).filter(([,policy])=>{
  if(policy.auth){const token=process.env[policy.auth.tokenEnv];return policy.auth.type==='bearer' && token && authorization===`Bearer ${token}`;}
  return policy.anonymous===true && authorization===undefined;
 });
 if(matches.length!==1)return authorization===undefined?401:403;
 const [name,policy]=matches[0];return policy.authorized===false?403:policy.scope ?? name;
}
/** Fixture labels select local policy, never wire encoding or authorization grants. */
export async function prepareRequestContent(request, bodies, config, subscription){
 const policy=subscription===undefined && config.subscriptions?.length===1?config.subscriptions[0]:config.subscriptions?.find(value=>value.id===subscription);
 for(const item of request.params.event.items ?? [])if(item.body){
  const category=item.kind==='reasoning'?'reasoning':item.category ?? item.kind;
  if(!policy?.upload || policy.authorizedContent?.includes(category)!==true || (policy.content?.[category] ?? policy.content?.default)!=='body')throw Error('Content not selected and authorized');
  const source=bodies?.find(value=>value.ref===item.body.ref);
  if(!source || typeof source.bodyBase64!=='string')throw Error('Unavailable fixture bytes');
  const result=await uploadBytes(policy.upload,Buffer.from(source.bodyBase64,'base64'),{allowLoopback:config.allowLoopbackUploads===true});
  if(result.status!==201 || result.body.size!==item.body.size || result.body.sha256!==item.body.sha256)throw Error('Required upload failed or bytes changed');
  item.body=result.body;
 }
}
