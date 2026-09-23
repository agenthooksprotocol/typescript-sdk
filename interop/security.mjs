import {createHmac,timingSafeEqual} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {request as http} from 'node:http';
import {request as https} from 'node:https';
export function authorize(req,auth) {
 // req.headers can silently retain only the first Authorization field.
 const raw=req.rawHeaders ?? [];
 if(raw.filter((name,index)=>index%2===0 && name.toLowerCase()==='authorization').length>1)return false;
 if(auth.mode==='none')return true;
 if(auth.mode==='mtls')return req.socket.authorized===true;
 const header=req.headers.authorization;
 if(typeof header!=='string' || !header.startsWith('Bearer '))return false;
 const token=header.slice(7);
 if(auth.mode==='bearer')return typeof auth.token==='string' && auth.token.length>0 && token===auth.token;
 if(!['oauth','workload'].includes(auth.mode))return false;
 try {
  const parts=token.split('.'); if(parts.length!==3)return false;
  const [h,p,s]=parts, header=JSON.parse(Buffer.from(h,'base64url')), claims=JSON.parse(Buffer.from(p,'base64url'));
  if(header.alg!=='HS256')return false;
  const key=auth.signingKey ?? `TEST-ONLY-ahp-interop-${auth.mode}-signing-key`;
  const expected=createHmac('sha256',key).update(`${h}.${p}`).digest(), supplied=Buffer.from(s,'base64url');
  const now=auth.clock ?? 1893456000;
  return expected.length===supplied.length && timingSafeEqual(expected,supplied) && claims.iss===(auth.issuer ?? 'urn:ahp:interop:local-issuer') && claims.aud===(auth.audience ?? 'urn:ahp:interop:local-server') && claims.purpose===(auth.purpose ?? auth.mode) && Number.isFinite(claims.exp) && claims.exp>now && (claims.nbf===undefined || claims.nbf<=now);
 } catch {return false;}
}
export async function accessToken(auth) {
 if(auth.mode==='bearer')return auth.token;
 if(auth.mode==='workload')return auth.assertion;
 if(auth.mode==='oauth') {const res=await fetch(auth.tokenEndpoint,{method:'POST',redirect:'error',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:auth.clientId,client_secret:auth.clientSecret,audience:auth.audience ?? 'urn:ahp:interop:local-server'}),signal:AbortSignal.timeout(10000)});if(!res.ok)throw Error('Token acquisition failed');const data=await res.json();if(typeof data.access_token!=='string')throw Error('Missing token');return data.access_token;}
}
export function sendStatus(endpoint,path,payload,auth,token) {return new Promise((resolve,reject)=>{
 const url=new URL(path,endpoint), tls=auth.mode==='mtls'?{ca:readFileSync(auth.caFile),cert:readFileSync(auth.certFile),key:readFileSync(auth.keyFile)}:{};
 const req=(url.protocol==='https:'?https:http)(url,{method:payload===undefined?'GET':'POST',...tls,headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})}},res=>{let text='';res.on('data',chunk=>{text+=chunk;if(text.length>4194304)req.destroy(Error('Oversized response'));});res.on('end',()=>{try{resolve({status:res.statusCode,value:text?JSON.parse(text):null});}catch(e){reject(e);}});});req.setTimeout(15000,()=>req.destroy(Error('HTTP watchdog')));req.on('error',reject);req.end(payload===undefined?undefined:JSON.stringify(payload));
 });}

export async function send(endpoint,path,payload,auth,token){const response=await sendStatus(endpoint,path,payload,auth,token);if(response.status!==200)throw Error(`HTTP failure: ${response.status}`);return response.value;}
