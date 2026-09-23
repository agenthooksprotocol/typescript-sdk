/** Test-only HTTP writer preserving repeated raw field lines. */
import {request as http} from 'node:http';
import {request as https} from 'node:https';
import {readFileSync} from 'node:fs';
export function rawExchange(endpoint,path,payload,auth={},fields=[]) {
 return new Promise((resolve,reject)=>{
  const url=new URL(path,endpoint), text=payload===undefined?undefined:JSON.stringify(payload);
  const tls=auth.mode==='mtls'?{ca:readFileSync(auth.caFile),cert:readFileSync(auth.certFile),key:readFileSync(auth.keyFile)}:{};
  const headers=['Host',url.host,'Connection','close',...fields,...(text===undefined?[]:['Content-Type','application/json','Content-Length',String(Buffer.byteLength(text))])];
  const req=(url.protocol==='https:'?https:http)(url,{method:text===undefined?'GET':'POST',headers,...tls},res=>{
   let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(data)});}catch(error){reject(error);}});
  });
  req.setTimeout(5000,()=>req.destroy(Error('Test HTTP watchdog')));req.on('error',reject);req.end(text);
 });
}
