import {UploadStore,authorizeUpload} from './content-upload.mjs';
import {TaskLineage} from './task-lineage.mjs';
import {createServer} from 'node:http';
import {createServer as tlsServer} from 'node:https';
import {readFileSync} from 'node:fs';
import {createInterface} from 'node:readline';
import {validateInterceptRequest,validateInterceptResponse,validateCapabilities,validateCapabilitiesRequest,validateCapabilitiesResponse} from '../packages/sdk/dist/src/draft/index.js';
import {authorize} from './security.mjs';
import {config, scenarios, atomic, body, reply, listen, discovery, manifest} from './common.mjs';
const cfg = await config(), rows = await scenarios(cfg.scenarioFile), receipts = [], barriers = new Map(), released = new Set();
const uploads=new UploadStore(authorization=>authorizeUpload(cfg,authorization));
const lineage=new TaskLineage();
let tlsRejections=0, tlsClientErrors=0;
const tlsClientErrorCodes={};
const tlsRejectionCodes={};
if(!validateCapabilities(discovery).ok) throw Error('Invalid discovery capabilities');
function capabilities(request) {
 if(!validateCapabilitiesRequest(request).ok) throw Error('Invalid discovery request');
 const response={jsonrpc:'2.0',id:request.id,result:{protocolVersion:'draft',manifest}};
 if(!validateCapabilitiesResponse(response).ok) throw Error('Invalid discovery response');
 return response;
}
const wait = name => released.has(name) ? Promise.resolve() : new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('Barrier watchdog')), 15000); const callbacks = barriers.get(name) ?? []; callbacks.push(() => {clearTimeout(timer);resolve();}); barriers.set(name,callbacks); });
async function intercept(request) {
  if(!validateInterceptRequest(request).ok) throw Error('Invalid canonical request');
  for(const item of request.params.event.items ?? [])if(item.body)uploads.resolve(cfg.contentScope ?? 'default',item.body);
  lineage.accept(request);
  const row = rows.find(s => s.id === request.params.event.id); if(!row) throw Error('Unknown scenario');
  receipts.push(structuredClone(request));
  if(row.barrier) await wait(row.barrier);
  if(!row.expectError && !validateInterceptResponse(row.response).ok) throw Error('Invalid canonical response');
  return row.response;
}
const handler = async (req,res) => { try {
  if(cfg.uploadPath && req.url===cfg.uploadPath){const result=await uploads.receive(req);reply(res,result.status,result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{});return;}
  if(!authorize(req,cfg.auth ?? {mode:'none'})) return reply(res,401,{error:'unauthorized'});
  if(req.method === 'GET' && req.url === '/capabilities') return reply(res,200,discovery);
  if(req.method === 'POST' && req.url === '/intercept') return reply(res,200,await intercept(await body(req)));
  reply(res,404,{});
} catch {reply(res,400,{error:'invalid request'});} };
const api = cfg.auth?.mode === 'mtls' ? tlsServer({ca:readFileSync(cfg.auth.caFile),cert:readFileSync(cfg.auth.certFile),key:readFileSync(cfg.auth.keyFile),requestCert:true,rejectUnauthorized:true},handler) : createServer(handler);
api.on('tlsClientError',(error,socket)=>{
 tlsClientErrors++;
 const rawCode=typeof error.code==='string' && /^[A-Z0-9_]{1,100}$/.test(error.code)?error.code:'TLS_HANDSHAKE_ERROR';
 tlsClientErrorCodes[rawCode]=(tlsClientErrorCodes[rawCode] ?? 0)+1;
 // Count only certificate/authentication TLS failures, not arbitrary resets.
 const code=typeof socket?.authorizationError==='string'?socket.authorizationError:(typeof error.code==='string'?error.code:'');
 if(/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|UNKNOWN_CA/.test(code)) {
  tlsRejections++;
  const redacted=/^[A-Z0-9_]{1,100}$/.test(code)?code:'TLS_CERTIFICATE_REJECTED';
  tlsRejectionCodes[redacted]=(tlsRejectionCodes[redacted] ?? 0)+1;
 }
});
const control = createServer(async (req,res) => { try {
  if(cfg.uploadPath && req.url===cfg.uploadPath){const result=await uploads.receive(req);reply(res,result.status,result.status===201?{ref:result.ref,size:result.size,sha256:result.sha256}:{});return;}
  if(req.method === 'GET' && req.url === '/health') return reply(res,200,{ready:true,tlsRejections,tlsRejectionCodes,tlsClientErrors,tlsClientErrorCodes,requests:structuredClone(receipts)});
  if(req.method === 'GET' && req.url === '/receipts') return reply(res,200,{requests:receipts});
  if(req.method === 'POST' && req.url === '/release') { const {barrier} = await body(req); released.add(barrier); for(const release of barriers.get(barrier) ?? []) release(); barriers.delete(barrier); return reply(res,200,{released:true}); }
  if(req.method === 'POST' && req.url === '/shutdown') {reply(res,200,{stopped:true}); setImmediate(() => process.exit(0)); return;}
  reply(res,404,{});
} catch {reply(res,400,{error:'invalid control request'});} });
const controlEndpoint = await listen(control);
const endpoint = cfg.transport === 'http' ? await listen(api,cfg.auth?.mode==='mtls'?'https':'http') : 'stdio';
if(cfg.transport === 'stdio') { const lines = createInterface({input:process.stdin}); lines.on('line', async line => { let request; try {request=JSON.parse(line); const response = request.method === 'hooks/capabilities' ? capabilities(request) : await intercept(request); process.stdout.write(JSON.stringify(response)+'\n');} catch {process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request?.id ?? null,error:{code:-32600,message:'Invalid request'}})+'\n');} }); lines.on('close',()=>process.exit(0)); }
await atomic(cfg.readinessFile,{endpoint,controlEndpoint,pid:process.pid});
