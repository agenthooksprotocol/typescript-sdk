import {manifest as coreManifest,discovery} from './common.mjs';
import {validateCanonical} from './lifecycle-common.mjs';
import {draftCodecs} from '../packages/sdk/dist/src/draft/index.js';
export const catalogueEvents=['tool.before','tool.after','turn.start','turn.finish.before','turn.end','turn.progress','model.request.before','model.response.after','model.error','model.switch.before','model.switch.after','tool.permission.request','tool.permission.resolved','tool.progress','tool.batch.after','context.compact.before','context.compact.after','task.change.before','task.change.after','workspace.change.before','workspace.change.after','file.changed'];
export const catalogueManifest={...coreManifest,events:catalogueEvents.map(event=>({event,modes:event==='tool.before'?['observe','intercept']:['observe'],...(event==='tool.before'?{capabilities:{...discovery,flow:{operations:['stop']}}}:{})})),managedPolicy:{scopes:['user','project'],disableable:true},gaps:[{path:'production',reason:'Synthetic native occurrences; no production harness mapping'},{path:'events.hook.failure',reason:'Unsupported by this synthetic host'},{path:'managedPolicy.managed',reason:'Host policy is disableable; managed enforcement unavailable'}]};
/** Registration feasibility uses validated discovery, never self-asserted identity. */
export function evaluateRegistration(registration,manifest,requirements=[],context={}){
 try{validateCanonical('registration',registration,draftCodecs.parseRegistration);}catch{return {accepted:false};}
 const reject=()=>({accepted:false}),ids=new Set(),subscribed=new Set();
 const resolve=name=>typeof context.environment?.[name]==='string'&&context.environment[name].length>0;
 for(const backend of registration.hooks){
  if(ids.has(backend.id))return reject();ids.add(backend.id);
  if(!manifest.transports.includes(backend.transport.type))return reject();
  const auth=backend.authentication;
  if(auth){
   if(!manifest.authentication.includes(auth.type))return reject();
   if(auth.type==='bearer' && (!auth.tokenEnv || !resolve(auth.tokenEnv)))return reject();
   // Opaque credential references need a trusted host resolver; this host has none.
   if(auth.type==='mtls'||auth.type==='workload'||auth.clientSecretRef||auth.tokenRef)return reject();
   if(auth.type==='oauth' && (auth.flow!=='authorization_code_pkce'||context.interactive!==true))return reject();
  }
  for(const sub of backend.subscriptions){
   const scope=sub.scope ?? 'user';
   if(!manifest.managedPolicy.scopes.includes(scope))return reject();
   if((scope==='managed'||sub.disableable===false)&&manifest.managedPolicy.disableable!==false)return reject();
   if(sub.upload?.auth && !resolve(sub.upload.auth.tokenEnv))return reject();
   for(const event of sub.events){
    if(!manifest.events.some(entry=>entry.event===event&&entry.modes.includes(sub.mode)))return reject();
    subscribed.add(JSON.stringify([event,sub.mode]));
   }
  }
 }
 for(const requirement of requirements){
  if(!subscribed.has(JSON.stringify([requirement.event,requirement.mode])))return reject();
  const entry=manifest.events.find(entry=>entry.event===requirement.event&&entry.modes.includes(requirement.mode));
  if(!entry)return reject();
  const caps=requirement.mode==='intercept'?entry.capabilities:undefined;
  for(const effect of requirement.effects ?? [])if(!caps?.effects?.includes(effect)||(effect==='ask'&&context.interactive!==true))return reject();
  for(const [target,operations] of Object.entries(requirement.modify ?? {}))for(const [operation,required] of Object.entries(operations))if(required===true&&(!caps?.effects?.includes('modify')||caps.modify?.[target]?.[operation]!==true))return reject();
 }
 return {accepted:true};
}
