import {evaluate} from './lifecycle-evaluator.mjs';
import {validateObserve} from './lifecycle-common.mjs';
export async function runChain(row,{send,control,observe,validate}){
 const original=structuredClone(row.requests.a),id=original.id;
 let event=structuredClone(original.params.event),halted=false,pending;
 const called=[],failures=[],remaining=[];
 for(const sub of row.chain.subscriptions){
  if(sub.mode==='observe'||halted){remaining.push(sub);continue}
  const request=structuredClone(original);request.params.event=structuredClone(event);if(sub.content==='omit')request.params.event.items=[];validate(request);
  called.push(sub.id);const response=send(request);await control('/wait',{id,count:called.length});
  if(row.chain.interrupt){await control('/mark',{scenario:row.id,kind:'cancelled',id});pending=response;halted=true;continue}
  await control('/release',{id});
  try{const state=evaluate(request,await response);event.tool.input=structuredClone(state.input);halted=state.decision==='deny'||state.flow==='stop'}
  catch{failures.push(sub.id);halted=sub.failurePolicy==='fail-closed'}
 }
 await control('/mark',{scenario:row.id,kind:'chain-settled',id});
 const deliveries=remaining.map(sub=>{
  const projected=structuredClone(event);
  if(sub.content==='omit')projected.items=[];
  else for(const item of projected.items??[]){delete item.body;delete item.gap;item.selection='metadata'}
  const note={jsonrpc:'2.0',method:'hooks/observe',params:{protocolVersion:'draft',event:projected}};validateObserve(note);
  return Promise.resolve().then(()=>observe(note));
 });
 // Test-controller drain is separate from the settled/stopped execution path.
 if(pending){await control('/release',{id});await pending}
 if(remaining.length)await control('/wait-observed',{eventId:id,count:remaining.length});
 if(row.chain.holdObservers)await control('/release',{id:id+':observers'});
 await Promise.all(deliveries);
 return {called,failures,observations:remaining.map(s=>s.id),input:event.tool.input};
}
