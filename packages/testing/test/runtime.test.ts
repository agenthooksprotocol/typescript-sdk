import test from 'node:test';
import assert from 'node:assert/strict';
import {stageBoundary,dispatchBoundary,dispatchObservations,ContentReceiver,prepareContent,Lineage,actualTaskChange,type BoundaryState,type BoundaryCapabilities} from '@agenthooksprotocol/sdk/draft';
const state = (): BoundaryState => ({input:{task:123},candidate:null,permission:'native',approval:'not-required',denied:false,messages:[]});
const caps: BoundaryCapabilities = {effects:['allow','ask','deny','return','message','modify','flow','inject'],modify:{input:{operations:['merge','replace']},output:{operations:['replace']}},flow:{operations:['continue','stop'],remainingContinuations:2},inject:{context:{append:true,deliverAt:['now','next_turn']}}};
function rejects(fn:()=>unknown): void {let failed=false;try{fn();}catch{failed=true;}assert.equal(failed,true);}
test('flow and injection are atomic, stop wins, denial is independent, continuation accumulates once',()=>{
 const before=state();
 const effects=[{type:'inject',target:'context',operation:'append',deliverAt:'next_turn',value:'context'},{type:'message',text:'hidden'},{type:'flow',operation:'continue',instruction:'again'},{type:'modify',target:'absent',operation:'replace',value:{}}];
 rejects(()=>stageBoundary(before,effects,caps,'a'));assert.deepEqual(before,state());
 let settled=stageBoundary(before,[{type:'flow',operation:'continue',instruction:'first'},{type:'deny',reason:'no'},{type:'inject',target:'context',operation:'append',deliverAt:'now',value:'context'}],caps,'a');
 settled=stageBoundary(settled,[{type:'flow',operation:'continue',instruction:'second'},{type:'flow',operation:'stop',reason:'done'}],caps,'b');
 assert.equal(settled.denied,true);assert.equal(settled.flow,'stop');assert.deepEqual(settled.instructions,['first','second']);assert.equal(settled.injections?.length,1);
 rejects(()=>stageBoundary(before,[{type:'flow',operation:'continue',instruction:'again'}],{...caps,flow:{operations:['continue'],remainingContinuations:0}},'a'));
 rejects(()=>stageBoundary(before,[{type:'inject',target:'context',operation:'append',deliverAt:'later',value:'x'}],caps,'a'));
});
test('request-scoped targets and operations reject rather than downgrade; permission invalidation retained',()=>{
 const before={...state(),permission:'allow' as const,approval:'approved' as const,candidate:{value:'cached',supplier:'a',input:{task:123}},values:{output:'old'}};
 const next=stageBoundary(before,[{type:'modify',target:'input',operation:'merge',value:{task:124}},{type:'modify',target:'output',operation:'replace',value:'new'}],caps,'b');
 assert.equal(next.permission,'native');assert.equal(next.approval,'pending');assert.equal(next.candidate,null);assert.equal(next.values?.output,'new');
 rejects(()=>stageBoundary(before,[{type:'modify',target:'output',operation:'merge',value:{}}],caps,'b'));
 rejects(()=>stageBoundary(before,[{type:'future'}],{effects:['future']},'b'));
 const same=stageBoundary(before,[{type:'modify',target:'input',operation:'merge',value:{task:123}}],caps,'b');assert.equal(same.approval,'approved');
});
test('all intercepts precede observations regardless of registration order; one settled event identity',async()=>{
 const views: unknown[]=[];
 const result=await dispatchBoundary('event-1',state(),[
 {mode:'observe',capabilities:caps,receive:async view=>{views.push(view);return [{type:'deny',reason:'ignored'}];}},
 {mode:'intercept',capabilities:caps,receive:async view=>{assert.equal(view.input.task,123);return [{type:'modify',target:'input',operation:'merge',value:{task:124}}];}},
 {mode:'intercept',capabilities:caps,receive:async view=>{assert.equal(view.input.task,124);return [{type:'message',text:'settled'}];}},
 ]);
 assert.equal(result.denied,false);assert.deepEqual(views,[{...result,eventId:'event-1'}]);
});
test('immutable credential-scoped content is ready before dispatch, selected and authorized with explicit gaps',async()=>{
 const receiver=new ContentReceiver(), trace:string[]=[];
 const items=[{id:'a',kind:'text',ref:'ref-a',bytes:new TextEncoder().encode('body')},{id:'b',kind:'reasoning',ref:'ref-b',bytes:new TextEncoder().encode('private')},{id:'c',kind:'image',ref:'ref-c',bytes:new TextEncoder().encode('image')},{id:'d',kind:'text',ref:'ref-d'}];
 const options={subscription:'one',requested:['text','reasoning'],authorized:['text'],maxBytes:10,mode:'intercept' as const,failClosed:false,upload:async(bytes:Uint8Array)=>{const descriptor=await receiver.upload('one',bytes);trace.push('upload');return descriptor;}};
 const view=await prepareContent(items,options);trace.push('dispatch');assert.deepEqual(trace,['upload','dispatch']);assert.deepEqual(view.map(v=>v.gap),[undefined,'permission_withheld','not_requested','source_unavailable']);
 const ref=view[0]!.ref!;assert.equal(receiver.read('two',ref),undefined);
 const original=receiver.read('one',ref)!;original[0]=0;assert.equal(new TextDecoder().decode(receiver.read('one',ref)),'body');
 const changed=await receiver.upload('one',new TextEncoder().encode('changed'));assert.equal(changed.ref===ref,false);assert.equal(new TextDecoder().decode(receiver.read('one',ref)),'body');
 const limited=await prepareContent([items[0]!],{...options,maxBytes:1});assert.equal(limited[0]?.gap,'limit_exceeded');
 const failed=await prepareContent([items[0]!],{...options,upload:async()=>{throw Error('offline');}});assert.equal(failed[0]?.gap,'transfer_failed');
 let blocked=false;try{await prepareContent([items[3]!],{...options,failClosed:true});}catch{blocked=true;}assert.equal(blocked,true);
 const observation=await prepareContent([items[3]!],{...options,mode:'observe',failClosed:true});assert.equal(observation[0]?.gap,'source_unavailable');
});
test('reasoning, skills and native expansion use ordinary content identities, not shadow events',async()=>{
 const receiver=new ContentReceiver();const kinds=['reasoning','skill','native'];
 const views=await prepareContent(kinds.map(kind=>({id:`item-${kind}`,kind,ref:`ref-${kind}`,bytes:new TextEncoder().encode(kind)})),{subscription:'s',requested:kinds,authorized:kinds,maxBytes:100,mode:'observe',failClosed:false,upload:async(bytes)=>receiver.upload('s',bytes)});
 assert.deepEqual(views.map(v=>v.id),kinds.map(k=>`item-${k}`));for(const view of views){assert.equal(view.gap,undefined);assert.equal(new TextDecoder().decode(receiver.read('s',view.ref!)),view.kind);}
});
test('lineage rejects cycles and task after events require actual changes, not callbacks or denied proposals',()=>{
 const lineage=new Lineage();lineage.add('tool');lineage.add('task-before','tool');lineage.add('task-after','task-before');lineage.add('orphan','unknown');rejects(()=>lineage.add('unknown','orphan'));rejects(()=>lineage.add('self','self'));
 assert.equal(actualTaskChange({status:'open'},{status:'open'},'after'),null);assert.equal(actualTaskChange({status:'open'},{status:'open'},'after'),null);
 assert.deepEqual(actualTaskChange({status:'open'},{status:'done'},'after','task-before'),{id:'after',type:'task.change.after',parentEventId:'task-before',before:{status:'open'},after:{status:'done'}});
});

test('unresponsive observation is not an execution gate; uploads have their own watchdog',async()=>{
 const result=await dispatchBoundary('event',state(),[{mode:'observe',capabilities:caps,receive:()=>new Promise(()=>{})}]);assert.deepEqual(result,state());
 const view=await prepareContent([{id:'a',kind:'text',ref:'r',bytes:new TextEncoder().encode('body')}],{subscription:'s',requested:['text'],authorized:['text'],maxBytes:10,mode:'observe',failClosed:true,timeoutMs:1,upload:()=>new Promise(()=>{})});assert.equal(view[0]?.gap,'transfer_failed');
});
test('content metadata binds uploaded UTF-8 bytes and only records confirmed upload',async()=>{
 const view=await prepareContent([{id:'a',kind:'text',ref:'r',bytes:new TextEncoder().encode('abc')}],{subscription:'s',requested:['text'],authorized:['text'],maxBytes:3,mode:'intercept',failClosed:true,upload:async(bytes)=>new ContentReceiver().upload('s',bytes)});
 assert.equal(view[0]?.sizeBytes,3);assert.equal(view[0]?.sha256,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
test('task proposals are derived from settled invocation input, with independent denial',()=>{
 const invocation=stageBoundary(state(),[{type:'allow'},{type:'modify',target:'input',operation:'merge',value:{task:124}}],caps,'rewrite');
 const proposal={taskId:invocation.input.task,status:'open'};assert.equal(proposal.taskId,124);
 const taskBoundary=stageBoundary({...state(),input:proposal},[{type:'deny',reason:'task policy'}],{effects:['deny']},'task-policy');
 assert.equal(actualTaskChange(proposal,taskBoundary.denied ? proposal : {...proposal,status:'done'},'after','before'),null);
});

test('task comparisons ignore object key order and expose committed partial changes',()=>{
 assert.equal(actualTaskChange({a:1,b:2},{b:2,a:1},'event'),null);
 const partial=actualTaskChange({status:'open',count:0},{status:'open',count:1},'partial');assert.equal(partial?.type,'task.change.after');
});

test('observation routing stays local and never adds subscription identity to the wire', async () => {
 const event={id:'event',source:'urn:ahp:test',type:'tool.before'};
 const subscriptions=[{id:'local-observer',mode:'observe' as const},{id:'called-interceptor',mode:'intercept' as const},{id:'uncalled-interceptor',mode:'intercept' as const}];
 const work:Array<()=>void>=[];
 const deliveries:Array<{notification:unknown;route:string}>=[];
 let complete!:()=>void;
 const done=new Promise<void>(resolve=>{complete=resolve;});
 dispatchObservations(event,subscriptions,new Set(['called-interceptor']),async projected=>projected,(notification,subscription)=>{
  deliveries.push({notification,route:subscription.id});if(deliveries.length===2)complete();
 },task=>work.push(task));
 assert.equal(work.length,2);for(const task of work)task();await done;
 assert.deepEqual(deliveries.map(item=>item.route),['local-observer','uncalled-interceptor']);
 for(const {notification} of deliveries)assert.deepEqual(notification,{jsonrpc:'2.0',method:'hooks/observe',params:{protocolVersion:'draft',event}});
});
