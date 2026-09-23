import test from 'node:test';
import assert from 'node:assert/strict';
import {effectiveEvent} from './settlement.mjs';
import {TaskLineage} from './task-lineage.mjs';
test('effective observation payload',()=>{
 const event={id:'e',source:'urn:test',tool:{input:{x:1}}};
 assert.deepEqual(effectiveEvent(event,{input:{x:2}}),{...event,tool:{input:{x:2}}});assert.equal(event.tool.input.x,1);
});
const wire=(id,type,parentEventId,task={id:'task',operation:'update',change:{status:'done'}})=>({params:{event:{id,source:'urn:source',type,parentEventId,task}}});
test('task lineage checks late parents, pair identities, source scope and actual updates',()=>{
 const lineage=new TaskLineage();
 lineage.accept(wire('after','task.change.after','before'));
 lineage.accept(wire('before','task.change.before','tool'));
 assert.throws(()=>lineage.accept(wire('tool','tool.before','after')));
 const mismatch=new TaskLineage();mismatch.accept(wire('after','task.change.after','before'));
 assert.throws(()=>mismatch.accept(wire('before','task.change.before',undefined,{id:'wrong',operation:'update',change:{x:1}})));
 assert.throws(()=>lineage.accept(wire('noop','task.change.after',undefined,{id:'task',operation:'update',change:{status:'done'},prior:{status:'done'}})));
 const independent=wire('before','task.change.before');independent.params.event.source='urn:other';lineage.accept(independent);
 assert.throws(()=>new TaskLineage({requireKnownParents:true}).accept(wire('child','task.change.after','absent')));
});

test('typed task/workspace operations enforce only advertised controls and validate effective payload',async()=>{
 const {evaluate}=await import('./lifecycle-evaluator.mjs');
 const request=(event,capabilities)=>({jsonrpc:'2.0',id:event.id,method:'hooks/intercept',params:{protocolVersion:'draft',event:{source:'urn:typescript:typed',time:'2026-01-01T00:00:00Z',...event},capabilities}});
 const response=(id,effects)=>({jsonrpc:'2.0',id,result:{protocolVersion:'draft',effects}});
 const task=request({id:'task-before',type:'task.change.before',task:{id:'durable-task',operation:'update',change:{status:'native-done'}}},{effects:['deny']});
 assert.equal(evaluate(task,response(task.id,[{type:'deny',reason:'policy'}])).decision,'deny');
 assert.throws(()=>evaluate(task,response(task.id,[{type:'allow'}])));
 const workspace=request({id:'workspace-before',type:'workspace.change.before',workspace:{kind:'cwd',change:{cwd:'/old'}}},{effects:['modify','deny'],modify:{workspace:{replace:true,merge:true}}});
 const modified=evaluate(workspace,response(workspace.id,[{type:'modify',target:'workspace',operation:'replace',value:{kind:'cwd',change:{cwd:'/new'}}}]));
 assert.equal(modified.decision,'allow');assert.equal(modified.values.workspace.change.cwd,'/new');
 assert.equal(evaluate(workspace,response(workspace.id,[{type:'deny',reason:'policy'}])).decision,'deny');
 assert.throws(()=>evaluate(workspace,response(workspace.id,[{type:'modify',target:'workspace',operation:'replace',value:{kind:'cwd'}}])));
});

test('short-circuit downgrades only uncalled interceptors, with filtered effective content and no observer wait',async()=>{
 const {dispatchObservations}=await import('./settlement.mjs');
 const received=[],routed=[];
 let resolve;
 const delivered=new Promise(r=>{resolve=r});
 const event={id:'same',source:'urn:test',type:'tool.before',secret:'effective'};
 dispatchObservations(event,[{id:'called',mode:'intercept'},{id:'remaining',mode:'intercept'},{id:'explicit',mode:'observe'}],['called'],async event=>{delete event.secret;return event},(note,subscription)=>{
  routed.push(subscription.id);
  received.push(note);if(received.length===2)resolve();
  return new Promise(()=>{}); // No processing completion, still no caller wait.
 });
 const timeout=setTimeout(()=>resolve(),1000);
 await delivered;clearTimeout(timeout);
 assert.equal(received.length,2);assert.deepEqual(routed.sort(),['explicit','remaining']);
 for(const note of received){assert.equal(note.method,'hooks/observe');assert.equal(note.params.event.id,'same');assert.equal(Object.hasOwn(note.params.event,'secret'),false);assert.deepEqual(Object.keys(note.params).sort(),['event','protocolVersion']);assert.equal(Object.hasOwn(note,'id'),false)}
 assert.equal(event.secret,'effective');
});
