import {isDeepStrictEqual as equal} from 'node:util';
/** One receiving connection. Call only after canonical envelope validation. */
export class TaskLineage {
 constructor({requireKnownParents=false}={}){this.events=new Map();this.parents=new Map();this.requireKnownParents=requireKnownParents;}
 accept(message){
  const event=message.params.event, key=JSON.stringify([event.source,event.id]);
  const parent=event.parentEventId===undefined?undefined:JSON.stringify([event.source,event.parentEventId]);
  const old=this.events.get(key);
  if(old){if(old.type!==event.type||this.parents.get(key)!==parent)throw Error('Inconsistent event identity');this.checkActual(event);return;}
  this.checkActual(event);
  if(parent!==undefined){
   if(this.requireKnownParents&&!this.events.has(parent))throw Error('Unknown producer parent');
   const seen=new Set([key]);
   for(let cursor=parent;cursor!==undefined;cursor=this.parents.get(cursor)){if(seen.has(cursor))throw Error('Cyclic lineage');seen.add(cursor);}
   if(this.events.has(parent))this.checkPair(this.events.get(parent),event);
  }
  for(const [child,edge] of this.parents)if(edge===key)this.checkPair(event,this.events.get(child));
  this.events.set(key,structuredClone(event));this.parents.set(key,parent);
 }
 checkPair(parent,child){for(const [family,identity] of [['task','id'],['workspace','kind']])if(parent.type===`${family}.change.before`&&child.type===`${family}.change.after`){if(parent[family][identity]!==child[family][identity]||(family==='task'&&parent.task.operation!==child.task.operation))throw Error('Mismatched before/after identity');}}
 checkActual(event){
  for(const family of ['task','workspace'])if(event.type===`${family}.change.after`){const {change,prior,operation}=event[family];if(family==='task'&&operation!=='update')continue;if(Object.keys(change).length===0||(prior&&Object.entries(change).every(([k,v])=>Object.hasOwn(prior,k)&&equal(v,prior[k]))))throw Error('No actual change');}
  if(event.type==='file.changed')for(const change of event.changes)if(change.operation==='update'&&Object.hasOwn(change,'before')&&Object.hasOwn(change,'after')&&equal(change.before,change.after))throw Error('No actual file change');
 }
}
