export function effectiveEvent(event, state){
 const result=structuredClone(event);
 if(state){
  if(result.tool)result.tool.input=structuredClone(state.input);
  else if(Object.hasOwn(result,'input'))result.input=structuredClone(state.input);
  for(const [target,value] of Object.entries(state.values ?? {})){
   if(target==='output'&&result.tool)result.tool.output=structuredClone(value);
   else if(target==='request'&&result.model)result.model.request=structuredClone(value);
   else if(target==='response'&&result.model)result.model.response=structuredClone(value);
   else result[target]=structuredClone(value);
  }
 }
 return result;
}
export function mutableValues(event){
 const values={};
 for(const target of ['output','prompt','request','response','content','instructions','summary','task','workspace'])if(Object.hasOwn(event,target))values[target]=structuredClone(event[target]);
 if(event.tool&&Object.hasOwn(event.tool,'output'))values.output=structuredClone(event.tool.output);
 if(event.model)for(const target of ['request','response'])if(Object.hasOwn(event.model,target))values[target]=structuredClone(event.model[target]);
 return values;
}

import {dispatchObservations as dispatch} from '../packages/sdk/dist/src/observation.js';
export function dispatchObservations(event, subscriptions, called, prepare, notify) {
 dispatch(event,subscriptions,new Set(called),prepare,notify,work=>{setImmediate(work).unref()});
}
