import {mutableValues,effectiveEvent} from './settlement.mjs';
// Lifecycle fixtures have no core-adapter synthetic task input constraint.
import { stageBoundary, validateInterceptRequest, validateInterceptResponse } from '../packages/sdk/dist/src/draft/index.js';
export function evaluate(request, response) {
  if (!validateInterceptRequest(request).ok || !validateInterceptResponse(response).ok || response.id !== request.id) throw Error('Invalid canonical envelope');
  const {event, state = {permission:'none',candidate:null}, capabilities} = request.params;
  const input = structuredClone(event.tool?.input ?? event.input ?? {});
  const before = { ...(state.flow && state.flow !== 'none' ? {flow:state.flow} : {}), ...(state.instructions !== undefined ? {instructions:structuredClone(state.instructions)} : {}), ...(state.injections !== undefined ? {injections:structuredClone(state.injections)} : {}), input, candidate: state.candidate == null ? null : {value: state.candidate.value, supplier: 'prior-candidate', input}, permission: state.permission === 'none' || state.permission === 'deny' ? 'native' : state.permission, approval: 'not-required', denied: state.permission === 'deny', messages: [], values:mutableValues(event) };
  const staged = stageBoundary(before, response.result.effects, capabilities, 'matrix', () => true);
  const effective=effectiveEvent(event,staged);
  if(!validateInterceptRequest({...request,params:{...request.params,event:effective}}).ok)throw Error('Invalid effective typed payload');
  const decision = staged.denied ? 'deny' : staged.permission === 'ask' ? 'ask' : 'allow';
  return {...(Object.keys(staged.values ?? {}).length?{values:staged.values}:{}),decision, executed: event.type === 'tool.before' && decision === 'allow' && staged.candidate === null && staged.flow !== 'stop', input: staged.input, messages: staged.messages, ...(staged.candidate && decision === 'allow' && staged.flow !== 'stop' ? {result: staged.candidate.value} : {}), ...(staged.flow ? {flow:staged.flow} : {}), ...(staged.continuationRemaining !== undefined && (response.result.effects.some(effect => effect.type === 'flow') || state.flow === 'continue' || state.flow === 'stop' || state.instructions !== undefined) ? {continuationInstructions:staged.instructions ?? [],continuationRemaining:staged.continuationRemaining} : {}), ...(staged.instructions !== undefined && staged.continuationRemaining === undefined ? {continuationInstructions:staged.instructions} : {}), ...(staged.injections ? {injections:staged.injections} : {})};
}
