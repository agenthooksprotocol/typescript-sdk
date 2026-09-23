import { validateEffect } from './draft/index.js';
import type { Effect, Capabilities } from './draft/index.js';
/** Synthetic pending-boundary evaluator. No external work occurs while staging. */
export interface PendingState {
  input: Record<string, unknown>;
  candidate: { value: unknown; supplier: string; input: Record<string, unknown> } | null;
  permission: 'native' | 'allow' | 'ask';
  approval: 'pending' | 'approved' | 'not-required';
  denied: boolean;
  messages: string[];
}
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
  return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every(k => Object.hasOwn(y, k) && equal(x[k], y[k]));
}
export function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function stageResponse(before: PendingState, effects: readonly Effect[], capabilities: Capabilities, supplier: string, validateInput: (input: Record<string, unknown>) => boolean = input => Number.isInteger(input.task) && (input.task as number) > 0): PendingState {
  const staged = clone(before);
  for (const effect of effects) {
    if (!validateEffect(effect).ok) throw new Error('Invalid effect');
    if (!capabilities.effects.includes(effect.type)) throw new Error('Unsupported effect');
    if (effect.type === 'modify') {
      if (effect.target !== 'input' || (effect.operation !== 'replace' && effect.operation !== 'merge') || capabilities.modify?.input?.[effect.operation] !== true) throw new Error('Unsupported target or operation');
    }
  }
  // Input mutations precede binding a result regardless of encoding order.
  for (const effect of effects.filter(e => e.type === 'modify')) {
    if (!object(effect.value)) throw new Error('Input must be an object');
    if (effect.operation === 'replace') staged.input = clone(effect.value);
    else if (effect.operation === 'merge') staged.input = { ...staged.input, ...clone(effect.value) };
    else throw new Error('Unsupported operation');
  }
  // Validate the final effective operation, never a partially staged replacement.
  if (!validateInput(staged.input)) throw new Error('Invalid effective tool input');
  if (!equal(before.input, staged.input)) {
    staged.candidate = null;
    if (staged.permission === 'allow') staged.permission = 'native';
    if (staged.approval === 'approved') staged.approval = 'pending';
  }
  for (const effect of effects) {
    switch (effect.type) {
      case 'modify': break;
      case 'return': staged.candidate = { value: clone(effect.value), supplier, input: clone(staged.input) }; break;
      case 'message':
        if (typeof effect.text !== 'string') throw new Error('Invalid message');
        staged.messages.push(effect.text); break;
      case 'deny': staged.denied = true; break;
      case 'ask': staged.permission = 'ask'; staged.approval = 'pending'; break;
      case 'allow': if (staged.permission !== 'ask') staged.permission = 'allow'; break;
      default: throw new Error('Unsupported effect');
    }
  }
  if (staged.denied) staged.candidate = null;
  return staged;
}
export function decide(state: PendingState, managedPolicy: 'allow' | 'deny'): string[] {
  const actions = ['policy'];
  if (state.denied || managedPolicy === 'deny') actions.push('blocked');
  else if (state.approval === 'pending' && state.permission !== 'allow') actions.push('approval-required');
  else if (state.candidate !== null) actions.push(`candidate:${state.candidate.supplier}`);
  else actions.push('execute');
  return actions;
}
