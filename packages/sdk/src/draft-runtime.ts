import { validateEffect } from './draft/index.js';
import { validateBodyReference, type BodyReference } from './content-upload.js';
/** Synthetic semantic harness. Wire acceptance remains the canonical validator's job. */
import { stageResponse, object, type PendingState } from './draft-atomic.js';
import type { Effect, Capabilities } from './draft/index.js';
export interface BoundaryState extends PendingState {
  flow?: 'stop' | 'continue';
  instructions?: string[];
  continuationRemaining?: number;
  injections?: unknown[];
  values?: Record<string, unknown>;
}
export interface BoundaryCapabilities {
  effects: string[];
  modify?: Record<string, { replace?: boolean; merge?: boolean; operations?: string[] }>;
  flow?: { operations: string[]; remainingContinuations?: number; continuationCount?: number; maxContinuations?: number };
  inject?: { context: { append: boolean; deliverAt: string[] } };
}
export type BoundaryEffect = {type: string; [key: string]: unknown};
export function stageBoundary(before: BoundaryState, effects: readonly BoundaryEffect[], caps: BoundaryCapabilities, supplier: string, validateInput: (input: Record<string, unknown>) => boolean = () => true): BoundaryState {
  // Stage all state, including scheduling and user-facing messages, before the single commit.
  let staged = structuredClone(before);
  if (staged.continuationRemaining === undefined && caps.flow?.remainingContinuations !== undefined) staged.continuationRemaining = caps.flow.remainingContinuations;
  const ordinary: BoundaryEffect[] = [];
  for (const effect of effects) {
    if (!validateEffect(effect).ok) throw Error('Invalid effect');
    if (!caps.effects.includes(effect.type)) throw Error('Unsupported effect');
    if (effect.type === 'flow') {
      const operation = effect.operation;
      if (typeof operation !== 'string' || !caps.flow?.operations.includes(operation)) throw Error('Unsupported flow operation');
      if (operation === 'continue') {
        if ((!(Number(staged.continuationRemaining) > 0) && before.flow !== 'continue') || (caps.flow.maxContinuations !== undefined && (caps.flow.continuationCount ?? 0) >= caps.flow.maxContinuations)) throw Error('Continuation unavailable');
        if (staged.flow !== 'stop') staged.flow = 'continue';
        if (typeof effect.instruction === 'string') staged.instructions = [...(staged.instructions ?? []), effect.instruction];
      } else if (operation === 'stop' && typeof effect.reason === 'string') staged.flow = 'stop';
      else throw Error('Invalid flow');
    } else if (effect.type === 'inject') {
      if (typeof effect.deliverAt !== 'string' || !caps.inject?.context.deliverAt.includes(effect.deliverAt) || caps.inject.context.append !== true || effect.target !== 'context' || effect.operation !== 'append' || !Object.hasOwn(effect, 'value')) throw Error('Unsupported injection');
      staged.injections = [...(staged.injections ?? []), structuredClone(effect)];
    } else if (effect.type === 'modify') {
      const target = effect.target, operation = effect.operation;
      if (typeof target !== 'string' || (operation !== 'replace' && operation !== 'merge')) throw Error('Unsupported modification');
      const targetCaps = caps.modify?.[target];
      if (!(targetCaps?.[operation] === true || targetCaps?.operations?.includes(operation))) throw Error('Unsupported target or operation');
      if (target === 'input') ordinary.push(effect);
      else {
        if (!staged.values || !Object.hasOwn(staged.values, target)) throw Error('Target unavailable');
        const previous = staged.values[target];
        if (operation === 'merge' && (!object(previous) || !object(effect.value))) throw Error('Merge requires objects');
        staged.values[target] = operation === 'merge' ? {...previous as object, ...structuredClone(effect.value) as object} : structuredClone(effect.value);
      }
    } else ordinary.push(effect);
  }
  if (!sameValue(before.values, staged.values)) {
    staged.candidate = null;
    if (staged.permission === 'allow') staged.permission = 'native';
    if (staged.approval === 'approved') staged.approval = 'pending';
  }
  const inputCaps = caps.modify?.input;
  const normalized = {effects:caps.effects, modify:{input:{replace:inputCaps?.replace === true || inputCaps?.operations?.includes('replace') === true, merge:inputCaps?.merge === true || inputCaps?.operations?.includes('merge') === true}}};
  staged = stageResponse(staged, ordinary as Effect[], normalized as Capabilities, supplier, validateInput);
  if (staged.continuationRemaining !== undefined) {
    if (staged.flow === 'continue' && before.flow !== 'continue') staged.continuationRemaining--;
    else if (staged.flow === 'stop' && before.flow === 'continue') staged.continuationRemaining++;
  }
  return staged;
}
export interface Delivery { mode: 'intercept' | 'observe'; capabilities: BoundaryCapabilities; receive(view: BoundaryState & {eventId: string}): Promise<BoundaryEffect[]> }
export async function dispatchBoundary(eventId: string, initial: BoundaryState, deliveries: Delivery[]): Promise<BoundaryState> {
  let state = structuredClone(initial);
  for (const [index, delivery] of deliveries.entries()) if (delivery.mode === 'intercept') {
    const effects = await delivery.receive({...structuredClone(state), eventId});
    state = stageBoundary(state, effects, delivery.capabilities, String(index));
  }
  // Observation is a settled snapshot, not a second effect channel or execution gate.
  void Promise.all(deliveries.filter(d => d.mode === 'observe').map(async delivery => {
    try { await delivery.receive({...structuredClone(state), eventId}); } catch { /* best effort */ }
  }));
  return state;
}
export interface ContentItem { id: string; kind: string; ref?: string; bytes?: Uint8Array }
export interface ContentView { id: string; kind: string; ref?: string; sizeBytes?: number; sha256?: string; gap?: 'not_requested' | 'permission_withheld' | 'source_unavailable' | 'transfer_failed' | 'limit_exceeded' }
/** Receiver storage scoped by the host's authenticated principal, not wire claims. */
export class ContentReceiver {
  private stored = new Map<string, Uint8Array>();
  async upload(scope: string, bytes: Uint8Array): Promise<BodyReference> {
    if (!scope || !(bytes instanceof Uint8Array)) throw Error('Authenticated scope and binary bytes required');
    const snapshot = bytes.slice();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', snapshot));
    const sha256 = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
    const ref = 'urn:ahp:content:' + crypto.randomUUID();
    this.stored.set(JSON.stringify([scope, ref]), snapshot);
    return {ref, size: snapshot.length, sha256};
  }
  read(scope: string, ref: string): Uint8Array | undefined { return this.stored.get(JSON.stringify([scope, ref]))?.slice(); }
}
export async function prepareContent(items: ContentItem[], options: {subscription: string; requested: string[]; authorized: string[]; maxBytes: number; mode: 'intercept' | 'observe'; failClosed: boolean; timeoutMs?: number; upload(bytes: Uint8Array): Promise<BodyReference>}): Promise<ContentView[]> {
  const result: ContentView[] = [];
  for (const item of items) {
    const view: ContentView = {id:item.id, kind:item.kind};
    if (!options.requested.includes(item.kind)) view.gap = 'not_requested';
    else if (!options.authorized.includes(item.kind)) view.gap = 'permission_withheld';
    else if (item.bytes === undefined) view.gap = 'source_unavailable';
    else if (item.bytes.length > options.maxBytes) view.gap = 'limit_exceeded';
    else try {
      const bytes = new Uint8Array(item.bytes);
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
      let timer: ReturnType<typeof setTimeout> | undefined;
      let confirmed: BodyReference;
      try { confirmed = await Promise.race([options.upload(bytes.slice()), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(Error('Upload timeout')), options.timeoutMs ?? 1000); })]); }
      finally { if (timer !== undefined) clearTimeout(timer); }
      const sha256 = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
      const body = validateBodyReference(confirmed, bytes.length, sha256);
      view.ref = body.ref;
      view.sizeBytes = body.size;
      view.sha256 = body.sha256;
    } catch { view.gap = 'transfer_failed'; }
    if (view.gap && view.gap !== 'not_requested' && options.mode === 'intercept' && options.failClosed) throw Error('Content delivery failure');
    result.push(view);
  }
  return result;
}
export class Lineage {
  private parents = new Map<string, string | undefined>();
  add(id: string, parent?: string): void {
    if (this.parents.has(id)) throw Error('Duplicate event');
    const seen = new Set([id]);
    for (let cursor = parent; cursor !== undefined; cursor = this.parents.get(cursor)) {
      if (seen.has(cursor)) throw Error('Cyclic lineage');
      seen.add(cursor);
    }
    this.parents.set(id, parent);
  }
}
function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>;
  return Object.keys(left).length === Object.keys(right).length && Object.keys(left).every(key => Object.hasOwn(right, key) && sameValue(left[key], right[key]));
}
export function actualTaskChange<T>(before: T, after: T, id: string, parentEventId?: string): {id:string; type:string; parentEventId?:string; before:T; after:T} | null {
  // Arguments are committed snapshots, not proposed values. Denial with no write
  // has equal snapshots; actual partial changes remain observable after refusal.
  if (sameValue(before, after)) return null;
  return {id, type:'task.change.after', ...(parentEventId === undefined ? {} : {parentEventId}), before:structuredClone(before), after:structuredClone(after)};
}
export {uploadContent, prepareWireContent} from './content-upload.js';
export type {UploadConfiguration, BodyReference, NormalizedContentInput, NormalizedContentView} from './content-upload.js';
export {dispatchObservations} from './observation.js';
export type {ObservationEvent, ObservationSubscription, ObservationNotification} from './observation.js';
