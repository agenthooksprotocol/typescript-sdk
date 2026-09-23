import { validateEffect } from "./draft/index.js";
/** Serial host-side text compaction. Responses commit atomically. Only `applied`
 * permits downstream use. Upload immutable UTF-8 bodies before wire exposure. */
export interface CompactionEffect { type: string; target?: string; operation?: string; value?: unknown; text?: string; reason?: string }
export interface CompactionObserver { supplier: string; run: (snapshot: any) => unknown }
export interface CompactionHook { supplier: string; failurePolicy: 'fail-open' | 'fail-closed'; run: (snapshot: any) => CompactionEffect[] }
const copy = <T>(v: T): T => structuredClone(v);
export function compactionCapabilities(boundary: 'before' | 'after', observeOnly = false): any {
  if (boundary !== 'before' && boundary !== 'after') throw new Error('unknown boundary');
  if (observeOnly) return { effects: [], modify: {} };
  return { effects: ['modify', 'message', ...(boundary === 'before' ? ['return', 'deny'] : [])], modify: { [boundary === 'before' ? 'instructions' : 'summary']: { replace: true, merge: false } } };
}
export function runCompaction(instructions: string, before: CompactionHook[] = [], after: CompactionHook[] = [], options: { generate?: (instructions: string) => string; itemId?: string; observeOnly?: boolean; observers?: CompactionObserver[] } = {}): any {
  const itemId = options.itemId ?? 'summary-1';
  if (typeof instructions !== 'string' || typeof itemId !== 'string' || !itemId) throw new Error('invalid input');
  for (const h of [...before, ...after]) if (typeof h.supplier !== 'string' || !h.supplier || !['fail-open', 'fail-closed'].includes(h.failurePolicy) || typeof h.run !== 'function') throw new Error('invalid hook');
  if (options.observers && !options.observeOnly) throw new Error('observers require observeOnly');
  for (const o of options.observers ?? []) if (typeof o.supplier !== 'string' || !o.supplier || typeof o.run !== 'function') throw new Error('invalid observer');
  let state: any = { instructions, candidate: null, summary: null, bodies: {}, messages: [], denied: false };
  const seen: any[] = [], failures: any[] = [];
  const summary = (staged: any, body: string) => {
    const ref = 'urn:ahp:compaction:utf8:' + Array.from(new TextEncoder().encode(body), b => b.toString(16).padStart(2, '0')).join('');
    staged.bodies[ref] = body; return { id: itemId, ref };
  };
  const pipeline = (boundary: 'before' | 'after', hooks: CompactionHook[]) => {
    const caps = compactionCapabilities(boundary, options.observeOnly === true && boundary === 'after');
    for (const hook of hooks) {
      const snapshot = { ...copy(state), boundary, capabilities: caps }; seen.push(copy(snapshot));
      try {
        const effects = hook.run(copy(snapshot));
        if (!Array.isArray(effects)) throw new Error('effects must be array');
        const staged = copy(state);
        for (const e of effects) {
          if (!e || typeof e !== 'object' || !validateEffect(e).ok || !caps.effects.includes(e.type)) throw new Error('unsupported effect');
          if (e.type === 'modify') {
            if (e.target !== (boundary === 'before' ? 'instructions' : 'summary') || e.operation !== 'replace' || typeof e.value !== 'string') throw new Error('invalid modification');
            if (boundary === 'before') staged.instructions = e.value;
            else staged.summary = summary(staged, e.value);
          } else if (e.type === 'deny' && (typeof e.reason !== 'string' || !e.reason)) throw new Error('denial requires reason');
          else if (e.type === 'return' && typeof e.value !== 'string') throw new Error('summary must be text');
          else if (e.type === 'message' && typeof e.text !== 'string') throw new Error('message must be text');
        }
        if (staged.instructions !== state.instructions) staged.candidate = null;
        for (const e of effects) {
          if (e.type === 'return') staged.candidate = { body: e.value, supplier: hook.supplier };
          else if (e.type === 'deny') staged.denied = true;
          else if (e.type === 'message') staged.messages.push(e.text);
        }
        state = staged;
      } catch {
        failures.push({ boundary, supplier: hook.supplier });
        if (hook.failurePolicy === 'fail-closed' && !(options.observeOnly && boundary === 'after')) return false;
      }
      if (state.denied) return false;
    }
    return true;
  };
  let generated = false, applied = false, provenance: any = null;
  if (pipeline('before', before)) {
    let body: string;
    if (state.candidate !== null) { body = state.candidate.body; provenance = { kind: 'supplied', supplier: state.candidate.supplier }; }
    else { body = (options.generate ?? (v => 'summary:' + v))(state.instructions); if (typeof body !== 'string') throw new Error('generator must return text'); generated = true; provenance = { kind: 'generated' }; }
    state.summary = summary(state, body); applied = options.observeOnly ? true : pipeline('after', after);
  }
  const result = { ...state, seen, failures, generated, provenance, applied };
  if (options.observeOnly && applied) {
    for (const observer of [...after, ...(options.observers ?? [])]) {
      const snapshot = { ...copy(state), boundary: 'after', applied: true, generated,
        provenance: copy(provenance), capabilities: compactionCapabilities('after', true) };
      seen.push(copy(snapshot));
      const notify = observer.run;
      // Scheduling never calls user code inline or awaits its returned promise.
      // Browser/Node observers must yield for I/O; blocking native work belongs
      // in a host worker. The unref'd timer cannot keep Node alive on shutdown.
      const timer = setTimeout(() => { void Promise.resolve().then(() => notify(snapshot)).catch(() => {}); }, 0);
      (timer as unknown as { unref?: () => void }).unref?.();
    }
  }
  return result;
}
