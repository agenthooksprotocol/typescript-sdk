/** One-way delivery of an already-settled boundary. */
export interface ObservationSubscription { id: string; mode: 'intercept' | 'observe'; }
export interface ObservationEvent { id: string; source: string; type: string; [key: string]: unknown; }
export interface ObservationNotification {
  jsonrpc: '2.0'; method: 'hooks/observe';
  params: {protocolVersion: 'draft'; event: ObservationEvent};
}
/** The host supplies matching subscriptions and invoked intercept subscription IDs.
 * prepare MUST apply existing content permissions/selections and confirm uploads.
 * Its failure drops only this best-effort delivery, never reopens the decision.
 * schedule MUST enqueue without awaiting work; it must not keep interrupted
 * execution alive. This injection supports browser and server host schedulers. */
export function dispatchObservations(
  event: ObservationEvent, subscriptions: readonly ObservationSubscription[], called: ReadonlySet<string>,
  prepare: (event: ObservationEvent, subscription: ObservationSubscription) => Promise<ObservationEvent>,
  notify: (notification: ObservationNotification, subscription: ObservationSubscription) => unknown,
  schedule: (work: () => void) => void,
): void {
  const snapshot = structuredClone(event);
  for (const subscription of structuredClone(subscriptions)) {
    if (subscription.mode !== 'observe' && !(subscription.mode === 'intercept' && !called.has(subscription.id))) continue;
    schedule(() => {
      void Promise.resolve().then(() => prepare(structuredClone(snapshot), subscription)).then(projected => {
        if (['id', 'source', 'type'].some(key => projected[key] !== snapshot[key])) throw Error('Observation changed boundary identity');
        return notify({jsonrpc: '2.0', method: 'hooks/observe', params: {protocolVersion: 'draft', event: projected}}, subscription);
      }).catch(() => {});
    });
  }
}
