import { parseInterceptResponse, stageResponse, decide, type PendingState, type Capabilities } from '@agenthooksprotocol/sdk/draft';

export interface Exchange { response: Promise<string>; cancel(): void }
export interface Interceptor {
  id: string; failurePolicy: 'fail-open' | 'fail-closed'; capabilities: Capabilities;
  start(state: PendingState): Exchange;
}
/** Synthetic asynchronous harness. Staging is pure; acceptance is a single commit. */
export class DecisionPipeline {
  state: PendingState;
  readonly trace: string[] = [];
  readonly messages: string[] = [];
  executions = 0;
  failures = 0;
  interrupted = false;
  private pending: { exchange: Exchange; end(reason: string): void } | undefined;
  constructor(initial: PendingState) { this.state = structuredClone(initial); }
  interrupt(): void {
    if (this.interrupted) return;
    this.interrupted = true;
    this.trace.push('interrupt');
    this.endPending('interrupted');
  }
  /** The harness clock invokes this at its deadline; tests drive the clock explicitly. */
  expire(): void { this.endPending('timeout'); }
  private endPending(reason: string): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = undefined;
    // Settle locally first: never await backend acknowledgement or cancellation.
    pending.end(reason);
    pending.exchange.cancel();
  }
  async run(subscribers: readonly Interceptor[], beforeExecute: () => Promise<void> = async () => {}): Promise<void> {
    for (const subscriber of subscribers) {
      if (this.interrupted) break;
      this.trace.push(`dispatch:${subscriber.id}`);
      try {
        const exchange = subscriber.start(this.state);
        // start() may synchronously call interrupt() before pending exists.
        // Observe late rejection, but never await a reply or backend cancellation.
        if (this.interrupted) {
          void exchange.response.catch(() => {});
          exchange.cancel();
          break;
        }
        const ended = new Promise<never>((_, reject) => {
          this.pending = { exchange, end: reason => reject(new Error(reason)) };
        });
        const body = await Promise.race([exchange.response, ended]);
        this.pending = undefined;
        if (this.interrupted) break;
        const decoded = parseInterceptResponse(body);
        if (!decoded.ok || decoded.value.id !== subscriber.id) throw new Error('Invalid response');
        const staged = stageResponse(this.state, decoded.value.result.effects, subscriber.capabilities, subscriber.id);
        if (this.interrupted) break;
        const messages = staged.messages.slice(this.state.messages.length);
        this.state = staged;
        this.trace.push(`accept:${subscriber.id}`);
        for (const message of messages) { this.messages.push(message); this.trace.push(`message:${message}`); }
      } catch (error) {
        this.pending = undefined;
        if (this.interrupted) break;
        this.failures++;
        this.trace.push(`reject:${subscriber.id}`, error instanceof Error && error.message === 'timeout' ? 'timeout' : 'backend-failure', `failure:${subscriber.failurePolicy}`);
        if (subscriber.failurePolicy === 'fail-closed') this.state = { ...this.state, denied: true };
      }
    }
    if (!this.interrupted) await beforeExecute();
    if (this.interrupted) { this.trace.push('interrupted'); return; }
    const actions = decide(this.state, 'allow');
    this.trace.push(...actions);
    if (actions.includes('execute')) this.executions++;
  }
}
