import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { NdjsonDecoder } from '@agenthooksprotocol/sdk';
import { parseInterceptRequest, parseInterceptResponse, stageResponse, decide, type PendingState, type Capabilities, draftCodecs } from '@agenthooksprotocol/sdk/draft';
import { request } from './client.js';

interface Subscriber {
  id: string;
  failurePolicy: 'fail-open' | 'fail-closed';
  capabilities: Capabilities;
  response: unknown;
  rawResponse?: string;
  httpStatus?: number;
}
export interface AtomicOutcome { state: PendingState; actions: string[]; trace: string[]; failures: number; executions: number; emittedMessages: string[]; requests: unknown[] }
export interface AtomicScenario {
  id: string; initial: PendingState; subscribers: Subscriber[];
  managedPolicy: 'allow' | 'deny'; expected: AtomicOutcome;
}
export interface AtomicRow { id: string; transport: 'http' | 'stdio'; actual: AtomicOutcome; expected: AtomicOutcome }
export function atomicScenarios(): AtomicScenario[] {
  return JSON.parse(readFileSync(new URL('../../../interop/atomic-scenarios.json', import.meta.url).pathname, 'utf8')).scenarios;
}
export async function runAtomicInterop(): Promise<AtomicRow[]> {
  const child = spawn(process.execPath, [new URL('./server.js', import.meta.url).pathname], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'], shell: false });
  const decoder = new NdjsonDecoder();
  let pending: { resolve: (line: string) => void; reject: (error: Error) => void } | undefined;
  let observed: { resolve: (value: unknown) => void; reject: (error: Error) => void } | undefined;
  let framingFailure = false;
  child.stderr.resume();
  child.stdout.on('data', (chunk: Uint8Array) => {
    try { for (const line of decoder.push(chunk)) {
      if (!pending) throw new Error('Unsolicited response');
      const waiter = pending; pending = undefined; waiter.resolve(line);
    } } catch { framingFailure = true; pending?.reject(new Error('Invalid stdout framing')); }
  });
  child.on('message', (message: any) => {
    if (message.type === 'atomic-request') {
      if (!observed) { framingFailure = true; return; }
      const waiter = observed; observed = undefined; waiter.resolve(message.request);
    }
  });
  const exited = new Promise<number | null>(resolve => child.once('exit', (code: number | null) => {
    const error = new Error('Atomic server exited');
    pending?.reject(error); observed?.reject(error); resolve(code);
  }));
  const deadline = setTimeout(() => child.kill(), 15000);
  try {
    const ready = await new Promise<{ httpPort: number }>((resolve, reject) => {
      child.once('message', (message: any) => message.type === 'ready' ? resolve(message) : reject(new Error('Missing readiness')));
      child.once('error', reject); child.once('exit', () => reject(new Error('Server failed before readiness')));
    });
    const rows: AtomicRow[] = [];
    // Each transport independently replays every language-neutral scenario.
    for (const transport of ['http', 'stdio'] as const) for (const scenario of atomicScenarios()) {
      const replies = Object.fromEntries(scenario.subscribers.map(s => [s.id, s.rawResponse ?? JSON.stringify(s.response)]));
      await new Promise<void>((resolve, reject) => {
        child.once('message', (message: any) => message.type === 'scripts-ready' ? resolve() : reject(new Error('Missing script acknowledgement')));
        child.send({ type: 'configure-scripts', replies, statuses: Object.fromEntries(scenario.subscribers.map(s => [s.id, s.httpStatus ?? 200])) });
      });
      let state: PendingState = JSON.parse(JSON.stringify(scenario.initial));
      const trace: string[] = [], requests: unknown[] = [];
      let failures = 0, executions = 0;
      const emittedMessages: string[] = [];
      const display = (text: string) => { emittedMessages.push(text); trace.push(`message:${text}`); };
      const executeOperation = () => { executions++; };
      for (const subscriber of scenario.subscribers) {
        const wire = { jsonrpc: '2.0', id: subscriber.id, method: 'hooks/intercept', params: {
          protocolVersion: 'draft', event: { id: subscriber.id, source: 'urn:ahp:interop', type: 'tool.before', time: '2026-01-01T00:00:00Z', session: { id: 'interop' }, call: {id:'call-1'}, path:'native', tool: {origin:'native', name: 'task', kind: 'task', input: state.input } }, capabilities: subscriber.capabilities,
          state: { permission: state.denied ? 'deny' : state.permission === 'native' ? 'none' : state.permission,
            candidate: state.candidate === null ? null : { value: state.candidate.value } },
        } };
        const checked = parseInterceptRequest(JSON.stringify(wire));
        if (!checked.ok) throw new Error('Invalid harness request');
        const body = draftCodecs.encodeInterceptRequest(checked.value);
        trace.push(`dispatch:${subscriber.id}`);
        const seen = new Promise<unknown>((resolve, reject) => { observed = { resolve, reject }; });
        try {
          const response = transport === 'stdio'
            ? new Promise<string>((resolve, reject) => { pending = { resolve, reject }; child.stdin.write(body + '\n'); }).then(body => ({ status: 200, body }))
            : request(ready.httpPort, '/none', body);
          const [received, view] = await Promise.all([response, seen]);
          requests.push(view);
          if (received.status !== 200) throw new Error('Unexpected HTTP status');
          const decoded = parseInterceptResponse(received.body);
          if (!decoded.ok || decoded.value.id !== subscriber.id) throw new Error('Invalid response');
          const staged = stageResponse(state, decoded.value.result.effects, subscriber.capabilities, subscriber.id);
          const messages = staged.messages.slice(state.messages.length);
          state = staged; // The sole commit point. No callbacks run during stageResponse.
          trace.push(`accept:${subscriber.id}`);
          for (const text of messages) display(text);
        } catch {
          // Acquisition is part of the same failure boundary. Release observation waiters.
          observed?.reject(new Error('Response acquisition failed')); observed = undefined;
          pending?.reject(new Error('Response acquisition failed')); pending = undefined;
          failures++;
          trace.push(`reject:${subscriber.id}`, `failure:${subscriber.failurePolicy}`);
          if (subscriber.failurePolicy === 'fail-closed') state = { ...state, denied: true };
        }
      }
      const actions = decide(state, scenario.managedPolicy);
      if (actions.includes('execute')) executeOperation();
      trace.push(...actions);
      rows.push({ id: scenario.id, transport, actual: { state, actions, trace, failures, executions, emittedMessages, requests }, expected: scenario.expected });
    }
    child.stdin.end();
    if (await exited !== 0 || framingFailure) throw new Error('Unclean atomic transport exit');
    decoder.end();
    return rows;
  } finally { clearTimeout(deadline); child.kill(); await exited; }
}
