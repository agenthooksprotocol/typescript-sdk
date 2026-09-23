/** Real bindings plus deterministic IPC script barriers; no cancellation RPC. */
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { NdjsonDecoder } from '@agenthooksprotocol/sdk';
import { parseInterceptRequest, parseInterceptResponse, draftCodecs } from '@agenthooksprotocol/sdk/draft';

export interface InterruptionOperation {
  response: Promise<string>;
  /** Backend has canonically validated the request and installed its hold. */
  received: Promise<void>;
  cancel(): void;
  /** Backend attempted its reply; stdio additionally waits for the frame to drain. */
  release(): Promise<void>;
  /** HTTP request closed, or stdio ID waiter detached (not process exit). */
  closed: Promise<void>;
}
export interface Transport {
  /** IDs are unique for this lifetime; persistent stdio permits one exchange at a time. */
  start(id: string, body: string, responseBody: string): InterruptionOperation;
  dispose(): Promise<void>;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  void promise.catch(() => {}); // Cancellation may precede the caller's observer.
  return { promise, resolve, reject };
}
type Operation = {
  configured: ReturnType<typeof deferred<void>>;
  received: ReturnType<typeof deferred<void>>;
  released: ReturnType<typeof deferred<void>>;
  drained: ReturnType<typeof deferred<void>>;
  closed: ReturnType<typeof deferred<void>>;
  response: ReturnType<typeof deferred<string>>;
  cancelled: boolean;
  sent: boolean;
  req?: any;
};

export async function openInterruptionTransport(kind: 'http' | 'stdio'): Promise<Transport> {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./interruption-server.js', import.meta.url))], {
    stdio: ['pipe', 'pipe', 'pipe', 'ipc'], shell: false,
  });
  const ready = deferred<number>(), exited = deferred<void>();
  const operations = new Map<string, Operation>();
  const waiters = new Map<string, Operation>();
  const decoder = new NdjsonDecoder();
  // A cancelled ID remains quarantined until its late frame is drained. No
  // multiplexing or respawn: remove its waiter, retain only framing ownership.
  let stdioId: string | undefined;
  let disposed = false;
  let failure: Error | undefined;
  let disposal: Promise<void> | undefined;
  let exitCode: number | null = null;
  function fail(error: Error): void {
    failure ??= error;
    ready.reject(error);
    for (const op of operations.values()) {
      op.configured.reject(error); op.received.reject(error); op.released.reject(error);
      op.drained.reject(error); op.response.reject(error);
      if (op.req) op.req.destroy(); else op.closed.resolve();
    }
    waiters.clear();
  }
  function send(message: object): void {
    if (!child.connected) { fail(new Error('Backend disconnected')); return; }
    child.send(message, (error: Error | null) => { if (error) fail(error); });
  }
  function accept(id: string, body: string): void {
    const op = operations.get(id)!;
    const waiter = waiters.get(id);
    waiters.delete(id);
    if (waiter) {
      const parsed = parseInterceptResponse(body);
      if (!parsed.ok || parsed.value.id !== id) op.response.reject(new Error('Invalid canonical response or mismatched ID'));
      else op.response.resolve(body);
    }
    if (kind === 'stdio') { stdioId = undefined; op.closed.resolve(); }
    op.drained.resolve();
  }
  child.stderr.resume();
  child.stdin.on('error', (error: Error) => { if (!disposed) fail(error); });
  child.stdout.on('error', (error: Error) => fail(error));
  child.stdout.on('data', (chunk: Uint8Array) => {
    try {
      for (const line of decoder.push(chunk)) {
        if (stdioId === undefined) throw new Error('Unsolicited stdout frame');
        accept(stdioId, line);
      }
    } catch (error) { fail(error instanceof Error ? error : new Error(String(error))); }
  });
  child.stdout.on('end', () => {
    try { decoder.end(); } catch (error) { fail(error instanceof Error ? error : new Error(String(error))); }
  });
  child.on('message', (message: any) => {
    if (message.type === 'ready') { ready.resolve(message.port); return; }
    if (message.type === 'fatal') { fail(new Error(message.message)); return; }
    const op = operations.get(message.id);
    if (!op) { fail(new Error('Unknown barrier ID')); return; }
    if (message.type === 'configured') op.configured.resolve();
    else if (message.type === 'received') op.received.resolve();
    else if (message.type === 'released') op.released.resolve();
  });
  child.on('error', (error: Error) => fail(error));
  child.once('close', (code: number | null) => {
    exitCode = code;
    clearTimeout(watchdog);
    fail(new Error('Interruption backend closed'));
    for (const op of operations.values()) op.closed.resolve();
    exited.resolve();
  });
  // Safety bound only: all normal ordering uses IPC or stream events.
  const watchdog = setTimeout(() => {
    fail(new Error('Interruption transport watchdog expired'));
    child.kill('SIGKILL');
  }, 30000);
  function dispose(): Promise<void> {
    if (disposal) return disposal;
    const priorFailure = failure;
    disposed = true;
    fail(new Error('Interruption transport disposed'));
    disposal = (async () => {
      const kill = setTimeout(() => child.kill('SIGKILL'), 2000);
      try {
        if (child.connected) send({ type: 'shutdown' });
        await exited.promise;
        if (priorFailure) throw priorFailure;
        if (exitCode !== 0) throw new Error('Unclean interruption backend exit');
      } finally { clearTimeout(kill); clearTimeout(watchdog); }
    })();
    return disposal;
  }
  let port: number;
  try { port = await ready.promise; } catch (error) { await dispose(); throw error; }
  return {
    dispose,
    start(id, body, responseBody) {
      if (disposed || failure) throw failure ?? new Error('Transport disposed');
      if (operations.has(id)) throw new Error('Operation IDs must be unique');
      if (kind === 'stdio' && stdioId !== undefined) throw new Error('Release and drain the previous stdio exchange first');
      const parsed = parseInterceptRequest(body);
      if (!parsed.ok || parsed.value.id !== id) throw new Error('Invalid canonical request or mismatched ID');
      const wire = draftCodecs.encodeInterceptRequest(parsed.value);
      const op: Operation = {
        configured: deferred<void>(), received: deferred<void>(), released: deferred<void>(), drained: deferred<void>(),
        response: deferred<string>(), closed: deferred<void>(), cancelled: false, sent: false,
      };
      operations.set(id, op); waiters.set(id, op);
      if (kind === 'stdio') stdioId = id;
      send({ type: 'configure', id, responseBody });
      void op.configured.promise.then(() => {
        if (disposed || failure || op.cancelled) return;
        op.sent = true;
        if (kind === 'stdio') {
          child.stdin.write(wire + '\n', (error: Error | null) => { if (error) fail(error); });
          return;
        }
        const req = request({ hostname: '127.0.0.1', port, path: '/', method: 'POST', agent: false,
          headers: { 'content-type': 'application/json' } }, (res: any) => {
          let response = '';
          const utf8 = new TextDecoder('utf-8', { fatal: true });
          res.on('data', (chunk: Uint8Array) => {
            try {
              response += utf8.decode(chunk, { stream: true });
              if (response.length > 1024 * 1024) throw new Error('Response too large');
            } catch (error) { req.destroy(error); }
          });
          res.on('error', (error: Error) => op.response.reject(error));
          res.on('aborted', () => op.response.reject(new Error('HTTP response aborted')));
          res.on('end', () => {
            try {
              if (res.statusCode !== 200) throw new Error('Unexpected HTTP status');
              accept(id, response + utf8.decode());
            } catch (error) { op.response.reject(error instanceof Error ? error : new Error(String(error))); }
          });
        });
        op.req = req;
        req.on('error', (error: Error) => { op.response.reject(error); op.received.reject(error); });
        req.once('close', () => op.closed.resolve());
        req.end(wire);
      }).catch((error: Error) => { op.response.reject(error); op.closed.resolve(); });
      let release: Promise<void> | undefined;
      return {
        response: op.response.promise, received: op.received.promise, closed: op.closed.promise,
        cancel() {
          if (op.cancelled) return;
          op.cancelled = true;
          const error = new Error('Operation cancelled'); error.name = 'AbortError';
          waiters.delete(id); op.response.reject(error);
          if (!op.sent) { op.received.reject(error); op.drained.resolve(); }
          if (op.req) op.req.destroy(error); else op.closed.resolve();
        },
        release() {
          release ??= (async () => {
            await op.configured.promise;
            // Stdio always sends complete frames; wait for the server to own it
            // even if locally cancelled. HTTP cancellation may destroy it earlier.
            if (!op.cancelled || (kind === 'stdio' && op.sent)) await op.received.promise;
            if (disposed || failure) throw failure ?? new Error('Transport disposed');
            send({ type: 'release', id });
            await op.released.promise;
            if (kind === 'stdio') {
              await op.drained.promise;
              if (stdioId === id) stdioId = undefined;
            }
          })();
          void release.catch(() => {});
          return release;
        },
      };
    },
  };
}
