/** Test-only backend: IPC scripts/barriers are not protocol cancellation RPCs. */
import { createServer } from 'node:http';
import process from 'node:process';
import { NdjsonDecoder } from '@agenthooksprotocol/sdk';
import { parseInterceptRequest } from '@agenthooksprotocol/sdk/draft';

type Hold = { response: string; respond?: (body: string, done: () => void) => void };
const holds = new Map<string, Hold>();
const send = (message: object): void => {
  if (process.connected) process.send(message, (error: Error | null) => { if (error) shutdown(); });
};
function receive(body: string, respond: NonNullable<Hold['respond']>): void {
  const parsed = parseInterceptRequest(body);
  if (!parsed.ok) throw new Error('Invalid canonical request');
  const id = parsed.value.id;
  if (typeof id !== 'string') throw new Error('Script IDs must be strings');
  const hold = holds.get(id);
  if (!hold || hold.respond) throw new Error('Missing or duplicate script');
  hold.respond = respond;
  send({ type: 'received', id });
}
const http = createServer(async (req: any, res: any) => {
  req.on('error', () => {});
  res.on('error', () => {}); // Late responses to destroyed streams are expected.
  try {
    if (req.method !== 'POST' || req.url !== '/') throw new Error('Invalid route');
    const utf8 = new TextDecoder('utf-8', { fatal: true });
    let body = '';
    for await (const chunk of req) {
      body += utf8.decode(chunk, { stream: true });
      if (body.length > 1024 * 1024) throw new Error('Request too large');
    }
    body += utf8.decode();
    receive(body, (reply, done) => {
      // Ack the attempt, not delivery: a destroyed stream may never call end's callback.
      try { res.writeHead(200, { 'content-type': 'application/json' }); res.end(reply); }
      finally { done(); }
    });
  } catch (error) {
    res.statusCode = 400; res.end();
    send({ type: 'fatal', message: String(error) });
  }
});
http.requestTimeout = 15000;
http.headersTimeout = 15000;
const decoder = new NdjsonDecoder();
process.stdin.on('data', (chunk: Uint8Array) => {
  try {
    for (const line of decoder.push(chunk)) receive(line, (reply, done) => {
      process.stdout.write(reply + '\n', (error: Error | null) => {
        if (error) send({ type: 'fatal', message: String(error) });
        else done();
      });
    });
  } catch (error) { send({ type: 'fatal', message: String(error) }); }
});
process.stdout.on('error', () => shutdown());
process.stdin.on('error', () => shutdown());
process.stdin.on('end', () => {
  try { decoder.end(); } catch { process.exitCode = 1; }
  shutdown();
});
let stopping = false;
function shutdown(): void {
  if (stopping) return;
  stopping = true;
  holds.clear();
  http.close(); http.closeAllConnections();
  process.stdin.destroy();
  if (process.connected) process.disconnect();
}
process.on('disconnect', shutdown);
process.on('message', (message: any) => {
  try {
    if (message.type === 'configure') {
      if (holds.has(message.id)) throw new Error('Duplicate script');
      // Deliberately raw: callers also script malformed response bytes.
      holds.set(message.id, { response: message.responseBody });
      send({ type: 'configured', id: message.id });
    } else if (message.type === 'release') {
      const hold = holds.get(message.id);
      if (!hold) throw new Error('Unknown script');
      holds.delete(message.id);
      const done = (): void => send({ type: 'released', id: message.id });
      if (hold.respond) hold.respond(hold.response, done);
      else done();
    } else if (message.type === 'shutdown') shutdown();
  } catch (error) { send({ type: 'fatal', message: String(error) }); }
});
http.on('error', (error: Error) => { send({ type: 'fatal', message: String(error) }); shutdown(); });
http.listen(0, '127.0.0.1', () => send({ type: 'ready', port: http.address().port }));
