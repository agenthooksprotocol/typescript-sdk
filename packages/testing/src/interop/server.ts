/** Non-normative loopback HTTP binding; stdout is exclusively SDK NDJSON. */
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { NdjsonDecoder, PROTOCOL_VERSION } from '@agenthooksprotocol/sdk';
import { parseInterceptRequest as parseDraftRequest } from '@agenthooksprotocol/sdk/draft';
import { createAuth } from './auth.js';

const fixture = (name: string) => readFileSync(new URL(`../../../interop/fixtures/${name}`, import.meta.url).pathname, 'utf8');
const auth = createAuth();
// Scripts travel only over the parent/child test control plane, never AHP fields.
let scriptedReplies: Record<string, string> = {};
let scriptedStatuses: Record<string, number> = {};
process.on('message', (message: any) => {
  if (message.type !== 'configure-scripts') return;
  scriptedReplies = message.replies;
  scriptedStatuses = message.statuses ?? {};
  process.send({ type: 'scripts-ready' });
});
function intercept(body: string): string {
  try {
    const decoded = parseDraftRequest(body);
    if (!decoded.ok) throw new Error('Invalid draft request');
    const envelope = decoded.value;
    if (Object.hasOwn(scriptedReplies, envelope.id)) {
      process.send({ type: 'atomic-request', request: envelope });
      const reply = scriptedReplies[envelope.id]!;
      delete scriptedReplies[envelope.id];
      return reply;
    }
    const request = envelope;
    return JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: PROTOCOL_VERSION, effects: [] } });
  } catch {
    return JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }
}
async function handler(req: any, res: any): Promise<void> {
  const respond = (status: number, body: string) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(body); };
  // Node may discard duplicate Authorization fields in req.headers. Inspect the
  // original field lines before any dispatch, including unauthenticated routes.
  const authorizationFields = req.rawHeaders.filter((_: string, index: number) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === 'authorization');
  if (authorizationFields.length > 1) { respond(401, '{}'); return; }
  const path = req.url;
  if (req.method !== 'POST') { respond(405, '{}'); return; }
  if (!['/none', '/bearer', '/oauth', '/workload', '/mtls', '/token'].includes(path)) { respond(404, '{}'); return; }
  if (path !== '/token' && !auth.authorize(path, req.headers, req.socket.authorized === true)) { respond(401, '{}'); return; }
  let body = '';
  const utf8 = new TextDecoder('utf-8', { fatal: true });
  try {
    for await (const chunk of req) {
      body += utf8.decode(chunk, { stream: true });
      if (body.length > 1024 * 1024) { respond(413, '{}'); return; }
    }
    body += utf8.decode();
    if (path === '/token') {
      const result = auth.token(new URLSearchParams(body));
      respond(result.status, JSON.stringify(result.body));
    } else {
      let status = 200;
      try { status = scriptedStatuses[JSON.parse(body).id] ?? 200; } catch { /* intercept reports malformed requests */ }
      respond(status, intercept(body));
    }
  } catch { respond(400, '{}'); }
}
const http = createServer((req: any, res: any) => { void handler(req, res); });
const tls = createTlsServer({ key: fixture('server-key.pem'), cert: fixture('server.pem'), ca: fixture('ca.pem'), requestCert: true, rejectUnauthorized: true }, (req: any, res: any) => { void handler(req, res); });
tls.on('tlsClientError', (error: { code?: string }) => {
  if (process.connected) process.send({ type: 'tls-rejection', code: error.code });
});
for (const server of [http, tls]) { server.requestTimeout = 5000; server.headersTimeout = 5000; }
const listen = (server: any): Promise<number> => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});
const [httpPort, httpsPort] = await Promise.all([listen(http), listen(tls)]);
const decoder = new NdjsonDecoder();
process.stdin.on('data', (chunk: Uint8Array) => {
  try { for (const line of decoder.push(chunk)) process.stdout.write(intercept(line) + '\n'); }
  catch { process.exitCode = 1; process.stdin.destroy(); shutdown(); }
});
function shutdown(): void {
  http.close(); tls.close(); http.closeAllConnections(); tls.closeAllConnections();
  if (process.connected) process.disconnect();
}
process.stdin.on('end', () => { try { decoder.end(); } catch { process.exitCode = 1; } shutdown(); });
process.on('disconnect', () => { process.stdin.destroy(); shutdown(); });
// IPC readiness is control-plane only: no banners, ports or secrets on stdout.
if (process.send) process.send({ type: 'ready', httpPort, httpsPort });
else process.stderr.write(JSON.stringify({ type: 'ready', httpPort, httpsPort }) + '\n');
