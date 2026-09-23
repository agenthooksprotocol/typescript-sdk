import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { NdjsonDecoder } from '@agenthooksprotocol/sdk';
import { parseInterceptRequest, parseInterceptResponse } from '@agenthooksprotocol/sdk/draft';
import { createAuth } from './auth.js';

interface Scenario { id: string; transport: string; auth: string; credential: string; expected: string }
export interface ScenarioResult { id: string; transport: string; auth: string; status: 'passed' | 'failed' | 'inapplicable'; expected: string; actual: string }
const fixture = (name: string) => readFileSync(new URL(`../../../interop/fixtures/${name}`, import.meta.url).pathname, 'utf8');
export function resolveCredential(reference: string, environment: Record<string, string | undefined>, credentials: Record<string, string>): string {
  const [kind, name] = reference.split(':');
  const value = name === undefined ? undefined : kind === 'env' ? environment[name] : kind === 'credential' ? credentials[name] : undefined;
  if (!value) throw new Error('Unresolved test credential reference');
  return value;
}
export function request(port: number, path: string, body: string, authorization?: string, tlsOptions?: object): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = (tlsOptions ? httpsRequest : httpRequest)({ hostname: '127.0.0.1', port, path, method: 'POST', agent: false, ...tlsOptions,
      headers: { 'content-type': path === '/token' ? 'application/x-www-form-urlencoded' : 'application/json', ...(authorization ? { authorization } : {}) } }, (res: any) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => { data += chunk; if (data.length > 1024 * 1024) req.destroy(new Error('Oversized response')); });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
      res.on('error', reject);
    });
    req.setTimeout(5000, () => req.destroy(new Error('Request deadline')));
    req.on('error', reject); req.end(body);
  });
}
export async function runInterop(): Promise<{ format: string; ok: boolean; results: ScenarioResult[] }> {
  const definitions = JSON.parse(readFileSync(new URL('../../../interop/scenarios.json', import.meta.url).pathname, 'utf8')) as { request: unknown; scenarios: Scenario[] };
  const auth = createAuth();
  const child = spawn(process.execPath, [new URL('./server.js', import.meta.url).pathname], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'], shell: false });
  let pending: { resolve: (line: string) => void; reject: (error: Error) => void } | undefined;
  const decoder = new NdjsonDecoder();
  const tlsRejections = new Set<string>();
  child.on('message', (message: any) => { if (message.type === 'tls-rejection') tlsRejections.add(message.code); });
  let stdoutFailure = false;
  // Never retain or report stderr: diagnostics may contain credentials in future adapters.
  child.stderr.resume();
  child.stdout.on('data', (chunk: Uint8Array) => {
    try { for (const line of decoder.push(chunk)) {
      if (!pending) throw new Error('Unsolicited stdout frame');
      const waiter = pending; pending = undefined; waiter.resolve(line);
    } } catch { stdoutFailure = true; pending?.reject(new Error('Invalid stdout framing')); }
  });
  const exited = new Promise<number | null>((resolve) => child.once('exit', (code: number | null) => { pending?.reject(new Error('Server exited')); resolve(code); }));
  const deadline = setTimeout(() => { child.kill(); }, 15000);
  try {
    const ready = await new Promise<{ httpPort: number; httpsPort: number }>((resolve, reject) => {
      child.once('message', (message: any) => message.type === 'ready' ? resolve(message) : reject(new Error('Invalid readiness')));
      child.once('error', reject); child.once('exit', () => reject(new Error('Server failed before readiness')));
    });
    const stdio = (body: string): Promise<string> => new Promise((resolve, reject) => { pending = { resolve, reject }; child.stdin.write(body + '\n'); });
    const outcome = (line: string, malformed: boolean): string => {
      if (malformed) return JSON.parse(line).error?.code === -32600 ? 'invalid-request' : 'unexpected-response';
      const result = parseInterceptResponse(line);
      if (!result.ok || result.value.id !== 'synthetic-request') throw Error('Invalid canonical response');
      return result.value.result.effects.length === 0 ? 'no-effect' : 'unexpected-effect';
    };
    async function execute(s: Scenario): Promise<ScenarioResult> {
      let actual = 'adapter-error';
      if (s.transport === 'stdio' && s.auth !== 'process-trust') actual = 'inapplicable';
      else try {
        const malformed = s.credential === 'malformed';
        const body = malformed ? '{"jsonrpc":"2.0"}' : JSON.stringify(definitions.request);
        if (!malformed && !parseInterceptRequest(body).ok) throw Error('Invalid canonical request'); // client-side SDK validation, not JSON echo
        if (s.transport === 'stdio') actual = outcome(await stdio(body), malformed);
        else {
          let authorization: string | undefined;
          const c = s.credential;
          if (c === 'invalid' && s.auth !== 'mtls') authorization = 'Bearer invalid-fixture';
          if ((s.auth === 'bearer' && ['valid', 'env'].includes(c)) || c === 'bearer') {
            const value = resolveCredential(c === 'env' ? 'env:AHP_TEST_BEARER' : 'credential:bearer', { AHP_TEST_BEARER: auth.credentials.bearer }, { bearer: auth.credentials.bearer });
            authorization = `Bearer ${value}`;
          }
          if ((s.auth === 'oauth' && ['valid', 'bad-client', 'missing-client', 'bad-grant'].includes(c)) || c === 'oauth') {
            const form = new URLSearchParams({ grant_type: c === 'bad-grant' ? 'password' : 'client_credentials', client_id: auth.credentials.clientId, client_secret: c === 'missing-client' ? '' : c === 'bad-client' ? 'wrong' : auth.credentials.clientSecret });
            const token = await request(ready.httpPort, '/token', form.toString());
            if (token.status !== 200) actual = token.status === 401 || token.status === 400 ? 'token-rejected' : 'unexpected-status';
            else authorization = `Bearer ${JSON.parse(token.body).access_token}`;
          }
          if (s.auth === 'workload' && ['valid', 'untrusted', 'issuer', 'audience', 'expired'].includes(c)) {
            authorization = `Bearer ${auth.assertion({ ...(c === 'untrusted' ? { untrusted: true } : {}), ...(c === 'issuer' ? { issuer: 'untrusted' } : {}), ...(c === 'audience' ? { audience: 'wrong' } : {}), ...(c === 'expired' ? { expired: true } : {}) })}`;
          }
          if (actual !== 'token-rejected') {
            const tls = s.transport === 'https' ? { ca: fixture(c === 'bad-server-ca' ? 'untrusted-ca.pem' : 'ca.pem'), ...(c === 'missing' ? {} : { cert: fixture(c === 'invalid' ? 'untrusted-client.pem' : 'client.pem'), key: fixture(c === 'invalid' ? 'untrusted-client-key.pem' : 'client-key.pem') }) } : undefined;
            try {
              const response = await request(tls ? ready.httpsPort : ready.httpPort, '/' + s.auth, body, authorization, tls);
              actual = response.status === 401 ? 'unauthorized' : response.status === 200 ? outcome(response.body, malformed) : 'unexpected-status';
            } catch (error) {
              // Only TLS-specific failures count, never connection refusal or timeout.
              const code = (error as { code?: string }).code ?? '';
              actual = tls && /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code) ? 'tls-rejected' : tls && c === 'invalid' && code === 'ECONNRESET' ? 'tls-reset' : 'transport-error';
            }
          }
        }
      } catch { actual = 'adapter-error'; }
      return { id: s.id, transport: s.transport, auth: s.auth, expected: s.expected, actual, status: actual !== s.expected ? 'failed' : actual === 'inapplicable' ? 'inapplicable' : 'passed' };
    }
    // Both listeners are live in one process; HTTP executes while stdio is active.
    const stdioRows = definitions.scenarios.filter(s => s.transport === 'stdio');
    const httpRows = definitions.scenarios.filter(s => s.transport !== 'stdio');
    const [stdioResults, httpResults] = await Promise.all([(async () => { const rows: ScenarioResult[] = []; for (const s of stdioRows) rows.push(await execute(s)); return rows; })(), Promise.all(httpRows.map(execute))]);
    child.stdin.end();
    const exitCode = await exited;
    decoder.end();
    // Node/OpenSSL may close an untrusted client handshake with ECONNRESET.
    // Require server-side certificate-verification evidence, not merely a reset.
    for (const row of httpResults) {
      if (row.id === 'mtls-invalid' && row.actual === 'tls-reset' &&
          [...tlsRejections].some(code => /^(SELF_SIGNED_CERT_IN_CHAIN|DEPTH_ZERO_SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT_LOCALLY|CERT_SIGNATURE_FAILURE|ERR_SSL_INVALID_PADDING)$/.test(code))) {
        row.actual = 'tls-rejected'; row.status = 'passed';
      }
    }
    const byId = new Map([...stdioResults, ...httpResults].map(row => [row.id, row]));
    const results = definitions.scenarios.map(row => byId.get(row.id)!);
    return { format: 'ahp-synthetic-interop-results/1', ok: exitCode === 0 && !stdoutFailure && results.every(r => r.status !== 'failed'), results };
  } finally { clearTimeout(deadline); child.kill(); await exited; }
}
