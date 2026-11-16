import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { auth, Hooks, Attachment } from 'agenthooksprotocol/client';
import { managedOAuth } from 'agenthooksprotocol/oauth';

let tls;
let certificates;
before(async () => {
  certificates = await mkdtemp(join(tmpdir(), 'ahp-tls-'));
  await writeFile(join(certificates, 'config'), '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', join(certificates, 'config'), '-keyout', join(certificates, 'key.pem'), '-out', join(certificates, 'cert.pem')], { stdio: 'ignore' });
  tls = { key: await readFile(join(certificates, 'key.pem')), cert: await readFile(join(certificates, 'cert.pem')) };
});
after(async () => { if (certificates) await rm(certificates, { recursive: true, force: true }); });

class MemoryStore {
  values = new Map();
  locks = new Map();
  async load(key, signal) { signal.throwIfAborted(); return structuredClone(this.values.get(key)); }
  async compareAndSet(key, expected, value, signal) {
    signal.throwIfAborted();
    if (this.values.get(key)?.generation !== expected) return false;
    if (value === undefined) this.values.delete(key); else this.values.set(key, structuredClone(value));
    return true;
  }
  async coordinate(key, signal, work) {
    const previous = this.locks.get(key) ?? Promise.resolve();
    let release;
    const owned = new Promise(resolve => { release = resolve; });
    const queued = previous.then(() => owned);
    this.locks.set(key, queued);
    await previous;
    try { signal.throwIfAborted(); return await work(); }
    finally { release(); if (this.locks.get(key) === queued) this.locks.delete(key); }
  }
}
const budget = () => ({ signal: new AbortController().signal, deadline: Date.now() + 10000 });
const input = () => ({ call: { id: 'call' }, path: 'native', tool: { name: 'test', origin: 'native', input: {} } });

async function environment(t) {
  let origin;
  const state = { metadataAvailable: true, challenge: false, deliveries: [], uploads: [], grants: [], metadata: 0 };
  const server = https.createServer(tls, async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    response.setHeader('content-type', 'application/json');
    if (request.url.startsWith('/.well-known/')) {
      state.metadata++;
      if (!state.metadataAvailable) { response.writeHead(503); response.end('{}'); return; }
      response.end(JSON.stringify(request.url.includes('oauth-protected-resource')
        ? { resource: `${origin}/events`, authorization_servers: [`${origin}/issuer`] }
        : { issuer: `${origin}/issuer`, token_endpoint: `${origin}/token`, grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['client_secret_basic'] }));
    } else if (request.url === '/token') {
      const params = new URLSearchParams(body);
      state.grants.push(params);
      response.end(JSON.stringify({ access_token: `access-${state.grants.length}`, token_type: 'Bearer', scope: params.get('scope') }));
    } else if (request.url === '/events/upload') {
      const bytes = Buffer.concat(chunks);
      state.uploads.push({ authorization: request.headers.authorization, bytes });
      response.writeHead(201);
      response.end(JSON.stringify({ ref: 'urn:test:upload', size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }));
    } else {
      state.deliveries.push({ authorization: request.headers.authorization, message: JSON.parse(body) });
      if (state.challenge) {
        response.writeHead(403, { 'www-authenticate': 'Bearer error="insufficient_scope", scope="audit"' });
        response.end('{}');
      } else {
        const message = JSON.parse(body);
        if (message.id === undefined) { response.writeHead(204); response.end(); return; }
        response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: 'draft', effects: [] } }));
      }
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `https://localhost:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const hostFetch = async (address, init = {}) => {
    const url = new URL(address);
    assert.equal(url.origin, origin);
    return new Promise((resolve, reject) => {
      const request = https.request(url, { method: init.method ?? 'GET', headers: Object.fromEntries(new Headers(init.headers)), signal: init.signal, ca: tls.cert, agent: false,
        lookup(host, options, done) { assert.equal(host, 'localhost'); if (options.all) done(null, [{ address: '127.0.0.1', family: 4 }]); else done(null, '127.0.0.1', 4); },
      }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
        response.on('end', () => resolve(new Response(response.statusCode === 204 ? null : Buffer.concat(chunks), { status: response.statusCode, headers: response.headers })));
      });
      request.on('error', reject); request.end(init.body === undefined ? undefined : init.body instanceof Uint8Array ? init.body : String(init.body));
    });
  };
  const store = new MemoryStore();
  const client = { issuer: `${origin}/issuer`, resource: `${origin}/events`, clientId: 'client', clientSecret: 'secret', flow: 'client_credentials', scopes: ['deliver'], allowedScopes: ['deliver', 'audit'] };
  const options = { namespace: 'host', store, policyFetch: hostFetch,
    checkDestination(url, _purpose, operation) { operation.signal.throwIfAborted(); assert.equal(url.origin, origin); },
    selectClient(issuers, resource, context) { assert.equal(context.backendId, 'e2e.backend'); assert.equal(context.purpose, 'event'); assert.deepEqual(issuers, [client.issuer]); assert.equal(resource, client.resource); return { ...client }; },
  };
  const context = { backendId: 'e2e.backend', purpose: 'event', url: `${origin}/events` };
  const hooks = (managed, upload, observe = false) => new Hooks({ protocolVersion: 'draft', hooks: [{ id: context.backendId, transport: { type: 'http', url: context.url }, subscriptions: [{ mode: observe ? 'observe' : 'intercept', events: ['tool.before'], ...(observe ? {} : { timeoutMs: 10000, failurePolicy: 'fail-closed' }), content: { default: upload ? 'body' : 'metadata' }, ...(upload ? { upload } : {}) }] }] }, {
    source: 'urn:test:oauth-transport', harness: { name: 'test', version: '1' }, capabilities: { toolBefore: { intercept: { deny: true }, observe: true } }, fetch: hostFetch,
    auth: auth.compose({ discover: managed.provider({ budget }) }),
  });
  return { state, store, context, client, options, hooks };
}

test('recreated managed provider sends cached unbound credentials through real Hooks HTTPS without discovery', async t => {
  const f = await environment(t);
  await managedOAuth(f.options).prepare(f.context, budget());
  const metadata = f.state.metadata;
  f.state.metadataAvailable = false;
  const hooks = f.hooks(managedOAuth(f.options));
  try {
    const result = await hooks.dispatch('tool.before', input());
    assert.deepEqual(result.diagnostics.filter(item => item.phase !== 'observation'), []);
    assert.equal(f.state.metadata, metadata);
    assert.equal(f.state.grants.length, 1);
    assert.equal(f.state.deliveries.length, 1);
    assert.equal(f.state.deliveries[0].authorization, 'Bearer access-1');
  } finally { await hooks.close(); }
});

test('allowed insufficient-scope challenge updates consent requirements without replaying an effectful delivery', async t => {
  const f = await environment(t);
  const managed = managedOAuth(f.options);
  await managed.prepare(f.context, budget());
  const hooks = f.hooks(managed);
  try {
    f.state.challenge = true;
    await hooks.dispatch('tool.before', input());
    assert.equal(f.state.deliveries.length, 1, 'intercept delivery must not be replayed');
    f.state.challenge = false;
    await hooks.dispatch('tool.before', input());
    assert.equal(f.state.deliveries.length, 2);
    assert.equal(f.state.grants.length, 2);
    assert(new Set(f.state.grants[1].get('scope').split(' ')).has('audit'));
    assert.equal(f.state.deliveries[1].authorization, 'Bearer access-2');
  } finally { await hooks.close(); }
});


test('independently prepared upload binding sends cached OAuth upfront through real upload transport', async t => {
  const f = await environment(t);
  const uploadUrl = `${f.context.url}/upload`;
  let uploadApproved = false;
  const options = { ...f.options, selectClient(issuers, resource, context, operation) {
    if (context.purpose !== 'upload') return f.options.selectClient(issuers, resource, context, operation);
    assert.equal(context.url, uploadUrl);
    if (!uploadApproved) throw Object.assign(new Error('host policy denied'), { code: 'access_denied' });
    return { ...f.client };
  } };
  const managed = managedOAuth(options);
  await managed.prepare(f.context, budget());
  const upload = { ...f.context, purpose: 'upload', url: uploadUrl, authentication: { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource, clientId: f.client.clientId, flow: f.client.flow, scopes: f.client.scopes } };
  await assert.rejects(managed.prepare(upload, budget()), { code: 'access_denied' });
  uploadApproved = true;
  await managed.prepare(upload, budget());
  const before = f.state.metadata;
  f.state.metadataAvailable = false;
  const hooks = f.hooks(managedOAuth(options), { endpoint: uploadUrl, maxBytes: 1000, timeoutMs: 10000 });
  try {
    const result = await hooks.toolBefore({ callId: 'upload', path: 'native', name: 'test', origin: 'native', input: {},
      items: [{ id: 'content', kind: 'attachment', mediaType: 'application/octet-stream', selection: 'body', body: Attachment.bytes(new Uint8Array([0, 1, 2])) }],
    });
    assert.deepEqual(result.diagnostics.filter(item => item.phase !== 'observation'), []);
    assert.equal(f.state.uploads.length, 1);
    assert.equal(f.state.uploads[0].authorization, 'Bearer access-2');
    assert.equal(f.state.deliveries[0].authorization, 'Bearer access-1');
    assert.equal(f.state.metadata, before);
    assert.equal(f.state.grants.length, 2, 'default upload and event grants stay isolated');
  } finally { await hooks.close(); }
});


test('cached unbound OAuth authenticates observation notifications upfront and never replays a rejected notification', async t => {
  const f = await environment(t);
  await managedOAuth(f.options).prepare(f.context, budget());
  const before = f.state.metadata;
  f.state.metadataAvailable = false;
  const hooks = f.hooks(managedOAuth(f.options), undefined, true);
  try {
    const first = await hooks.dispatch('tool.before', input());
    assert.deepEqual(first.diagnostics, []);
    assert.equal(f.state.deliveries.length, 1);
    assert.equal(f.state.deliveries[0].message.method, 'hooks/observe');
    assert.equal(f.state.deliveries[0].message.id, undefined);
    assert.equal(f.state.deliveries[0].authorization, 'Bearer access-1');
    f.state.challenge = true;
    await hooks.dispatch('tool.before', input());
    assert.equal(f.state.deliveries.length, 2, 'rejected notification must not be replayed');
    assert.equal(f.state.deliveries[1].authorization, 'Bearer access-1');
    assert.equal(f.state.metadata, before);
  } finally { await hooks.close(); }
});
