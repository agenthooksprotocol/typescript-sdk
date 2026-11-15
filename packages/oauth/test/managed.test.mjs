import assert from 'node:assert/strict';
import { test, before } from 'node:test';
import https from 'node:https';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { managedOAuth } from '../dist/src/index.js';

const parity = ['pkce-completion', 'client-credentials', 'unconfigured-challenge', 'purpose-isolation',
  'destination-isolation', 'stale-401', 'refresh-single-flight', 'transient-refresh', 'invalid-grant', 'deadline-cancel', 'redaction'];
try {
  const manifest = JSON.parse(await readFile('/tmp/ahp-auth-parity-cases.json', 'utf8'));
  for (const id of parity) assert.ok(manifest.cases.some(item => item.id === id), id);
} catch (error) { if (error.code !== 'ENOENT') throw error; }

let tls;
before(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ahp-managed-oauth-'));
  try {
    const config = join(dir, 'openssl.cnf');
    await writeFile(config, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
      '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-config', config], { stdio: 'ignore' });
    tls = { key: await readFile(join(dir, 'key.pem')), cert: await readFile(join(dir, 'cert.pem')) };
  } finally { await rm(dir, { recursive: true, force: true }); }
});
const budget = (signal = new AbortController().signal, ms = 5000) => ({ signal, deadline: Date.now() + ms });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

// Structural host implementation: atomic generation CAS and abort-aware FIFO locks.
class Store {
  values = new Map(); locks = new Map(); writes = 0;
  async load(key, signal) { signal.throwIfAborted(); return this.values.get(key); }
  async compareAndSet(key, generation, value, signal) {
    signal.throwIfAborted();
    if (this.values.get(key)?.generation !== generation) return false;
    if (value === undefined) this.values.delete(key); else this.values.set(key, value);
    this.writes++; return true;
  }
  async coordinate(key, signal, work) {
    signal.throwIfAborted();
    await new Promise((resolve, reject) => {
      const queue = this.locks.get(key);
      if (!queue) { this.locks.set(key, []); resolve(); return; }
      const waiter = { resolve, signal, abort: undefined };
      waiter.abort = () => {
        const index = queue.indexOf(waiter);
        if (index !== -1) queue.splice(index, 1);
        reject(signal.reason);
      };
      signal.addEventListener('abort', waiter.abort, { once: true }); queue.push(waiter);
    });
    try { signal.throwIfAborted(); return await work(); }
    finally {
      const queue = this.locks.get(key), next = queue.shift();
      if (next) { next.signal.removeEventListener('abort', next.abort); next.resolve(); }
      else this.locks.delete(key);
    }
  }
  expire() { for (const [key, value] of this.values) this.values.set(key, { ...value, expiresAt: Date.now() - 1 }); }
}

async function fixture(t, overrides = {}) {
  const requests = [], checked = [], tokens = [];
  const state = { metadataStatus: 200, tokenStatus: 200, tokenError: undefined, tokenGate: undefined,
    tokenEntered: deferred(), fallback: false, resourceOverride: undefined, issuerOverride: undefined,
    scope: 'deliver', authorizationEndpoint: undefined, tokenEndpoint: undefined, ...overrides };
  let origin;
  const server = https.createServer(tls, async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = new URLSearchParams(Buffer.concat(chunks).toString());
      const path = new URL(req.url, origin).pathname; requests.push(path);
      res.setHeader('content-type', 'application/json');
      if (path === '/token') {
        tokens.push({ body, authorization: req.headers.authorization }); state.tokenEntered.resolve();
        if (state.tokenGate) await state.tokenGate.promise;
        res.statusCode = state.tokenStatus;
        res.end(JSON.stringify(state.tokenError ?? { access_token: `access-${tokens.length}`, token_type: 'Bearer',
          expires_in: 3600, ...(state.omitRefreshToken ? {} : { refresh_token: `refresh-${tokens.length}` }), scope: state.scope }));
      } else if (path === '/.well-known/oauth-authorization-server/issuer') {
        res.statusCode = state.metadataStatus;
        res.end(JSON.stringify({ issuer: state.issuerOverride ?? `${origin}/issuer`,
          authorization_endpoint: state.authorizationEndpoint ?? `${origin}/authorize`, token_endpoint: state.tokenEndpoint ?? `${origin}/token`,
          grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'], response_types_supported: ['code'],
          code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
          ...state.authorizationMetadata }));
      } else if (path.startsWith('/.well-known/oauth-protected-resource') || path === '/advertised') {
        const root = path === '/.well-known/oauth-protected-resource';
        if (state.fallback && !root) { res.statusCode = 404; res.end('{}'); }
        else res.end(JSON.stringify({ resource: state.resourceOverride ?? (root ? origin : `${origin}/events`),
          authorization_servers: [`${origin}/issuer`], bearer_methods_supported: ['header'], ...state.resourceMetadata }));
      } else { res.statusCode = 404; res.end('{}'); }
    } catch { if (!res.destroyed) { res.statusCode = 500; res.end('{}'); } }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `https://localhost:${server.address().port}`;
  t.after(async () => { state.tokenGate?.resolve(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const store = new Store();
  const client = { issuer: `${origin}/issuer`, resource: `${origin}/events`, clientId: 'client',
    flow: 'authorization_code_pkce', scopes: ['deliver'], redirectUri: `${origin}/callback` };
  const context = { backendId: 'backend', purpose: 'event', url: `${origin}/events` }, denied = new Set();
  const checkDestination = (url, purpose, operation) => {
    operation.signal.throwIfAborted(); checked.push({ url: url.href, purpose, deadline: operation.deadline });
    if (url.origin !== origin || denied.has(purpose)) throw new Error('destination denied');
  };
  const policyFetch = async (address, init, { purpose, operation }) => {
    const url = new URL(address); checkDestination(url, purpose, operation);
    assert.equal(init.redirect, 'error'); assert.equal(init.signal, operation.signal);
    // Origin allowlist plus connect-time DNS pinning; certificate/hostname verification stays on.
    return new Promise((resolve, reject) => {
      const req = https.request(url, { method: init.method ?? 'GET', headers: Object.fromEntries(new Headers(init.headers)),
        signal: operation.signal, ca: tls.cert, agent: false,
        lookup(hostname, options, done) {
          assert.equal(hostname, 'localhost');
          if (options.all) done(null, [{ address: '127.0.0.1', family: 4 }]); else done(null, '127.0.0.1', 4);
        } }, response => {
        if (response.statusCode >= 300 && response.statusCode < 400) { response.resume(); reject(new Error('redirect denied')); return; }
        const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
        response.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: response.headers })));
      });
      req.on('error', reject); req.end(init.body === undefined ? undefined : String(init.body));
    });
  };
  const options = { namespace: 'tenant-a', store, policyFetch, checkDestination,
    selectClient: (issuers, resource, _context, operation) => {
      operation.signal.throwIfAborted(); assert.deepEqual(issuers, [`${origin}/issuer`]);
      assert.equal(resource, state.fallback ? origin : `${origin}/events`); return { ...client, scopes: [...client.scopes] };
    } };
  const managed = managedOAuth(options);
  const prepare = (extra = {}, operation = budget()) => managed.prepare({ ...context, challenged: true, ...extra }, operation);
  const callback = (pending, extra = {}) => {
    const url = new URL(client.redirectUri);
    url.search = new URLSearchParams({ code: 'code-secret', state: new URL(pending.authorizationUrl).searchParams.get('state'), iss: client.issuer, ...extra }).toString();
    return url.href;
  };
  const login = async () => { const pending = await prepare(); assert.equal(pending.type, 'pending_login'); return managed.complete(pending, callback(pending), budget()); };
  return { origin, state, requests, checked, tokens, client, context, store, options, denied, managed, prepare, callback, login };
}
function classified(codes) {
  return error => {
    assert.ok(codes.includes(error.code), `unexpected error code ${error.code}`); assert.equal(error.cause, undefined);
    const text = `${error}\n${inspect(error)}\n${JSON.stringify(error)}`;
    for (const secret of ['access-1', 'refresh-1', 'code-secret', 'client-secret', 'description-secret']) assert.ok(!text.includes(secret), `public error leaked ${secret}`);
    return true;
  };
}

test('[pkce-completion] TLS exchange binds state, PKCE, issuer and resource', async t => {
  const f = await fixture(t), pending = await f.prepare(); assert.equal(pending.type, 'pending_login');
  const authorization = new URL(pending.authorizationUrl);
  assert.equal(authorization.searchParams.get('resource'), f.client.resource);
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('response_type'), 'code'); assert.equal(authorization.searchParams.get('scope'), 'deliver');
  assert.ok(authorization.searchParams.get('state').length >= 32); assert.equal(f.tokens.length, 0);
  const ready = await f.managed.complete(pending, f.callback(pending), budget()); assert.equal(ready.credential.token, 'access-1');
  const body = f.tokens[0].body;
  assert.equal(body.get('grant_type'), 'authorization_code'); assert.equal(body.get('resource'), f.client.resource);
  assert.equal(body.get('redirect_uri'), f.client.redirectUri); assert.equal(body.get('code'), 'code-secret');
  assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'), authorization.searchParams.get('code_challenge'));
  assert.ok(f.checked.some(item => item.purpose === 'authorization'));
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['invalid_configuration']));
});
for (const [name, changes] of [['state', { state: 'incorrect' }], ['issuer', { iss: 'https://evil.invalid' }]]) {
  test(`[pkce-completion] rejects callback ${name} before exchange`, async t => {
    const f = await fixture(t), pending = await f.prepare();
    await assert.rejects(f.managed.complete(pending, f.callback(pending, changes), budget()), classified(['access_denied', 'provider_failed']));
    assert.equal(f.tokens.length, 0); assert.equal(f.store.values.size, 0);
  });
}
test('[client-credentials] provider exchanges confidential client credentials', async t => {
  const f = await fixture(t); Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'client-secret' });
  const provider = f.managed.provider({ budget: () => budget() });
  assert.equal((await provider.credential({ ...f.context, challenged: true })).token, 'access-1');
  assert.equal(f.tokens[0].body.get('grant_type'), 'client_credentials'); assert.equal(f.tokens[0].body.get('resource'), f.client.resource);
  assert.equal(f.tokens[0].body.get('scope'), 'deliver');
  assert.equal(decodeURIComponent(Buffer.from(f.tokens[0].authorization.slice(6), 'base64').toString()), 'client:client-secret');
  assert.equal(f.checked.some(item => item.purpose === 'authorization'), false);
});
test('[unconfigured-challenge] advertised metadata precedes fallback', async t => {
  const f = await fixture(t); await f.prepare({ challenge: `Bearer resource_metadata="${f.origin}/advertised"` });
  assert.deepEqual(f.requests.slice(0, 2), ['/advertised', '/.well-known/oauth-authorization-server/issuer']);
});
test('[unconfigured-challenge] fallback probes path before origin on 404', async t => {
  const f = await fixture(t, { fallback: true }); f.client.resource = f.origin; await f.prepare();
  assert.deepEqual(f.requests.slice(0, 3), ['/.well-known/oauth-protected-resource/events', '/.well-known/oauth-protected-resource', '/.well-known/oauth-authorization-server/issuer']);
});
for (const kind of ['resource', 'issuer']) {
  test(`[destination-isolation] rejects nonexact ${kind}`, async t => {
    const f = await fixture(t);
    if (kind === 'resource') f.state.resourceOverride = `${f.origin}/events/other`; else f.state.issuerOverride = `${f.origin}/issuer/`;
    await assert.rejects(f.prepare(), classified(['discovery_failed'])); assert.equal(f.tokens.length, 0); assert.equal(f.store.values.size, 0);
  });
}
test('local scope policy rejects challenge escalation', async t => {
  const f = await fixture(t); await assert.rejects(f.prepare({ challenge: 'Bearer scope="deliver admin"' }), classified(['access_denied']));
  assert.equal(f.checked.some(item => item.purpose === 'authorization'), false); assert.equal(f.tokens.length, 0);
});
for (const purpose of ['metadata', 'authorization', 'token']) {
  test(`denied ${purpose} destinations fail closed`, async t => {
    const f = await fixture(t);
    if (purpose === 'token') {
      const pending = await f.prepare(); f.denied.add(purpose);
      await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['untrusted_destination']));
    } else { f.denied.add(purpose); await assert.rejects(f.prepare(), classified(['untrusted_destination'])); }
    assert.equal(f.tokens.length, 0); assert.equal(f.store.values.size, 0);
  });
}
test('untrusted authorization/token origins never reach transport', async t => {
  for (const kind of ['authorizationEndpoint', 'tokenEndpoint']) {
    const f = await fixture(t); f.state[kind] = 'https://evil.invalid/steal';
    if (kind === 'tokenEndpoint') {
      const pending = await f.prepare(); await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['untrusted_destination']));
    } else await assert.rejects(f.prepare(), classified(['untrusted_destination']));
    assert.equal(f.tokens.length, 0);
  }
});
test('[refresh-single-flight] concurrent instances refresh once and reload', async t => {
  const f = await fixture(t); await f.login(); f.store.expire(); const second = managedOAuth(f.options);
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? f.managed : second).prepare({ ...f.context, challenged: true }, budget())));
  assert.ok(results.every(result => result.credential.token === 'access-2')); assert.equal(f.tokens.length, 2);
  assert.equal(f.tokens[1].body.get('grant_type'), 'refresh_token'); assert.equal(f.tokens[1].body.get('refresh_token'), 'refresh-1');
  assert.equal(f.tokens[1].body.get('resource'), f.client.resource); assert.equal(f.tokens[1].body.get('scope'), 'deliver');
});
for (const [id, error, status] of [['transient-refresh', 'temporarily_unavailable', 503], ['invalid-grant', 'invalid_grant', 400]]) {
  test(`[${id}] durable refresh recovery state`, async t => {
    const f = await fixture(t); await f.login(); f.store.expire(); const previous = [...f.store.values.values()][0];
    Object.assign(f.state, { tokenStatus: status, tokenError: { error, error_description: 'description-secret refresh-1' } });
    await assert.rejects(f.prepare(), classified(id === 'invalid-grant' ? ['refresh_rejected', 'interaction_required'] : ['provider_failed']));
    const current = [...f.store.values.values()][0]; assert.equal(current.generation, previous.generation); assert.equal(current.refreshToken, 'refresh-1');
    if (id === 'transient-refresh') assert.deepEqual(current, previous);
    else { assert.equal(current.refreshRejected, true); assert.equal((await f.prepare()).type, 'pending_login'); assert.equal(f.tokens.length, 2); }
  });
}
test('[stale-401] A rejection cannot invalidate B', async t => {
  const f = await fixture(t), a = await f.login(); f.store.expire(); const b = await f.prepare();
  await f.managed.challenge({ ...f.context, credential: a.credential, response: new Response(null, { status: 401 }) }, budget());
  assert.equal((await f.prepare()).credential.token, b.credential.token); assert.equal([...f.store.values.values()][0].rejected, undefined); assert.equal(f.tokens.length, 2);
});
test('[deadline-cancel] native cancellation prevents late persistence', async t => {
  const f = await fixture(t), pending = await f.prepare(); f.state.tokenGate = deferred();
  const controller = new AbortController(), reason = new DOMException('host cancelled', 'AbortError');
  const completion = f.managed.complete(pending, f.callback(pending), budget(controller.signal));
  await f.state.tokenEntered.promise; controller.abort(reason); await assert.rejects(completion, error => error === reason);
  f.state.tokenGate.resolve(); await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(f.store.values.size, 0); assert.equal(f.store.writes, 0);
});
test('[deadline-cancel] deadline is absolute across discovery and exchange', async t => {
  const f = await fixture(t), operation = budget(undefined, 1000), pending = await f.prepare({}, operation); f.state.tokenGate = deferred();
  await assert.rejects(f.managed.complete(pending, f.callback(pending), { ...operation, deadline: Date.now() + 35 }), error => error.name === 'TimeoutError');
  assert.ok(f.checked.filter(item => item.purpose !== 'token').every(item => item.deadline === operation.deadline));
  f.state.tokenGate.resolve(); assert.equal(f.store.writes, 0);
});
test('[deadline-cancel] cancelled lock waiter never persists', async t => {
  const f = await fixture(t); await f.login(); f.store.expire(); const key = [...f.store.values.keys()][0], entered = deferred(), release = deferred();
  const owner = f.store.coordinate(key, new AbortController().signal, async () => { entered.resolve(); await release.promise; }); await entered.promise;
  const controller = new AbortController(), reason = new DOMException('cancel waiter', 'AbortError'), waiting = f.prepare({}, budget(controller.signal));
  while ((f.store.locks.get(key)?.length ?? 0) === 0) await new Promise(resolve => setTimeout(resolve, 2));
  controller.abort(reason); await assert.rejects(waiting, error => error === reason); release.resolve(); await owner;
  assert.equal(f.tokens.length, 1); assert.equal(f.store.writes, 1);
});
test('[destination-isolation] namespaces and paths cannot reuse credentials', async t => {
  const f = await fixture(t, { fallback: true }); f.client.resource = f.origin; await f.login();
  const other = managedOAuth({ ...f.options, namespace: 'tenant-b' });
  assert.equal((await other.prepare({ ...f.context, challenged: true }, budget())).type, 'pending_login');
  assert.equal((await f.prepare({ url: `${f.origin}/events/child` })).type, 'pending_login'); assert.equal(f.tokens.length, 1);
});
test('[purpose-isolation] upload cannot inherit event credential or attempt', async t => {
  const f = await fixture(t), event = await f.login(); assert.equal((await f.prepare({ purpose: 'upload' })).type, 'pending_login');
  await assert.rejects(f.managed.challenge({ ...f.context, purpose: 'upload', credential: event.credential, response: new Response(null, { status: 401 }) }, budget()), classified(['invalid_configuration']));
  assert.equal((await f.prepare()).credential.token, event.credential.token); assert.equal(f.tokens.length, 1);
});
test('[redaction] hostile token response is absent from errors and causes', async t => {
  const f = await fixture(t), pending = await f.prepare();
  Object.assign(f.state, { tokenStatus: 400, tokenError: { error: 'invalid_request', error_description: 'description-secret code-secret refresh-1 access-1 client-secret' } });
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['provider_failed'])); assert.equal(f.store.values.size, 0);
});

test('configured bindings require exact local issuer, resource and client identity', async t => {
  for (const field of ['issuer', 'resource', 'clientId']) {
    const f = await fixture(t);
    const authentication = { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource,
      clientId: f.client.clientId, flow: f.client.flow, scopes: ['deliver'], [field]: `${f.client[field]}/different` };
    await assert.rejects(f.prepare({ authentication }), classified(['invalid_configuration']));
    assert.equal(f.tokens.length, 0);
    assert.equal(f.store.values.size, 0);
  }
});

test('malformed advertised resource metadata must not downgrade to fallback', async t => {
  const f = await fixture(t, { resourceOverride: 'https://other.invalid/resource' });
  await assert.rejects(f.prepare({ challenge: `Bearer resource_metadata="${f.origin}/advertised"` }), classified(['discovery_failed']));
  assert.deepEqual(f.requests, ['/advertised']);
});

test('provider scopes cannot expand local authorization', async t => {
  const f = await fixture(t, { scope: 'deliver admin' }), pending = await f.prepare();
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['provider_failed']));
  assert.equal(f.store.values.size, 0);
});

test('expired budget performs no discovery, exchange or persistence', async t => {
  const f = await fixture(t);
  await assert.rejects(f.prepare({}, budget(undefined, -1)), error => error.name === 'TimeoutError');
  assert.equal(f.requests.length, 0);
  assert.equal(f.store.writes, 0);
});

test('[stale-401] current rejection is notification only, next prepare owns refresh', async t => {
  const f = await fixture(t), ready = await f.login();
  await f.managed.challenge({ ...f.context, credential: ready.credential, response: new Response(null, { status: 401 }) }, budget());
  assert.equal(f.tokens.length, 1);
  assert.equal([...f.store.values.values()][0].rejected, true);
  assert.equal((await f.prepare()).credential.token, 'access-2');
  assert.equal(f.tokens.length, 2);
  assert.ok(f.requests.every(path => path !== '/events'));
});

for (const field of ['origin', 'resource', 'state', 'code_challenge', 'code_challenge_method']) {
  test(`authorization policy URL mutation (${field}) rejects before UI handoff`, async t => {
    const f = await fixture(t);
    const managed = managedOAuth({ ...f.options, checkDestination(url, purpose, operation) {
      f.options.checkDestination(url, purpose, operation);
      if (purpose === 'authorization') {
        if (field === 'origin') url.hostname = 'evil.invalid';
        else url.searchParams.set(field, 'attacker-controlled');
      }
    } });
    await assert.rejects(managed.prepare({ ...f.context, challenged: true }, budget()), classified(['untrusted_destination']));
    assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
  });
}

test('selectClient receives frozen context, binding and nested scopes', async t => {
  const f = await fixture(t);
  const authentication = { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource,
    clientId: f.client.clientId, flow: f.client.flow, scopes: ['deliver'] };
  let selected = false;
  const managed = managedOAuth({ ...f.options, selectClient(issuers, resource, context, operation) {
    selected = true;
    assert.ok(Object.isFrozen(context)); assert.ok(Object.isFrozen(context.authentication));
    assert.ok(Object.isFrozen(context.authentication.scopes));
    assert.throws(() => { context.url = `${f.origin}/broader`; }, TypeError);
    assert.throws(() => { context.authentication.resource = f.origin; }, TypeError);
    assert.throws(() => { context.authentication.scopes.push('admin'); }, TypeError);
    return f.options.selectClient(issuers, resource, context, operation);
  } });
  const pending = await managed.prepare({ ...f.context, authentication }, budget());
  assert.ok(selected); assert.equal(pending.type, 'pending_login');
  const ready = await managed.complete(pending, f.callback(pending), budget());
  assert.equal(ready.credential.token, 'access-1');
  assert.equal(f.tokens[0].body.get('resource'), f.client.resource);
  assert.equal(new URL(pending.authorizationUrl).searchParams.get('scope'), 'deliver');
});

test('prepare snapshots caller identity and binding before its first await', async t => {
  const f = await fixture(t);
  const input = { ...f.context, authentication: { type: 'oauth', issuer: f.client.issuer,
    resource: f.client.resource, clientId: f.client.clientId, flow: f.client.flow, scopes: ['deliver'] } };
  const preparing = f.managed.prepare(input, budget());
  input.url = `${f.origin}/broader`; input.purpose = 'upload'; input.backendId = 'other-backend';
  input.authentication.resource = f.origin; input.authentication.scopes.push('admin');
  const pending = await preparing;
  const ready = await f.managed.complete(pending, f.callback(pending), budget());
  assert.equal(ready.credential.token, 'access-1');
  assert.equal(f.tokens[0].body.get('resource'), f.client.resource);
  assert.equal(new URL(pending.authorizationUrl).searchParams.get('scope'), 'deliver');
  const original = { ...f.context, authentication: { type: 'oauth', issuer: f.client.issuer,
    resource: f.client.resource, clientId: f.client.clientId, flow: f.client.flow, scopes: ['deliver'] } };
  assert.equal((await f.managed.prepare(original, budget())).credential.token, ready.credential.token);
  const key = JSON.parse([...f.store.values.keys()][0]);
  assert.ok(key.includes(f.context.url)); assert.ok(key.includes('event')); assert.ok(!key.includes('other-backend'));
});

test('cancel pending login invalidates completion and permits fresh login', async t => {
  const f = await fixture(t), pending = await f.prepare();
  await f.managed.cancel(pending, budget());
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['invalid_configuration']));
  const next = await f.prepare(); assert.notEqual(next, pending);
  assert.notEqual(new URL(next.authorizationUrl).searchParams.get('state'), new URL(pending.authorizationUrl).searchParams.get('state'));
  assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
});

test('pending expires at original prepare deadline despite a fresh completion budget', async t => {
  const f = await fixture(t), operation = budget(undefined, 250), pending = await f.prepare({}, operation);
  assert.equal(pending.expiresAt, operation.deadline);
  await new Promise(resolve => setTimeout(resolve, Math.max(0, pending.expiresAt - Date.now() + 10)));
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), error => error.name === 'TimeoutError');
  assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
});

test('completion in flight cannot extend the original prepare deadline', async t => {
  const f = await fixture(t), original = budget(undefined, 250), pending = await f.prepare({}, original);
  f.state.tokenGate = deferred();
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), error => error.name === 'TimeoutError');
  assert.ok(f.checked.filter(item => item.purpose === 'token').every(item => item.deadline === original.deadline));
  f.state.tokenGate.resolve(); await new Promise(resolve => setTimeout(resolve, 15));
  assert.equal(f.store.writes, 0);
});

for (const source of ['prepare-budget', 'context']) {
  test(`pending completion preserves original ${source} cancellation`, async t => {
    const f = await fixture(t), controller = new AbortController();
    const pending = await f.prepare(source === 'context' ? { signal: controller.signal } : {},
      budget(source === 'prepare-budget' ? controller.signal : undefined));
    const reason = new DOMException('original operation cancelled', 'AbortError');
    controller.abort(reason);
    await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), error => error === reason);
    assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
  });
}

test('provider budget cannot disconnect caller context signal during exchange', async t => {
  const f = await fixture(t); Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'client-secret' });
  f.state.tokenGate = deferred();
  const controller = new AbortController(), reason = new DOMException('delivery cancelled', 'AbortError');
  const provider = f.managed.provider({ budget: () => budget() });
  const getting = provider.credential({ ...f.context, challenged: true, signal: controller.signal });
  await f.state.tokenEntered.promise; controller.abort(reason);
  await assert.rejects(getting, error => error === reason);
  f.state.tokenGate.resolve(); await new Promise(resolve => setTimeout(resolve, 15));
  assert.equal(f.store.writes, 0);
});

test('refresh response without refresh_token retains the previous refresh credential', async t => {
  const f = await fixture(t); await f.login(); f.store.expire(); f.state.omitRefreshToken = true;
  assert.equal((await f.prepare()).credential.token, 'access-2');
  assert.equal([...f.store.values.values()][0].refreshToken, 'refresh-1');
  f.store.expire(); assert.equal((await f.prepare()).credential.token, 'access-3');
  assert.equal(f.tokens[2].body.get('refresh_token'), 'refresh-1');
});

for (const document of ['resourceMetadata', 'authorizationMetadata']) {
  test(`unsupported signed_metadata in ${document} fails closed`, async t => {
    const f = await fixture(t); f.state[document] = { signed_metadata: 'unverified.jwt.claims' };
    await assert.rejects(f.prepare(), classified(['unsupported_binding']));
    assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
    assert.equal(f.checked.some(item => item.purpose === 'authorization'), false);
  });
}

test('authorization server protected_resources must include exact selected resource', async t => {
  const f = await fixture(t); f.state.authorizationMetadata = { protected_resources: [`${f.origin}/events/`] };
  await assert.rejects(f.prepare(), classified(['discovery_failed']));
  assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
});

for (const redirectUri of ['https://user:password@example.com/callback', 'http://example.com/callback',
  'https://example.com/callback#fragment', 'https://example.com/callback?state=preexisting',
  'https://example.com/callback?code=preexisting', 'https://example.com/callback?iss=preexisting']) {
  test(`unsafe redirect URI rejected: ${redirectUri}`, async t => {
    const f = await fixture(t); f.client.redirectUri = redirectUri;
    await assert.rejects(f.prepare(), classified(['invalid_configuration']));
    assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
  });
}

for (const source of ['prepare-budget', 'context']) {
  test(`in-flight completion remains linked to original ${source} signal`, async t => {
    const f = await fixture(t), controller = new AbortController();
    const pending = await f.prepare(source === 'context' ? { signal: controller.signal } : {},
      budget(source === 'prepare-budget' ? controller.signal : undefined));
    f.state.tokenGate = deferred();
    const completing = f.managed.complete(pending, f.callback(pending), budget());
    await f.state.tokenEntered.promise;
    const reason = new DOMException('original operation cancelled during completion', 'AbortError');
    controller.abort(reason);
    await assert.rejects(completing, error => error === reason);
    f.state.tokenGate.resolve(); await new Promise(resolve => setTimeout(resolve, 15));
    assert.equal(f.store.writes, 0); assert.equal(f.store.values.size, 0);
  });
}

for (const source of ['prepare-budget', 'context']) {
  test(`aborted pending ${source} signal does not poison a fresh prepare`, async t => {
    const f = await fixture(t), original = new AbortController();
    const pending = await f.prepare(source === 'context' ? { signal: original.signal } : {},
      budget(source === 'prepare-budget' ? original.signal : undefined));
    original.abort(new DOMException('abandoned login', 'AbortError'));
    const fresh = await f.prepare({}, budget());
    assert.equal(fresh.type, 'pending_login'); assert.notEqual(fresh, pending);
    assert.notEqual(new URL(fresh.authorizationUrl).searchParams.get('state'),
      new URL(pending.authorizationUrl).searchParams.get('state'));
    assert.equal((await f.managed.complete(fresh, f.callback(fresh), budget())).credential.token, 'access-1');
    assert.equal(f.tokens.length, 1); assert.equal(f.store.writes, 1);
  });
}

test('mutating supplied budget signal during discovery cannot replace captured completion signal', async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  const original = new AbortController(), replacement = new AbortController();
  const supplied = budget(original.signal);
  const managed = managedOAuth({ ...f.options, async selectClient(...args) {
    entered.resolve(); await release.promise; return f.options.selectClient(...args);
  } });
  const preparing = managed.prepare({ ...f.context, challenged: true }, supplied);
  await entered.promise;
  supplied.signal = replacement.signal;
  release.resolve();
  const pending = await preparing;
  const reason = new DOMException('captured original cancelled', 'AbortError');
  original.abort(reason);
  assert.equal(replacement.signal.aborted, false);
  await assert.rejects(managed.complete(pending, f.callback(pending), budget()), error => error === reason);
  assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
});

test('mutable host load object cannot change the expected generation during refresh', async t => {
  const f = await fixture(t); await f.login(); f.store.expire();
  const [key, loaded] = [...f.store.values.entries()][0];
  const originalGeneration = loaded.generation;
  const expectations = [];
  const compareAndSet = f.store.compareAndSet.bind(f.store);
  f.store.compareAndSet = async (key, expected, value, signal) => {
    expectations.push(expected); return compareAndSet(key, expected, value, signal);
  };
  f.state.tokenEntered = deferred(); f.state.tokenGate = deferred();
  const refreshing = f.prepare();
  await f.state.tokenEntered.promise;
  // Simulate a host which returns a live mutable record and an independent owner
  // publishing generation B while this request is waiting on the token endpoint.
  Object.assign(loaded, { generation: 'newer-generation', token: 'newer-access',
    refreshToken: 'newer-refresh', expiresAt: Date.now() + 3_600_000 });
  f.state.tokenGate.resolve();
  await assert.rejects(refreshing, classified(['provider_failed']));
  assert.deepEqual(expectations, [originalGeneration]);
  assert.equal(f.store.values.get(key).generation, 'newer-generation');
  assert.equal(f.store.values.get(key).token, 'newer-access');
  assert.equal(f.store.values.get(key).refreshToken, 'newer-refresh');
  assert.equal(f.store.writes, 1);
  assert.equal((await f.prepare()).credential.token, 'newer-access');
  assert.equal(f.tokens.length, 2);
});

test('configured clientSecretRef without resolved secret fails credential_unavailable', async t => {
  const f = await fixture(t);
  const authentication = { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource,
    clientId: f.client.clientId, flow: f.client.flow, scopes: ['deliver'], clientSecretRef: 'missing-secret' };
  await assert.rejects(f.prepare({ authentication }), classified(['credential_unavailable']));
  assert.equal(f.tokens.length, 0); assert.equal(f.store.writes, 0);
  assert.equal(f.checked.some(item => item.purpose === 'authorization'), false);
});
