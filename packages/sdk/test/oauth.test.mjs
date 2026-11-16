import assert from 'node:assert/strict';
import { test, before } from 'node:test';
import https from 'node:https';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { managedOAuth } from '../dist/src/oauth/index.js';

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
  values = new Map(); bindings = new Map(); locks = new Map(); writes = 0;
  async load(key, signal) { signal.throwIfAborted(); return (key.startsWith("ahp.oauth.binding:") ? this.bindings : this.values).get(key); }
  async compareAndSet(key, generation, value, signal) {
    signal.throwIfAborted();
    const values = key.startsWith("ahp.oauth.binding:") ? this.bindings : this.values;
    if (values.get(key)?.generation !== generation) return false;
    if (value === undefined) values.delete(key); else values.set(key, value);
    if (values === this.values) this.writes++; return true;
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
      if (path === '/token' || path === '/rotated-token') {
        tokens.push({ path, body, authorization: req.headers.authorization }); state.tokenEntered.resolve();
        if (state.tokenGate) await state.tokenGate.promise;
        if (state.expectedClientSecret !== undefined && (typeof req.headers.authorization !== 'string' ||
            decodeURIComponent(Buffer.from(req.headers.authorization.slice(6), 'base64').toString()) !== `client:${state.expectedClientSecret}`)) {
          res.statusCode = 400; res.end(JSON.stringify({ error: 'invalid_client' })); return;
        }
        res.statusCode = state.tokenStatus;
        res.end(JSON.stringify(state.tokenError ?? state.tokenResponse ?? { access_token: `access-${tokens.length}`, token_type: 'Bearer',
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
    if (id === 'invalid-grant') assert.equal((await f.prepare()).type, 'pending_login');
    else await assert.rejects(f.prepare(), classified(['provider_failed']));
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
    await assert.rejects(f.prepare({ authentication }), classified(['invalid_configuration', 'credential_unavailable', 'discovery_failed']));
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
  await assert.rejects(f.managed.complete(pending, f.callback(pending), budget()), classified(['access_denied']));
  assert.equal([...f.store.values.values()][0].refreshToken, 'refresh-1');
  assert.equal([...f.store.values.values()][0].rejected, true);
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
  const key = [...f.store.values.keys()][0];
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
    if (!key.startsWith("ahp.oauth.binding:")) expectations.push(expected); return compareAndSet(key, expected, value, signal);
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

const lifecycleVectors = JSON.parse(await readFile(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url), 'utf8'));
const { AuthError } = await import('../dist/src/client/auth.js');
const { bindingKey, grantKey } = await import('../dist/src/oauth/index.js');
for (const vector of lifecycleVectors.recovery) {
  test(`shared recovery: ${vector.code}`, () => {
    assert.equal(new AuthError(vector.code).recovery, vector.recovery);
  });
}
for (const vector of lifecycleVectors.keys) {
  test(`shared framed keys: ${vector.id}`, () => {
    const v = vector.input;
    const context = { backendId: v.backend_id, purpose: v.purpose, url: v.destination };
    const client = { issuer: v.issuer, resource: v.resource, clientId: v.client_id, flow: v.flow,
      scopes: [], allowedScopes: v.allowed_scopes, ...(v.grant_partition === undefined ? {} : { grantPartition: v.grant_partition }) };
    assert.equal(bindingKey(v.namespace, context), vector.binding_key);
    assert.equal(grantKey(v.namespace, context, client), vector.grant_key);
  });
}
for (const vector of lifecycleVectors.token_responses) {
  test(`shared token response through native HTTPS: ${vector.id}`, async t => {
    const f = await fixture(t, { tokenResponse: vector.response });
    Object.assign(f.client, { scopes: vector.requested, allowedScopes: vector.allowed, requiredScopes: vector.required });
    let complete;
    if (vector.exchange === 'refresh') {
      f.state.tokenResponse = { access_token: 'initial', token_type: 'Bearer', refresh_token: 'initial-refresh', scope: vector.previous_granted.join(' ') };
      const initial = await f.login();
      f.state.tokenResponse = vector.response;
      await f.managed.challenge({ ...f.context, credential: initial.credential, response: new Response(null, { status: 401 }) }, budget());
      complete = f.prepare();
    } else {
      const pending = await f.prepare();
      complete = f.managed.complete(pending, f.callback(pending), budget());
    }
    if (vector.usable) assert.equal((await complete).credential.token, vector.response.access_token);
    else await assert.rejects(complete, { code: vector.error ?? 'interaction_required' });
    const stored = [...f.store.values.values()][0];
    assert.equal(stored.refreshToken, vector.response.refresh_token);
    if (vector.granted) assert.deepEqual([...stored.scopes].sort(), [...vector.granted].sort());
    if (vector.expiry === 'unknown') assert.equal(stored.expiresAt, undefined);
    else if (vector.expiry === 'known') assert(stored.expiresAt > Date.now());
    if (!vector.accepted) assert.equal(stored.rejected, true);
  });
}

test('invalid callback does not consume pending; valid denial and invalid_grant do', async t => {
  const f = await fixture(t), pending = await f.prepare();
  await assert.rejects(f.managed.complete(pending, f.callback(pending, { state: 'stray' }), budget()), { code: 'access_denied' });
  assert.equal((await f.managed.complete(pending, f.callback(pending), budget())).credential.token, 'access-1');
  const g = await fixture(t), denied = await g.prepare();
  const denial = new URL(g.callback(denied)); denial.searchParams.delete('code'); denial.searchParams.set('error', 'access_denied');
  await assert.rejects(g.managed.complete(denied, denial.href, budget()), { code: 'access_denied' });
  await assert.rejects(g.managed.complete(denied, g.callback(denied), budget()), { code: 'invalid_configuration' });
  const h = await fixture(t, { tokenStatus: 400, tokenError: { error: 'invalid_grant' } }), stale = await h.prepare();
  await assert.rejects(h.managed.complete(stale, h.callback(stale), budget()), { code: 'interaction_required' });
  assert.notEqual(await h.prepare(), stale);
});

test('dispatch cannot create or shorten a host-owned pending login', async t => {
  const f = await fixture(t), provider = f.managed.provider({ budget: () => budget(undefined, 100) });
  const context = { ...f.context, challenged: true };
  await assert.rejects(provider.credential(context), { code: 'interaction_required' });
  const hostBudget = budget(undefined, 10000), pending = await f.managed.prepare(context, hostBudget);
  assert.equal(pending.expiresAt, hostBudget.deadline);
  await assert.rejects(provider.credential(context), { code: 'interaction_required' });
  assert.equal(await f.managed.prepare(context, budget()), pending);
  await f.managed.cancel(pending, budget());
  assert.notEqual(await f.managed.prepare(context, budget()), pending);
});

test('cached bindings survive recreation and metadata outage; secrets are resolved fresh', async t => {
  const f = await fixture(t); await f.login();
  f.state.metadataStatus = 503;
  const before = f.requests.length, recreated = managedOAuth(f.options);
  assert.equal((await recreated.prepare(f.context, budget())).credential.token, 'access-1');
  assert.equal(f.requests.length, before);
  assert(!JSON.stringify([...f.store.bindings.values()]).includes('clientSecret'));
});

test('unknown expiry initial and rotating refresh remain usable, including narrowed refresh inheritance', async t => {
  const f = await fixture(t, { tokenResponse: { access_token: 'unknown', token_type: 'Bearer', refresh_token: 'rotate-1', scope: 'deliver' } });
  const first = await f.login();
  assert.equal((await f.prepare()).credential.token, 'unknown');
  f.state.tokenResponse = { access_token: 'rotated', token_type: 'Bearer', refresh_token: 'rotate-2' };
  await f.managed.challenge({ ...f.context, credential: first.credential, response: new Response(null, { status: 401 }) }, budget());
  assert.equal((await f.prepare()).credential.token, 'rotated');
  assert.equal([...f.store.values.values()][0].refreshToken, 'rotate-2');
  assert.equal([...f.store.values.values()][0].expiresAt, undefined);
  assert.equal((await f.prepare()).credential.token, 'rotated');
});

test('shared grant partition opts independent bindings into one consent only after local approval', async t => {
  const f = await fixture(t); f.client.grantPartition = 'host-approved';
  await f.login();
  let approved = false;
  const independentlyApproved = managedOAuth({ ...f.options, selectClient: (issuers, resource, context, operation) => {
    if (!approved && (context.purpose !== 'event' || context.backendId !== f.context.backendId || context.url !== f.context.url)) {
      throw new AuthError('access_denied');
    }
    return f.options.selectClient(issuers, resource, context, operation);
  } });
  const authentication = { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource,
    clientId: f.client.clientId, flow: f.client.flow, scopes: [...f.client.scopes] };
  const provider = independentlyApproved.provider({ budget: () => budget() });
  for (const context of [
    { ...f.context, purpose: 'upload' },
    { ...f.context, backendId: 'unapproved-backend' },
    { ...f.context, url: `${f.origin}/events/child` },
  ]) {
    await assert.rejects(provider.credential({ ...context, authentication }), { code: 'access_denied' });
    assert.equal(f.tokens.length, 1, 'no denied binding can acquire or dispatch a credential');
    assert.equal(f.store.bindings.size, 1, 'denied bindings are not persisted as authorized');
  }
  approved = true;
  assert.equal((await independentlyApproved.prepare({ ...f.context, purpose: 'upload' }, budget())).credential.token, 'access-1');
  assert.equal(f.tokens.length, 1);
  assert.equal(f.store.bindings.size, 2);
});

test('PKCE scope step-up persists requirement for host prepare and rejects forbidden scopes', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  const first = await f.login();
  const challenge = scope => ({ ...f.context, credential: first.credential,
    response: new Response(null, { status: 403, headers: { 'www-authenticate': `Bearer error="insufficient_scope", scope="${scope}"` } }) });
  await assert.rejects(f.managed.challenge(challenge('admin'), budget()), { code: 'access_denied' });
  assert.equal([...f.store.values.values()][0].rejected, undefined);
  await assert.rejects(f.managed.challenge(challenge('audit'), budget()), { code: 'interaction_required' });
  const pending = await f.prepare();
  assert(new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').includes('audit'));
  assert.equal(f.tokens.length, 1);
});

test('pending scope context replacement invalidates stale callbacks and keeps replacement ownership', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  const oldController = new AbortController(), operation = budget(oldController.signal, 10000);
  const first = await f.prepare({}, operation);
  assert.equal(await f.prepare({}, operation), first);
  f.client.scopes = ['deliver', 'audit'];
  const replacementBudget = budget(undefined, 9000), second = await f.prepare({}, replacementBudget);
  assert.notEqual(second, first);
  await assert.rejects(f.managed.complete(first, f.callback(first), budget()), { code: 'invalid_configuration' });
  oldController.abort();
  assert.equal(await f.prepare({}, replacementBudget), second);
  f.client.requiredScopes = ['deliver'];
  const third = await f.prepare({}, replacementBudget);
  assert.notEqual(third, second, 'explicit requirements are part of pending eligibility');
  const thirdCallback = f.callback(third);
  f.client.redirectUri = `${f.origin}/other-callback`;
  const fourth = await f.prepare({}, replacementBudget);
  assert.notEqual(fourth, third, 'exact redirect identity is part of pending eligibility');
  await assert.rejects(f.managed.complete(third, thirdCallback, budget()), { code: 'invalid_configuration' });
  await f.managed.cancel(fourth, budget());
});

test('pending budget replacement does not borrow or extend prior login lifetime', async t => {
  const f = await fixture(t), short = budget(undefined, 1000);
  const first = await f.prepare({}, short);
  const long = budget(undefined, 10000), second = await f.prepare({}, long);
  assert.notEqual(second, first);
  assert.equal(second.expiresAt, long.deadline);
  await assert.rejects(f.managed.complete(first, f.callback(first), budget()), { code: 'invalid_configuration' });
  assert.equal(await f.prepare({}, long), second);
  assert.equal(await f.prepare({}, short), second, 'a covered shorter budget can poll the same host operation');
});

test('scope challenge without required scope denies without changing grant; explicit host requirement permits step-up', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  const initial = await f.login();
  const challenge = { ...f.context, credential: initial.credential, response: new Response(null, {
    status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope"' } }) };
  const previous = [...f.store.values.values()][0];
  await assert.rejects(f.managed.challenge(challenge, budget()), { code: 'access_denied' });
  assert.deepEqual([...f.store.values.values()][0], previous);
  f.client.requiredScopes = ['audit'];
  await assert.rejects(f.managed.challenge(challenge, budget()), { code: 'interaction_required' });
  const pending = await f.prepare();
  assert(new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').includes('audit'));
  assert.equal(f.tokens.length, 1);
});

test('client credentials transient reissue retries without login or discarding current credentials', async t => {
  const f = await fixture(t); Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'client-secret' });
  const first = await f.prepare(); assert.equal(first.type, 'ready');
  f.store.expire(); f.state.tokenStatus = 503; f.state.tokenError = { error: 'temporarily_unavailable' };
  const previous = [...f.store.values.values()][0];
  await assert.rejects(f.prepare(), { code: 'provider_failed', recovery: 'retry' });
  assert.deepEqual([...f.store.values.values()][0], previous);
  f.state.tokenStatus = 200; f.state.tokenError = undefined;
  assert.equal((await f.prepare()).credential.token, 'access-3');
  assert.equal(f.tokens[2].body.get('grant_type'), 'client_credentials');
});

test('transient rotating refresh retains old material and a later native HTTP retry can recover', async t => {
  const f = await fixture(t); await f.login(); f.store.expire();
  f.state.tokenStatus = 503; f.state.tokenError = { error: 'temporarily_unavailable' };
  await assert.rejects(f.prepare(), { code: 'provider_failed', recovery: 'retry' });
  assert.equal([...f.store.values.values()][0].refreshToken, 'refresh-1');
  f.state.tokenStatus = 200; f.state.tokenError = undefined;
  assert.equal((await f.prepare()).credential.token, 'access-3');
  assert.equal(f.tokens[2].body.get('refresh_token'), 'refresh-1');
  assert.equal([...f.store.values.values()][0].refreshToken, 'refresh-3');
});

test('metadata and secret rotation rebuild outside grant lock and never persist client secret', async t => {
  const f = await fixture(t, { authorizationMetadata: { grant_types_supported: ['authorization_code'] } });
  f.client.clientSecret = 'old-client-secret'; await f.login();
  const firstKey = [...f.store.values.keys()][0];
  f.client.clientSecret = 'new-client-secret'; f.store.expire();
  f.state.authorizationMetadata = { grant_types_supported: ['authorization_code', 'refresh_token'] };
  const checkDestination = f.options.checkDestination;
  // Recreated providers share the host store, not a process-local cache.
  const next = managedOAuth({ ...f.options, checkDestination: (url, purpose, operation) => {
    if (purpose === 'metadata') assert.equal(f.store.locks.size, 0, 'discovery must never hold a host-store lock');
    return checkDestination(url, purpose, operation);
  } });
  assert.equal((await next.prepare({ ...f.context, challenged: true }, budget())).credential.token, 'access-2');
  assert.equal([...f.store.values.keys()][0], firstKey);
  assert.equal(decodeURIComponent(Buffer.from(f.tokens[1].authorization.slice(6), 'base64').toString()), 'client:new-client-secret');
  const persisted = JSON.stringify([...f.store.bindings.values(), ...f.store.values.values()]);
  assert(!persisted.includes('old-client-secret')); assert(!persisted.includes('new-client-secret'));
});

test('configured preset never requests protected-resource metadata', async t => {
  const f = await fixture(t);
  const authentication = { type: 'oauth', issuer: f.client.issuer, resource: f.client.resource,
    clientId: f.client.clientId, flow: f.client.flow, scopes: [...f.client.scopes] };
  const pending = await f.prepare({ authentication });
  await f.managed.complete(pending, f.callback(pending), budget());
  assert(f.requests.includes('/.well-known/oauth-authorization-server/issuer'));
  assert(!f.requests.some(path => path.includes('oauth-protected-resource')));
});

for (const redirect of ['http://127.0.0.1:42819/callback', 'http://127.0.0.2:42819/callback', 'http://[::1]:42819/callback', 'http://[0:0:0:0:0:0:0:1]:42819/callback']) {
  test(`literal loopback redirect completes through native HTTPS token endpoint: ${redirect}`, async t => {
    const f = await fixture(t); f.client.redirectUri = redirect;
    const pending = await f.prepare();
    assert.equal((await f.managed.complete(pending, f.callback(pending), budget())).credential.token, 'access-1');
  });
}
test('HTTP localhost hostname redirect is not literal loopback', async t => {
  const f = await fixture(t); f.client.redirectUri = 'http://localhost:42819/callback';
  await assert.rejects(f.prepare(), { code: 'invalid_configuration' });
});

test('anonymous 401 learns trusted binding and advises PKCE host without creating pending login', async t => {
  const f = await fixture(t), provider = f.managed.provider({ budget: () => budget(undefined, 100) });
  assert.equal(await provider.credential(f.context), undefined);
  assert.equal(f.requests.length, 0);
  const response = new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } });
  await assert.rejects(provider.challenge({ ...f.context, response, credential: undefined }), { code: 'interaction_required' });
  assert.equal(f.tokens.length, 0);
  assert.equal(f.store.bindings.size, 1);
  const hostBudget = budget(undefined, 10000), pending = await f.managed.prepare(f.context, hostBudget);
  assert.equal(pending.expiresAt, hostBudget.deadline);
});

test('anonymous 401 acquires client credentials noninteractively for the next unsafe delivery', async t => {
  const f = await fixture(t); Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'secret' });
  const provider = f.managed.provider({ budget: () => budget() });
  assert.equal(await provider.credential(f.context), undefined);
  await provider.challenge({ ...f.context, credential: undefined, response: new Response(null, {
    status: 401, headers: { 'www-authenticate': 'Bearer' } }) });
  assert.equal(f.tokens.length, 1);
  assert.equal((await provider.credential(f.context)).token, 'access-1');
});

test('refresh cannot broaden prior grant; rotated refresh persists quarantined before denial', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  const initial = await f.login();
  f.state.tokenResponse = { access_token: 'too-broad', token_type: 'Bearer', scope: 'deliver audit', refresh_token: 'quarantined-rotation' };
  await f.managed.challenge({ ...f.context, credential: initial.credential, response: new Response(null, { status: 401 }) }, budget());
  await assert.rejects(f.prepare(), { code: 'access_denied' });
  assert.equal(f.tokens[1].body.get('scope'), 'deliver');
  const stored = [...f.store.values.values()][0];
  assert.equal(stored.refreshToken, 'quarantined-rotation');
  assert.equal(stored.rejected, true); assert.equal(stored.refreshQuarantined, true);
  assert.equal((await f.prepare()).type, 'pending_login');
  assert.equal(f.tokens.length, 2, 'quarantined grant cannot refresh into broader permissions');
  await assert.rejects(f.managed.provider({ budget: () => budget() }).credential(f.context), { code: 'interaction_required' });
  const recreated = managedOAuth(f.options);
  await assert.rejects(recreated.provider({ budget: () => budget() }).credential(f.context), { code: 'interaction_required' });
  assert.equal(f.tokens.length, 2, 'recreated provider cannot use or refresh a quarantined broader grant');
  assert.equal([...f.store.values.values()][0].refreshToken, 'quarantined-rotation');
});

test('concurrent scope challenges merge requirements even after rejection', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit', 'write'];
  const initial = await f.login();
  const challenge = scope => f.managed.challenge({ ...f.context, credential: initial.credential,
    response: new Response(null, { status: 403, headers: { 'www-authenticate': `Bearer error="insufficient_scope", scope="${scope}"` } }) }, budget());
  const results = await Promise.allSettled([challenge('audit'), challenge('write')]);
  for (const result of results) { assert.equal(result.status, 'rejected'); assert.equal(result.reason.code, 'interaction_required'); }
  assert.deepEqual([...f.store.values.values()][0].requiredScopes.sort(), ['audit', 'write']);
  const pending = await f.prepare();
  assert.deepEqual(new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').sort(), ['audit', 'deliver', 'write']);
});

test('anonymous insufficient scope persists binding requirement for recreated host prepare', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  await assert.rejects(f.managed.challenge({ ...f.context, credential: undefined,
    response: new Response(null, { status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="audit"' } }) }, budget()), { code: 'interaction_required' });
  assert.equal(f.tokens.length, 0);
  const pending = await managedOAuth(f.options).prepare(f.context, budget());
  assert.deepEqual(new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').sort(), ['audit', 'deliver']);
});

test('anonymous insufficient scope acquires CC approved scopes without human login', async t => {
  const f = await fixture(t, { scope: 'deliver audit' });
  Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'secret', allowedScopes: ['deliver', 'audit'] });
  const provider = f.managed.provider({ budget: () => budget() });
  assert.equal(await provider.credential(f.context), undefined);
  await provider.challenge({ ...f.context, credential: undefined, response: new Response(null, { status: 403,
    headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="audit"' } }) });
  assert.equal(f.tokens.length, 1);
  assert(f.tokens[0].body.get('scope').split(' ').includes('audit'));
  assert.equal((await provider.credential(f.context)).token, 'access-1');
  assert.deepEqual([...f.store.bindings.values()][0].requiredScopes, ['audit']);
});

for (const redirect of ['http://127.1/callback', 'http://127.00.0.1/callback', 'http://2130706433/callback',
  'http://[::ffff:127.0.0.1]/callback', 'http://128.0.0.1/callback']) {
  test(`ambiguous or non-loopback HTTP literal is denied: ${redirect}`, async t => {
    const f = await fixture(t); f.client.redirectUri = redirect;
    await assert.rejects(f.prepare(), { code: 'invalid_configuration' });
  });
}


test('unexpired grant missing new host-required scopes renews issuer metadata outside store locks', async t => {
  const f = await fixture(t);
  Object.assign(f.client, { flow: 'client_credentials', clientSecret: 'secret', allowedScopes: ['deliver', 'audit'] });
  await f.prepare();
  const previous = [...f.store.values.values()][0];
  assert(previous.expiresAt > Date.now() + 30000);
  assert.deepEqual(previous.scopes, ['deliver']);
  const originalKey = [...f.store.values.keys()][0];
  f.client.requiredScopes = ['audit'];
  f.state.scope = 'deliver audit';
  f.state.tokenEndpoint = `${f.origin}/rotated-token`;
  f.state.authorizationMetadata = { token_endpoint_auth_methods_supported: ['client_secret_post'] };
  const checkDestination = f.options.checkDestination;
  const renewed = managedOAuth({ ...f.options, checkDestination(url, purpose, operation) {
    if (purpose === 'metadata') assert.equal(f.store.locks.size, 0, 'renewal discovery must run outside host-store locks');
    return checkDestination(url, purpose, operation);
  } });
  assert.equal((await renewed.prepare(f.context, budget())).credential.token, 'access-2');
  assert.equal(f.tokens[1].path, '/rotated-token');
  assert.equal(f.tokens[1].authorization, undefined);
  assert.equal(f.tokens[1].body.get('client_secret'), 'secret');
  assert(f.tokens[1].body.get('scope').split(' ').includes('audit'));
  assert.equal([...f.store.values.keys()][0], originalKey);
  assert.notEqual([...f.store.values.values()][0].generation, previous.generation);
});

test('persisted network requirements cannot authorize a scope-less challenge as host policy', async t => {
  const f = await fixture(t, { scope: 'deliver audit' });
  f.client.allowedScopes = ['deliver', 'audit'];
  const response = scope => new Response(null, { status: 403, headers: {
    'www-authenticate': `Bearer error="insufficient_scope"${scope === undefined ? '' : `, scope="${scope}"`}`,
  } });
  await assert.rejects(f.managed.challenge({ ...f.context, credential: undefined, response: response('audit') }, budget()),
    { code: 'interaction_required' });
  assert.deepEqual([...f.store.bindings.values()][0].requiredScopes, ['audit']);
  const recreated = managedOAuth(f.options), hostBudget = budget(undefined, 10000);
  const pending = await recreated.prepare(f.context, hostBudget);
  const bindingBefore = structuredClone([...f.store.bindings.values()][0]);
  await assert.rejects(recreated.challenge({ ...f.context, credential: undefined, response: response() }, budget()),
    { code: 'access_denied' });
  assert.equal(await recreated.prepare(f.context, hostBudget), pending, 'denial must not replace pending host consent');
  assert.deepEqual([...f.store.bindings.values()][0], bindingBefore);
  const ready = await recreated.complete(pending, f.callback(pending), budget());
  const credentialBefore = structuredClone([...f.store.values.values()][0]);
  await assert.rejects(recreated.challenge({ ...f.context, credential: ready.credential, response: response() }, budget()),
    { code: 'access_denied' });
  assert.deepEqual([...f.store.values.values()][0], credentialBefore, 'denial must not reject an otherwise usable credential');
  assert.equal((await recreated.prepare(f.context, budget())).credential.token, ready.credential.token);
  assert.equal(f.tokens.length, 1);
});


test('pending reuse compares explicit host requirements even when network requirements already match', async t => {
  const f = await fixture(t); f.client.allowedScopes = ['deliver', 'audit'];
  await assert.rejects(f.managed.challenge({ ...f.context, credential: undefined, response: new Response(null, {
    status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="audit"' },
  }) }, budget()), { code: 'interaction_required' });
  const hostBudget = budget(undefined, 10000);
  const first = await f.prepare({}, hostBudget);
  f.client.requiredScopes = ['audit'];
  const replacement = await f.prepare({}, hostBudget);
  assert.notEqual(replacement, first, 'equal merged scopes must not hide a changed explicit host requirement');
  await assert.rejects(f.managed.complete(first, f.callback(first), budget()), { code: 'invalid_configuration' });
  f.state.scope = 'deliver audit';
  assert.equal((await f.managed.complete(replacement, f.callback(replacement), budget())).credential.token, 'access-1');
});


test('code completion resolves a rotated client secret outside coordination without replacing consent', async t => {
  const f = await fixture(t); f.client.clientSecret = 'revoked-secret';
  let selections = 0;
  const managed = managedOAuth({ ...f.options, selectClient(...args) {
    assert.equal(f.store.locks.size, 0, 'runtime client selection must be outside store coordination');
    selections++; return f.options.selectClient(...args);
  } });
  const controller = new AbortController(), hostBudget = budget(controller.signal, 30000);
  const pending = await managed.prepare({ ...f.context, challenged: true }, hostBudget);
  const callback = f.callback(pending), authorization = new URL(pending.authorizationUrl);
  f.client.clientSecret = 'rotated-secret'; f.state.expectedClientSecret = 'rotated-secret';
  const ready = await managed.complete(pending, callback, budget());
  assert.equal(ready.credential.token, 'access-1'); assert.equal(selections, 2);
  assert.equal(f.tokens.length, 1, 'revoked secret must never reach the token endpoint');
  assert.equal(decodeURIComponent(Buffer.from(f.tokens[0].authorization.slice(6), 'base64').toString()), 'client:rotated-secret');
  assert.equal(createHash('sha256').update(f.tokens[0].body.get('code_verifier')).digest('base64url'), authorization.searchParams.get('code_challenge'));
  assert.equal(pending.expiresAt, hostBudget.deadline);
  const persisted = JSON.stringify([...f.store.values.values(), ...f.store.bindings.values()]);
  assert(!persisted.includes('revoked-secret')); assert(!persisted.includes('rotated-secret'));
});

for (const [field, changed] of [
  ['issuer', client => `${client.issuer}/other`],
  ['resource', client => `${client.resource}/other`],
  ['clientId', () => 'other-client'],
  ['flow', () => 'client_credentials'],
  ['redirectUri', client => `${client.redirectUri}/other`],
  ['scopes', () => ['deliver', 'audit']],
  ['requiredScopes', () => ['deliver']],
  ['allowedScopes', () => ['deliver']],
  ['grantPartition', () => 'other-partition'],
]) {
  test(`code completion denies incompatible current ${field} without consuming original consent`, async t => {
    const f = await fixture(t); f.client.clientSecret = 'secret'; f.client.allowedScopes = ['deliver', 'audit'];
    const pending = await f.prepare(), callback = f.callback(pending);
    const original = f.client[field]; f.client[field] = changed(f.client);
    await assert.rejects(f.managed.complete(pending, callback, budget()), { code: 'invalid_configuration' });
    assert.equal(f.tokens.length, 0);
    if (original === undefined) delete f.client[field]; else f.client[field] = original;
    assert.equal((await f.managed.complete(pending, callback, budget())).credential.token, 'access-1');
  });
}


test('host credential lookup failure before callback claim preserves the original pending consent', async t => {
  const f = await fixture(t); f.client.clientSecret = 'secret';
  let unavailable = false;
  const managed = managedOAuth({ ...f.options, selectClient(...args) {
    assert.equal(f.store.locks.size, 0);
    if (unavailable) throw { code: 'credential_unavailable', message: 'private host lookup failure' };
    return f.options.selectClient(...args);
  } });
  const pending = await managed.prepare({ ...f.context, challenged: true }, budget()), callback = f.callback(pending);
  unavailable = true;
  await assert.rejects(managed.complete(pending, callback, budget()), { code: 'credential_unavailable' });
  assert.equal(f.tokens.length, 0);
  unavailable = false;
  assert.equal((await managed.complete(pending, callback, budget())).credential.token, 'access-1');
});

test('completion cancellation during current-client selection does not claim or replace host consent', async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  let block = false;
  const managed = managedOAuth({ ...f.options, async selectClient(...args) {
    assert.equal(f.store.locks.size, 0);
    if (block) { entered.resolve(); await release.promise; args[3].signal.throwIfAborted(); }
    return f.options.selectClient(...args);
  } });
  const pending = await managed.prepare({ ...f.context, challenged: true }, budget()), callback = f.callback(pending);
  block = true;
  const controller = new AbortController(), reason = new Error('host cancelled callback processing');
  const completing = managed.complete(pending, callback, budget(controller.signal));
  await entered.promise; controller.abort(reason);
  await assert.rejects(completing, error => error === reason);
  assert.equal(f.tokens.length, 0);
  block = false; release.resolve();
  assert.equal((await managed.complete(pending, callback, budget())).credential.token, 'access-1');
});


test('pending reuse compares original host-requested scopes even when expanded consent scopes match', async t => {
  const f = await fixture(t); Object.assign(f.client, { allowedScopes: ['deliver', 'audit'], requiredScopes: ['audit'] });
  const hostBudget = budget(undefined, 30000), first = await f.prepare({}, hostBudget);
  f.client.scopes = ['deliver', 'audit'];
  const replacement = await f.prepare({}, budget(undefined, 10000));
  assert.notEqual(replacement, first);
  await assert.rejects(f.managed.complete(first, f.callback(first), budget()), { code: 'invalid_configuration' });
  f.state.scope = 'deliver audit';
  assert.equal((await f.managed.complete(replacement, f.callback(replacement), budget())).credential.token, 'access-1');
});

test('valid consent denial is claimed once without resolving unavailable runtime client credentials', async t => {
  const f = await fixture(t); let unavailable = false, selections = 0;
  const managed = managedOAuth({ ...f.options, selectClient(...args) {
    selections++; if (unavailable) throw { code: 'credential_unavailable' };
    return f.options.selectClient(...args);
  } });
  const pending = await managed.prepare({ ...f.context, challenged: true }, budget());
  const denied = new URL(f.callback(pending)); denied.searchParams.delete('code'); denied.searchParams.set('error', 'access_denied');
  unavailable = true;
  await assert.rejects(managed.complete(pending, denied.href, budget()), { code: 'access_denied' });
  assert.equal(selections, 1); assert.equal(f.tokens.length, 0);
  await assert.rejects(managed.complete(pending, denied.href, budget()), { code: 'invalid_configuration' });
});
