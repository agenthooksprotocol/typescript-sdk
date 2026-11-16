import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { test } from 'node:test';
import { managedOAuth } from '../dist/src/index.js';

const budget = (signal = new AbortController().signal, ms = 5000) => ({ signal, deadline: Date.now() + ms });
function fixture() {
  const values = new Map(), locks = new Map();
  const state = { tokenCalls: 0, writes: 0 };
  const store = {
    async load(key, signal) { signal.throwIfAborted(); return values.get(key); },
    async compareAndSet(key, expected, value, signal) {
      signal.throwIfAborted();
      if (values.get(key)?.generation !== expected) return false;
      values.set(key, value); state.writes++; return true;
    },
    async coordinate(key, signal, work) {
      const previous = locks.get(key) ?? Promise.resolve();
      let release;
      const next = new Promise(resolve => { release = resolve; });
      locks.set(key, next);
      try { await previous; signal.throwIfAborted(); return await work(); }
      finally { release(); if (locks.get(key) === next) locks.delete(key); }
    },
  };
  const client = { issuer: 'https://issuer.example', resource: 'https://api.example/events',
    clientId: 'client', flow: 'authorization_code_pkce', scopes: ['deliver'], redirectUri: 'https://app.example/callback' };
  const context = { backendId: 'backend', purpose: 'event', url: client.resource,
    authentication: { type: 'oauth', issuer: client.issuer, resource: client.resource,
      clientId: client.clientId, flow: client.flow, scopes: client.scopes } };
  const options = {
    namespace: 'review', store, selectClient: () => client,
    checkDestination: (_url, _purpose, operation) => operation.signal.throwIfAborted(),
    async policyFetch(url, _init, { operation }) {
      operation.signal.throwIfAborted();
      let body;
      if (url === 'https://issuer.example/token') {
        state.tokenCalls++;
        await state.tokenGate;
        operation.signal.throwIfAborted();
        body = { access_token: 'access', token_type: 'Bearer', expires_in: 3600, scope: 'deliver' };
      } else if (url.startsWith('https://api.example/.well-known/')) {
        body = { resource: client.resource, authorization_servers: [client.issuer] };
      } else {
        body = { issuer: client.issuer, authorization_endpoint: 'https://issuer.example/authorize',
          token_endpoint: 'https://issuer.example/token', response_types_supported: ['code'],
          code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'] };
      }
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    },
  };
  const oauth = managedOAuth(options);
  const callback = pending => `https://app.example/callback?code=code&state=${new URL(pending.authorizationUrl).searchParams.get('state')}`;
  return { oauth, options, context, values, state, callback };
}

test('pending completion rejects a superseded generation before sending a code', async () => {
  const f = fixture();
  const pending = await f.oauth.prepare(f.context, budget());
  let storedKey;
  const coordinate = f.options.store.coordinate;
  f.options.store.coordinate = (key, signal, work) => { storedKey = key; return coordinate(key, signal, work); };
  assert.equal(await f.oauth.prepare(f.context, budget()), pending);
  f.values.set(storedKey, { token: 'new', expiresAt: Date.now() + 60000, scopes: ['deliver'], generation: 'new' });
  await assert.rejects(f.oauth.complete(pending, f.callback(pending), budget()), { code: 'invalid_configuration' });
  assert.equal(f.state.tokenCalls, 0);
  assert.equal(f.values.get(storedKey).generation, 'new');
});

test('pending reuse requires its original base generation', async () => {
  const f = fixture();
  let key;
  const coordinate = f.options.store.coordinate;
  f.options.store.coordinate = (k, signal, work) => { key = k; return coordinate(k, signal, work); };
  const old = await f.oauth.prepare(f.context, budget());
  f.values.set(key, { token: 'expired', expiresAt: 0, scopes: ['deliver'], generation: 'replacement' });
  const fresh = await f.oauth.prepare(f.context, budget());
  assert.notEqual(fresh, old);
  await assert.rejects(f.oauth.complete(old, f.callback(old), budget()), { code: 'invalid_configuration' });
  assert.equal((await f.oauth.complete(fresh, f.callback(fresh), budget())).type, 'ready');
});

test('aborting an abandoned login releases retained signal listeners immediately', async () => {
  const f = fixture(), controller = new AbortController();
  const pending = await f.oauth.prepare(f.context, budget(controller.signal));
  assert.ok(getEventListeners(controller.signal, 'abort').length > 0);
  controller.abort();
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  await assert.rejects(f.oauth.complete(pending, f.callback(pending), budget()), { name: 'AbortError' });
});

test('prepare lazily prunes expired login listeners without background work', async () => {
  const f = fixture(), controller = new AbortController();
  const expired = await f.oauth.prepare(f.context, budget(controller.signal, 200));
  assert.ok(getEventListeners(controller.signal, 'abort').length > 0);
  await new Promise(resolve => setTimeout(resolve, 250));
  await assert.rejects(f.oauth.complete(expired, f.callback(expired), budget()), { name: 'TimeoutError' });
  const fresh = await f.oauth.prepare(f.context, budget());
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  await f.oauth.cancel(fresh, budget());
});

test('parallel prepares share a pending login and completion consumes it once', async () => {
  const f = fixture(), signal = new AbortController().signal;
  const pending = await Promise.all(Array.from({ length: 4 }, () => f.oauth.prepare(f.context, budget(signal))));
  assert.ok(pending.every(value => value === pending[0]));
  const result = await Promise.allSettled(Array.from({ length: 2 }, () => f.oauth.complete(pending[0], f.callback(pending[0]), budget())));
  assert.equal(result.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(f.state.tokenCalls, 1);
  assert.equal(f.state.writes, 1);
  assert.equal(getEventListeners(signal, 'abort').length, 0);
});

test('foreign attempts cannot reject credentials and configured bearer does not fall back', async () => {
  const f = fixture();
  const pending = await f.oauth.prepare(f.context, budget());
  const { credential } = await f.oauth.complete(pending, f.callback(pending), budget());
  const foreign = managedOAuth(f.options);
  await assert.rejects(foreign.challenge({ ...f.context, credential, response: new Response(null, { status: 401 }) }, budget()), { code: 'invalid_configuration' });
  await assert.rejects(f.oauth.challenge({ ...f.context, purpose: 'upload', credential, response: new Response(null, { status: 401 }) }, budget()), { code: 'invalid_configuration' });
  await assert.rejects(f.oauth.prepare({ ...f.context, authentication: { type: 'bearer', tokenEnv: 'TOKEN' } }, budget()), { code: 'unsupported_binding' });
  assert.equal(f.state.writes, 1);
});
