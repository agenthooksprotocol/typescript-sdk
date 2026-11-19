import assert from 'node:assert/strict';
import { test } from 'node:test';
import { managedOAuth } from '../dist/src/oauth/index.js';

const budget = (signal = new AbortController().signal, ms = 5000) => ({ signal, deadline: Date.now() + ms });

// A store shared by every "process" (managedOAuth instance) in a test.
function memoryStore() {
  const values = new Map(), locks = new Map();
  return {
    values,
    grants: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.grant:')).map(([, value]) => value),
    pending: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.pending:')).map(([, value]) => value),
    indexes: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.pending-index:')).map(([, value]) => value),
    async load(key, signal) { signal.throwIfAborted(); return structuredClone(values.get(key)); },
    async compareAndSet(key, expected, value, signal) {
      signal.throwIfAborted();
      if (values.get(key)?.generation !== expected) return false;
      if (value === undefined) values.delete(key); else values.set(key, structuredClone(value));
      return true;
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
}

/** In-memory authorization server and receiver metadata; no TLS or sockets. */
function fixture(overrides = {}) {
  const store = memoryStore();
  const state = { tokenCalls: [], metadataCalls: 0, metadataDown: false, tokenStatus: 200, tokenError: undefined, scope: undefined, next: 0 };
  const client = { issuer: 'https://issuer.example', resource: 'https://api.example/events', clientId: 'client',
    flow: 'authorization_code_pkce', scopes: ['deliver'], redirectUri: 'https://app.example/callback', ...overrides };
  const context = { backendId: 'backend', purpose: 'event', url: client.resource };
  const options = {
    namespace: 'lifecycle', store, selectClient: () => ({ ...client, scopes: [...client.scopes] }),
    checkDestination: (_url, _purpose, operation) => operation.signal.throwIfAborted(),
    async policyFetch(url, init, { operation }) {
      operation.signal.throwIfAborted();
      if (url === 'https://issuer.example/token') {
        const body = new URLSearchParams(String(init.body));
        state.tokenCalls.push(body);
        if (state.tokenStatus !== 200) return Response.json(state.tokenError ?? {}, { status: state.tokenStatus });
        const n = ++state.next;
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600,
          refresh_token: `refresh-${n}`, scope: state.scope ?? body.get('scope') ?? client.scopes.join(' ') });
      }
      state.metadataCalls++;
      if (state.metadataDown) return new Response('{}', { status: 503 });
      if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource: client.resource, authorization_servers: [client.issuer] });
      return Response.json({ issuer: client.issuer, authorization_endpoint: 'https://issuer.example/authorize',
        token_endpoint: 'https://issuer.example/token', response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'] });
    },
  };
  const oauth = managedOAuth(options);
  // A callback arrives at the login's own redirect, named in its authorization URL.
  const callback = (pending, extra = {}) => {
    const url = new URL(new URL(pending.authorizationUrl).searchParams.get('redirect_uri'));
    url.search = new URLSearchParams({ code: 'code', state: new URL(pending.authorizationUrl).searchParams.get('state'), ...extra }).toString();
    return url.href;
  };
  const scopeOf = pending => new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').sort();
  const expire = () => { for (const [key, value] of store.values) if (value.kind === 'grant') store.values.set(key, { ...value, expiresAt: Date.now() - 1 }); };
  const login = async (instance = oauth) => {
    const pending = await instance.prepare({ ...context, challenged: true }, budget());
    return instance.complete(callback(pending), budget());
  };
  return { oauth, options, store, state, client, context, callback, scopeOf, expire, login };
}

test('[pending-login-owned-by-creating-process] by default the creating instance holds the login and completes it by state', async () => {
  const f = fixture();
  const pending = await f.oauth.prepare(f.context, budget());
  assert.deepEqual(Object.keys(pending).sort(), ['authorizationUrl', 'expiresAt', 'state', 'type']);
  assert.equal(pending.state, new URL(pending.authorizationUrl).searchParams.get('state'));
  assert.equal(f.store.pending().length, 0, 'nothing about the login is persisted');
  // Another process sharing the store cannot complete it; that attempt consumes nothing.
  await assert.rejects(managedOAuth(f.options).complete(f.callback(pending), budget()), { code: 'interaction_required' });
  assert.equal((await f.oauth.complete(f.callback(pending), budget())).credential.token, 'access-1');
  assert.equal(f.state.tokenCalls.length, 1);
});

test('[pending-login-persisted-cross-process-completion] a persisted login completes from another process by its callback alone', async () => {
  const f = fixture();
  const options = { ...f.options, persistPendingLogins: true };
  assert.throws(() => managedOAuth({ ...options, persistPendingLogins: 'yes' }), { code: 'invalid_configuration' });
  const pending = await managedOAuth(options).prepare(f.context, budget());
  const [record] = f.store.pending();
  assert.equal(record.state, pending.state);
  // The PKCE verifier is only in the pending record: not in the handle, index or any other record.
  const verifier = record.verifier;
  assert.ok(verifier);
  assert.equal(JSON.stringify(pending).includes(verifier), false);
  for (const [key, value] of f.store.values) {
    if (!key.startsWith('ahp.oauth.pending:')) assert.equal(JSON.stringify(value).includes(verifier), false, key);
  }
  // A pasted callback URL is enough: the other process finds the login by state.
  assert.equal((await managedOAuth(options).complete(f.callback(pending), budget())).credential.token, 'access-1');
  assert.equal(f.store.pending().length, 0);
  assert.equal(f.state.tokenCalls[0].get('code_verifier'), verifier);
  await assert.rejects(managedOAuth(options).complete(f.callback(pending), budget()), { code: 'interaction_required' });
});

test('[pending-login-fixed-lifetime] lifetime is fixed at creation and survives the creating budget', async () => {
  assert.throws(() => managedOAuth({ ...fixture().options, loginLifetimeMs: 600_001 }), { code: 'invalid_configuration' });
  const f = fixture(), short = managedOAuth({ ...f.options, loginLifetimeMs: 300 });
  const controller = new AbortController(), before = Date.now();
  const pending = await short.prepare(f.context, budget(controller.signal, 50));
  assert(pending.expiresAt >= before + 300 && pending.expiresAt <= Date.now() + 300);
  controller.abort();
  await new Promise(resolve => setTimeout(resolve, 80));
  // The creating budget is cancelled and past its deadline; the login is still valid.
  const ok = await short.complete(f.callback(pending), budget());
  assert.equal(ok.credential.token, 'access-1');
  const brief = managedOAuth({ ...f.options, loginLifetimeMs: 30 });
  const expiring = await brief.prepare({ ...f.context, purpose: 'upload' }, budget());
  await new Promise(resolve => setTimeout(resolve, 50));
  await assert.rejects(brief.complete(f.callback(expiring), budget()), { code: 'interaction_required' });
});

test('[cached-token-metadata-outage] host prepare serves a usable cached token without metadata calls', async () => {
  const f = fixture();
  await f.login();
  const metadata = f.state.metadataCalls;
  assert.equal((await managedOAuth(f.options).prepare({ ...f.context, challenged: false }, budget())).credential.token, 'access-1');
  assert.equal(f.state.metadataCalls, metadata);
});

test('[pending-logins-concurrent-per-state] concurrent prepares create separate logins, each completed only by its own callback', async () => {
  const f = fixture({ allowedScopes: ['deliver', 'audit'] });
  const first = await f.oauth.prepare(f.context, budget(), { redirectUri: 'http://127.0.0.1:50001/callback' });
  const second = await f.oauth.prepare(f.context, budget(), { redirectUri: 'http://127.0.0.1:50002/callback' });
  assert.notEqual(first.state, second.state);
  assert.equal(new URL(second.authorizationUrl).searchParams.get('redirect_uri'), 'http://127.0.0.1:50002/callback');
  // One login's state at another login's redirect is invalid and consumes neither.
  const crossed = new URL(f.callback(first)); crossed.port = '50002';
  await assert.rejects(f.oauth.complete(crossed.href, budget()), { code: 'access_denied' });
  // Completion consumes a login exactly once.
  const results = await Promise.allSettled([0, 1].map(() => f.oauth.complete(f.callback(second), budget())));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'interaction_required');
  assert.equal((await f.oauth.complete(f.callback(first), budget())).credential.token, 'access-2', 'the other login is still valid');
  assert.deepEqual(f.state.tokenCalls.map(body => body.get('redirect_uri')),
    ['http://127.0.0.1:50002/callback', 'http://127.0.0.1:50001/callback']);
});

test('[pending-logins-capped-per-grant-key] beyond the cap the oldest login is cancelled, atomically in a persisted store', async () => {
  // Per process, default cap 5: the sixth login cancels the first only.
  const f = fixture();
  const logins = [];
  for (let n = 0; n < 6; n++) logins.push(await f.oauth.prepare(f.context, budget()));
  await assert.rejects(f.oauth.complete(f.callback(logins[0]), budget()), { code: 'interaction_required' });
  // Another grant key has its own count.
  const upload = await f.oauth.prepare({ ...f.context, purpose: 'upload' }, budget());
  assert.equal((await f.oauth.complete(f.callback(logins[1]), budget())).credential.token, 'access-1');
  assert.equal((await f.oauth.complete(f.callback(upload), budget())).credential.token, 'access-2');
  assert.throws(() => managedOAuth({ ...f.options, maxPendingLogins: 0 }), { code: 'invalid_configuration' });

  // Per store: concurrent prepares from several processes keep exactly the cap.
  const g = fixture();
  const options = { ...g.options, persistPendingLogins: true, maxPendingLogins: 2 };
  const created = await Promise.all(Array.from({ length: 5 }, () => managedOAuth(options).prepare(g.context, budget())));
  assert.equal(g.store.pending().length, 2);
  assert.deepEqual(g.store.indexes()[0].states, created.slice(3).map(pending => pending.state));
  await assert.rejects(managedOAuth(options).complete(g.callback(created[2]), budget()), { code: 'interaction_required' });
  assert.equal((await managedOAuth(options).complete(g.callback(created[4]), budget())).credential.token, 'access-1');

  // Expired logins are deleted.
  const h = fixture();
  const brief = { ...h.options, persistPendingLogins: true, loginLifetimeMs: 20 };
  await managedOAuth(brief).prepare(h.context, budget());
  await new Promise(resolve => setTimeout(resolve, 40));
  const fresh = await managedOAuth(brief).prepare(h.context, budget());
  assert.deepEqual(h.store.pending().map(record => record.state), [fresh.state]);
  await new Promise(resolve => setTimeout(resolve, 40));
  await assert.rejects(managedOAuth(brief).complete(h.callback(fresh), budget()), { code: 'interaction_required' });
  assert.equal(h.store.pending().length, 0);
  // An abandoned expired login's verifier is swept by the next host prepare for its grant key, even one that creates no login.
  const k = fixture();
  const sweeping = { ...k.options, persistPendingLogins: true, loginLifetimeMs: 20 };
  await k.login(managedOAuth(sweeping));
  const grantKey = [...k.store.values.keys()].find(key => key.startsWith('ahp.oauth.grant:'));
  const grant = k.store.values.get(grantKey);
  k.store.values.set(grantKey, { ...grant, token: undefined, refreshToken: undefined });
  await managedOAuth(sweeping).prepare(k.context, budget());
  assert.equal(k.store.pending().length, 1);
  await new Promise(resolve => setTimeout(resolve, 40));
  k.store.values.set(grantKey, { ...grant, token: 'access-9', expiresAt: Date.now() + 3_600_000 });
  assert.equal((await managedOAuth(sweeping).prepare(k.context, budget())).type, 'ready');
  assert.deepEqual([k.store.pending(), k.store.indexes()], [[], []]);
});

test('[pending-completion-newest-grant-wins] completing one login leaves the others valid; the newest completion replaces the grant', async () => {
  const f = fixture();
  const first = await f.oauth.prepare(f.context, budget());
  const second = await f.oauth.prepare(f.context, budget());
  const third = await f.oauth.prepare(f.context, budget());
  await f.oauth.complete(f.callback(second), budget());
  assert.equal(f.store.grants()[0].token, 'access-1');
  await f.oauth.complete(f.callback(first), budget());
  await f.oauth.complete(f.callback(third), budget());
  assert.equal(f.store.grants().length, 1);
  assert.equal(f.store.grants()[0].token, 'access-3');
  assert.equal(f.store.grants()[0].refreshToken, 'refresh-3');
});

test('[pending-login-end-states] completion, cancel (including by the cap) and expiry each end a login; cancel keeps the grant', async () => {
  const f = fixture();
  const completed = await f.oauth.prepare(f.context, budget());
  await f.oauth.complete(f.callback(completed), budget());
  await assert.rejects(f.oauth.complete(f.callback(completed), budget()), { code: 'interaction_required' });
  const upload = { ...f.context, purpose: 'upload' };
  const cancelled = await f.oauth.prepare(upload, budget());
  await f.oauth.cancel(cancelled, budget());
  await assert.rejects(f.oauth.complete(f.callback(cancelled), budget()), { code: 'interaction_required' });
  assert.equal(f.store.grants().length, 1, 'cancel never deletes a stored grant');
  assert.equal((await f.oauth.prepare(f.context, budget())).type, 'ready');
  const brief = managedOAuth({ ...f.options, loginLifetimeMs: 1 });
  const expired = await brief.prepare(upload, budget());
  await new Promise(resolve => setTimeout(resolve, 10));
  await assert.rejects(brief.complete(f.callback(expired), budget()), { code: 'interaction_required' });
  const capped = managedOAuth({ ...f.options, maxPendingLogins: 1 });
  const evicted = await capped.prepare(upload, budget());
  await capped.prepare(upload, budget());
  await assert.rejects(capped.complete(f.callback(evicted), budget()), { code: 'interaction_required' });
  assert.equal(f.store.grants().length, 1);
});

test('[step-up-required-scopes-round-trip] interaction_required carries required scopes that prepare accepts', async () => {
  const f = fixture({ allowedScopes: ['deliver', 'audit'] });
  const first = await f.login();
  const response = new Response(null, { status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="audit"' } });
  const error = await f.oauth.challenge({ ...f.context, credential: first.credential, response }, budget()).then(() => assert.fail('expected step-up'), error => error);
  assert.equal(error.code, 'interaction_required');
  assert.deepEqual(error.requiredScopes, ['audit']);
  const pending = await f.oauth.prepare(f.context, budget(), { requiredScopes: error.requiredScopes });
  assert.deepEqual(f.scopeOf(pending), ['audit', 'deliver']);
  f.state.scope = 'deliver audit';
  assert.equal((await f.oauth.complete(f.callback(pending), budget())).credential.token, 'access-2');
  assert.deepEqual([...f.store.grants()[0].scopes].sort(), ['audit', 'deliver']);
});

test('[prepare-required-outside-ceiling-denied] explicit required scopes outside the ceiling fail access_denied', async () => {
  const f = fixture({ allowedScopes: ['deliver'] });
  await assert.rejects(f.oauth.prepare(f.context, budget(), { requiredScopes: ['admin'] }), { code: 'access_denied' });
  assert.equal(f.store.pending().length, 0);
  assert.equal(f.state.tokenCalls.length, 0);
});

test('[scope-ceiling-narrowing-keeps-grant] narrowing hides scopes at use only; refresh and widening keep them', async () => {
  const f = fixture({ scopes: ['deliver', 'audit'], allowedScopes: ['deliver', 'audit'] });
  await f.login();
  Object.assign(f.client, { scopes: ['deliver'], allowedScopes: ['deliver'] });
  await assert.rejects(f.oauth.prepare(f.context, budget(), { requiredScopes: ['audit'] }), { code: 'access_denied' });
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  f.expire(); f.state.scope = undefined;
  // The refresh response omits scope: the previous grant (deliver audit) is recorded, not the narrow ceiling.
  const refreshed = await f.oauth.prepare(f.context, budget());
  assert.equal(refreshed.credential.token, 'access-2');
  assert.deepEqual([...f.store.grants()[0].scopes].sort(), ['audit', 'deliver']);
  Object.assign(f.client, { scopes: ['deliver', 'audit'], allowedScopes: ['deliver', 'audit'] });
  assert.equal((await f.oauth.prepare(f.context, budget(), { requiredScopes: ['audit'] })).credential.token, 'access-2');
  assert.equal(f.state.tokenCalls.length, 2, 'widening again needs no new consent');
});

test('[scope-ceiling-widening-keeps-grant] widening the ceiling finds the existing grant', async () => {
  const f = fixture();
  await f.login();
  f.client.allowedScopes = ['deliver', 'audit', 'write'];
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  assert.equal(f.state.tokenCalls.length, 1);
});

test('[unbound-lookup-anonymous-fallback] store miss, missing deadline or policy refusal sends anonymously', async () => {
  const f = fixture();
  const provider = f.oauth.provider({ budget: () => budget() });
  assert.equal(await provider.credential(f.context), undefined);
  const noDeadline = f.oauth.provider({ budget() { throw new Error('no deadline'); } });
  assert.equal(await noDeadline.credential(f.context), undefined);
  await f.login();
  let refuse = true;
  const refusing = managedOAuth({ ...f.options, selectClient: (...args) => {
    if (refuse) throw Object.assign(new Error('policy'), { code: 'access_denied' });
    return f.options.selectClient(...args);
  } }).provider({ budget: () => budget() });
  assert.equal(await refusing.credential(f.context), undefined);
  refuse = false;
  assert.equal((await refusing.credential(f.context)).token, 'access-1');
  assert.equal(f.store.pending().length, 0, 'the lookup never creates a login');
});

test('[unbound-lookup-refreshes-expired-token] the up-front lookup refreshes with cached metadata and no discovery', async () => {
  const f = fixture();
  await f.login();
  f.expire(); f.state.metadataDown = true;
  const metadata = f.state.metadataCalls;
  const provider = managedOAuth(f.options).provider({ budget: () => budget() });
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert.equal(f.state.metadataCalls, metadata);
  assert.equal(f.state.tokenCalls.at(-1).get('grant_type'), 'refresh_token');
});

test('[up-front-refresh-failure-no-anonymous-fallback] a known binding whose refresh fails fails the operation', async () => {
  const f = fixture();
  await f.login();
  f.expire();
  const provider = f.oauth.provider({ budget: () => budget() });
  Object.assign(f.state, { tokenStatus: 503, tokenError: { error: 'temporarily_unavailable' } });
  await assert.rejects(provider.credential(f.context), { code: 'provider_failed', recovery: 'retry' });
  Object.assign(f.state, { tokenStatus: 400, tokenError: { error: 'invalid_grant' } });
  await assert.rejects(provider.credential(f.context), { code: 'refresh_rejected', recovery: 'login' });
});

test('[token-validation-failure-clears-in-flight] invalid responses leave no stuck state and a retry recovers', async () => {
  const f = fixture();
  const fetch = f.options.policyFetch;
  let invalid = true;
  const options = { ...f.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (!invalid || !url.endsWith('/token')) return response;
    const body = await response.json();
    return Response.json({ ...body, expires_in: 0 });
  } };
  const oauth = managedOAuth(options);
  const pending = await oauth.prepare(f.context, budget());
  await assert.rejects(oauth.complete(f.callback(pending), budget()), { code: 'provider_failed', recovery: 'retry' });
  assert.equal(f.store.grants().length, 0, 'an invalid initial exchange persists nothing');
  assert.equal(f.store.pending().length, 0, 'the claimed login is not left in flight');
  invalid = false; await f.login(oauth); invalid = true;
  f.expire();
  await assert.rejects(oauth.prepare(f.context, budget()), { code: 'provider_failed' });
  const [grant] = f.store.grants();
  assert.equal(grant.token, undefined); assert.equal(grant.refreshToken, 'refresh-3', 'valid rotated refresh token persisted');
  invalid = false;
  assert.equal((await oauth.prepare(f.context, budget())).credential.token, 'access-4');
  assert.equal(f.state.tokenCalls.at(-1).get('refresh_token'), 'refresh-3');
});

test('[insufficient-scope-step-up] only Bearer 403 insufficient_scope steps up; other 403s are denials', async () => {
  const f = fixture({ allowedScopes: ['deliver', 'audit'] });
  const { credential } = await f.login();
  await assert.rejects(f.oauth.challenge({ ...f.context, credential, response: new Response(null, { status: 403 }) }, budget()), { code: 'access_denied' });
  await assert.rejects(f.oauth.challenge({ ...f.context, credential, response: new Response(null, {
    status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="admin"' } }) }, budget()), { code: 'access_denied' });
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1', 'denials never reject the grant');
});

test('foreign attempts cannot reject credentials and configured bearer does not fall back', async () => {
  const f = fixture();
  const { credential } = await f.login();
  assert.equal(JSON.stringify(credential).includes('access-1'), false, 'token is not enumerable');
  const foreign = managedOAuth(f.options);
  await assert.rejects(foreign.challenge({ ...f.context, credential, response: new Response(null, { status: 401 }) }, budget()), { code: 'invalid_configuration' });
  await assert.rejects(f.oauth.challenge({ ...f.context, purpose: 'upload', credential, response: new Response(null, { status: 401 }) }, budget()), { code: 'invalid_configuration' });
  await assert.rejects(f.oauth.prepare({ ...f.context, authentication: { type: 'bearer', tokenEnv: 'TOKEN' } }, budget()), { code: 'unsupported_binding' });
  assert.equal(f.store.grants()[0].token, 'access-1');
});

test('[narrowed-refresh-scope-inheritance] a refresh without scope inherits the narrowed grant', async () => {
  const f = fixture({ scopes: ['read', 'write'] });
  f.state.scope = 'read';
  await f.login();
  f.expire(); f.state.scope = undefined;
  const fetch = f.options.policyFetch;
  const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (!url.endsWith('/token')) return response;
    const { scope: _scope, ...body } = await response.json();
    return Response.json(body);
  } });
  assert.equal((await oauth.prepare(f.context, budget())).credential.token, 'access-2');
  assert.equal(f.state.tokenCalls[1].get('scope'), 'read');
  assert.deepEqual(f.store.grants()[0].scopes, ['read']);
  assert.equal((await oauth.prepare(f.context, budget(), { requiredScopes: ['write'] })).type, 'pending_login', 'write needs new consent, not a refresh');
});

test('[refresh-broadening-scope-ignored] a broadening refresh records the prior grant and stays usable', async () => {
  const f = fixture({ scopes: ['read', 'write'] });
  f.state.scope = 'read';
  await f.login();
  f.expire(); f.state.scope = 'read write';
  const provider = f.oauth.provider({ budget: () => budget() });
  assert.equal((await provider.credential({ ...f.context, authentication: undefined })).token, 'access-2');
  assert.deepEqual(f.store.grants()[0].scopes, ['read']);
  assert.equal(f.store.grants()[0].refreshToken, 'refresh-2');
  f.client.requiredScopes = ['write'];
  await assert.rejects(provider.credential({ ...f.context, challenged: true }), { code: 'interaction_required' });
});

test('[extra-granted-scope-ignored] scopes outside the ceiling are dropped from the recorded grant', async () => {
  const f = fixture({ allowedScopes: ['deliver'] });
  f.state.scope = 'deliver openid offline_access admin';
  assert.equal((await f.login()).credential.token, 'access-1');
  assert.deepEqual(f.store.grants()[0].scopes, ['deliver']);
});

test('[up-front-client-credentials-reacquire] the lookup re-acquires an expired client-credentials grant from persisted metadata', async () => {
  const f = fixture({ flow: 'client_credentials', clientSecret: 'secret' });
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  f.expire(); f.state.metadataDown = true;
  const metadata = f.state.metadataCalls;
  const provider = managedOAuth(f.options).provider({ budget: () => budget() });
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert.equal(f.state.metadataCalls, metadata);
  assert.equal(f.state.tokenCalls.at(-1).get('grant_type'), 'client_credentials');
});

test('[up-front-lookup-issuer-metadata-only] a binding without persisted metadata fetches only issuer metadata', async () => {
  const f = fixture();
  await f.login();
  f.expire();
  for (const [key, value] of f.store.values) {
    if (value.kind === 'binding') { const { metadata: _metadata, ...rest } = value; f.store.values.set(key, rest); }
  }
  const urls = [];
  const fetch = f.options.policyFetch;
  const options = { ...f.options, policyFetch: (url, init, context) => { urls.push(url); return fetch(url, init, context); } };
  const provider = managedOAuth(options).provider({ budget: () => budget() });
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert(urls.every(url => !url.includes('oauth-protected-resource')), 'no protected-resource discovery');
  assert(urls.some(url => url.startsWith('https://issuer.example/.well-known/')));
  f.expire(); f.state.metadataDown = true;
  for (const [key, value] of f.store.values) {
    if (value.kind === 'binding') { const { metadata: _metadata, ...rest } = value; f.store.values.set(key, rest); }
  }
  await assert.rejects(provider.credential(f.context), { code: 'discovery_failed' });
});

test('[known-binding-without-token-requires-login] a known PKCE binding with dropped tokens fails interaction_required until prepare', async () => {
  const f = fixture();
  await f.login();
  for (const [key, value] of f.store.values) if (value.kind === 'grant') f.store.values.delete(key);
  const provider = f.oauth.provider({ budget: () => budget() });
  await assert.rejects(provider.credential(f.context), { code: 'interaction_required' });
  assert.equal(f.store.pending().length, 0);
  await f.login();
  assert.equal((await provider.credential(f.context)).token, 'access-2');
});

test('[challenge-renews-rejected-unexpired-token] a 401 on an unknown-expiry token renews it so it is never resent', async () => {
  const f = fixture();
  const fetch = f.options.policyFetch;
  const options = { ...f.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (!url.endsWith('/token')) return response;
    const { expires_in: _expires, ...body } = await response.json();
    return Response.json(body);
  } };
  const oauth = managedOAuth(options), provider = oauth.provider({ budget: () => budget() });
  const { credential } = await f.login(oauth);
  assert.equal(f.store.grants()[0].expiresAt, undefined);
  // A notification is not replayed: challenge handling alone must renew the token.
  await provider.challenge({ ...f.context, credential, response: new Response(null, { status: 401 }) });
  assert.equal(f.state.tokenCalls.at(-1).get('grant_type'), 'refresh_token');
  assert.equal((await provider.credential(f.context)).token, 'access-2');
});

test('[step-up-keeps-previous-grant] step-up consent requests and records the previous grant plus the new scopes', async () => {
  const f = fixture({ scopes: ['files', 'read'], allowedScopes: ['files', 'read'] });
  await f.login();
  Object.assign(f.client, { scopes: ['read'], allowedScopes: ['read', 'write'] });
  const pending = await f.oauth.prepare(f.context, budget(), { requiredScopes: ['write'] });
  assert.deepEqual(f.scopeOf(pending), ['files', 'read', 'write']);
  f.state.scope = 'files read write openid';
  await f.oauth.complete(f.callback(pending), budget());
  assert.deepEqual([...f.store.grants()[0].scopes].sort(), ['files', 'read', 'write'], 'earlier scopes are not lost');
});

test('[stale-metadata-refetch-once] a moved token endpoint refetches issuer metadata once; OAuth errors never refetch', async () => {
  const f = fixture();
  await f.login();
  const fetch = f.options.policyFetch;
  const urls = [];
  let moved = false, issuer = 'https://issuer.example';
  const options = { ...f.options, async policyFetch(url, init, context) {
    urls.push(url);
    if (url === 'https://issuer.example/token' && moved) return new Response('gone', { status: 410 });
    if (url === 'https://issuer.example/token2') return fetch('https://issuer.example/token', init, context);
    const response = await fetch(url, init, context);
    if (!url.includes('oauth-authorization-server')) return response;
    return Response.json({ ...await response.json(), issuer, ...(moved ? { token_endpoint: 'https://issuer.example/token2' } : {}) });
  } };
  const provider = managedOAuth(options).provider({ budget: () => budget() });
  // Moved endpoint: one issuer-metadata refetch, persisted, then one retry.
  moved = true; f.expire(); urls.length = 0;
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert.equal(urls.filter(url => url.includes('oauth-authorization-server')).length, 1);
  assert(urls.every(url => !url.includes('oauth-protected-resource')));
  const binding = [...f.store.values.values()].find(value => value.kind === 'binding');
  assert.equal(binding.metadata.token_endpoint, 'https://issuer.example/token2');
  // An OAuth error response never triggers a refetch.
  f.expire(); urls.length = 0;
  Object.assign(f.state, { tokenStatus: 400, tokenError: { error: 'invalid_client' } });
  await assert.rejects(provider.credential(f.context), { code: 'credential_unavailable' });
  assert.equal(urls.filter(url => url.includes('oauth-authorization-server')).length, 0);
  // A changed issuer after a transport failure is discovery_failed; the host repairs with prepare.
  Object.assign(f.state, { tokenStatus: 200, tokenError: undefined });
  for (const [key, value] of f.store.values) if (value.kind === 'binding') f.store.values.set(key, { ...value, metadata: { ...value.metadata, token_endpoint: 'https://issuer.example/token' } });
  issuer = 'https://other-issuer.example';
  await assert.rejects(provider.credential(f.context), { code: 'discovery_failed', recovery: 'retry' });
});

test('[stale-metadata-refetch-once] a DNS failure before sending refetches issuer metadata once and retries', async () => {
  const f = fixture();
  await f.login();
  const fetch = f.options.policyFetch;
  let unresolvable = true, metadata = 0;
  const options = { ...f.options, async policyFetch(url, init, context) {
    if (url.includes('oauth-authorization-server')) metadata++;
    if (url.endsWith('/token') && unresolvable) {
      unresolvable = false;
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo'), { code: 'ENOTFOUND' }) });
    }
    return fetch(url, init, context);
  } };
  f.expire();
  assert.equal((await managedOAuth(options).provider({ budget: () => budget() }).credential(f.context)).token, 'access-2');
  assert.equal(metadata, 1);
});

for (const [kind, failure] of [
  ['reset after send', () => { throw new TypeError('fetch failed', { cause: Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }) }); }],
  ['5xx with a non-OAuth body', () => new Response('<html>bad gateway</html>', { status: 502 })],
  ['read timeout', () => { throw new TypeError('fetch failed', { cause: Object.assign(new Error('timeout'), { code: 'UND_ERR_BODY_TIMEOUT' }) }); }],
]) {
  test(`[ambiguous-renewal-failure-no-refetch] ${kind} keeps retry advice without refetch or immediate retry`, async () => {
    const f = fixture();
    await f.login();
    const fetch = f.options.policyFetch;
    let metadata = 0, token = 0;
    const options = { ...f.options, async policyFetch(url, init, context) {
      if (url.includes('oauth-authorization-server')) metadata++;
      if (url.endsWith('/token')) { token++; return failure(); }
      return fetch(url, init, context);
    } };
    f.expire();
    const before = structuredClone(f.store.grants()[0]);
    await assert.rejects(managedOAuth(options).provider({ budget: () => budget() }).credential(f.context), { code: 'provider_failed', recovery: 'retry' });
    assert.equal(token, 1, 'the presented refresh token is not replayed');
    assert.equal(metadata, 0);
    assert.deepEqual(f.store.grants()[0], before);
  });
}

// Host policy moves the resource to a new authorization server while the old one is gone.
function movedIssuer(f, { oldUp = false } = {}) {
  const NEW = 'https://new-issuer.example';
  const urls = [];
  const options = { ...f.options,
    selectClient: issuers => ({ ...f.client, issuer: issuers.includes(NEW) ? NEW : issuers[0], scopes: [...f.client.scopes] }),
    async policyFetch(url, init, context) {
      urls.push(url);
      if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource: f.client.resource, authorization_servers: [NEW] });
      if (url.startsWith('https://issuer.example/') && !oldUp) return new Response('gone', { status: 503 });
      if (url === `${NEW}/token`) return Response.json({ access_token: 'new-as', token_type: 'Bearer', expires_in: 3600, refresh_token: 'new-refresh' });
      if (url.startsWith(`${NEW}/.well-known/`)) return Response.json({ issuer: NEW, authorization_endpoint: `${NEW}/authorize`, token_endpoint: `${NEW}/token`,
        response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'] });
      return f.options.policyFetch(url, init, context);
    } };
  return { NEW, urls, options };
}

for (const persisted of [true, false]) {
  test(`exchange-needing prepare repairs a binding whose stored issuer is gone or untrusted (metadata ${persisted ? 'persisted' : 'missing'})`, async () => {
    const f = fixture();
    await f.login();
    for (const [key, value] of f.store.values) {
      if (value.kind === 'grant') f.store.values.delete(key);
      if (value.kind === 'binding' && !persisted) { const { metadata: _metadata, ...rest } = value; f.store.values.set(key, rest); }
    }
    const moved = movedIssuer(f);
    const pending = await managedOAuth(moved.options).prepare(f.context, budget());
    assert.equal(pending.type, 'pending_login');
    assert(pending.authorizationUrl.startsWith(moved.NEW));
    assert(moved.urls.some(url => url.includes('oauth-protected-resource')), 'full discovery ran');
    assert.equal([...f.store.values.values()].find(value => value.kind === 'binding').issuer, moved.NEW);
  });
}

test('challenge handling runs full discovery and rebinds a resource that moved to a new authorization server', async () => {
  const f = fixture({ flow: 'client_credentials', clientSecret: 'secret' });
  const moved = movedIssuer(f, { oldUp: true });
  const oauth = managedOAuth(moved.options), provider = oauth.provider({ budget: () => budget() });
  // Bind to the old issuer first: protected-resource metadata then still named it.
  await managedOAuth(f.options).prepare(f.context, budget());
  const credential = await provider.credential(f.context);
  assert.equal(credential.token, 'access-1');
  await provider.challenge({ ...f.context, credential, response: new Response(null, { status: 401, headers: {
    'www-authenticate': 'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/events"' } }) });
  assert.equal((await provider.credential(f.context)).token, 'new-as');
  assert.equal([...f.store.values.values()].find(value => value.kind === 'binding').issuer, moved.NEW);
});

test('[unbound-lookup-anonymous-fallback] the lookup surfaces config and identity errors; only selectClient rejection is anonymous', async () => {
  const f = fixture();
  await f.login();
  const lookup = mutate => managedOAuth({ ...f.options, selectClient: (...args) => mutate(f.options.selectClient(...args)) })
    .provider({ budget: () => budget() }).credential(f.context);
  for (const mutate of [c => ({ ...c, scopes: ['bad scope'] }), c => ({ ...c, requiredScopes: ['admin'] }), c => ({ ...c, clientId: '' }),
    c => ({ ...c, issuer: 'https://other.example' }), c => ({ ...c, resource: 'https://api.example/' })]) {
    await assert.rejects(lookup(mutate), error => error.code !== undefined);
  }
  for (const mutate of [c => ({ ...c, clientId: 'other' }), c => ({ ...c, grantPartition: 'other' })]) {
    await assert.rejects(lookup(mutate), { code: 'discovery_failed' }, 'a grant-key mismatch on a known binding is not a store miss');
  }
  assert.equal(await lookup(() => { throw new Error('policy refused'); }), undefined);
  assert.equal((await lookup(c => c)).token, 'access-1');
});

test('[token-validation-failure-clears-in-flight] a received refresh response is committed despite caller abort or a slow store', async () => {
  for (const scenario of ['abort', 'slow-store']) {
    const f = fixture();
    await f.login(); f.expire();
    const controller = new AbortController();
    const store = scenario === 'slow-store'
      ? { ...f.store, async compareAndSet(...args) { await new Promise(resolve => setTimeout(resolve, 300)); return f.store.compareAndSet(...args); } }
      : f.store;
    const oauth = managedOAuth({ ...f.options, store, async policyFetch(url, init, context) {
      const response = await f.options.policyFetch(url, init, context);
      if (url.endsWith('/token')) queueMicrotask(() => controller.abort());
      return response;
    } });
    await assert.rejects(oauth.prepare(f.context, budget(scenario === 'abort' ? controller.signal : undefined, scenario === 'abort' ? 5000 : 150)));
    await new Promise(resolve => setTimeout(resolve, 400));
    assert.equal(f.store.grants()[0].refreshToken, 'refresh-2', `${scenario}: rotated refresh token persisted`);
  }
});

for (const [kind, response] of [
  ['201 status', () => new Response(JSON.stringify({ access_token: 'n', token_type: 'Bearer', refresh_token: 'rotated' }), { status: 201, headers: { 'content-type': 'application/json' } })],
  ['form-urlencoded body', () => new Response('access_token=n&token_type=Bearer&refresh_token=rotated', { headers: { 'content-type': 'application/x-www-form-urlencoded' } })],
  ['text/plain JSON with malformed expires_in', () => new Response('{"access_token":"n","token_type":"Bearer","expires_in":"3600.5","refresh_token":"rotated"}', { headers: { 'content-type': 'text/plain' } })],
  ['missing access_token', () => Response.json({ refresh_token: 'rotated', token_type: 'Bearer' })],
  ['null expires_in', () => Response.json({ access_token: 'n', token_type: 'Bearer', expires_in: null, refresh_token: 'rotated' })],
  ['overflowing expires_in', () => new Response('{"access_token":"n","token_type":"Bearer","expires_in":1e400,"refresh_token":"rotated"}', { headers: { 'content-type': 'application/json' } })],
]) {
  test(`[token-validation-failure-clears-in-flight] an invalid refresh response (${kind}) persists the rotated refresh token`, async () => {
    const f = fixture();
    await f.login(); f.expire();
    const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
      return url.endsWith('/token') ? response() : f.options.policyFetch(url, init, context);
    } });
    await assert.rejects(oauth.prepare(f.context, budget()), { code: 'provider_failed', recovery: 'retry' });
    assert.equal(f.store.grants()[0].refreshToken, 'rotated');
    assert.equal(f.store.grants()[0].token, undefined);
  });
}

// A real token endpoint over node:http, reached with undici fetch; the response is
// re-wrapped only to keep the logical HTTPS URL for the redirect check.
async function realTokenServer(t, body) {
  const { createServer } = await import('node:http');
  const server = createServer((request, response) => { request.resume(); request.on('end', () => {
    const text = JSON.stringify(body);
    response.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
    response.end(text);
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}/token`;
}

test('[token-validation-failure-clears-in-flight] a caller abort after a real HTTP token response still commits the rotated refresh token', async t => {
  const endpoint = await realTokenServer(t, { access_token: 'acc-new', token_type: 'Bearer', expires_in: 3600, refresh_token: 'rotated-real' });
  const f = fixture();
  await f.login(); f.expire();
  const controller = new AbortController();
  const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
    if (url !== 'https://issuer.example/token') return f.options.policyFetch(url, init, context);
    assert.notEqual(init.signal, controller.signal, 'the transfer is not bound to the caller');
    const response = await fetch(endpoint, { method: init.method, headers: init.headers, body: init.body, signal: init.signal });
    await new Promise(resolve => setTimeout(resolve, 20));
    controller.abort();
    return new Response(response.body, { status: response.status, headers: response.headers });
  } });
  await assert.rejects(oauth.prepare(f.context, budget(controller.signal)), { name: 'AbortError' });
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(f.store.grants()[0].refreshToken, 'rotated-real');
});

for (const [kind, configure] of [
  ['protected-resource metadata 503', (url, broken) => broken && url.includes('oauth-protected-resource') ? new Response('x', { status: 503 }) : undefined],
  ['issuer metadata 503 without persisted metadata', (url, broken) => broken && url.includes('oauth-authorization-server') ? new Response('x', { status: 503 }) : undefined],
]) {
  test(`a 401 drops the rejected token before discovery, even when discovery fails (${kind})`, async () => {
    const f = fixture();
    let broken = false;
    const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
      return configure(url, broken) ?? (broken && url.endsWith('/token') ? new Response('down', { status: 503 }) : f.options.policyFetch(url, init, context));
    } });
    const { credential } = await f.login(oauth);
    for (const [key, value] of f.store.values) {
      if (value.kind === 'binding' && kind.includes('without')) { const { metadata: _metadata, ...rest } = value; f.store.values.set(key, rest); }
    }
    broken = true;
    const provider = oauth.provider({ budget: () => budget() });
    await assert.rejects(provider.challenge({ ...f.context, credential, response: new Response(null, { status: 401 }) }));
    assert.equal(f.store.grants()[0].token, undefined, 'the revoked token is not left stored');
    assert.equal(f.store.grants()[0].refreshToken, 'refresh-1');
    const next = await provider.credential(f.context).then(value => value?.token, error => error.code);
    assert.notEqual(next, 'access-1', 'the revoked token is never resent');
  });
}

test('challenge handling alone rebinds a moved resource, without any token acquisition', async () => {
  const f = fixture();
  const moved = movedIssuer(f, { oldUp: true });
  const fetch = moved.options.policyFetch;
  let rebound = false;
  const options = { ...moved.options, async policyFetch(url, init, context) {
    // The old resource metadata names the old issuer until the challenge.
    if (!rebound && url.startsWith('https://api.example/.well-known/')) return Response.json({ resource: f.client.resource, authorization_servers: ['https://issuer.example'] });
    const response = await fetch(url, init, context);
    if (!url.endsWith('/token')) return response;
    const { refresh_token: _refresh, ...body } = await response.json();
    return Response.json(body);
  } };
  const oauth = managedOAuth(options), provider = oauth.provider({ budget: () => budget() });
  const { credential } = await f.login(oauth);
  const tokens = f.state.tokenCalls.length;
  rebound = true;
  await provider.challenge({ ...f.context, credential, response: new Response(null, { status: 401 }) });
  assert.equal(f.state.tokenCalls.length, tokens, 'no acquisition ran');
  assert.equal([...f.store.values.values()].find(value => value.kind === 'binding').issuer, moved.NEW);
});

test('a host budget failure followed by a store load failure is a classified AuthError', async () => {
  const f = fixture();
  const oauth = managedOAuth({ ...f.options, store: { ...f.store, async load() { throw new Error('db down: secret detail'); } } });
  const provider = oauth.provider({ budget() { throw new Error('no deadline'); } });
  await assert.rejects(provider.credential(f.context), error => error.code === 'provider_failed' && !String(error).includes('secret detail'));
});

test('a caller abort while the token request has not completed returns promptly', async () => {
  const f = fixture();
  await f.login(); f.expire();
  const controller = new AbortController();
  // A stalled connect: policyFetch never settles.
  const oauth = managedOAuth({ ...f.options, policyFetch: (url, init, context) =>
    url.endsWith('/token') ? new Promise(() => {}) : f.options.policyFetch(url, init, context) });
  const preparing = oauth.prepare(f.context, budget(controller.signal));
  await new Promise(resolve => setTimeout(resolve, 20));
  const started = Date.now();
  controller.abort();
  await assert.rejects(preparing, { name: 'AbortError' });
  assert(Date.now() - started < 100);
});

test('[token-validation-failure-clears-in-flight] a token body delayed past a caller abort is still read and committed', async t => {
  const { createServer } = await import('node:http');
  const server = createServer((request, response) => { request.resume(); request.on('end', () => {
    const text = JSON.stringify({ access_token: 'late', token_type: 'Bearer', expires_in: 3600, refresh_token: 'rotated-late' });
    response.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
    response.flushHeaders();
    setTimeout(() => response.end(text), 100);
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const f = fixture();
  await f.login(); f.expire();
  const controller = new AbortController();
  const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
    if (url !== 'https://issuer.example/token') return f.options.policyFetch(url, init, context);
    const response = await fetch(`http://127.0.0.1:${server.address().port}/token`, { method: init.method, headers: init.headers, body: init.body, signal: init.signal });
    setTimeout(() => controller.abort(), 10); // headers received, body still in flight
    return new Response(response.body, { status: response.status, headers: response.headers });
  } });
  await assert.rejects(oauth.prepare(f.context, budget(controller.signal)), { name: 'AbortError' });
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal(f.store.grants()[0].refreshToken, 'rotated-late');
});

test('[refresh-invalid-grant-drops-tokens] invalid_grant over real HTTP after a caller abort still drops the dead refresh token', async t => {
  const { createServer } = await import('node:http');
  const server = createServer((request, response) => { request.resume(); request.on('end', () => {
    const text = JSON.stringify({ error: 'invalid_grant' });
    response.writeHead(400, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
    response.flushHeaders();
    setTimeout(() => response.end(text), 50);
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const f = fixture();
  await f.login(); f.expire();
  const controller = new AbortController();
  const oauth = managedOAuth({ ...f.options, async policyFetch(url, init, context) {
    if (url !== 'https://issuer.example/token') return f.options.policyFetch(url, init, context);
    const response = await fetch(`http://127.0.0.1:${server.address().port}/token`, { method: init.method, headers: init.headers, body: init.body, signal: init.signal });
    setTimeout(() => controller.abort(), 10);
    return new Response(response.body, { status: response.status, headers: response.headers });
  } });
  await assert.rejects(oauth.prepare(f.context, budget(controller.signal)), { name: 'AbortError' });
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(f.store.grants().length, 0, 'compare-and-delete ran despite the abort');
});
