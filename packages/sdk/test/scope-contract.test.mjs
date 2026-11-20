// Cross-SDK scope and step-up contract, rules 1-12: one test per rule.
// R = host-required (H) ∪ explicit prepare (E) ∪ 403 insufficient_scope challenge (Ch).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { managedOAuth } from '../dist/src/oauth/index.js';
import { auth, AuthError } from '../dist/src/client/auth.js';

const budget = (signal = new AbortController().signal, ms = 5000) => ({ signal, deadline: Date.now() + ms });

function memoryStore() {
  const values = new Map(), locks = new Map();
  return {
    values,
    grants: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.grant:')).map(([, value]) => value),
    pending: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.pending:')).map(([, value]) => value),
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

const issuer = 'https://issuer.example', resource = 'https://api.example/events';
/** In-memory authorization server; `state.network` counts every policyFetch (network I/O). */
function fixture(clientOverrides = {}, optionOverrides = {}) {
  const store = memoryStore();
  const state = { network: [], tokenCalls: [], scope: undefined, next: 0 };
  const client = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['deliver'],
    allowedScopes: ['audit', 'deliver'], requiredScopes: ['deliver'], redirectUri: 'https://app.example/callback', ...clientOverrides };
  const context = { backendId: 'backend', purpose: 'event', url: resource };
  const options = {
    namespace: 'scope-contract', store,
    selectClient: () => structuredClone(client),
    checkDestination: (_url, _purpose, operation) => operation.signal.throwIfAborted(),
    async policyFetch(url, init, { operation }) {
      operation.signal.throwIfAborted();
      state.network.push(url);
      if (url === `${issuer}/token`) {
        const body = new URLSearchParams(String(init.body));
        state.tokenCalls.push(body);
        const n = ++state.next;
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600,
          refresh_token: `refresh-${n}`, scope: state.scope ?? body.get('scope') ?? client.scopes.join(' ') });
      }
      if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource, authorization_servers: [issuer] });
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'] });
    },
    ...optionOverrides,
  };
  const oauth = managedOAuth(options);
  const provider = oauth.provider({ budget: () => budget() });
  const callback = (pending, extra = {}) => {
    const url = new URL(client.redirectUri);
    url.search = new URLSearchParams({ code: 'code', state: pending.state, iss: issuer, ...extra }).toString();
    return url.href;
  };
  const scopeOf = pending => new URL(pending.authorizationUrl).searchParams.get('scope').split(' ').sort();
  const login = async (extra = {}) => {
    const pending = await oauth.prepare({ ...context, challenged: true }, budget(), extra);
    return oauth.complete(callback(pending), budget());
  };
  const forbidden = (status, header) => new Response(null, { status, headers: header === undefined ? {} : { 'www-authenticate': header } });
  /** Run the provider's challenge handling, as Hooks does, with the credential that was sent. */
  const challenge = (status, header, credential) => provider.challenge({ ...context, response: forbidden(status, header), credential });
  /** The transport's replay: the challenge header is carried on the context. */
  const replay = header => provider.credential({ ...context, challenged: true, challenge: header });
  return { oauth, provider, options, store, state, client, context, callback, scopeOf, login, challenge, replay };
}

/** Exact code, recovery and sorted scope array (undefined: the error carries none). */
function rejects(code, scopes) {
  return error => {
    assert.ok(error instanceof AuthError, `not an AuthError: ${error}`);
    assert.equal(error.code, code);
    assert.equal(error.recovery, { access_denied: 'none', interaction_required: 'login', invalid_configuration: 'configure' }[code] ?? error.recovery);
    assert.deepEqual(error.requiredScopes === undefined ? undefined : [...error.requiredScopes], scopes);
    return true;
  };
}

test('scope contract rule 1: preset scopes are requested, never required', async () => {
  const preset = { type: 'oauth', issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['deliver', 'extra'] };
  const f = fixture({ scopes: ['deliver', 'extra'], allowedScopes: ['audit', 'deliver', 'extra'], requiredScopes: [] });
  const context = { ...f.context, authentication: preset };
  const pending = await f.oauth.prepare(context, budget());
  assert.deepEqual(f.scopeOf(pending), ['deliver', 'extra'], 'preset scopes are requested');
  // The server grants less than the preset requested: R is empty, so the grant still satisfies.
  f.state.scope = 'deliver';
  const ready = await f.oauth.complete(f.callback(pending), budget());
  assert.equal(ready.type, 'ready');
  assert.deepEqual(f.store.grants()[0].scopes, ['deliver']);
  assert.equal((await f.provider.credential(context)).token, ready.credential.token);
  // A refusal names R only, never the preset scopes.
  await assert.rejects(f.oauth.prepare(context, budget(), { requiredScopes: ['admin'] }), rejects('access_denied', ['admin']));
  const stepUp = await f.oauth.prepare(context, budget(), { requiredScopes: ['audit'] });
  assert.equal(stepUp.type, 'pending_login');
  f.state.scope = 'deliver';
  await assert.rejects(f.oauth.complete(f.callback(stepUp), budget()), rejects('access_denied', ['audit']));
});

test('scope contract rule 2: every scoped error carries the full R, including challenge() and the legacy provider', async () => {
  const f = fixture();
  // challenge(): 403 step-up carries H ∪ Ch, not Ch alone.
  const header = 'Bearer error="insufficient_scope", scope="audit"';
  await assert.rejects(f.challenge(403, header, undefined), rejects('interaction_required', ['audit', 'deliver']));
  // The replayed credential() carries the same set.
  await assert.rejects(f.replay(header), rejects('interaction_required', ['audit', 'deliver']));
  // prepare: H ∪ E ∪ Ch, sorted, on a ceiling refusal.
  await assert.rejects(f.oauth.prepare({ ...f.context, challenge: 'Bearer error="insufficient_scope", scope="zeta"' }, budget(),
    { requiredScopes: ['admin'] }), rejects('access_denied', ['admin', 'deliver', 'zeta']));
  // Legacy auth(): refusals carry H ∪ Ch.
  const legacy = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'],
    selectClient: () => ({ issuer: 'https://identity.example.com', resource: 'https://hooks.example.com/api', clientId: 'client',
      flow: 'client_credentials', scopes: ['hooks'], allowedScopes: ['hooks', 'audit'], requiredScopes: ['hooks'] }),
    async fetch(input) {
      const target = String(input);
      if (target.includes('oauth-protected-resource')) return Response.json({ resource: 'https://hooks.example.com/api', authorization_servers: ['https://identity.example.com'] });
      if (target.includes('well-known')) return Response.json({ issuer: 'https://identity.example.com', token_endpoint: 'https://identity.example.com/token', grant_types_supported: ['client_credentials'] });
      return Response.json({ access_token: 'token-1', token_type: 'Bearer', expires_in: 3600, scope: 'hooks' });
    } });
  await assert.rejects(legacy.authenticate({ url: 'https://hooks.example.com/api/events', challenge: 'Bearer error="insufficient_scope", scope="admin"' }),
    rejects('access_denied', ['admin', 'hooks']));
  // Granted narrower than R: access_denied names R.
  await assert.rejects(legacy.authenticate({ url: 'https://hooks.example.com/api/events', challenge: 'Bearer error="insufficient_scope", scope="audit"' }),
    rejects('access_denied', ['audit', 'hooks']));
});

test('scope contract rule 3: a requirement outside the ceiling is refused locally, before any network I/O', async () => {
  const f = fixture();
  const ready = await f.login();
  f.state.network.length = 0;
  const header = 'Bearer error="insufficient_scope", scope="admin"';
  // Challenge with a cached binding: no protected-resource or issuer fetch.
  await assert.rejects(f.challenge(403, header, ready.credential), rejects('access_denied', ['admin', 'deliver']));
  assert.equal(f.state.network.length, 0);
  // Replayed credential and host prepare with a cached binding.
  await assert.rejects(f.replay(header), rejects('access_denied', ['admin', 'deliver']));
  await assert.rejects(f.oauth.prepare(f.context, budget(), { requiredScopes: ['admin'] }), rejects('access_denied', ['admin', 'deliver']));
  assert.equal(f.state.network.length, 0);
  assert.equal(f.store.pending().length, 0);
  // A host-required scope outside the ceiling is the same case, never invalid_configuration.
  const host = fixture({ requiredScopes: ['admin'] });
  const preset = { ...host.context, authentication: { type: 'oauth', issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['deliver'] } };
  await assert.rejects(host.oauth.prepare(preset, budget()), rejects('access_denied', ['admin']));
  await assert.rejects(host.provider.credential(preset), rejects('access_denied', ['admin']));
  assert.equal(host.state.network.length, 0);
  // Client credentials preset (proactive delivery path): refused before any token request.
  const cc = fixture({ flow: 'client_credentials', clientSecret: 'secret', requiredScopes: ['admin'] });
  const ccPreset = { ...cc.context, authentication: { type: 'oauth', issuer, resource, clientId: 'client', flow: 'client_credentials', scopes: ['deliver'] } };
  await assert.rejects(cc.provider.credential(ccPreset), rejects('access_denied', ['admin']));
  assert.equal(cc.state.network.length, 0);
  // Unbound and unknown: protected-resource metadata names the issuer whose client (and
  // ceiling) the host selects, so exactly that one fetch precedes the refusal.
  const fresh = fixture({ requiredScopes: ['admin'] });
  await assert.rejects(fresh.oauth.prepare(fresh.context, budget()), rejects('access_denied', ['admin']));
  assert.deepEqual(fresh.state.network, ['https://api.example/.well-known/oauth-protected-resource/events']);
  // On a 401 the rejected token is retired first, then the refusal is still local.
  const retired = fixture({ flow: 'client_credentials', clientSecret: 'secret', requiredScopes: [] });
  const sent = await retired.provider.credential({ ...retired.context, challenged: true });
  retired.client.requiredScopes = ['admin'];
  retired.state.network.length = 0;
  await assert.rejects(retired.challenge(401, `Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource"`, sent),
    rejects('access_denied', ['admin']));
  assert.equal(retired.store.grants()[0].token, undefined, 'the rejected token was retired');
  assert.equal(retired.store.grants()[0].refreshToken, 'refresh-1', 'refresh material is kept');
  assert.equal(retired.state.network.length, 0);
});

test('scope contract rule 4: requested scopes outside the ceiling are invalid_configuration', async () => {
  const f = fixture({ scopes: ['deliver', 'extra'], allowedScopes: ['deliver'] });
  await assert.rejects(f.oauth.prepare(f.context, budget()), rejects('invalid_configuration', undefined));
  await assert.rejects(f.replay('Bearer error="insufficient_scope", scope="deliver"'), rejects('invalid_configuration', undefined));
  // With a stored binding it is local policy: no rediscovery, no network I/O.
  const stored = fixture();
  await stored.login();
  stored.client.scopes = ['deliver', 'extra'];
  stored.state.network.length = 0;
  await assert.rejects(stored.oauth.prepare(stored.context, budget()), rejects('invalid_configuration', undefined));
  await assert.rejects(stored.provider.credential(stored.context), rejects('invalid_configuration', undefined));
  assert.equal(stored.state.network.length, 0);
  // A preset whose scopes differ from the selected client's requested scopes.
  const preset = fixture();
  await assert.rejects(preset.provider.credential({ ...preset.context, authentication: { type: 'oauth', issuer, resource, clientId: 'client',
    flow: 'authorization_code_pkce', scopes: ['files'] } }), rejects('invalid_configuration', undefined));
  assert.equal(preset.state.network.length, 0);
});

test('scope contract rule 5: a 401 scope is requested within the ceiling, never required', async () => {
  const f = fixture({ flow: 'client_credentials', clientSecret: 'secret', requiredScopes: [] });
  const first = await f.provider.credential({ ...f.context, challenged: true });
  assert.equal(first.token, 'access-1');
  // A 401 naming an in-ceiling and an out-of-ceiling scope: no access_denied; only audit is added.
  await f.challenge(401, 'Bearer error="invalid_token", scope="audit admin"', first);
  assert.deepEqual(f.state.tokenCalls.at(-1).get('scope').split(' ').sort(), ['audit', 'deliver']);
  // The replay is not refused, and even error="insufficient_scope" on a 401 adds no requirement.
  const replayed = await f.replay('Bearer error="invalid_token", scope="admin"');
  assert.equal(replayed.token, 'access-2');
  await f.challenge(401, 'Bearer error="insufficient_scope", scope="admin"', replayed);
  // PKCE: the 401 scope only widens the next sign-in, and R stays H.
  const p = fixture({ allowedScopes: ['audit', 'deliver'] });
  await assert.rejects(p.replay('Bearer scope="admin audit"'), rejects('interaction_required', ['deliver']));
  const pending = await p.oauth.prepare({ ...p.context, challenge: 'Bearer scope="admin audit"' }, budget());
  assert.deepEqual(p.scopeOf(pending), ['audit', 'deliver']);
  p.state.scope = 'deliver';
  assert.equal((await p.oauth.complete(p.callback(pending), budget())).type, 'ready', 'a hint is not a requirement');
});

test('scope contract rule 6: 403 insufficient_scope without scope uses H ∪ E, else access_denied with no scopes', async () => {
  const none = fixture({ requiredScopes: [] });
  await assert.rejects(none.challenge(403, 'Bearer error="insufficient_scope"', undefined), rejects('access_denied', undefined));
  await assert.rejects(none.replay('Bearer error="insufficient_scope"'), rejects('interaction_required', undefined));
  const host = fixture({ requiredScopes: ['deliver'] });
  await assert.rejects(host.challenge(403, 'Bearer error="insufficient_scope"', undefined), rejects('interaction_required', ['deliver']));
  // With explicit E on prepare, the login's R is H ∪ E.
  const pending = await host.oauth.prepare({ ...host.context, challenge: 'Bearer error="insufficient_scope"' }, budget(), { requiredScopes: ['audit'] });
  assert.deepEqual(host.scopeOf(pending), ['audit', 'deliver']);
  host.state.scope = 'deliver';
  await assert.rejects(host.oauth.complete(host.callback(pending), budget()), rejects('access_denied', ['audit', 'deliver']));
});

test('scope contract rule 7: a malformed challenge scope fails closed with access_denied and no scopes', async () => {
  const malformed = ['scope=""', 'scope="audit  deliver"', 'scope=" audit"', 'scope="audit "', 'scope="aud\\\\it"', 'scope="audit\tdeliver"',
    'scope="audit", scope="deliver"'];
  for (const parameter of malformed) {
    const f = fixture();
    const header = `Bearer error="insufficient_scope", ${parameter}`;
    await assert.rejects(f.challenge(403, header, undefined), rejects('access_denied', undefined), header);
    assert.equal(f.state.network.length, 0, header);
    await assert.rejects(f.oauth.prepare({ ...f.context, challenge: header }, budget()), rejects('access_denied', undefined), header);
  }
  // A 401: the token is retired first, then the malformed scope fails closed, with no I/O.
  for (const header of ['Bearer scope="read  write"', 'Bearer scope="deliver", scope="audit"']) {
    const f = fixture({ flow: 'client_credentials', clientSecret: 'secret' });
    const sent = await f.provider.credential({ ...f.context, challenged: true });
    f.state.network.length = 0;
    await assert.rejects(f.challenge(401, header, sent), rejects('access_denied', undefined), header);
    assert.equal(f.store.grants()[0].token, undefined, header);
    assert.equal(f.state.network.length, 0, header);
  }
  // Legacy provider: same strict grammar.
  const legacy = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'],
    selectClient: () => ({ issuer: 'https://identity.example.com', resource: 'https://hooks.example.com/api', clientId: 'client',
      flow: 'client_credentials', scopes: ['hooks'] }),
    async fetch() { return Response.json({ resource: 'https://hooks.example.com/api', authorization_servers: ['https://identity.example.com'] }); } });
  await assert.rejects(legacy.authenticate({ url: 'https://hooks.example.com/api/events', challenge: 'Bearer error="insufficient_scope", scope="hooks  hooks"' }),
    rejects('access_denied', undefined));
});

test('scope contract rule 8: insufficient_scope for scopes already granted is access_denied with R, no replay or login', async () => {
  const f = fixture();
  f.state.scope = 'audit deliver';
  const ready = await f.login({ requiredScopes: ['audit'] });
  const tokenCalls = f.state.tokenCalls.length;
  await assert.rejects(f.challenge(403, 'Bearer error="insufficient_scope", scope="audit"', ready.credential), rejects('access_denied', ['audit', 'deliver']));
  // No scope, but H is already granted.
  await assert.rejects(f.challenge(403, 'Bearer error="insufficient_scope"', ready.credential), rejects('access_denied', ['deliver']));
  assert.equal(f.state.tokenCalls.length, tokenCalls);
  assert.equal(f.store.pending().length, 0);
  // Client credentials: no reacquisition loop either.
  const cc = fixture({ flow: 'client_credentials', clientSecret: 'secret' });
  const sent = await cc.provider.credential({ ...cc.context, challenged: true });
  await assert.rejects(cc.challenge(403, 'Bearer error="insufficient_scope", scope="deliver"', sent), rejects('access_denied', ['deliver']));
  assert.equal(cc.state.tokenCalls.length, 1);
});

test('scope contract rule 9: complete() enforces the R stored on the pending login', async () => {
  const f = fixture();
  const pending = await f.oauth.prepare({ ...f.context, challenge: 'Bearer error="insufficient_scope", scope="audit"' }, budget());
  f.state.scope = 'deliver';
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), error => {
    rejects('access_denied', ['audit', 'deliver'])(error);
    assert.equal(error.loginEnded, true);
    return true;
  });
  assert.deepEqual(f.store.grants()[0].scopes, ['deliver'], 'the narrower grant is persisted');
  assert.equal(f.store.grants()[0].refreshToken, 'refresh-1');
  assert.equal(f.store.pending().length, 0);
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), rejects('interaction_required', undefined));
  // Narrowing the ceiling after prepare: effective grant = granted ∩ current ceiling.
  const narrowed = fixture();
  const login = await narrowed.oauth.prepare(narrowed.context, budget(), { requiredScopes: ['audit'] });
  narrowed.client.allowedScopes = ['deliver'];
  narrowed.state.scope = 'audit deliver';
  await assert.rejects(narrowed.oauth.complete(narrowed.callback(login), budget()), rejects('access_denied', ['audit', 'deliver']));
  // Even when the narrowed ceiling excludes a host-required scope, the login is still
  // claimed, the grant persisted, and the error carries the stored R.
  const hosted = fixture({ requiredScopes: ['audit', 'deliver'] });
  const hostedLogin = await hosted.oauth.prepare(hosted.context, budget());
  hosted.client.allowedScopes = ['deliver'];
  hosted.state.scope = 'audit deliver';
  await assert.rejects(hosted.oauth.complete(hosted.callback(hostedLogin), budget()), error => {
    rejects('access_denied', ['audit', 'deliver'])(error);
    assert.equal(error.loginEnded, true);
    return true;
  });
  assert.deepEqual(hosted.store.grants()[0].scopes, ['audit', 'deliver']);
});

test('scope contract rule 10: refresh and client-credentials grants narrower than R are access_denied, grant persisted', async () => {
  const f = fixture();
  f.state.scope = 'audit deliver';
  await f.login({ requiredScopes: ['audit'] });
  for (const [key, value] of f.store.values) if (value.kind === 'grant') f.store.values.set(key, { ...value, expiresAt: Date.now() - 1 });
  f.state.scope = 'deliver';
  await assert.rejects(f.oauth.prepare(f.context, budget(), { requiredScopes: ['audit'] }), rejects('access_denied', ['audit', 'deliver']));
  assert.equal(f.state.tokenCalls.at(-1).get('grant_type'), 'refresh_token');
  assert.deepEqual(f.store.grants()[0].scopes, ['deliver']);
  assert.equal(f.store.grants()[0].token, 'access-2');
  const cc = fixture({ flow: 'client_credentials', clientSecret: 'secret' });
  cc.state.scope = 'deliver';
  await assert.rejects(cc.oauth.prepare(cc.context, budget(), { requiredScopes: ['audit'] }), rejects('access_denied', ['audit', 'deliver']));
  assert.deepEqual(cc.store.grants()[0].scopes, ['deliver']);
});

test('scope contract rule 11: host-policy errors never carry scopes', async () => {
  const scopedHostError = code => new AuthError(code, ['host-secret-scope']);
  const selection = fixture({}, { selectClient: () => { throw scopedHostError('access_denied'); } });
  await assert.rejects(selection.oauth.prepare(selection.context, budget()), rejects('access_denied', undefined));
  await assert.rejects(selection.replay('Bearer error="insufficient_scope", scope="audit"'), rejects('access_denied', undefined));
  const destination = fixture({}, { checkDestination: () => { throw scopedHostError('interaction_required'); } });
  await assert.rejects(destination.oauth.prepare(destination.context, budget()), rejects('interaction_required', undefined));
  const loader = fixture();
  loader.store.load = async () => { throw scopedHostError('access_denied'); };
  await assert.rejects(loader.oauth.prepare(loader.context, budget()), rejects('access_denied', undefined));
  // A foreign SDK copy's AuthError-shaped error from host budget policy.
  const budgeted = fixture();
  const provider = budgeted.oauth.provider({ budget: () => { throw Object.assign(new Error('x'), { name: 'AuthError', code: 'access_denied', requiredScopes: ['x'] }); } });
  budgeted.store.values.set('placeholder', {});
  await assert.rejects(provider.challenge({ ...budgeted.context, response: new Response(null, { status: 401 }), credential: undefined }),
    rejects('access_denied', undefined));
});

test('scope contract rule 12: every complete() error carries loginEnded', async () => {
  const ended = (code, value) => error => { assert.equal(error.code, code); assert.equal(error.loginEnded, value); return true; };
  const f = fixture({}, { loginLifetimeMs: 600_000 });
  const pending = await f.oauth.prepare(f.context, budget());
  // Rejected before the claim: the login is still pending.
  await assert.rejects(f.oauth.complete(f.callback(pending, { iss: 'https://evil.example' }), budget()), ended('access_denied', false));
  const stray = new URL(f.callback(pending)); stray.pathname = '/other';
  await assert.rejects(f.oauth.complete(stray.href, budget()), ended('access_denied', false));
  await assert.rejects(f.oauth.complete(f.callback(pending), { signal: new AbortController().signal, deadline: Number.NaN }),
    ended('invalid_configuration', false));
  // A missing or duplicated code is rejected before the claim too.
  const noCode = new URL(f.callback(pending)); noCode.searchParams.delete('code');
  await assert.rejects(f.oauth.complete(noCode.href, budget()), ended('access_denied', false));
  await assert.rejects(f.oauth.complete(`${f.callback(pending)}&code=again`, budget()), ended('access_denied', false));
  await assert.rejects(f.oauth.complete(`${f.callback(pending)}#fragment`, budget()), ended('access_denied', false));
  assert.equal(f.store.pending().length, 0, 'process-owned logins are not in the store');
  // Unknown state, no state, unparseable callback: no such login.
  await assert.rejects(f.oauth.complete(f.callback({ state: 'unknown' }), budget()), ended('interaction_required', true));
  await assert.rejects(f.oauth.complete('https://app.example/callback?code=x', budget()), ended('interaction_required', true));
  await assert.rejects(f.oauth.complete('not a url', budget()), ended('access_denied', true));
  // Consent denied: consumed.
  const denied = await f.oauth.prepare(f.context, budget());
  await assert.rejects(f.oauth.complete(f.callback(denied, { error: 'access_denied', code: '' }), budget()), ended('access_denied', true));
  // The first login is still completable after the rejected callbacks; a second callback finds it ended.
  assert.equal((await f.oauth.complete(f.callback(pending), budget())).type, 'ready');
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), ended('interaction_required', true));
  // Expired.
  const short = fixture({}, { loginLifetimeMs: 1 });
  const expiring = await short.oauth.prepare(short.context, budget());
  await new Promise(resolve => setTimeout(resolve, 5));
  await assert.rejects(short.oauth.complete(short.callback(expiring), budget()), ended('interaction_required', true));
  // Codes and recovery are unchanged; the flag is additive.
  const error = await short.oauth.complete('not a url', budget()).catch(failure => failure);
  assert.equal(error.recovery, 'none');
  assert.equal(Object.hasOwn(new AuthError('access_denied'), 'loginEnded'), false);
});

/** The legacy auth() provider (Hooks' default) against an unbound CC target; `fetches` counts network requests. */
function legacyFixture({ grant } = {}) {
  const fetches = [], tokens = [];
  const provider = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'],
    selectClient: () => ({ issuer: 'https://identity.example.com', resource: 'https://hooks.example.com/api', clientId: 'client',
      flow: 'client_credentials', scopes: ['hooks'], allowedScopes: ['audit', 'hooks'], requiredScopes: ['hooks'] }),
    async fetch(input, init) {
      const target = String(input);
      fetches.push(target);
      if (target.includes('oauth-protected-resource')) return Response.json({ resource: 'https://hooks.example.com/api', authorization_servers: ['https://identity.example.com'] });
      if (target.includes('well-known')) return Response.json({ issuer: 'https://identity.example.com', token_endpoint: 'https://identity.example.com/token', grant_types_supported: ['client_credentials'] });
      const body = new URLSearchParams(String(init.body));
      tokens.push(body);
      return Response.json({ access_token: `token-${tokens.length}`, token_type: 'Bearer', expires_in: 3600, scope: grant ?? body.get('scope') });
    } });
  const url = 'https://hooks.example.com/api/events';
  return { provider, fetches, tokens, url };
}

test('scope contract rule 3 (legacy auth): a known client refuses R outside the ceiling before any network I/O', async () => {
  const f = legacyFixture();
  assert.equal((await f.provider.authenticate({ url: f.url, challenged: true })).token, 'token-1');
  const before = f.fetches.length;
  await assert.rejects(f.provider.authenticate({ url: f.url, challenge: 'Bearer error="insufficient_scope", scope="admin"' }),
    rejects('access_denied', ['admin', 'hooks']));
  assert.equal(f.fetches.length, before, 'no protected-resource, issuer or token request');
  // Unbound and unknown: only the protected-resource fetch that client selection needs.
  const fresh = legacyFixture();
  await assert.rejects(fresh.provider.authenticate({ url: fresh.url, challenge: 'Bearer error="insufficient_scope", scope="admin"' }),
    rejects('access_denied', ['admin', 'hooks']));
  assert.deepEqual(fresh.fetches, ['https://hooks.example.com/.well-known/oauth-protected-resource/api/events']);
});

test('scope contract unchanged (legacy auth): a step-up requirement is operation-scoped, a 401 scope only requested', async () => {
  // The server never grants audit: the step-up fails for that operation only.
  const f = legacyFixture({ grant: 'hooks' });
  await f.provider.authenticate({ url: f.url, challenged: true });
  await assert.rejects(f.provider.authenticate({ url: f.url, challenge: 'Bearer error="insufficient_scope", scope="audit"' }),
    rejects('access_denied', ['audit', 'hooks']));
  assert.deepEqual(f.tokens.at(-1).get('scope').split(' ').sort(), ['audit', 'hooks']);
  // A later operation without the challenge requires host-required scopes only.
  assert.equal((await f.provider.authenticate({ url: f.url })).token, 'token-2');
  // A 401 scope joins the next request's scopes (within the ceiling), never R or the cache.
  const g = legacyFixture({ grant: 'hooks' });
  assert.equal((await g.provider.authenticate({ url: g.url, challenge: 'Bearer error="invalid_token", scope="audit admin"' })).token, 'token-1');
  assert.deepEqual(g.tokens.at(-1).get('scope').split(' ').sort(), ['audit', 'hooks']);
  assert.equal((await g.provider.authenticate({ url: g.url, challenged: true })).token, 'token-2');
  assert.deepEqual(g.tokens.at(-1).get('scope').split(' '), ['hooks'], 'the 401 hint was not kept');
});
