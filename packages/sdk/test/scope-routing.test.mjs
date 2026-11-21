// Scope contract v2, sections 5 and 7: every entry point produces `decide`'s outcome, the
// transport routes challenges to the provider, a race uses the newer generation, an older
// pending record still completes, and host failures carry no scopes.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Hooks } from 'agenthooksprotocol/client';
import { managedOAuth } from '../dist/src/oauth/index.js';
import { auth, AuthError } from '../dist/src/client/auth.js';
import { observeDecisions } from '../dist/src/client/decision.js';

const budget = () => ({ signal: new AbortController().signal, deadline: Date.now() + 5000 });
const issuer = 'https://issuer.example', resource = 'https://api.example/events';
const input = () => ({ call: { id: 'call' }, path: 'native', tool: { name: 'test', origin: 'native', input: {} } });

function memoryStore() {
  const values = new Map(), locks = new Map();
  return {
    values, failLoad: undefined,
    grants: () => [...values].filter(([key]) => key.startsWith('ahp.oauth.grant:')).map(([, value]) => value),
    async load(key, signal) { signal.throwIfAborted(); if (this.failLoad?.(key)) throw new AuthError('access_denied', ['store-scope']); return structuredClone(values.get(key)); },
    async compareAndSet(key, expected, value) {
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
function managedWorld(client, extra = {}) {
  const store = memoryStore(), state = { tokens: [], n: 0, network: 0, fail: undefined };
  const options = { namespace: 'routing', store, persistPendingLogins: true,
    selectClient: () => structuredClone(client), checkDestination: () => {},
    async policyFetch(url, init) {
      state.network++;
      if (state.fail) return state.fail(url);
      if (url === `${issuer}/token`) {
        const body = new URLSearchParams(String(init.body)); state.tokens.push(body);
        const n = ++state.n;
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600, scope: body.get('scope') ?? '',
          ...(client.flow === 'client_credentials' ? {} : { refresh_token: `refresh-${n}` }) });
      }
      if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource, authorization_servers: [issuer] });
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'] });
    }, ...extra };
  const oauth = managedOAuth(options);
  return { store, state, client, oauth, provider: oauth.provider({ budget }), context: { backendId: 'backend', purpose: 'event', url: resource } };
}
const cc = (overrides = {}) => ({ issuer, resource, clientId: 'client', clientSecret: 'secret', flow: 'client_credentials',
  scopes: ['read'], allowedScopes: ['read', 'write'], requiredScopes: [], ...overrides });
/** Run an entry point while recording every decision it makes. */
async function decided(work) {
  const decisions = [];
  const stop = observeDecisions((decisionInput, decision) => decisions.push({ input: decisionInput, decision }));
  try { return { outcome: await work().then(value => ({ value }), error => ({ error })), decisions }; } finally { stop(); }
}
function failedLike(result, code, scopes) {
  assert.ok(result.decisions.length > 0, 'the entry point ran decide');
  const last = result.decisions.at(-1).decision.outcome;
  assert.equal(last.type, 'fail');
  assert.equal(result.outcome.error?.code, code);
  assert.equal(last.error.code, code);
  assert.deepEqual([...(result.outcome.error.requiredScopes ?? [])], scopes);
}

test('[entry-points-route-through-decide] every TS entry point produces decide\'s outcome', async () => {
  // H outside the ceiling: decide step 4 refuses with R on every path.
  const managed = managedWorld(cc());
  await managed.oauth.prepare(managed.context, budget());
  const sent = await managed.provider.credential(managed.context);
  managed.client.requiredScopes = ['admin'];
  const preset = { ...managed.context, authentication: { type: 'oauth', issuer, resource, clientId: 'client', flow: 'client_credentials', scopes: ['read'] } };
  const forbidden = new Response(null, { status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="write"' } });
  const entries = {
    'managedOAuth.prepare': () => managed.oauth.prepare(managed.context, budget()),
    'provider.credential (up-front lookup)': () => managed.provider.credential(managed.context),
    'provider.credential (preset delivery)': () => managed.provider.credential(preset),
    'provider.credential (challenged replay)': () => managed.provider.credential({ ...managed.context, challenged: true,
      challenge: 'Bearer error="insufficient_scope", scope="write"', challengeStatus: 403, rejectedCredential: sent }),
    'managedOAuth.challenge': () => managed.oauth.challenge({ ...managed.context, credential: sent, response: forbidden.clone() }, budget()),
    'provider.challenge': () => managed.provider.challenge({ ...managed.context, credential: sent, response: forbidden.clone() }),
  };
  for (const [name, entry] of Object.entries(entries)) {
    const result = await decided(entry);
    assert.ok(result.outcome.error, name);
    failedLike(result, 'access_denied', result.decisions.at(-1).decision.required);
    assert.ok(result.outcome.error.requiredScopes.includes('admin'), name);
  }
  // The legacy auth() provider: authenticate, credential and challenge.
  const legacyClient = { issuer: 'https://identity.example.com', resource: 'https://hooks.example.com/api', clientId: 'client',
    flow: 'client_credentials', scopes: ['hooks'], allowedScopes: ['hooks'], requiredScopes: ['hooks'] };
  const legacy = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'], selectClient: () => ({ ...legacyClient }),
    async fetch(url, init) {
      const target = String(url);
      if (target.includes('oauth-protected-resource')) return Response.json({ resource: legacyClient.resource, authorization_servers: [legacyClient.issuer] });
      if (target.includes('well-known')) return Response.json({ issuer: legacyClient.issuer, token_endpoint: `${legacyClient.issuer}/token`, grant_types_supported: ['client_credentials'] });
      return Response.json({ access_token: 'legacy-1', token_type: 'Bearer', expires_in: 3600, scope: new URLSearchParams(String(init.body)).get('scope') });
    } });
  const url = 'https://hooks.example.com/api/events', cache = new Map();
  const legacyContext = { backendId: 'legacy', purpose: 'event', url, cache };
  const first = await legacy.credential({ ...legacyContext, challenged: true });
  legacyClient.requiredScopes = ['admin'];
  const legacyEntries = {
    'auth().authenticate': () => legacy.authenticate({ url, cache, challenged: true }),
    'auth().credential': () => legacy.credential({ ...legacyContext, challenged: true }),
    'auth().challenge': () => legacy.challenge({ ...legacyContext, credential: first,
      response: new Response(null, { status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="hooks"' } }) }),
  };
  for (const [name, entry] of Object.entries(legacyEntries)) {
    const result = await decided(entry);
    assert.ok(result.outcome.error, name);
    failedLike(result, 'access_denied', [...result.decisions.at(-1).decision.required]);
  }
  // A malformed 403 and a 401 carrying error="insufficient_scope", through every challenge entry point.
  const managedTwo = managedWorld(cc());
  await managedTwo.oauth.prepare(managedTwo.context, budget());
  const credential = await managedTwo.provider.credential(managedTwo.context);
  const malformed = await decided(() => managedTwo.provider.challenge({ ...managedTwo.context, credential,
    response: new Response(null, { status: 403, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="read  write"' } }) }));
  failedLike(malformed, 'access_denied', []);
  const unauthorized = await decided(() => managedTwo.provider.challenge({ ...managedTwo.context, credential,
    response: new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="admin"' } }) }));
  assert.equal(unauthorized.outcome.error, undefined, 'a 401 never steps up');
  assert.deepEqual([...unauthorized.decisions.at(-1).decision.required], []);
});

/** A Hooks client over an injected fetch: the endpoint answers from `respond`. */
function hooksWith(provider, respond) {
  const deliveries = [];
  const hooks = new Hooks({ protocolVersion: 'draft', hooks: [{ id: 'routing.backend', transport: { type: 'http', url: resource },
    subscriptions: [{ mode: 'intercept', events: ['tool.before'], timeoutMs: 5000, failurePolicy: 'fail-closed', content: { default: 'metadata' } }] }] },
  { source: 'urn:test:scope-routing', harness: { name: 'test', version: '1' }, capabilities: { toolBefore: { intercept: { deny: true } } },
    auth: provider, async fetch(_url, init) {
      const message = JSON.parse(String(init.body));
      deliveries.push({ authorization: new Headers(init.headers).get('authorization'), message });
      const answer = respond(deliveries.length, deliveries.at(-1));
      if (answer) return answer;
      return Response.json({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: 'draft', effects: [] } });
    } });
  return { hooks, deliveries };
}
function spyProvider() {
  const calls = [];
  return { calls, credential: async () => ({ type: 'bearer', token: 'token' }), async challenge(context) {
    calls.push({ status: context.response.status, header: context.response.headers.get('www-authenticate') });
    if (context.response.status === 403 && /scope="[^"]*  /.test(context.response.headers.get('www-authenticate') ?? '')) throw new AuthError('access_denied');
  } };
}

test('[transport-challenge-routing] the transport hands every 401, and only a parseable Bearer insufficient_scope 403, to the provider', async () => {
  const cases = [
    { status: 401, header: 'Bearer error="invalid_token"', provider: true },
    { status: 401, header: 'Bearer scope="read", scope="write"', provider: true },
    { status: 403, header: 'Bearer error="insufficient_scope", scope="write"', provider: true },
    { status: 403, header: 'Bearer error="insufficient_scope", scope="read  write"', provider: true, failed: true },
    { status: 403, header: 'Bearer error="invalid_token"', provider: false },
    { status: 403, header: 'Bearer error="insufficient_scope", Bearer scope="x"', provider: false },
    { status: 403, header: undefined, provider: false },
  ];
  for (const item of cases) {
    const spy = spyProvider();
    const { hooks, deliveries } = hooksWith(spy, n => n === 1 ? new Response('{}', { status: item.status, headers: item.header ? { 'www-authenticate': item.header } : {} }) : undefined);
    try {
      const result = await hooks.dispatch('tool.before', input());
      const label = `${item.status} ${item.header}`;
      assert.equal(spy.calls.length > 0, item.provider, label);
      const diagnostics = result.diagnostics.filter(diagnostic => diagnostic.phase !== 'observation');
      if (!item.provider) assert.equal(deliveries.length, 1, `${label}: returned without a retry`);
      else if (item.failed) assert.equal(diagnostics[0]?.auth?.code, 'access_denied', label);
      else assert.equal(deliveries.length, 2, `${label}: replayed once`);
    } finally { await hooks.close(); }
  }
});

test('[replay-rejection-retires-token] a token rejected on the replay is handed to the provider, so a 401 retires it', async () => {
  const w = managedWorld(cc());
  w.context.backendId = 'routing.backend';
  await w.oauth.prepare(w.context, budget());
  const { hooks, deliveries } = hooksWith(w.provider, () => new Response('{}', { status: 401, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } }));
  try {
    await hooks.dispatch('tool.before', input());
    assert.equal(deliveries.length, 2, 'replayed once');
    assert.equal(deliveries[0].authorization, 'Bearer access-1');
    assert.equal(deliveries[1].authorization, 'Bearer access-2');
    // The replay's token was rejected too: the provider renewed it, so access-2 is never resent.
    assert.notEqual(w.store.grants()[0].token, 'access-2');
    assert.equal(w.state.tokens.length, 3);
  } finally { await hooks.close(); }
});

test('race: a newer stored generation than the one sent is used (decide step 5)', async () => {
  const w = managedWorld(cc({ scopes: ['read', 'write'] }));
  await w.oauth.prepare(w.context, budget());
  const sent = await w.provider.credential(w.context);
  // Another process stepped up meanwhile: a newer generation already covers R.
  await w.oauth.prepare(w.context, budget(), { forceRegistration: false });
  for (const [key, value] of w.store.values) if (value.kind === 'grant') w.store.values.set(key, { ...value, generation: 'newer', token: 'access-newer', scopes: ['read', 'write'] });
  const header = 'Bearer error="insufficient_scope", scope="write"';
  const tokens = w.state.tokens.length;
  await w.provider.challenge({ ...w.context, credential: sent, response: new Response(null, { status: 403, headers: { 'www-authenticate': header } }) });
  const replay = await w.provider.credential({ ...w.context, challenged: true, challenge: header, challengeStatus: 403, rejectedCredential: sent });
  assert.equal(replay.token, 'access-newer');
  assert.equal(w.state.tokens.length, tokens, 'no acquisition, no login');
  // The same generation covering R is the server disagreeing with our record: access_denied with R.
  const current = await w.provider.credential(w.context);
  await assert.rejects(w.provider.challenge({ ...w.context, credential: current, response: new Response(null, { status: 403, headers: { 'www-authenticate': header } }) }),
    error => error.code === 'access_denied' && error.requiredScopes.join() === 'write');
});

test('upgrade: a pending record without a stored R completes against its prepare-time H, else the current H', async () => {
  for (const [prepareTime, current, expected] of [[['write'], ['read'], ['write']], [undefined, ['write'], ['write']]]) {
    const pkce = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read', 'write'],
      requiredScopes: [], redirectUri: 'https://app.example/callback' };
    const w = managedWorld(pkce);
    const pending = await w.oauth.prepare(w.context, budget());
    const [key, record] = [...w.store.values].find(([name]) => name.startsWith('ahp.oauth.pending:'));
    const { requiredScopes: _stored, ...older } = record;
    const { requiredScopes: _host, ...client } = older.client;
    w.store.values.set(key, { ...older, client: prepareTime ? { ...client, requiredScopes: prepareTime } : client });
    w.client.requiredScopes = current;
    const callback = `https://app.example/callback?code=c&state=${pending.state}&iss=${encodeURIComponent(issuer)}`;
    await assert.rejects(w.oauth.complete(callback, budget()), error => {
      assert.equal(error.code, 'access_denied');
      assert.deepEqual([...error.requiredScopes], expected);
      assert.equal(error.loginEnded, true);
      return true;
    });
  }
});

test('host failures (store, network, callback and source) carry no scopes', async () => {
  // Store.
  const store = managedWorld(cc());
  store.store.failLoad = () => true;
  await assert.rejects(store.oauth.prepare(store.context, budget()), error => error.code === 'access_denied' && error.requiredScopes === undefined);
  // Network: a host policyFetch rejecting with a scoped error.
  const network = managedWorld(cc());
  network.state.fail = () => { throw new AuthError('interaction_required', ['network-scope']); };
  await assert.rejects(network.oauth.prepare(network.context, budget()), error => error.code === 'interaction_required' && error.requiredScopes === undefined);
  // Callback: client selection.
  const selection = managedWorld(cc(), { selectClient: () => { throw new AuthError('access_denied', ['selection-scope']); } });
  await assert.rejects(selection.oauth.prepare(selection.context, budget()), error => error.code === 'access_denied' && error.requiredScopes === undefined);
  // Callback: destination policy.
  const destination = managedWorld(cc(), { checkDestination: () => { throw new AuthError('access_denied', ['destination-scope']); } });
  await assert.rejects(destination.oauth.prepare(destination.context, budget()), error => error.code === 'access_denied' && error.requiredScopes === undefined);
  // Source: the client source is no longer permitted at completion.
  const pkce = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read'], requiredScopes: ['read'],
    redirectUri: 'https://app.example/callback' };
  const source = managedWorld(pkce);
  const pending = await source.oauth.prepare(source.context, budget());
  delete source.client.clientId; source.client.registration = { clientName: 'x' };
  await assert.rejects(source.oauth.complete(`https://app.example/callback?code=c&state=${pending.state}&iss=${encodeURIComponent(issuer)}`, budget()),
    error => error.code === 'invalid_configuration' && error.requiredScopes === undefined && error.loginEnded === false);
  // The legacy provider: a host selectClient error with scopes.
  const legacy = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'],
    selectClient: () => { throw new AuthError('access_denied', ['legacy-scope']); },
    async fetch() { return Response.json({ resource: 'https://hooks.example.com/api', authorization_servers: ['https://identity.example.com'] }); } });
  await assert.rejects(legacy.authenticate({ url: 'https://hooks.example.com/api/events', challenged: true }),
    error => error.code === 'access_denied' && error.requiredScopes === undefined);
  // loginEnded appears only on complete() errors.
  const other = await store.oauth.prepare(store.context, budget()).catch(error => error);
  assert.equal(Object.hasOwn(other, 'loginEnded'), false);
});

test('legacy auth(): configuration, challenge form and unreplayed failures come from decide', async () => {
  const make = overrides => {
    const client = { issuer: 'https://identity.example.com', resource: 'https://hooks.example.com/api', clientId: 'client',
      flow: 'client_credentials', scopes: ['hooks'], ...overrides };
    return auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'], selectClient: () => ({ ...client }),
      async fetch(url, init) {
        const target = String(url);
        if (target.includes('oauth-protected-resource')) return Response.json({ resource: client.resource, authorization_servers: [client.issuer] });
        if (target.includes('well-known')) return Response.json({ issuer: client.issuer, token_endpoint: `${client.issuer}/token`, grant_types_supported: ['client_credentials'] });
        return Response.json({ access_token: 'legacy-1', token_type: 'Bearer', expires_in: 3600, scope: new URLSearchParams(String(init.body)).get('scope') });
      } });
  };
  const url = 'https://hooks.example.com/api/events';
  // Step 1: S ⊄ C.
  await assert.rejects(make({ allowedScopes: [] }).authenticate({ url, challenged: true }), error => error.code === 'invalid_configuration');
  // Step 2: a duplicated scope parameter is access_denied, not discovery_failed.
  await assert.rejects(make({}).authenticate({ url, challenge: 'Bearer error="insufficient_scope", scope="a", scope="b"', challengeStatus: 403 }),
    error => error.code === 'access_denied' && error.requiredScopes === undefined);
  // challenge() decides with the known client: no scope and no H, or a malformed scope, fails even unreplayed.
  const provider = make({}), cache = new Map(), context = { backendId: 'legacy', purpose: 'event', url, cache };
  const credential = await provider.credential({ ...context, challenged: true });
  for (const header of ['Bearer error="insufficient_scope"', 'Bearer error="insufficient_scope", scope="hooks  hooks"']) {
    await assert.rejects(provider.challenge({ ...context, credential, response: new Response(null, { status: 403, headers: { 'www-authenticate': header } }) }),
      error => error.code === 'access_denied' && error.requiredScopes === undefined, header);
  }
});

test('complete(): a cancellation reason that cannot carry loginEnded is wrapped, keeping it as the cause', async () => {
  const pkce = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read'], requiredScopes: [],
    redirectUri: 'https://app.example/callback' };
  const w = managedWorld(pkce);
  const pending = await w.oauth.prepare(w.context, budget());
  const controller = new AbortController();
  controller.abort('caller gave up');
  const error = await w.oauth.complete(`https://app.example/callback?code=c&state=${pending.state}`, { signal: controller.signal, deadline: Date.now() + 1000 })
    .catch(failure => failure);
  assert.equal(error.name, 'AbortError');
  assert.equal(error.cause, 'caller gave up');
  assert.equal(error.loginEnded, false);
});

test('complete(): host policy runs before the claim for a consent denial too', async () => {
  const pkce = () => ({ issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read'],
    requiredScopes: [], redirectUri: 'https://app.example/callback' });
  const denial = pending => `https://app.example/callback?error=access_denied&state=${pending.state}&iss=${encodeURIComponent(issuer)}`;
  // A failing client selection keeps its code, carries no scopes and leaves the login pending.
  let failing = true;
  const client = pkce();
  const w = managedWorld(client, { selectClient: () => {
    if (failing) throw new AuthError('credential_unavailable', ['host-scope']);
    return structuredClone(client);
  } });
  failing = false;
  const pending = await w.oauth.prepare(w.context, budget());
  failing = true;
  await assert.rejects(w.oauth.complete(denial(pending), budget()), error =>
    error.code === 'credential_unavailable' && error.requiredScopes === undefined && error.loginEnded === false);
  failing = false;
  await assert.rejects(w.oauth.complete(denial(pending), budget()), error => error.code === 'access_denied' && error.loginEnded === true);
  // A client source no longer permitted: invalid_configuration, login pending.
  const source = managedWorld(pkce());
  const login = await source.oauth.prepare(source.context, budget());
  delete source.client.clientId; source.client.registration = { clientName: 'x' };
  await assert.rejects(source.oauth.complete(denial(login), budget()), error =>
    error.code === 'invalid_configuration' && error.requiredScopes === undefined && error.loginEnded === false);
  assert.equal([...source.store.values.keys()].filter(key => key.startsWith('ahp.oauth.pending:')).length, 1, 'the login is still pending');
});

test('decide: client credentials always reissue, even with a stored refresh token; PKCE refreshes', async () => {
  const { decide, parseChallenge } = await import('../dist/src/client/decision.js');
  const grant = { generation: 'g', granted: ['read'], tokenValid: false, refresh: true };
  const base = { op: 'credential', grant, challenge: parseChallenge(undefined, undefined) };
  assert.equal(decide({ ...base, config: { flow: 'client_credentials', requested: ['read'] } }).outcome.type, 'acquire');
  assert.equal(decide({ ...base, config: { flow: 'authorization_code_pkce', requested: ['read'] } }).outcome.type, 'refresh');
  // Through managedOAuth: an expired client-credentials grant holding a refresh token is reissued.
  const w = managedWorld(cc());
  await w.oauth.prepare(w.context, budget());
  for (const [key, value] of w.store.values) if (value.kind === 'grant') w.store.values.set(key, { ...value, expiresAt: Date.now() - 1, refreshToken: 'stray' });
  await w.provider.credential(w.context);
  assert.equal(w.state.tokens.at(-1).get('grant_type'), 'client_credentials');
});

test('complete(): loginEnded on a caller\'s abort reason stays configurable and writable', async () => {
  const pkce = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read'], requiredScopes: [],
    redirectUri: 'https://app.example/callback' };
  const w = managedWorld(pkce);
  const pending = await w.oauth.prepare(w.context, budget());
  const reason = new Error('caller gave up'), controller = new AbortController();
  controller.abort(reason);
  const callback = `https://app.example/callback?code=c&state=${pending.state}`;
  for (let i = 0; i < 2; i++) {
    const error = await w.oauth.complete(callback, { signal: controller.signal, deadline: Date.now() + 1000 }).catch(failure => failure);
    assert.equal(error, reason);
    assert.equal(error.loginEnded, false);
  }
  const descriptor = Object.getOwnPropertyDescriptor(reason, 'loginEnded');
  assert.equal(descriptor.configurable, true); assert.equal(descriptor.writable, true);
});

test('step 0: a 401 retires the rejected token before target, argument and budget checks', async () => {
  const setup = async () => {
    const w = managedWorld(cc());
    await w.oauth.prepare(w.context, budget());
    const sent = await w.provider.credential(w.context);
    return { w, sent };
  };
  const unauthorized = () => new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } });
  const retired = w => assert.equal(w.store.grants()[0].token, undefined, 'the rejected token was retired');
  // An unsupported binding on the challenge context.
  {
    const { w, sent } = await setup();
    await assert.rejects(w.oauth.challenge({ ...w.context, authentication: { type: 'magic' }, credential: sent, response: unauthorized() }, budget()));
    retired(w);
  }
  // An invalid prepare argument on a replayed 401 context.
  {
    const { w, sent } = await setup();
    await assert.rejects(w.oauth.prepare({ ...w.context, challenged: true, challengeStatus: 401, rejectedCredential: sent }, budget(), { requiredScopes: 'read' }),
      { code: 'invalid_configuration' });
    retired(w);
  }
  // A failing host budget on the provider's challenge and replay.
  for (const call of ['challenge', 'credential']) {
    const { w, sent } = await setup();
    const provider = w.oauth.provider({ budget() { throw new Error('no budget'); } });
    await assert.rejects(call === 'challenge'
      ? provider.challenge({ ...w.context, credential: sent, response: unauthorized() })
      : provider.credential({ ...w.context, challenged: true, challengeStatus: 401, rejectedCredential: sent }));
    retired(w);
  }
  // A malformed budget is not exhausted: the retirement still comes first.
  {
    const { w, sent } = await setup();
    await assert.rejects(w.oauth.challenge({ ...w.context, credential: sent, response: unauthorized() }, { signal: undefined, deadline: Number.NaN }),
      { code: 'invalid_configuration' });
    retired(w);
  }
  // Only an already aborted budget fails first.
  {
    const { w, sent } = await setup();
    const controller = new AbortController(); controller.abort();
    await assert.rejects(w.oauth.challenge({ ...w.context, credential: sent, response: unauthorized() }, { signal: controller.signal, deadline: Date.now() + 1000 }));
    assert.equal(w.store.grants()[0].token, 'access-1', 'an aborted caller retires nothing');
  }
});

test('complete(): the token-endpoint destination check runs before the claim, a consent denial included', async () => {
  const pkce = { issuer, resource, clientId: 'client', flow: 'authorization_code_pkce', scopes: ['read'], allowedScopes: ['read'], requiredScopes: [],
    redirectUri: 'https://app.example/callback' };
  for (const denial of [false, true]) {
    let refuse = false;
    const w = managedWorld(pkce, { checkDestination: (url, purpose) => {
      if (refuse && purpose === 'token') throw new AuthError('untrusted_destination', ['destination-scope']);
    } });
    const pending = await w.oauth.prepare(w.context, budget());
    const callback = denial
      ? `https://app.example/callback?error=access_denied&state=${pending.state}&iss=${encodeURIComponent(issuer)}`
      : `https://app.example/callback?code=c&state=${pending.state}&iss=${encodeURIComponent(issuer)}`;
    refuse = true;
    await assert.rejects(w.oauth.complete(callback, budget()), error =>
      error.code === 'untrusted_destination' && error.requiredScopes === undefined && error.loginEnded === false);
    assert.equal(w.state.tokens.length, 0, 'no token request');
    // The login is still pending: once policy allows it, the same callback completes it.
    refuse = false;
    if (denial) await assert.rejects(w.oauth.complete(callback, budget()), error => error.code === 'access_denied' && error.loginEnded === true);
    else assert.equal((await w.oauth.complete(callback, budget())).type, 'ready');
  }
});

/** A managed world whose stored binding has lost its persisted issuer metadata. */
async function withoutMetadata(client) {
  const w = managedWorld(client);
  await w.oauth.prepare(w.context, budget());
  for (const [key, value] of w.store.values) if (value.kind === 'binding') { const { metadata: _m, ...rest } = value; w.store.values.set(key, rest); }
  const binding = () => [...w.store.values.values()].find(value => value.kind === 'binding');
  return { w, binding };
}

test('a stored binding without issuer metadata decides use and local refusals with no request, and fetches it once for a renewal', async () => {
  // use: no network at all.
  {
    const { w } = await withoutMetadata(cc());
    w.state.network = 0;
    assert.equal((await w.provider.credential(w.context)).token, 'access-1');
    assert.equal(w.state.network, 0);
  }
  // Step 4 and step 5 refusals: no network.
  {
    const { w } = await withoutMetadata(cc({ scopes: ['read', 'write'] }));
    const sent = await w.provider.credential(w.context);
    w.state.network = 0;
    await assert.rejects(w.provider.challenge({ ...w.context, credential: sent, response: new Response(null, { status: 403,
      headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="write"' } }) }),
    error => error.code === 'access_denied' && error.requiredScopes.join() === 'write');
    w.client.requiredScopes = ['admin'];
    await assert.rejects(w.provider.credential(w.context), error => error.code === 'access_denied');
    assert.equal(w.state.network, 0);
  }
  // A challenge that renews fetches the issuer's metadata once and persists it.
  {
    const { w, binding } = await withoutMetadata(cc());
    const sent = await w.provider.credential(w.context);
    w.state.network = 0;
    await w.provider.challenge({ ...w.context, credential: sent, response: new Response(null, { status: 403,
      headers: { 'www-authenticate': 'Bearer error="insufficient_scope", scope="write"' } }) });
    // One issuer-metadata request, then the token request.
    assert.equal(w.state.network, 2);
    assert.ok(binding().metadata, 'the fetched metadata is persisted');
  }
  // A delivery lookup that renews persists the fetched metadata.
  {
    const { w, binding } = await withoutMetadata(cc());
    for (const [key, value] of w.store.values) if (value.kind === 'grant') w.store.values.set(key, { ...value, expiresAt: Date.now() - 1 });
    w.state.network = 0;
    assert.equal((await w.provider.credential(w.context)).token, 'access-2');
    assert.equal(w.state.network, 2);
    assert.ok(binding().metadata, 'the fetched metadata is persisted');
  }
});

test('the stale-metadata refetch keeps a host destination refusal\'s code', async () => {
  const w = managedWorld(cc());
  await w.oauth.prepare(w.context, budget());
  for (const [key, value] of w.store.values) if (value.kind === 'grant') w.store.values.set(key, { ...value, expiresAt: Date.now() - 1 });
  // The token endpoint is unreachable (provably unprocessed), so the issuer's metadata is refetched; the host refuses it.
  let refuse = false;
  const managed = managedOAuth({ namespace: 'routing', store: w.store, selectClient: () => structuredClone(w.client),
    checkDestination: (url, purpose) => { if (refuse && purpose === 'metadata') throw new AuthError('untrusted_destination', ['host-scope']); },
    async policyFetch(url, init) {
      if (url === `${issuer}/token`) { refuse = true; throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); }
      return Response.json({ issuer, token_endpoint: `${issuer}/token`, grant_types_supported: ['client_credentials'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'] });
    } });
  await assert.rejects(managed.provider({ budget }).credential(w.context),
    error => error.code === 'untrusted_destination' && error.requiredScopes === undefined);
});

test('a usable grant on a new target or a metadata-less binding is used with no authorization-server request', async () => {
  // Each case runs against a fresh world whose policyFetch records URLs.
  const world = client => {
    const store = managedWorld(client).store, urls = [];
    const oauth = managedOAuth({ namespace: 'routing', store, persistPendingLogins: true, selectClient: () => structuredClone(client), checkDestination: () => {},
      async policyFetch(url, init) {
        urls.push(url);
        if (url === `${issuer}/register`) {
          const body = JSON.parse(String(init.body));
          return Response.json({ client_id: `issued-${urls.length}`, client_secret: 'issued-secret', token_endpoint_auth_method: body.token_endpoint_auth_method }, { status: 201 });
        }
        if (url === `${issuer}/token`) return Response.json({ access_token: `access-${urls.length}`, token_type: 'Bearer', expires_in: 3600,
          scope: new URLSearchParams(String(init.body)).get('scope') ?? '' });
        if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource: url.includes('/uploads') ? `${resource.replace('/events', '/uploads')}` : resource, authorization_servers: [issuer] });
        return Response.json({ issuer, token_endpoint: `${issuer}/token`, registration_endpoint: `${issuer}/register`,
          grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['client_secret_basic'] });
      } });
    const issuerRequests = () => urls.filter(url => url.startsWith(issuer)).length;
    return { store, urls, oauth, issuerRequests, provider: oauth.provider({ budget }) };
  };
  const events = { backendId: 'backend', purpose: 'event', url: resource };
  const bindings = store => [...store.values.values()].filter(value => value.kind === 'binding');
  // 0. A host-assigned shared grant partition: a new, unbound upload binding uses the event grant.
  {
    const w = world(cc({ grantPartition: 'shared' }));
    await w.oauth.prepare(events, budget());
    const before = w.issuerRequests(), uploads = { ...events, purpose: 'upload' };
    assert.equal((await w.provider.credential({ ...uploads, challenged: true })).token, 'access-3');
    assert.equal(w.issuerRequests(), before, 'no authorization-server request');
    assert.equal(bindings(w.store).length, 2, 'the upload binding is stored');
    assert.ok(bindings(w.store).some(value => value.metadata === undefined), 'without the issuer metadata');
  }
  // 1. A lost binding record: the challenged replay uses the still-usable grant.
  {
    const w = world(cc());
    await w.oauth.prepare(events, budget());
    for (const [key, value] of w.store.values) if (value.kind === 'binding') w.store.values.delete(key);
    const before = w.issuerRequests();
    assert.equal((await w.provider.credential({ ...events, challenged: true })).token, 'access-3');
    assert.equal(w.issuerRequests(), before, 'no authorization-server request');
    assert.equal(bindings(w.store).length, 1, 'the binding is learned again');
    assert.equal(bindings(w.store)[0].metadata, undefined, 'without the issuer metadata');
  }
  // 2. prepare on a stored binding without metadata: use, no request at all.
  {
    const w = world(cc());
    await w.oauth.prepare(events, budget());
    for (const [key, value] of w.store.values) if (value.kind === 'binding') { const { metadata: _m, ...rest } = value; w.store.values.set(key, rest); }
    const before = w.urls.length;
    assert.equal((await w.oauth.prepare(events, budget())).credential.token, 'access-3');
    assert.equal(w.urls.length, before);
  }
  // 3. A forced client-credentials re-registration acquires, never serving the replaced client's token.
  {
    const dcr = { issuer, resource, flow: 'client_credentials', scopes: ['read'], allowedScopes: ['read'], requiredScopes: [], registration: { clientName: 'x' } };
    const secrets = new Map();
    const store = managedWorld(dcr).store, urls = [];
    const oauth = managedOAuth({ namespace: 'routing', store, selectClient: () => structuredClone(dcr), checkDestination: () => {},
      secrets: { async put(r, v) { secrets.set(r, v); }, async get(r) { return secrets.get(r); }, async delete(r) { secrets.delete(r); } },
      async policyFetch(url, init) {
        urls.push(url);
        if (url === `${issuer}/register`) return Response.json({ client_id: `issued-${urls.length}`, client_secret: 's', token_endpoint_auth_method: 'client_secret_basic' }, { status: 201 });
        if (url === `${issuer}/token`) return Response.json({ access_token: `access-${urls.length}`, token_type: 'Bearer', expires_in: 3600, scope: 'read' });
        if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource, authorization_servers: [issuer] });
        return Response.json({ issuer, token_endpoint: `${issuer}/token`, registration_endpoint: `${issuer}/register`,
          grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['client_secret_basic'] });
      } });
    const first = await oauth.prepare(events, budget());
    for (const [key, value] of store.values) if (value.kind === 'binding') { const { metadata: _m, ...rest } = value; store.values.set(key, rest); }
    const forced = await oauth.prepare(events, budget(), { forceRegistration: true });
    assert.notEqual(forced.credential.token, first.credential.token);
    assert.ok(urls.filter(url => url === `${issuer}/register`).length >= 2, 'registered anew');
  }
});
