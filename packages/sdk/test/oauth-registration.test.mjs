import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { clientIdentity, managedOAuth, registrationKey } from '../dist/src/oauth/index.js';
import { acceptRegistration, chooseSource, failureKey, registrationRequest } from '../dist/src/oauth/registration.js';

const vectors = JSON.parse(readFileSync(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url), 'utf8'));
const budget = (ms = 5000) => ({ signal: new AbortController().signal, deadline: Date.now() + ms });
const ISSUER = 'https://issuer.example', OTHER = 'https://other.example', RESOURCE = 'https://api.example/events';
const REDIRECT = 'http://127.0.0.1:8765/callback', CIMD = 'https://adapter.example/oauth/client.json';
const POLICY = { clientName: 'Example Adapter' };

// A store shared by every "process" (managedOAuth instance) in a test.
function memoryStore({ exclusive = () => true } = {}) {
  const values = new Map(), locks = new Map();
  return {
    values,
    of: prefix => [...values].filter(([key]) => key.startsWith(prefix)).map(([, value]) => value),
    async load(key, signal) { signal.throwIfAborted(); return structuredClone(values.get(key)); },
    async compareAndSet(key, expected, value, signal) {
      signal.throwIfAborted();
      await new Promise(resolve => setImmediate(resolve));
      if (values.get(key)?.generation !== expected) return false;
      if (value === undefined) values.delete(key); else values.set(key, structuredClone(value));
      return true;
    },
    async coordinate(key, signal, work) {
      if (!exclusive(key)) return work();
      const previous = locks.get(key) ?? Promise.resolve();
      let release;
      const next = new Promise(resolve => { release = resolve; });
      locks.set(key, next);
      try { await previous; signal.throwIfAborted(); return await work(); }
      finally { release(); if (locks.get(key) === next) locks.delete(key); }
    },
  };
}
function secretStore() {
  const values = new Map(), deleted = [];
  return {
    values, deleted,
    async put(reference, secret) { values.set(reference, secret); },
    async get(reference) { return values.get(reference); },
    async delete(reference) { deleted.push(reference); values.delete(reference); },
  };
}

/**
 * In-memory authorization servers and receiver; every network request is logged.
 * `client` is the host's selectClient result (no client_id by default: DCR).
 */
function fixture({ client: overrides = {}, metadata = {}, options: extra = {}, secrets = secretStore(), store = memoryStore() } = {}) {
  const state = {
    requests: [], registrations: [], tokenCalls: [], next: 0, clients: 0,
    metadata: { [ISSUER]: { ...metadata }, [OTHER]: {} },
    register: undefined, // (body, n) => Response
    expiresAt: undefined, // client_secret_expires_at for new registrations
    invalid: new Set(), // client ids the token endpoint rejects with invalid_client
  };
  const client = { issuer: ISSUER, resource: RESOURCE, flow: 'authorization_code_pkce', scopes: ['deliver'],
    redirectUri: REDIRECT, registration: POLICY, ...overrides };
  const context = { backendId: 'backend', purpose: 'event', url: RESOURCE };
  const destinations = [];
  const options = {
    namespace: 'account', store, ...(secrets ? { secrets } : {}),
    selectClient: (_issuers, _resource, ctx) => structuredClone(typeof client.select === 'function' ? client.select(ctx) : withoutSelect(client)),
    checkDestination: (url, purpose, operation) => { operation.signal.throwIfAborted(); destinations.push([url.href, purpose]); },
    async policyFetch(url, init, { purpose, operation }) {
      operation.signal.throwIfAborted();
      state.requests.push({ url, purpose, init });
      const origin = new URL(url).origin;
      if (url.endsWith('/register')) {
        const body = JSON.parse(init.body);
        const n = ++state.clients;
        state.registrations.push({ url, body, authorization: init.headers.Authorization, redirect: init.redirect });
        if (state.delay) await new Promise(resolve => setTimeout(resolve, state.delay));
        if (state.register) return state.register(body, n);
        const confidential = body.grant_types.includes('client_credentials');
        return Response.json({ client_id: `dcr-${n}`, ...(confidential ? { client_secret: `secret-${n}` } : {}),
          ...(state.expiresAt === undefined ? {} : { client_secret_expires_at: state.expiresAt }) }, { status: 201 });
      }
      if (url.endsWith('/token')) {
        const body = new URLSearchParams(String(init.body));
        const basic = init.headers instanceof Headers ? init.headers.get('authorization') : new Headers(init.headers).get('authorization');
        const id = basic?.startsWith('Basic ') ? decodeURIComponent(atob(basic.slice(6)).split(':')[0]) : body.get('client_id');
        const secret = basic?.startsWith('Basic ') ? decodeURIComponent(atob(basic.slice(6)).split(':')[1]) : body.get('client_secret');
        state.tokenCalls.push({ id, secret, body });
        if (state.invalid.has(id)) return Response.json({ error: 'invalid_client' }, { status: 401 });
        const n = ++state.next;
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600,
          ...(body.get('grant_type') === 'client_credentials' ? {} : { refresh_token: `refresh-${n}` }),
          scope: body.get('scope') ?? 'deliver' });
      }
      if (url.startsWith('https://api.example/.well-known/')) {
        return Response.json({ resource: RESOURCE, authorization_servers: [ISSUER, OTHER] });
      }
      const issuer = [ISSUER, OTHER].find(value => value === origin);
      if (!issuer) return new Response('', { status: 404 });
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        registration_endpoint: `${issuer}/register`, response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
        ...state.metadata[issuer] }, { headers: { 'content-type': 'application/json' } });
    },
    ...extra,
  };
  const oauth = managedOAuth(options);
  const provider = (instance = oauth) => instance.provider({ budget: () => budget() });
  // A callback arrives at the login's own redirect, named in its authorization URL.
  const callback = (pending, extra = {}) => {
    const url = new URL(new URL(pending.authorizationUrl).searchParams.get('redirect_uri'));
    url.search = new URLSearchParams({ code: 'code', state: new URL(pending.authorizationUrl).searchParams.get('state'), ...extra }).toString();
    return url.href;
  };
  const login = async (instance = oauth, ctx = context, prepareOptions) => {
    const pending = await instance.prepare({ ...ctx, challenged: true }, budget(), prepareOptions);
    return instance.complete(callback(pending), budget());
  };
  const expire = () => { for (const [key, value] of store.values) if (value.kind === 'grant') store.values.set(key, { ...value, expiresAt: Date.now() - 1 }); };
  const registrations = () => store.of('ahp.oauth.registration:');
  const grants = () => store.of('ahp.oauth.grant:');
  const markers = () => store.of('ahp.oauth.registration-failure:');
  const key = registrationKey('account', client.issuer);
  const patchRecord = patch => store.values.set(key, { ...store.values.get(key), ...patch });
  return { oauth, options, store, secrets, state, client, context, provider, callback, login, expire, registrations, grants, markers, key,
    patchRecord, destinations };
}
function withoutSelect({ select: _select, ...client }) { return client; }
const cc = (rest = {}) => ({ client: { flow: 'client_credentials', redirectUri: undefined, ...rest } });
const errorCode = code => error => { assert.equal(error.code, code); return true; };
const clientIdOf = pending => new URL(pending.authorizationUrl).searchParams.get('client_id');
const redirectOf = pending => new URL(pending.authorizationUrl).searchParams.get('redirect_uri');
/** Bind a real loopback listener on an ephemeral port, as MCP clients do per login. */
async function ephemeralRedirect() {
  const { createServer } = await import('node:http');
  const server = createServer((_request, response) => response.end());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { redirect: `http://127.0.0.1:${server.address().port}/callback`, close: () => new Promise(resolve => server.close(resolve)) };
}

// ---- Shared vectors ---------------------------------------------------------

test('registration key vectors frame namespace and exact issuer only', () => {
  for (const vector of vectors.registration_keys) {
    assert.equal(registrationKey(vector.input.namespace, vector.input.issuer), vector.registration_key, vector.id);
  }
});

test('client selection vectors', () => {
  for (const vector of vectors.client_selection) {
    const input = vector.input;
    const client = { issuer: ISSUER, resource: RESOURCE, flow: input.flow, scopes: [],
      ...(input.preregistered_client_id === null ? {} : { clientId: input.preregistered_client_id }),
      ...(input.redirect === null ? {} : { redirectUri: input.redirect }),
      ...(input.cimd ? { clientMetadataDocument: { url: input.cimd.url, redirectUris: input.cimd.redirect_uris } } : {}),
      ...(input.dcr_permitted ? { registration: POLICY } : {}) };
    if (vector.expect.error) {
      assert.throws(() => chooseSource(client, input.as_metadata, input.secret_hook), errorCode(vector.expect.error), vector.id);
      continue;
    }
    const choice = chooseSource(client, input.as_metadata, input.secret_hook);
    assert.equal(choice.source, vector.expect.source, vector.id);
    assert.equal(clientIdentity(choice), vector.expect.client_identity, vector.id);
    if (vector.expect.client_id) assert.equal(choice.clientId, vector.expect.client_id, vector.id);
    if (vector.expect.token_endpoint_auth_method) assert.equal(choice.method, vector.expect.token_endpoint_auth_method, vector.id);
  }
});

test('registration response vectors', () => {
  for (const vector of vectors.registration_responses) {
    const run = () => acceptRegistration(vector.flow, vector.request, vector.status, vector.response ?? undefined, vector.now);
    if (!vector.expect.accepted) { assert.throws(run, errorCode(vector.expect.error), vector.id); continue; }
    const accepted = run();
    assert.equal(accepted.clientId, vector.expect.record.client_id, vector.id);
    assert.equal(accepted.clientSecretExpiresAt ?? null, vector.expect.record.client_secret_expires_at, vector.id);
    assert.equal(accepted.clientSecret !== undefined, vector.expect.record.secret_ref, vector.id);
  }
  // The SDK builds the vectors' PKCE request for a loopback redirect.
  const pkce = vectors.registration_responses.find(vector => vector.id === 'pkce-minimal');
  assert.deepEqual(registrationRequest({ flow: 'authorization_code_pkce', redirectUri: REDIRECT, registration: POLICY }, 'none'), pkce.request);
  assert.equal(registrationRequest({ flow: 'authorization_code_pkce', redirectUri: 'https://app.example/cb', registration: POLICY }, 'none')
    .application_type, undefined, 'native only for a loopback redirect');
});

// ---- Selection order --------------------------------------------------------

test('[registration-order-preregistered-cimd-dcr] pre-registered, then CIMD, then permitted DCR, else credential_unavailable', async () => {
  const document = { url: CIMD, redirectUris: [REDIRECT] };
  const f = fixture({ client: { clientId: 'client', clientMetadataDocument: document }, metadata: { client_id_metadata_document_supported: true } });
  assert.equal(clientIdOf(await f.oauth.prepare(f.context, budget())), 'client');
  delete f.client.clientId;
  assert.equal(clientIdOf(await f.oauth.prepare({ ...f.context, purpose: 'upload' }, budget())), CIMD);
  f.state.metadata[ISSUER] = {};
  assert.equal(clientIdOf(await f.oauth.prepare({ ...f.context, backendId: 'third' }, budget())), 'dcr-1');
  assert.equal(f.state.registrations.length, 1);
  delete f.client.registration;
  await assert.rejects(f.oauth.prepare({ ...f.context, backendId: 'fourth' }, budget()), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 1);
});

test('[dcr-preregistered-wins] a pre-registered client beats CIMD and DCR and makes a recorded selection obsolete', async () => {
  const f = fixture(cc({ metadata: { client_id_metadata_document_supported: true } }));
  const provider = f.provider();
  assert.equal((await provider.credential({ ...f.context, challenged: true })).token, 'access-1');
  assert.equal(f.state.tokenCalls.at(-1).id, 'dcr-1');
  Object.assign(f.client, { clientId: 'pre', clientSecret: 'pre-secret' });
  // The lookup: another client identity is another grant key, so the DCR token is never presented under it.
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert.deepEqual(f.state.tokenCalls.map(call => call.id), ['dcr-1', 'pre']);
  assert.equal(f.state.registrations.length, 1);
  assert.deepEqual(f.store.of('ahp.oauth.binding:')[0].client, { source: 'preregistered', clientId: 'pre' });
  assert.equal(f.grants().length, 2);
});

// ---- CIMD -------------------------------------------------------------------

const cimd = (rest = {}) => ({ client: { registration: undefined, clientMetadataDocument: { url: CIMD, redirectUris: [REDIRECT, 'https://adapter.example/callback'] }, ...rest },
  metadata: { client_id_metadata_document_supported: true } });

test('[cimd-used-when-supported] the CIMD URL is the client_id; no secret, auth none and no registration record', async () => {
  const f = fixture(cimd({ clientSecret: 'never-sent' }));
  const ready = await f.login();
  assert.equal(ready.credential.token, 'access-1');
  const exchange = f.state.tokenCalls[0];
  assert.equal(exchange.id, CIMD);
  assert.equal(exchange.secret, null);
  assert.deepEqual(f.registrations(), []);
  assert.equal(f.secrets.values.size, 0);
  assert.equal(f.store.of('ahp.oauth.binding:')[0].client.source, 'cimd');
  assert.match(f.store.of('ahp.oauth.binding:')[0].grantKey, /:cimd:https:\/\/adapter\.example\/oauth\/client\.json/);
  assert.doesNotMatch(JSON.stringify([...f.store.values]), /never-sent/);
});

test('[cimd-not-supported-falls-back-to-dcr] absent or non-true support skips CIMD and uses permitted DCR', async () => {
  for (const supported of [undefined, 'true', 1]) {
    const f = fixture(cimd({ registration: POLICY }));
    f.state.metadata[ISSUER] = supported === undefined ? {} : { client_id_metadata_document_supported: supported };
    assert.equal(clientIdOf(await f.oauth.prepare(f.context, budget())), 'dcr-1');
    assert.equal(f.state.registrations[0].body.token_endpoint_auth_method, 'none');
  }
});

test('[cimd-redirect-mismatch-invalid-configuration] a redirect matching no declared entry fails before any login or registration', async () => {
  for (const redirectUri of ['http://127.0.0.1:8765/other', 'http://[::1]:8765/callback', 'https://adapter.example/other']) {
    const f = fixture(cimd({ registration: POLICY }));
    await assert.rejects(f.oauth.prepare(f.context, budget(), { redirectUri }), errorCode('invalid_configuration'), redirectUri);
    assert.deepEqual(f.store.of('ahp.oauth.pending:'), []);
    assert.equal(f.state.registrations.length, 0);
    assert.equal(f.state.requests.some(({ purpose }) => purpose === 'token'), false);
  }
});

test('[cimd-portless-loopback-redirect-matches] a declared loopback redirect matches any port; the exact redirect is sent; localhost never', async () => {
  for (const [declared, redirect] of [['http://127.0.0.1/callback', 'http://127.0.0.1:51004/callback'],
    ['http://127.0.0.1:8765/callback', 'http://127.0.0.1:51005/callback'], ['http://[::1]/callback', 'http://[::1]:51006/callback']]) {
    const f = fixture(cimd({ clientMetadataDocument: { url: CIMD, redirectUris: [declared] } }));
    const pending = await f.oauth.prepare(f.context, budget(), { redirectUri: redirect });
    assert.equal(clientIdOf(pending), CIMD);
    assert.equal(redirectOf(pending), redirect, 'the authorization request carries the port');
    await f.oauth.complete(f.callback(pending), budget());
    assert.equal(f.state.tokenCalls[0].body.get('redirect_uri'), redirect);
  }
  // Not a loopback match: userinfo, or https compared exactly.
  const userinfo = fixture(cimd({ clientMetadataDocument: { url: CIMD, redirectUris: ['http://127.0.0.1/callback'] } }));
  await assert.rejects(userinfo.oauth.prepare(userinfo.context, budget(), { redirectUri: 'http://user@127.0.0.1:51004/callback' }),
    errorCode('invalid_configuration'));
  // localhost is invalid_configuration even when declared, and for a pre-registered client, before any network.
  for (const client of [{ clientMetadataDocument: { url: CIMD, redirectUris: ['http://localhost:51004/callback'] } }, { clientId: 'client' }]) {
    const f = fixture(cimd(client));
    await assert.rejects(f.oauth.prepare(f.context, budget(), { redirectUri: 'http://localhost:51004/callback' }), errorCode('invalid_configuration'));
    assert.equal(f.state.registrations.length + f.state.tokenCalls.length, 0);
    assert.equal(f.destinations.some(([, purpose]) => purpose === 'authorization'), false);
  }
});

test('[cimd-portless-loopback-redirect-matches] a login with a prepare-only redirect leaves CIMD lookups and refreshes working', async () => {
  // The host configures no redirect: it binds a port per login and passes it to prepare only.
  const f = fixture(cimd({ redirectUri: undefined, clientMetadataDocument: { url: CIMD, redirectUris: ['http://127.0.0.1/callback'] } }));
  const pending = await f.oauth.prepare(f.context, budget(), { redirectUri: 'http://127.0.0.1:51010/callback' });
  await f.oauth.complete(f.callback(pending), budget());
  // The up-front lookup serves the token, and refreshes it once expired, without any redirect.
  assert.equal((await f.provider().credential(f.context)).token, 'access-1');
  f.expire();
  assert.equal((await f.provider().credential(f.context)).token, 'access-2');
  assert.equal((await f.provider(managedOAuth(f.options)).credential({ ...f.context, challenged: true })).token, 'access-2');
  assert.deepEqual(f.state.tokenCalls.map(call => [call.id, call.body.get('grant_type')]),
    [[CIMD, 'authorization_code'], [CIMD, 'refresh_token']]);
  // A login still needs a declared redirect.
  f.store.values.clear();
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('invalid_configuration'));
});

test('[cimd-never-fetched-by-sdk] no request targets the CIMD URL or anything derived from it', async () => {
  const f = fixture(cimd());
  await f.login();
  f.expire();
  await f.provider().credential(f.context);
  assert.ok(f.state.requests.length > 0);
  assert.ok(f.state.requests.every(({ url }) => !url.startsWith('https://adapter.example')));
  assert.ok(f.destinations.every(([url]) => !url.startsWith('https://adapter.example')));
});

test('[cimd-client-credentials-not-used] client credentials never use CIMD; they register with a secret method', async () => {
  const f = fixture({ ...cimd({ registration: POLICY, flow: 'client_credentials', redirectUri: undefined }) });
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  assert.equal(f.state.registrations[0].body.token_endpoint_auth_method, 'client_secret_basic');
  assert.deepEqual(f.state.tokenCalls.map(({ id, secret }) => [id, secret]), [['dcr-1', 'secret-1']]);
});

test('[cimd-invalid-client-no-dcr-fallback] invalid_client for a CIMD client is invalid_configuration, never DCR', async () => {
  const f = fixture(cimd({ registration: POLICY }));
  f.state.invalid.add(CIMD);
  const pending = await f.oauth.prepare(f.context, budget());
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), errorCode('invalid_configuration'));
  // The authorization endpoint reporting invalid_client is also misconfiguration.
  const again = await f.oauth.prepare(f.context, budget());
  await assert.rejects(f.oauth.complete(f.callback(again, { error: 'invalid_client', code: undefined }).replace('code=undefined&', ''), budget()),
    errorCode('invalid_configuration'));
  // A refresh rejected with invalid_client too.
  f.state.invalid.clear();
  await f.login();
  f.state.invalid.add(CIMD);
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('invalid_configuration'));
  assert.equal(f.state.registrations.length, 0);
});

// ---- DCR eligibility ----------------------------------------------------------

test('[dcr-policy-disallows-registration] an advertised registration_endpoint without host permission sends nothing', async () => {
  for (const flow of ['authorization_code_pkce', 'client_credentials']) {
    const f = fixture({ client: { registration: undefined, flow } });
    await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('credential_unavailable'));
    assert.equal(f.state.registrations.length, 0);
  }
});

test('[dcr-registration-endpoint-destination-policy] insecure, refused or redirecting registration endpoints are untrusted', async () => {
  const insecure = fixture({ metadata: { registration_endpoint: 'http://issuer.example/register' } });
  await assert.rejects(insecure.oauth.prepare(insecure.context, budget()), errorCode('untrusted_destination'));
  assert.equal(insecure.state.registrations.length, 0);
  const refused = fixture({ options: { checkDestination(url, purpose) { if (purpose === 'registration') throw new Error('no'); } } });
  await assert.rejects(refused.oauth.prepare(refused.context, budget()), errorCode('untrusted_destination'));
  assert.equal(refused.state.registrations.length, 0);
  const redirecting = fixture();
  redirecting.state.register = () => new Response(null, { status: 302, headers: { location: 'https://evil.example/register' } });
  await assert.rejects(redirecting.oauth.prepare(redirecting.context, budget()), errorCode('untrusted_destination'));
  assert.equal(redirecting.state.registrations.length, 1);
  assert.equal(redirecting.state.registrations[0].redirect, 'manual');
  assert.ok(redirecting.state.requests.every(({ url }) => !url.startsWith('https://evil.example')));
});

// ---- PKCE: DCR per login, as in MCP clients -------------------------------------

test('[dcr-pkce-registers-per-login] only host prepare registers, inside each login, with its exact redirect and application_type native', async () => {
  const f = fixture();
  // Delivery, challenge handling and the lookup never register a PKCE client.
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('interaction_required'));
  await f.oauth.challenge({ ...f.context, response: new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } }), credential: undefined }, budget());
  await assert.rejects(f.provider().credential(f.context), errorCode('interaction_required'));
  assert.equal(f.state.registrations.length, 0);
  // Each login registers anew, with its own redirect, and is authorized with its own client.
  const first = await f.oauth.prepare(f.context, budget(), { redirectUri: 'http://127.0.0.1:50001/callback' });
  const second = await f.oauth.prepare(f.context, budget(), { redirectUri: 'https://app.example/callback' });
  assert.deepEqual(f.state.registrations.map(({ body }) => [body.redirect_uris, body.application_type]),
    [[['http://127.0.0.1:50001/callback'], 'native'], [['https://app.example/callback'], undefined]]);
  assert.deepEqual([clientIdOf(first), clientIdOf(second)], ['dcr-1', 'dcr-2']);
  assert.deepEqual(f.registrations(), [], 'no registration record for PKCE');
  // Each callback completes only its own login, with its own client.
  await f.oauth.complete(f.callback(second), budget());
  await f.oauth.complete(f.callback(first), budget());
  assert.deepEqual(f.state.tokenCalls.map(call => call.id), ['dcr-2', 'dcr-1']);
  assert.equal(f.state.registrations.length, 2);
});

test('[dcr-issued-client-stored-with-grant] completion commits the issued client with the tokens under the dcr identity; refresh uses it', async () => {
  const f = fixture();
  await f.login();
  const [grant] = f.grants();
  assert.deepEqual([grant.clientId, grant.token, grant.refreshToken], ['dcr-1', 'access-1', 'refresh-1']);
  const [key] = [...f.store.values.keys()].filter(key => key.startsWith('ahp.oauth.grant:'));
  assert.match(key, /3:dcr23:authorization_code_pkce/);
  assert.doesNotMatch(key, /dcr-1/, 'an issued client_id never enters the grant key');
  assert.deepEqual(f.store.of('ahp.oauth.binding:')[0].client, { source: 'dcr' });
  // A re-registered client replaces the stored one under the same key (here after the tokens were dropped).
  f.store.values.set(key, { ...f.store.values.get(key), token: undefined, refreshToken: undefined });
  await f.login();
  assert.equal(f.grants().length, 1);
  assert.deepEqual([f.grants()[0].clientId, f.grants()[0].token], ['dcr-2', 'access-2']);
  assert.equal(f.store.values.get(key).clientId, 'dcr-2');
  // Refresh presents the stored client and keeps it with the rotated tokens.
  f.expire();
  assert.equal((await f.provider().credential(f.context)).token, 'access-3');
  assert.deepEqual([f.state.tokenCalls.at(-1).id, f.state.tokenCalls.at(-1).body.get('refresh_token')], ['dcr-2', 'refresh-2']);
  assert.deepEqual([f.grants()[0].clientId, f.grants()[0].refreshToken], ['dcr-2', 'refresh-3']);
  // A grant without its client cannot refresh: the next login is needed.
  f.store.values.set(key, { ...f.store.values.get(key), clientId: undefined });
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('interaction_required'));
  assert.equal(f.state.tokenCalls.length, 3);
});

test('[dcr-pkce-invalid-client-drops-grant] invalid_client ends only its login at completion; at refresh it compare-and-deletes the matching grant', async () => {
  const f = fixture({ client: { allowedScopes: ['deliver', 'audit'] } });
  await f.login();
  const before = f.grants()[0];
  // Completion of a step-up login: its client is rejected. The stored grant (an older valid client) is kept.
  const pending = await f.oauth.prepare(f.context, budget(), { requiredScopes: ['audit'] });
  f.state.invalid.add(clientIdOf(pending));
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), errorCode('interaction_required'));
  assert.deepEqual(f.grants(), [before]);
  await assert.rejects(f.oauth.complete(f.callback(pending), budget()), errorCode('interaction_required'), 'that login has ended');
  // Refresh: a rejected stored client deletes the grant it was presented for.
  f.state.invalid.add('dcr-1');
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('interaction_required'));
  assert.deepEqual(f.grants(), []);
  assert.equal(f.state.registrations.length, 2, 'no registration outside prepare');
  // A newer grant (another client or refresh token) written meanwhile is kept.
  const g = fixture();
  await g.login();
  const [key] = [...g.store.values.keys()].filter(key => key.startsWith('ahp.oauth.grant:'));
  g.state.invalid.add('dcr-1');
  g.expire();
  const fetch = g.options.policyFetch;
  const racing = managedOAuth({ ...g.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (url.endsWith('/token')) g.store.values.set(key, { ...g.store.values.get(key), generation: 'newer', clientId: 'dcr-9', refreshToken: 'refresh-9' });
    return response;
  } });
  await assert.rejects(g.provider(racing).credential(g.context), errorCode('interaction_required'));
  assert.deepEqual([g.grants()[0].clientId, g.grants()[0].refreshToken], ['dcr-9', 'refresh-9']);
  // Same client but a rotated refresh token is newer too.
  g.state.invalid.add('dcr-9');
  const rotating = managedOAuth({ ...g.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (url.endsWith('/token')) g.store.values.set(key, { ...g.store.values.get(key), generation: 'newest', refreshToken: 'refresh-10' });
    return response;
  } });
  g.store.values.set(key, { ...g.store.values.get(key), expiresAt: Date.now() - 1 });
  await assert.rejects(g.provider(rotating).credential(g.context), errorCode('interaction_required'));
  assert.equal(g.grants()[0].refreshToken, 'refresh-10');
  // Same refresh token but another client (a newer login's) is kept too.
  g.state.invalid.add('dcr-11');
  const reclient = managedOAuth({ ...g.options, async policyFetch(url, init, context) {
    const response = await fetch(url, init, context);
    if (url.endsWith('/token')) g.store.values.set(key, { ...g.store.values.get(key), generation: 'reclient', clientId: 'dcr-12' });
    return response;
  } });
  g.store.values.set(key, { ...g.store.values.get(key), clientId: 'dcr-11', expiresAt: Date.now() - 1 });
  await assert.rejects(g.provider(reclient).credential(g.context), errorCode('interaction_required'));
  assert.deepEqual([g.grants()[0].clientId, g.grants()[0].refreshToken], ['dcr-12', 'refresh-10']);
});

test('[loopback-redirect-ephemeral-port-per-login] each login binds its own port; authorization, DCR, token and callback use it exactly', async () => {
  const f = fixture();
  const listeners = [await ephemeralRedirect(), await ephemeralRedirect()];
  try {
    const [a, b] = listeners.map(listener => listener.redirect);
    assert.notEqual(a, b);
    const first = await f.oauth.prepare(f.context, budget(), { redirectUri: a });
    const second = await f.oauth.prepare(f.context, budget(), { redirectUri: b });
    assert.deepEqual([redirectOf(first), redirectOf(second)], [a, b]);
    assert.deepEqual(f.state.registrations.map(({ body }) => body.redirect_uris), [[a], [b]]);
    // A callback on another port is not this login's redirect, and consumes nothing.
    const moved = new URL(f.callback(first)); moved.port = new URL(b).port;
    await assert.rejects(f.oauth.complete(moved.href, budget()), errorCode('access_denied'));
    await f.oauth.complete(f.callback(first), budget());
    await f.oauth.complete(f.callback(second), budget());
    assert.deepEqual(f.state.tokenCalls.map(call => call.body.get('redirect_uri')), [a, b]);
  } finally { await Promise.all(listeners.map(listener => listener.close())); }
});

test('[lookup-never-registers-pkce] the up-front lookup never registers PKCE; client credentials may', async () => {
  const f = fixture();
  await f.login();
  for (const key of [...f.store.values.keys()]) if (key.startsWith('ahp.oauth.grant:')) f.store.values.delete(key);
  await assert.rejects(f.provider().credential(f.context), errorCode('interaction_required'));
  assert.equal(f.state.registrations.length, 1);
  const c = fixture(cc());
  await c.oauth.prepare(c.context, budget());
  c.store.values.delete(c.key);
  c.expire();
  assert.equal((await c.provider().credential(c.context)).token, 'access-2');
  assert.equal(c.state.registrations.length, 2);
});

test('[dcr-metadata-change-keeps-selection] new CIMD support or a removed registration_endpoint keeps the recorded client', async () => {
  const f = fixture({ client: { clientMetadataDocument: { url: CIMD, redirectUris: [REDIRECT] } } });
  await f.login();
  f.state.metadata[ISSUER] = { client_id_metadata_document_supported: true, registration_endpoint: undefined };
  f.expire();
  // Host prepare rediscovers metadata and refreshes with the grant's DCR client.
  assert.equal((await f.oauth.prepare({ ...f.context, challenged: true }, budget())).credential.token, 'access-2');
  assert.equal(f.state.tokenCalls.at(-1).id, 'dcr-1');
  const [binding] = f.store.of('ahp.oauth.binding:');
  assert.equal(binding.metadata.client_id_metadata_document_supported, true);
  assert.deepEqual(binding.client, { source: 'dcr' });
  assert.equal(f.state.registrations.length, 1);
});

test('[dcr-response-validation-invalid-configuration] an invalid 2xx registration persists nothing and is not retried', async () => {
  for (const response of [{ client_id: 'dcr', redirect_uris: ['https://evil.example/cb'] }, { client_id: 'dcr', redirect_uris: ['http://127.0.0.1:9999/callback'] },
    { client_id: 'dcr', token_endpoint_auth_method: 'client_secret_basic' }]) {
    const f = fixture();
    f.state.register = () => Response.json(response, { status: 201 });
    await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('invalid_configuration'));
    assert.equal(f.state.registrations.length, 1);
    assert.equal(f.store.values.size, 1, 'only the binding');
    assert.equal(f.secrets.values.size, 0);
    assert.equal(f.destinations.some(([, purpose]) => purpose === 'authorization'), false, 'no login');
  }
  // A PKCE secret is ignored, never persisted.
  const f = fixture();
  f.state.register = () => Response.json({ client_id: 'dcr-public', client_secret: 'pkce-secret', client_secret_expires_at: 1 }, { status: 201 });
  await f.login();
  assert.equal(f.state.tokenCalls[0].secret, null);
  assert.equal(f.secrets.values.size, 0);
  assert.doesNotMatch(JSON.stringify([...f.store.values]), /pkce-secret/);
});

// ---- Client credentials: one persisted registration -----------------------------

test('[dcr-registers-once-across-processes] concurrent processes register once; a losing compare-and-set uses the winner', async () => {
  const f = fixture(cc());
  const results = await Promise.all(Array.from({ length: 4 }, () => f.provider(managedOAuth(f.options)).credential({ ...f.context, challenged: true })));
  assert.equal(f.state.registrations.length, 1);
  assert.ok(results.every(result => result.token.startsWith('access-')));
  // Without serialization both register; the loser deletes only its own fresh secret reference.
  const racing = fixture({ ...cc(), store: memoryStore({ exclusive: key => !key.startsWith('ahp.oauth.registration:') }) });
  racing.state.delay = 20;
  const [a, b] = [managedOAuth(racing.options), managedOAuth(racing.options)];
  await Promise.all([a.prepare(racing.context, budget()), b.prepare(racing.context, budget())]);
  assert.equal(racing.state.registrations.length, 2);
  const [record] = racing.registrations();
  assert.deepEqual([...racing.secrets.values.keys()], [record.secretRef]);
  assert.equal(racing.secrets.deleted.length, 1);
  assert.notEqual(racing.secrets.deleted[0], record.secretRef);
  assert.ok(racing.state.tokenCalls.every(call => call.id === record.clientId), 'both processes use the winning record');
});

test('[dcr-registration-reused-across-grants] every client-credentials grant in the namespace at the issuer reuses one registration', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  await f.oauth.prepare({ ...f.context, purpose: 'upload' }, budget());
  f.client.grantPartition = 'shared';
  await f.oauth.prepare({ ...f.context, backendId: 'other' }, budget());
  assert.equal(f.state.registrations.length, 1);
  assert.equal(f.grants().length, 3);
  assert.ok(f.state.tokenCalls.every(call => call.id === 'dcr-1'));
  const [record] = f.registrations();
  assert.deepEqual(Object.keys(record).sort(), ['clientId', 'generation', 'kind', 'secretRef', 'tokenEndpointAuthMethod']);
  assert.equal(record.tokenEndpointAuthMethod, 'client_secret_basic');
});

test('client credentials authenticate with the registered method even when metadata changes', async () => {
  const f = fixture(cc());
  f.state.metadata[ISSUER] = { token_endpoint_auth_methods_supported: ['client_secret_post'] };
  await f.oauth.prepare(f.context, budget());
  assert.equal(f.registrations()[0].tokenEndpointAuthMethod, 'client_secret_post');
  f.state.metadata[ISSUER] = { token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'] };
  f.expire();
  await f.oauth.prepare({ ...f.context, challenged: true }, budget());
  assert.ok(f.state.tokenCalls.every(call => call.body.get('client_secret') === 'secret-1'), 'client_secret_post both times');
});

test('[dcr-expired-secret-reregisters] an expired or unresolvable secret re-registers before any token request, including in the lookup', async () => {
  for (const breakIt of ['expired', 'unresolvable']) {
    const f = fixture(cc());
    await f.oauth.prepare(f.context, budget());
    const [old] = f.registrations();
    if (breakIt === 'expired') f.patchRecord({ clientSecretExpiresAt: Math.floor(Date.now() / 1000) - 1 });
    else f.secrets.values.delete(old.secretRef);
    f.expire();
    const before = f.state.requests.length;
    assert.equal((await f.provider().credential(f.context)).token, 'access-2', breakIt);
    assert.deepEqual(f.state.requests.slice(before).map(({ purpose }) => purpose), ['registration', 'token'], breakIt);
    assert.equal(f.state.tokenCalls.at(-1).id, 'dcr-2');
  }
});

test('[dcr-invalid-client-reregisters-once] invalid_client deletes the registration; client credentials replace it once', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  f.state.invalid.add('dcr-1');
  f.expire();
  const metadata = f.state.requests.filter(({ purpose }) => purpose === 'metadata').length;
  assert.equal((await f.provider().credential(f.context)).token, 'access-2');
  assert.deepEqual(f.state.tokenCalls.map(call => call.id), ['dcr-1', 'dcr-1', 'dcr-2']);
  assert.equal(f.state.requests.filter(({ purpose }) => purpose === 'metadata').length, metadata, 'no metadata refetch');
  assert.equal(f.grants().length, 1, 'the grant key does not move');
  // The replacement is rejected too: at most one re-registration, then credential_unavailable.
  f.state.invalid.add('dcr-2').add('dcr-3');
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 3);
  assert.deepEqual(f.registrations(), []);
  // The repeat counts as a failed registration: no re-registration on every operation until the backoff passes.
  const [marker] = f.markers();
  assert.deepEqual([marker.attempts, marker.code], [1, 'credential_unavailable']);
  for (const instance of [f.oauth, managedOAuth(f.options)]) {
    await assert.rejects(f.provider(instance).credential(f.context), errorCode('credential_unavailable'));
  }
  assert.equal(f.state.registrations.length, 3);
});

test('[dcr-secret-not-in-token-record] the client secret is written only through the secret hook', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  const [record] = f.registrations();
  assert.match(record.secretRef, /^[0-9a-f-]{36}$/);
  assert.deepEqual([...f.secrets.values], [[record.secretRef, 'secret-1']]);
  assert.doesNotMatch(JSON.stringify([...f.store.values]), /secret-1/);
  f.state.invalid.add('dcr-1').add('dcr-2');
  f.expire();
  const error = await f.provider().credential(f.context).catch(error => error);
  assert.equal(error.code, 'credential_unavailable');
  assert.doesNotMatch(JSON.stringify([...f.store.values]) + JSON.stringify(error) + String(error.message), /secret-[0-9]/);
  // Both rejected registrations are compare-and-deleted with their secrets.
  assert.equal(f.secrets.values.size, 0);
  assert.equal(f.secrets.deleted.length, 2);
  // A persisted PKCE pending login never holds a secret either.
  const p = fixture({ client: { clientId: 'client', clientSecret: 'host-secret' }, options: { persistPendingLogins: true } });
  await p.oauth.prepare(p.context, budget());
  assert.equal(p.store.of('ahp.oauth.pending:').length, 1);
  assert.doesNotMatch(JSON.stringify([...p.store.values]), /host-secret/);
});

test('[dcr-no-secret-hook-no-confidential-registration] without a secret hook client credentials never register; PKCE does', async () => {
  const f = fixture({ ...cc(), secrets: null });
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 0);
  const p = fixture({ secrets: null });
  assert.equal(clientIdOf(await p.oauth.prepare(p.context, budget())), 'dcr-1');
});

test('[dcr-management-fields-not-persisted] registration_access_token and registration_client_uri are ignored', async () => {
  const f = fixture(cc());
  f.state.register = (_body, n) => Response.json({ client_id: `dcr-${n}`, client_secret: 'secret', registration_access_token: 'rat-value',
    registration_client_uri: 'https://issuer.example/register/dcr-1' }, { status: 201 });
  await f.oauth.prepare(f.context, budget());
  f.expire();
  await f.provider().credential(f.context);
  assert.doesNotMatch(JSON.stringify([...f.store.values]) + JSON.stringify([...f.secrets.values]), /rat-value|register\/dcr-1/);
  assert.ok(f.state.requests.every(({ url }) => url !== 'https://issuer.example/register/dcr-1'));
});

test('[dcr-initial-access-token-scoped] an initial access token goes only to its own issuer and is never persisted', async () => {
  const f = fixture(cc());
  f.secrets.values.set('vault:iat', 'iat-value');
  f.client.select = ctx => ({ ...withoutSelect(f.client), ...(ctx.backendId === 'other'
    ? { issuer: OTHER, registration: POLICY } : { registration: { ...POLICY, initialAccessTokenRef: 'vault:iat' } }) });
  await f.oauth.prepare(f.context, budget());
  await f.oauth.prepare({ ...f.context, backendId: 'other' }, budget());
  assert.deepEqual(f.state.registrations.map(({ url, authorization }) => [url, authorization]),
    [[`${ISSUER}/register`, 'Bearer iat-value'], [`${OTHER}/register`, undefined]]);
  assert.doesNotMatch(JSON.stringify([...f.store.values]), /iat-value/);
  // An unresolvable reference sends no request.
  const p = fixture({ client: { registration: { ...POLICY, initialAccessTokenRef: 'vault:missing' } } });
  await assert.rejects(p.oauth.prepare(p.context, budget()), errorCode('credential_unavailable'));
  assert.equal(p.state.registrations.length, 0);
});

test('[dcr-replaced-secret-deleted] a replaced record\'s secret is deleted after the compare-and-set, and only that one', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  const [old] = f.registrations();
  f.patchRecord({ clientSecretExpiresAt: 1 });
  f.expire();
  await f.provider().credential(f.context);
  const [current] = f.registrations();
  assert.deepEqual(f.secrets.deleted, [old.secretRef]);
  assert.deepEqual([...f.secrets.values.keys()], [current.secretRef]);
  // A losing compare-and-set keeps the old record's secret and deletes its own.
  const store = memoryStore();
  const losing = fixture({ ...cc(), store });
  await losing.oauth.prepare(losing.context, budget());
  const [kept] = losing.registrations();
  losing.patchRecord({ clientSecretExpiresAt: 1 });
  const compareAndSet = store.compareAndSet;
  store.compareAndSet = async (key, expected, value, signal) => {
    if (value?.kind === 'registration') { store.values.set(key, { ...store.values.get(key), generation: 'concurrent', clientSecretExpiresAt: 0 }); return false; }
    return compareAndSet(key, expected, value, signal);
  };
  losing.expire();
  await losing.provider().credential(losing.context);
  assert.equal(losing.secrets.deleted.length, 1);
  assert.notEqual(losing.secrets.deleted[0], kept.secretRef);
  assert.ok(losing.secrets.values.has(kept.secretRef));
});

test('host prepare keeps a usable client-credentials registration', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  f.expire();
  await f.oauth.prepare(f.context, budget());
  await f.oauth.prepare({ ...f.context, purpose: 'upload' }, budget());
  assert.equal(f.state.registrations.length, 1);
});

// ---- Client-credentials backoff -------------------------------------------------

test('[registration-transient-failure-backs-off] no request until the shared backoff passes; the last code is returned; prepare bypasses it', async () => {
  const outcomes = [[503, 'provider_failed'], [408, 'provider_failed'], [429, 'provider_failed'], ['network', 'provider_failed'],
    [401, 'credential_unavailable'], [403, 'credential_unavailable'], [400, 'invalid_configuration']];
  for (const [status, code] of outcomes) {
    const f = fixture(cc());
    await f.oauth.prepare(f.context, budget());
    f.patchRecord({ clientSecretExpiresAt: 1 });
    f.expire();
    f.state.register = () => { if (status === 'network') throw new TypeError('fetch failed'); return new Response('', { status }); };
    const before = Date.now();
    await assert.rejects(f.provider().credential(f.context), errorCode(code), String(status));
    // Other paths and processes sharing the store send nothing and keep the code (retry advice for retryable failures).
    for (let i = 0; i < 3; i++) {
      await assert.rejects(f.provider(managedOAuth(f.options)).credential(f.context), errorCode(code), String(status));
      await assert.rejects(f.provider().credential({ ...f.context, purpose: 'upload', challenged: true }), errorCode(code), String(status));
    }
    assert.equal(f.state.registrations.length, 2, String(status));
    const [marker] = f.markers();
    assert.equal(marker.attempts, 1);
    assert.ok(marker.nextAttemptAt >= before + 60_000 && marker.nextAttemptAt <= Date.now() + 60_000);
    if (code === 'provider_failed') {
      const error = await f.provider().credential(f.context).catch(error => error);
      assert.equal(error.recovery, 'retry');
    }
  }
  // Once elapsed the next attempt doubles; host prepare bypasses it; a success clears it.
  const f = fixture(cc());
  f.state.register = () => new Response('', { status: 503 });
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('provider_failed'));
  f.store.values.set(failureKey(f.key), { ...f.markers()[0], nextAttemptAt: Date.now() - 1 });
  const before = Date.now();
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('provider_failed'));
  assert.equal(f.markers()[0].attempts, 2);
  assert.ok(f.markers()[0].nextAttemptAt >= before + 120_000);
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('provider_failed'));
  assert.equal(f.state.registrations.length, 3, 'prepare sent a request during the backoff');
  f.state.register = undefined;
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  assert.deepEqual(f.markers(), []);
  // An unattended host recovers by itself once the backoff passes.
  const u = fixture(cc());
  u.state.register = () => new Response('', { status: 503 });
  await assert.rejects(u.provider().credential({ ...u.context, challenged: true }), errorCode('provider_failed'));
  u.state.register = undefined;
  u.store.values.set(failureKey(u.key), { ...u.markers()[0], nextAttemptAt: Date.now() - 1 });
  assert.equal((await u.provider().credential({ ...u.context, challenged: true })).token, 'access-1');
  assert.deepEqual(u.markers(), []);
});

test('[registration-retry-after-honoured] Retry-After sets the next attempt no earlier than itself or the backoff, capped', async () => {
  const date = new Date(Date.now() + 300_000).toUTCString();
  for (const [header, expected] of [['120', 120_000], ['10', 60_000], ['7200', 3_600_000], [date, 300_000]]) {
    const f = fixture(cc());
    f.state.register = () => new Response('', { status: 429, headers: { 'retry-after': header } });
    const before = Date.now();
    await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('provider_failed'));
    const [marker] = f.markers();
    const delay = marker.nextAttemptAt - before;
    assert.ok(Math.abs(delay - expected) <= 2000, `${header}: ${delay}`);
  }
  const custom = fixture({ ...cc(), options: { registrationBackoff: { initialMs: 1000, maxMs: 5000 } } });
  custom.state.register = () => new Response('', { status: 503, headers: { 'retry-after': '60' } });
  const before = Date.now();
  await assert.rejects(custom.oauth.prepare(custom.context, budget()), errorCode('provider_failed'));
  const [marker] = custom.markers();
  assert.ok(Math.abs(marker.nextAttemptAt - before - 5000) <= 2000);
});

test('concurrent client-credentials failures send one registration request per permitted attempt and keep the count', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  f.patchRecord({ clientSecretExpiresAt: 1 });
  f.state.register = () => new Response('', { status: 503 });
  for (let round = 1; round <= 3; round++) {
    f.expire();
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => f.provider(managedOAuth(f.options)).credential(f.context)));
    assert.deepEqual(results.map(result => result.reason.code), Array(4).fill('provider_failed'));
    assert.equal(f.state.registrations.length, 1 + round);
    const [marker] = f.markers();
    assert.equal(marker.attempts, round);
    f.store.values.set(failureKey(f.key), { ...marker, nextAttemptAt: Date.now() - 1 });
  }
});

test('a registration sent before the caller aborts is still persisted with its secret', async () => {
  const { createServer } = await import('node:http');
  const controller = new AbortController();
  let received = 0;
  const server = createServer(async (request, response) => {
    for await (const _chunk of request);
    received++;
    controller.abort();
    await new Promise(resolve => setTimeout(resolve, 30));
    response.setHeader('content-type', 'application/json');
    response.statusCode = 201;
    response.end(JSON.stringify({ client_id: 'dcr-http', client_secret: 'secret-http' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const f = fixture(cc());
    const inner = f.options.policyFetch;
    const oauth = managedOAuth({ ...f.options, policyFetch: (url, init, context) => url.endsWith('/register')
      ? fetch(`http://127.0.0.1:${server.address().port}/register`, init) : inner(url, init, context) });
    await assert.rejects(oauth.prepare(f.context, { signal: controller.signal, deadline: Date.now() + 5000 }), { name: 'AbortError' });
    for (let i = 0; i < 100 && f.registrations().length === 0; i++) await new Promise(resolve => setTimeout(resolve, 10));
    const [record] = f.registrations();
    assert.equal(record.clientId, 'dcr-http');
    assert.equal(f.secrets.values.get(record.secretRef), 'secret-http');
    assert.deepEqual(f.markers(), []);
    assert.equal((await oauth.prepare(f.context, budget())).credential.token, 'access-1');
    assert.equal(f.state.tokenCalls[0].id, 'dcr-http');
    assert.equal(received, 1);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

