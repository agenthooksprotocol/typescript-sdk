import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { managedOAuth, registrationKey } from '../dist/src/oauth/index.js';
import { acceptRegistration, chooseSource, failureKey, requestDigest } from '../dist/src/oauth/registration.js';

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
  const callback = (pending, extra = {}) => {
    const url = new URL(REDIRECT);
    url.search = new URLSearchParams({ code: 'code', state: new URL(pending.authorizationUrl).searchParams.get('state'), ...extra }).toString();
    return url.href;
  };
  const login = async (instance = oauth, ctx = context, prepareOptions) => {
    const pending = await instance.prepare({ ...ctx, challenged: true }, budget(), prepareOptions);
    return instance.complete(pending, callback(pending), budget());
  };
  const expire = () => { for (const [key, value] of store.values) if (value.kind === 'grant') store.values.set(key, { ...value, expiresAt: Date.now() - 1 }); };
  const registrations = () => store.of('ahp.oauth.registration:');
  const markers = () => store.of('ahp.oauth.registration-failure:');
  const key = registrationKey('account', client.issuer, client.flow, client.flow === 'client_credentials' ? '' : client.redirectUri);
  const patchRecord = patch => store.values.set(key, { ...store.values.get(key), ...patch });
  return { oauth, options, store, secrets, state, client, context, provider, callback, login, expire, registrations, markers, key,
    patchRecord, destinations };
}
function withoutSelect({ select: _select, ...client }) { return client; }
const cc = (rest = {}) => ({ client: { flow: 'client_credentials', redirectUri: undefined, ...rest } });
const errorCode = code => error => { assert.equal(error.code, code); return true; };
const clientIdOf = pending => new URL(pending.authorizationUrl).searchParams.get('client_id');

// ---- Shared vectors ---------------------------------------------------------

test('registration key vectors frame namespace, exact issuer, flow and redirect only', () => {
  for (const vector of vectors.registration_keys) {
    const { namespace, issuer, flow, redirect } = vector.input;
    assert.equal(registrationKey(namespace, issuer, flow, redirect), vector.registration_key, vector.id);
  }
});

test('registration request digest vectors', async () => {
  for (const vector of vectors.registration_request_digests) {
    const input = vector.input;
    const digest = await requestDigest({ clientName: input.client_name, softwareId: input.software_id,
      softwareVersion: input.software_version, scopes: input.registration_scope, initialAccessTokenRef: input.initial_access_token_ref });
    assert.equal(digest, vector.request_digest, vector.id);
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
    for (const field of ['registration_access_token', 'registration_client_uri', 'client_secret', 'scope']) {
      assert.equal(Object.hasOwn(accepted.metadata, field), false, `${vector.id} keeps ${field}`);
    }
  }
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
  // The lookup: a new grant key, so the old DCR token is never presented under the new client.
  assert.equal((await provider.credential(f.context)).token, 'access-2');
  assert.deepEqual(f.state.tokenCalls.map(call => call.id), ['dcr-1', 'pre']);
  assert.equal(f.state.registrations.length, 1);
  assert.equal(f.store.of('ahp.oauth.binding:')[0].client.source, 'preregistered');
  assert.equal(f.store.of('ahp.oauth.grant:').length, 2);
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

test('[cimd-redirect-mismatch-invalid-configuration] a redirect not in the document fails before any login or registration', async () => {
  const f = fixture(cimd({ registration: POLICY, redirectUri: 'http://127.0.0.1:9999/callback' }));
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('invalid_configuration'));
  assert.deepEqual(f.store.of('ahp.oauth.pending:'), []);
  assert.equal(f.state.registrations.length, 0);
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
  await assert.rejects(f.oauth.complete(pending, f.callback(pending), budget()), errorCode('invalid_configuration'));
  // The authorization endpoint reporting invalid_client is also misconfiguration.
  const again = await f.oauth.prepare(f.context, budget());
  await assert.rejects(f.oauth.complete(again, f.callback(again, { error: 'invalid_client', code: undefined }).replace('code=undefined&', ''), budget()),
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

test('[dcr-pkce-registers-only-in-prepare] PKCE registers only in host prepare; client credentials in any acquisition', async () => {
  const f = fixture();
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('interaction_required'));
  assert.equal(f.state.registrations.length, 0);
  await f.oauth.prepare(f.context, budget());
  assert.equal(f.state.registrations.length, 1);
  const c = fixture(cc());
  assert.equal((await c.provider().credential({ ...c.context, challenged: true })).token, 'access-1');
  assert.equal(c.state.registrations.length, 1);
  // Challenge handling may register a client-credentials client too.
  const h = fixture(cc());
  await h.oauth.challenge({ ...h.context, response: new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } }), credential: undefined }, budget());
  assert.equal(h.state.registrations.length, 1);
});

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

test('[dcr-registration-reused-across-grants] grants in other bindings and partitions reuse one registration', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  await f.oauth.prepare({ ...f.context, purpose: 'upload' }, budget());
  f.client.grantPartition = 'shared';
  await f.oauth.prepare({ ...f.context, backendId: 'other' }, budget());
  assert.equal(f.state.registrations.length, 1);
  assert.equal(f.store.of('ahp.oauth.grant:').length, 3);
  assert.ok(f.state.tokenCalls.every(call => call.id === 'dcr-1'));
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
  // The replacement is rejected too: at most one re-registration, then credential_unavailable and a marker.
  f.state.invalid.add('dcr-2').add('dcr-3');
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 3);
  assert.equal(f.markers()[0].attempts, 1);
  // PKCE: interaction_required, and the next prepare registers a new client.
  const p = fixture();
  await p.login();
  p.state.invalid.add('dcr-1');
  p.expire();
  await assert.rejects(p.provider().credential(p.context), errorCode('interaction_required'));
  assert.deepEqual(p.registrations(), []);
  assert.equal(clientIdOf(await p.oauth.prepare(p.context, budget())), 'dcr-2');
});

test('[dcr-new-client-id-new-grant] a replacement client_id is a new grant key; the old grant is not migrated', async () => {
  const grantKeys = f => [...f.store.values.keys()].filter(key => key.startsWith('ahp.oauth.grant:'));
  for (const grantPartition of [undefined, 'shared']) {
    const f = fixture(cc({ ...(grantPartition ? { grantPartition } : {}) }));
    await f.oauth.prepare(f.context, budget());
    const [oldGrant] = f.store.of('ahp.oauth.grant:');
    f.state.invalid.add('dcr-1');
    f.expire();
    assert.equal((await f.provider().credential(f.context)).token, 'access-2');
    const keys = grantKeys(f);
    assert.ok(keys.some(key => key.includes('5:dcr-2')));
    const old = keys.find(key => key.includes('5:dcr-1'));
    // Replacement compare-and-deletes the old binding-scoped grant; a shared partition is kept.
    if (grantPartition) assert.equal(f.store.values.get(old).generation, oldGrant.generation, 'not migrated');
    else assert.equal(old, undefined);
    assert.equal(f.store.of('ahp.oauth.binding:')[0].client.clientId, 'dcr-2');
    // A forced re-registration does the same.
    await f.oauth.prepare(f.context, budget(), { forceRegistration: true });
    const forced = grantKeys(f);
    assert.ok(forced.some(key => key.includes('5:dcr-3')));
    assert.equal(forced.some(key => key.includes('5:dcr-2')), grantPartition !== undefined, String(grantPartition));
  }
  const p = fixture();
  await p.login();
  p.state.invalid.add('dcr-1');
  p.expire();
  await assert.rejects(p.provider().credential(p.context), errorCode('interaction_required'));
  const pending = await p.oauth.prepare(p.context, budget());
  assert.match(p.store.of('ahp.oauth.pending:')[0].grantKey, /5:dcr-2/);
  assert.equal(p.store.of('ahp.oauth.grant:').length, 1, 'the old grant is left, not migrated');
  assert.equal((await p.oauth.complete(pending, p.callback(pending), budget())).credential.token, 'access-2');
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
  // A PKCE pending login never holds a secret either.
  const p = fixture({ client: { clientSecret: 'host-secret' } });
  await p.oauth.prepare(p.context, budget());
  assert.doesNotMatch(JSON.stringify([...p.store.values]), /host-secret/);
});

test('[dcr-no-secret-hook-no-confidential-registration] without a secret hook client credentials never register; PKCE does', async () => {
  const f = fixture({ ...cc(), secrets: null });
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 0);
  const p = fixture({ secrets: null });
  assert.equal(clientIdOf(await p.oauth.prepare(p.context, budget())), 'dcr-1');
});

test('[dcr-metadata-change-keeps-selection] new CIMD support or a removed registration_endpoint keeps the recorded client', async () => {
  const f = fixture({ client: { clientMetadataDocument: { url: CIMD, redirectUris: [REDIRECT] } } });
  await f.login();
  f.state.metadata[ISSUER] = { client_id_metadata_document_supported: true, registration_endpoint: undefined };
  f.expire();
  // Host prepare rediscovers metadata and refreshes with the recorded DCR client.
  assert.equal((await f.oauth.prepare({ ...f.context, challenged: true }, budget())).credential.token, 'access-2');
  assert.equal(f.state.tokenCalls.at(-1).id, 'dcr-1');
  const [binding] = f.store.of('ahp.oauth.binding:');
  assert.equal(binding.metadata.client_id_metadata_document_supported, true);
  assert.deepEqual([binding.client.source, binding.client.clientId], ['dcr', 'dcr-1']);
  assert.equal(f.state.registrations.length, 1);
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
  f.secrets.values.delete('vault:iat');
  await f.oauth.prepare(f.context, budget(), { forceRegistration: true }).catch(error => assert.equal(error.code, 'credential_unavailable'));
  assert.equal(f.state.registrations.length, 2);
});

test('[lookup-never-registers-pkce] the up-front lookup never registers PKCE; client credentials may', async () => {
  const f = fixture();
  await f.login();
  f.store.values.delete(f.key);
  await assert.rejects(f.provider().credential(f.context), errorCode('interaction_required'));
  assert.equal(f.state.registrations.length, 1);
  const c = fixture(cc());
  await c.oauth.prepare(c.context, budget());
  c.store.values.delete(c.key);
  c.expire();
  assert.equal((await c.provider().credential(c.context)).token, 'access-2');
  assert.equal(c.state.registrations.length, 2);
});

// ---- Failed marker ------------------------------------------------------------

test('[dcr-failed-marker-bounds-registration] a failure persists a marker; only prepare, success or a policy change clear it', async () => {
  const f = fixture(cc());
  f.state.register = () => Response.json({ error: 'invalid_client_metadata' }, { status: 400 });
  const before = Date.now();
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('invalid_configuration'));
  const [marker] = f.markers();
  assert.equal(marker.attempts, 1);
  assert.ok(marker.failedAt >= before && marker.nextAttemptAt === marker.failedAt + 60_000);
  assert.equal(marker.requestDigest, await requestDigest(POLICY));
  // Other paths and processes send nothing until it elapses.
  for (const instance of [f.oauth, managedOAuth(f.options)]) {
    await assert.rejects(f.provider(instance).credential({ ...f.context, challenged: true }), errorCode('credential_unavailable'));
  }
  assert.equal(f.state.registrations.length, 1);
  // Elapsed: the next attempt doubles the backoff.
  f.store.values.set(failureKey(f.key), { ...marker, nextAttemptAt: Date.now() - 1 });
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('invalid_configuration'));
  const [second] = f.markers();
  assert.deepEqual([second.attempts, second.nextAttemptAt - second.failedAt], [2, 120_000]);
  // Host prepare clears it and sends immediately.
  await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('invalid_configuration'));
  assert.equal(f.state.registrations.length, 3);
  assert.equal(f.markers()[0].attempts, 1);
  // A changed request digest clears it.
  f.state.register = undefined;
  f.client.registration = { ...POLICY, softwareVersion: '2' };
  assert.equal((await f.provider().credential({ ...f.context, challenged: true })).token, 'access-1');
  assert.deepEqual(f.markers(), []);
  // A success clears it.
  f.store.values.set(failureKey(f.key), { ...marker, requestDigest: await requestDigest(f.client.registration), nextAttemptAt: 0 });
  f.store.values.delete(f.key);
  f.expire();
  await f.provider().credential(f.context);
  assert.deepEqual(f.markers(), []);
});

test('[dcr-response-validation-invalid-configuration] an invalid 2xx registration persists nothing and is not retried', async () => {
  for (const response of [{ client_id: 'dcr', client_secret: 'secret' }, { client_id: 'dcr', redirect_uris: ['https://evil.example/cb'] },
    { client_id: 'dcr', token_endpoint_auth_method: 'client_secret_basic' }]) {
    const f = fixture();
    f.state.register = () => Response.json(response, { status: 201 });
    await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('invalid_configuration'));
    assert.equal(f.state.registrations.length, 1);
    assert.deepEqual(f.registrations(), []);
    assert.equal(f.secrets.values.size, 0);
    assert.deepEqual(f.store.of('ahp.oauth.pending:'), []);
  }
});

test('[prepare-force-reregistration] forceRegistration replaces the registration and clears the marker; an expired login alone never does', async () => {
  const f = fixture({ options: { loginLifetimeMs: 30 } });
  const first = await f.oauth.prepare(f.context, budget());
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(clientIdOf(await f.oauth.prepare(f.context, budget())), clientIdOf(first), 'expiry alone keeps the client');
  assert.equal(f.state.registrations.length, 1);
  const [old] = f.registrations();
  f.store.values.set(failureKey(f.key), { kind: 'registration_failure', generation: 'm', requestDigest: old.requestDigest,
    failedAt: Date.now(), attempts: 3, nextAttemptAt: Date.now() + 60_000 });
  const forced = await f.oauth.prepare(f.context, budget(), { forceRegistration: true });
  assert.equal(clientIdOf(forced), 'dcr-2');
  const [replacement] = f.registrations();
  assert.notEqual(replacement.generation, old.generation);
  assert.deepEqual(f.markers(), []);
  // A confidential record's secret is deleted with it.
  const c = fixture(cc());
  await c.oauth.prepare(c.context, budget());
  const [secretRef] = c.secrets.values.keys();
  await c.oauth.prepare(c.context, budget(), { forceRegistration: true });
  assert.deepEqual(c.secrets.deleted, [secretRef]);
  assert.equal(c.registrations()[0].clientId, 'dcr-2');
});

test('[dcr-policy-change-reregisters] a changed name, software id, scope or token reference re-registers with the new policy', async () => {
  for (const change of [{ clientName: 'Renamed' }, { softwareId: 'id' }, { scopes: ['read'] }, { initialAccessTokenRef: 'vault:iat' }]) {
    const f = fixture(cc());
    f.secrets.values.set('vault:iat', 'iat');
    await f.oauth.prepare(f.context, budget());
    const [old] = f.registrations();
    f.client.registration = { ...POLICY, ...change };
    f.expire();
    await f.provider().credential(f.context);
    const body = f.state.registrations[1].body;
    assert.equal(body.client_name, change.clientName ?? POLICY.clientName);
    if (change.softwareId) assert.equal(body.software_id, 'id');
    if (change.scopes) assert.equal(body.scope, 'read');
    if (change.initialAccessTokenRef) assert.equal(f.state.registrations[1].authorization, 'Bearer iat');
    assert.ok(f.secrets.deleted.includes(old.secretRef));
    assert.equal(f.registrations()[0].requestDigest, await requestDigest(f.client.registration));
  }
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

test('[cc-registration-auto-repairs-after-backoff] an unattended host re-registers after the backoff without prepare', async () => {
  const f = fixture(cc());
  f.state.register = () => new Response('', { status: 503 });
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('provider_failed'));
  await assert.rejects(f.provider().credential({ ...f.context, challenged: true }), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 1);
  f.state.register = undefined;
  const [marker] = f.markers();
  f.store.values.set(failureKey(f.key), { ...marker, nextAttemptAt: Date.now() - 1 });
  assert.equal((await f.provider().credential({ ...f.context, challenged: true })).token, 'access-1');
  assert.equal(f.state.registrations.length, 2);
  assert.deepEqual(f.markers(), []);
});

// ---- Proactive renewal --------------------------------------------------------

test('[cc-proactive-reregistration-before-expiry] inside the margin a successful acquisition re-registers; outside it does not', async () => {
  const f = fixture(cc());
  const now = Math.floor(Date.now() / 1000);
  f.state.expiresAt = now + 100;
  // client_id_issued_at far in the past would put it inside the margin if it were relied on.
  f.state.register = (_body, n) => Response.json({ client_id: `dcr-${n}`, client_secret: `secret-${n}`,
    client_secret_expires_at: f.state.expiresAt, client_id_issued_at: now - 100_000 }, { status: 201 });
  await f.oauth.prepare(f.context, budget());
  assert.equal(f.state.registrations.length, 1, 'remaining 100s, margin 10s: not due');
  // Registered 1000s ago: margin min(110s, 1h) covers the remaining 100s.
  f.patchRecord({ registeredAt: Date.now() - 1_000_000 });
  f.expire();
  const before = f.state.requests.length;
  assert.equal((await f.provider().credential(f.context)).token, 'access-2');
  assert.deepEqual(f.state.requests.slice(before).map(({ purpose }) => purpose), ['token', 'registration']);
  assert.equal(f.state.tokenCalls.at(-1).id, 'dcr-1', 'the operation used the current client');
  assert.equal(f.registrations()[0].clientId, 'dcr-2');
  // The one-hour cap: a long-lived secret renews only within its last hour.
  const capped = fixture(cc());
  capped.state.expiresAt = now + 3 * 3600;
  await capped.oauth.prepare(capped.context, budget());
  capped.patchRecord({ registeredAt: Date.now() - 100 * 3600_000 });
  capped.expire();
  await capped.provider().credential(capped.context);
  assert.equal(capped.state.registrations.length, 1);
  capped.patchRecord({ clientSecretExpiresAt: now + 3500 });
  capped.expire();
  await capped.provider().credential(capped.context);
  assert.equal(capped.state.registrations.length, 2);
});

test('[proactive-reregistration-once-across-processes] concurrent renewals inside the margin register once', async () => {
  const f = fixture(cc());
  f.state.expiresAt = Math.floor(Date.now() / 1000) + 100;
  const contexts = ['a', 'b', 'c'].map(backendId => ({ ...f.context, backendId }));
  for (const context of contexts) await f.oauth.prepare(context, budget());
  assert.equal(f.state.registrations.length, 1);
  f.state.expiresAt = Math.floor(Date.now() / 1000) + 7200;
  f.patchRecord({ registeredAt: Date.now() - 1_000_000 });
  f.expire();
  await Promise.all(contexts.map(context => f.provider(managedOAuth(f.options)).credential(context)));
  assert.equal(f.state.tokenCalls.length, 6, 'each grant acquired');
  assert.equal(f.state.registrations.length, 2, 'exactly one renewal');
});

test('[proactive-renewal-failure-keeps-current-registration] a failed renewal advances the marker but the operation succeeds', async () => {
  const f = fixture(cc());
  f.state.expiresAt = Math.floor(Date.now() / 1000) + 100;
  await f.oauth.prepare(f.context, budget());
  const [record] = f.registrations();
  f.patchRecord({ registeredAt: Date.now() - 1_000_000 });
  f.state.register = () => new Response('', { status: 429, headers: { 'retry-after': '30' } });
  f.expire();
  assert.equal((await f.provider().credential(f.context)).token, 'access-2');
  assert.equal(f.markers()[0].attempts, 1);
  const [current] = f.registrations();
  assert.deepEqual([current.clientId, current.secretRef], [record.clientId, record.secretRef]);
  assert.deepEqual(f.secrets.deleted, []);
  // The marker suppresses the next renewal; the current client keeps acquiring.
  f.expire();
  assert.equal((await f.provider().credential(f.context)).token, 'access-3');
  assert.equal(f.state.registrations.length, 2);
  assert.deepEqual(f.state.tokenCalls.map(call => call.id), ['dcr-1', 'dcr-1', 'dcr-1']);
});

test('[marker-blocks-only-registration] an active marker still sends a valid token; PKCE still needs interaction', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  const digest = await requestDigest(POLICY);
  f.store.values.set(failureKey(f.key), { kind: 'registration_failure', generation: 'm', requestDigest: digest,
    failedAt: Date.now(), attempts: 1, nextAttemptAt: Date.now() + 60_000 });
  f.patchRecord({ clientSecretExpiresAt: 1 });
  assert.equal((await f.provider().credential(f.context)).token, 'access-1');
  f.expire();
  await assert.rejects(f.provider().credential(f.context), errorCode('credential_unavailable'));
  assert.equal(f.state.registrations.length, 1);
  const p = fixture();
  await p.login();
  p.store.values.delete(p.key);
  p.store.values.set(failureKey(p.key), { kind: 'registration_failure', generation: 'm', requestDigest: digest,
    failedAt: Date.now(), attempts: 1, nextAttemptAt: Date.now() + 60_000 });
  p.expire();
  await assert.rejects(p.provider().credential(p.context), errorCode('interaction_required'));
});

test('a forced re-registration reissuing the same client_id never reuses the stale-generation login', async () => {
  const f = fixture();
  f.state.register = () => Response.json({ client_id: 'dcr-same' }, { status: 201 });
  const stale = await f.oauth.prepare(f.context, budget());
  assert.deepEqual(await f.oauth.prepare(f.context, budget()), stale, 'same generation: reused');
  const fresh = await f.oauth.prepare(f.context, budget(), { forceRegistration: true });
  assert.equal(clientIdOf(fresh), 'dcr-same');
  assert.notEqual(fresh.id, stale.id);
  assert.equal(f.store.of('ahp.oauth.pending:')[0].registration.generation, f.registrations()[0].generation);
  await assert.rejects(f.oauth.complete(stale, f.callback(stale), budget()), errorCode('interaction_required'));
});

test('host prepare clears a failed marker even when a valid token means it registers nothing', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  f.store.values.set(failureKey(f.key), { kind: 'registration_failure', generation: 'm', requestDigest: await requestDigest(POLICY),
    failedAt: Date.now(), attempts: 4, nextAttemptAt: Date.now() + 60_000 });
  assert.equal((await f.oauth.prepare(f.context, budget())).credential.token, 'access-1');
  assert.deepEqual(f.markers(), []);
  assert.equal(f.state.registrations.length, 1);
});

test('a stale failed-marker write never overwrites a newer one (compare-and-set without exclusive locks)', async () => {
  const f = fixture({ ...cc(), store: memoryStore({ exclusive: key => !key.startsWith('ahp.oauth.registration:') }),
    options: { registrationBackoff: { initialMs: 0, maxMs: 0 } } });
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  f.state.register = async (_body, n) => { if (n === 1) await gate; return new Response('', { status: 503 }); };
  const slow = f.provider().credential({ ...f.context, challenged: true });
  while (f.state.registrations.length < 1) await new Promise(resolve => setImmediate(resolve));
  for (let i = 0; i < 3; i++) {
    await assert.rejects(f.provider(managedOAuth(f.options)).credential({ ...f.context, challenged: true }), errorCode('provider_failed'));
  }
  assert.equal(f.markers()[0].attempts, 3);
  release();
  await assert.rejects(slow, errorCode('provider_failed'));
  assert.equal(f.markers()[0].attempts, 3, 'the stale writer read no marker and loses its compare-and-set');
});

test('[stale-callback-does-not-delete-new-registration] invalid_client at completion deletes only the login\'s generation', async () => {
  const f = fixture();
  f.state.register = () => Response.json({ client_id: 'dcr-same' }, { status: 201 });
  const upload = { ...f.context, purpose: 'upload' };
  const stale = await f.oauth.prepare(f.context, budget());
  const fresh = await f.oauth.prepare(upload, budget(), { forceRegistration: true });
  const [current] = f.registrations();
  assert.notEqual(f.store.of('ahp.oauth.pending:').find(login => login.id === stale.id).registration.generation, current.generation);
  f.state.invalid.add('dcr-same');
  await assert.rejects(f.oauth.complete(stale, f.callback(stale), budget()), errorCode('interaction_required'));
  assert.equal(f.registrations()[0].generation, current.generation, 'the newer registration survives');
  f.state.invalid.clear();
  assert.equal((await f.oauth.complete(fresh, f.callback(fresh), budget())).credential.token, 'access-1');
  // A login at the current generation is deleted by its own invalid_client.
  const next = await f.oauth.prepare(f.context, budget());
  f.state.invalid.add('dcr-same');
  await assert.rejects(f.oauth.complete(next, f.callback(next), budget()), errorCode('interaction_required'));
  assert.deepEqual(f.registrations(), []);
});

test('[registration-transient-failure-backs-off] 5xx, 408, 429, network and 401/403 failures suppress further requests', async () => {
  const outcomes = [[503, 'provider_failed'], [408, 'provider_failed'], [429, 'provider_failed'], ['network', 'provider_failed'],
    [401, 'credential_unavailable'], [403, 'credential_unavailable']];
  for (const [status, code] of outcomes) {
    const f = fixture(cc());
    await f.oauth.prepare(f.context, budget());
    f.patchRecord({ clientSecretExpiresAt: 1 });
    f.expire();
    f.state.register = () => { if (status === 'network') throw new TypeError('fetch failed'); return new Response('', { status }); };
    await assert.rejects(f.provider().credential(f.context), errorCode(code), String(status));
    for (let i = 0; i < 3; i++) {
      await assert.rejects(f.provider(managedOAuth(f.options)).credential(f.context), errorCode('credential_unavailable'));
      await assert.rejects(f.provider().credential({ ...f.context, purpose: 'upload', challenged: true }), errorCode('credential_unavailable'));
    }
    assert.equal(f.state.registrations.length, 2, String(status));
    assert.equal(f.markers()[0].attempts, 1);
  }
});

test('[registration-retry-after-honoured] Retry-After sets the next attempt no earlier than itself or the backoff, capped', async () => {
  const date = new Date(Date.now() + 300_000).toUTCString();
  for (const [header, expected] of [['120', 120_000], ['10', 60_000], ['7200', 3_600_000], [date, 300_000]]) {
    const f = fixture(cc());
    f.state.register = () => new Response('', { status: 429, headers: { 'retry-after': header } });
    await assert.rejects(f.oauth.prepare(f.context, budget()), errorCode('provider_failed'));
    const [marker] = f.markers();
    const delay = marker.nextAttemptAt - marker.failedAt;
    assert.ok(Math.abs(delay - expected) <= 2000, `${header}: ${delay}`);
  }
  const custom = fixture({ ...cc(), options: { registrationBackoff: { initialMs: 1000, maxMs: 5000 } } });
  custom.state.register = () => new Response('', { status: 503, headers: { 'retry-after': '60' } });
  await assert.rejects(custom.oauth.prepare(custom.context, budget()), errorCode('provider_failed'));
  const [marker] = custom.markers();
  assert.equal(marker.nextAttemptAt - marker.failedAt, 5000);
});

test('[marker-update-atomic-across-processes] concurrent failures send one request per permitted attempt and keep the count', async () => {
  const f = fixture(cc());
  await f.oauth.prepare(f.context, budget());
  f.patchRecord({ clientSecretExpiresAt: 1 });
  f.state.register = () => new Response('', { status: 503 });
  for (let round = 1; round <= 3; round++) {
    f.expire();
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => f.provider(managedOAuth(f.options)).credential(f.context)));
    assert.deepEqual(results.map(result => result.reason.code).sort(),
      ['credential_unavailable', 'credential_unavailable', 'credential_unavailable', 'provider_failed']);
    assert.equal(f.state.registrations.length, 1 + round);
    const [marker] = f.markers();
    assert.equal(marker.attempts, round);
    assert.equal(marker.nextAttemptAt - marker.failedAt, 60_000 * 2 ** (round - 1));
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
