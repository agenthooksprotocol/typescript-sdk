// The decision table (scope contract v2, section 7): every shared scope_decisions and
// completions vector, run against managedOAuth at its real host boundaries (policyFetch,
// store, selectClient, checkDestination). Every field a vector defines is asserted; a
// field the spec does not define fails the run.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { managedOAuth } from '../dist/src/oauth/index.js';
import { AuthError, auth, classifyAuthError } from '../dist/src/client/auth.js';
import { observeDecisions } from '../dist/src/client/decision.js';
import { KNOWN_FEATURES, skipFor } from './fixtures/sdk-features.mjs';

const vectors = JSON.parse(readFileSync(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url), 'utf8'));
const budget = () => ({ signal: new AbortController().signal, deadline: Date.now() + 5000 });
const sorted = (...sets) => [...new Set(sets.flat())].sort();
const issuer = 'https://issuer.example', resource = 'https://api.example/events';
const redirect = 'https://app.example/callback?app=1', cimdUrl = 'https://app.example/client.json';
const generation = n => `generation-${n}`;

/** The last decision's R during an operation: the probe sees every `decide` call. */
let lastRequired;
observeDecisions((_input, decision) => { lastRequired = [...decision.required]; });

// The field vocabulary of spec/draft/sdk-auth-lifecycle.md (Executable coverage).
const VECTOR_FIELDS = ['id', 'requires', 'input', 'expect'];
const SCOPE_INPUT = ['flow', 'path', 'binding', 'requested', 'host_required', 'explicit', 'ceiling', 'preset_scopes', 'grant', 'sent',
  'challenge', 'prior_401_hint', 'host_error', 'target_error'];
const SCOPE_EXPECT = ['code', 'scopes', 'required', 'action', 'acquisition_scopes', 'retired', 'authorization_server_requests',
  'network_calls', 'network_calls_max'];
const COMPLETION_INPUT = ['pending', 'handle', 'client_source', 'source_permitted', 'callback', 'host_error', 'claim', 'exchange',
  'stored_required', 'prepare_time_host_required', 'current_host_required', 'granted', 'ceiling'];
const COMPLETION_EXPECT = ['code', 'scopes', 'login_ended', 'grant_persisted'];
const TOKEN_ERROR_INPUT = ['grant_type', 'client_source', 'error'];
const TOKEN_ERROR_EXPECT = ['code', 'reregistrations'];
/** Members of the nested objects a vector may carry, at every level. */
const NESTED = {
  grant: ['generation', 'granted', 'token', 'refresh'],
  challenge: ['status', 'www_authenticate'],
  host_error: ['callback', 'target', 'code', 'scopes'],
  target_error: ['check', 'code'],
  claim: ['outcome', 'error_code', 'reread'],
};
function known(path, value, members) {
  assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value), `${path}: not an object`);
  for (const key of Object.keys(value)) assert.ok(members.includes(key), `${path}: unknown field ${key}`);
}
/** Every member at every nesting level is one the spec defines; any other fails the run. */
function defined(vector, input, expect) {
  known(vector.id, vector, VECTOR_FIELDS);
  known(`${vector.id}.input`, vector.input, input);
  known(`${vector.id}.expect`, vector.expect, expect);
  if (vector.requires !== undefined) assert.ok(Array.isArray(vector.requires) && vector.requires.every(item => typeof item === 'string'), `${vector.id}.requires`);
  const leaf = (path, value) => {
    if (Array.isArray(value)) value.forEach((item, index) => assert.ok(item === null || typeof item !== 'object', `${path}[${index}]: unexpected object`));
    else assert.ok(value === null || typeof value !== 'object', `${path}: unexpected object`);
  };
  for (const [section, members] of [['input', vector.input], ['expect', vector.expect]]) {
    for (const [key, value] of Object.entries(members)) {
      const path = `${vector.id}.${section}.${key}`;
      const nested = section === 'input' ? NESTED[key] : undefined;
      // `claim` is the string `ok` or an object; `grant` may be null.
      if (nested && value !== null && typeof value === 'object') {
        known(path, value, nested);
        for (const [inner, innerValue] of Object.entries(value)) leaf(`${path}.${inner}`, innerValue);
      } else leaf(path, value);
    }
  }
}
function compare(vector, result) {
  for (const [key, want] of Object.entries(vector.expect)) {
    if (key === 'network_calls_max') assert.ok(result.network_calls <= want, `${vector.id}: network_calls ${result.network_calls} > ${want}`);
    else assert.deepEqual(result[key], want, `${vector.id}: ${key} in ${JSON.stringify(result)}`);
  }
}

function memoryStore() {
  const values = new Map(), locks = new Map(), writes = [];
  return {
    values, writes, failClaim: undefined, failLoad: undefined,
    async load(key, signal) {
      signal.throwIfAborted();
      if (this.failLoad?.(key)) throw new Error('store unavailable');
      return structuredClone(values.get(key));
    },
    async compareAndSet(key, expected, value) {
      writes.push({ key, expected, value: value && structuredClone(value) });
      const failure = this.failClaim?.(key, value);
      if (failure === 'before') throw new Error('store unavailable');
      if (values.get(key)?.generation !== expected) return false;
      if (value === undefined) values.delete(key); else values.set(key, structuredClone(value));
      if (failure === 'after') throw new Error('store unavailable');
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

/** One host and authorization server; `state.network` counts every request, `state.authorizationServer` the issuer's. */
function world({ flow, requested, ceiling, required = [], source = 'preregistered', extra = {} }) {
  const store = memoryStore(), secrets = new Map();
  const state = { network: 0, authorizationServer: 0, tokens: [], scope: undefined, tokenError: undefined, n: 0, hostError: undefined };
  const client = { issuer, resource, flow, scopes: requested, allowedScopes: ceiling, requiredScopes: required, redirectUri: redirect,
    ...(source === 'preregistered' ? { clientId: 'client' } : {}),
    ...(source === 'preregistered' && flow === 'client_credentials' ? { clientSecret: 'secret' } : {}),
    ...(source === 'cimd' ? { clientMetadataDocument: { url: cimdUrl, redirectUris: [redirect] } } : {}),
    ...(source === 'dcr' ? { registration: { clientName: 'vectors' } } : {}) };
  const hostError = callback => {
    const failure = state.hostError;
    if (failure?.callback === callback) throw new AuthError(failure.code, failure.scopes);
  };
  const options = {
    namespace: 'vectors', store,
    secrets: { async put(ref, value) { secrets.set(ref, value); }, async get(ref) { return secrets.get(ref); }, async delete(ref) { secrets.delete(ref); } },
    selectClient: () => { hostError('client_selection'); return structuredClone(client); },
    checkDestination: (url, purpose) => {
      const failure = state.hostError;
      if (failure?.callback === 'destination' && ((failure.target === 'registration_endpoint' && purpose === 'registration') ||
          (failure.target === 'issuer_metadata' && purpose === 'metadata' && url.origin === issuer) ||
          (failure.target === 'protected_resource_metadata' && purpose === 'metadata' && url.origin !== issuer) ||
          (failure.target === 'token_endpoint' && purpose === 'token'))) hostError('destination');
    },
    async policyFetch(url, init) {
      state.network++;
      if (url.startsWith(issuer)) state.authorizationServer++;
      if (url === `${issuer}/register`) {
        state.registrations = (state.registrations ?? 0) + 1;
        const body = JSON.parse(String(init.body)), n = ++state.n;
        return Response.json({ client_id: `issued-${n}`, token_endpoint_auth_method: body.token_endpoint_auth_method,
          ...(body.token_endpoint_auth_method === 'none' ? {} : { client_secret: `issued-secret-${n}` }) }, { status: 201 });
      }
      if (url === `${issuer}/token`) {
        const body = new URLSearchParams(String(init.body));
        state.tokens.push(body);
        if (state.tokenError) return state.tokenError();
        const n = ++state.n;
        // Client credentials issue no refresh token (RFC 6749 section 4.4.3).
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600,
          ...(flow === 'client_credentials' ? {} : { refresh_token: `refresh-${n}` }), scope: state.scope ?? body.get('scope') ?? '' });
      }
      if (url.startsWith('https://api.example/.well-known/')) return Response.json({ resource, authorization_servers: [issuer] });
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        registration_endpoint: `${issuer}/register`, client_id_metadata_document_supported: true, response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'] });
    },
    ...extra,
  };
  const oauth = managedOAuth(options);
  return { store, state, client, oauth, provider: oauth.provider({ budget }) };
}
const settle = async promise => { try { return { value: await promise }; } catch (error) { return { error }; } };
const urlScopes = pending => sorted(new URL(pending.authorizationUrl).searchParams.get('scope').split(' '));
const grantKeys = w => [...w.store.values.keys()].filter(key => key.startsWith('ahp.oauth.grant:'));
const callbackFor = (pending, params = {}) => {
  const url = new URL(redirect);
  for (const [name, value] of Object.entries({ code: 'code', state: pending.state, iss: issuer, ...params })) {
    if (value !== undefined) url.searchParams.set(name, value);
  }
  return url.href;
};
function errorFields(error) {
  assert.ok(error instanceof AuthError, `not an AuthError: ${error?.stack ?? error}`);
  return { code: error.code, ...(['access_denied', 'interaction_required'].includes(error.code) ? { scopes: [...(error.requiredScopes ?? [])] } : {}) };
}

/** Seed the stored binding and a grant through the real flows, with a valid configuration. */
async function seed(w, context, input) {
  const valid = input.requested.filter(scope => (input.ceiling ?? input.requested).includes(scope));
  Object.assign(w.client, { scopes: valid, requiredScopes: [] });
  if (input.binding === 'preset' && input.preset_scopes) w.client.scopes = [...input.preset_scopes];
  if (input.flow === 'client_credentials') await w.oauth.prepare(context, budget());
  else await w.oauth.complete(callbackFor(await w.oauth.prepare(context, budget())), budget());
}
function writeGrant(w, key, grant) {
  if (!grant) { w.store.values.delete(key); return; }
  w.store.values.set(key, { kind: 'grant', generation: generation(grant.generation), scopes: [...grant.granted],
    token: `seeded-${grant.generation}`, expiresAt: grant.token === 'valid' ? Date.now() + 3_600_000 : Date.now() - 1,
    ...(grant.refresh ? { refreshToken: `seeded-refresh-${grant.generation}` } : {}) });
}

async function decideVector(input) {
  const ceiling = input.ceiling ?? input.requested;
  const w = world({ flow: input.flow, requested: [...input.requested], ceiling: [...ceiling],
    source: input.host_error?.target === 'registration_endpoint' ? 'dcr' : 'preregistered' });
  const authentication = { type: 'oauth', issuer, resource, clientId: 'client', flow: input.flow,
    ...(input.preset_scopes ? { scopes: [...input.preset_scopes] } : {}) };
  const context = { backendId: 'backend', purpose: 'event', url: resource, ...(input.binding === 'preset' ? { authentication } : {}) };
  let sent, key;
  if (input.binding !== 'unbound' && (input.binding === 'stored' || input.grant)) {
    await seed(w, context, input);
    [key] = grantKeys(w);
    // An earlier operation's 401 hint: it must not reach this operation.
    if (input.prior_401_hint) {
      const credential = await w.provider.credential(context);
      await settle(w.provider.challenge({ ...context, credential,
        response: new Response(null, { status: 401, headers: { 'www-authenticate': `Bearer scope="${input.prior_401_hint.join(' ')}"` } }) }));
    }
    if (input.sent !== undefined && input.sent !== null) {
      // The credential the challenged request sent: generation `sent`.
      writeGrant(w, key, { generation: input.sent, granted: input.grant?.granted ?? [], token: 'valid', refresh: false });
      sent = await w.provider.credential(context);
    }
    writeGrant(w, key, input.grant);
    if (input.grant === null) for (const stale of [...w.store.values.keys()]) if (stale.startsWith('ahp.oauth.registration')) w.store.values.delete(stale);
  }
  Object.assign(w.client, { scopes: [...input.requested], allowedScopes: [...ceiling], requiredScopes: [...input.host_required] });
  w.state.hostError = input.host_error;
  const tokensBefore = w.state.tokens.length, writesBefore = w.store.writes.length;
  w.state.network = 0; w.state.authorizationServer = 0; lastRequired = undefined;
  let outcome;
  if (input.path === 'prepare') outcome = await settle(w.oauth.prepare(context, budget(), { requiredScopes: input.explicit }));
  else if (input.path === 'challenge' || (input.path === 'fresh' && input.binding === 'unbound')) {
    // An unbound `fresh` vector is an anonymous request receiving the vector's 401, handled by `challenge`.
    const response = new Response(null, { status: input.challenge.status, headers: { 'www-authenticate': input.challenge.www_authenticate } });
    // A target check that fails before any decide step: an unsupported binding on the challenged request.
    const target = input.target_error?.check === 'unsupported_binding' ? { authentication: { type: 'unsupported' } } : {};
    if (input.target_error) assert.equal(input.target_error.check, 'unsupported_binding', 'known target check');
    outcome = await settle(w.provider.challenge({ ...context, ...target, response, credential: sent }));
  } else outcome = await settle(w.provider.credential(context));
  const result = { network_calls: w.state.network, authorization_server_requests: w.state.authorizationServer, required: lastRequired };
  // The target check yields the code the vector names for it.
  if (input.target_error) assert.equal(outcome.error?.code, input.target_error.code, 'target_error code');
  if (input.challenge?.status === 401) {
    const sentGeneration = input.sent === null || input.sent === undefined ? undefined : generation(input.sent);
    result.retired = w.store.writes.slice(writesBefore).some(write => write.key === key && sentGeneration !== undefined &&
      write.expected === sentGeneration && write.value && write.value.token === undefined);
  }
  if (outcome.error) return { ...result, ...errorFields(outcome.error) };
  const tokens = w.state.tokens.slice(tokensBefore);
  result.code = null;
  if (outcome.value?.type === 'pending_login') { result.action = 'login'; result.acquisition_scopes = urlScopes(outcome.value); }
  else if (tokens.some(body => body.get('grant_type') === 'client_credentials')) {
    result.action = 'acquire';
    result.acquisition_scopes = sorted(tokens.at(-1).get('scope').split(' '));
  } else if (tokens.some(body => body.get('grant_type') === 'refresh_token')) result.action = 'refresh';
  else result.action = 'use';
  return result;
}

/**
 * Temporary, until the next spec commit replaces it: this vector of spec 14d9eed demands
 * an issuer-metadata request before a PKCE 403 step-up's interaction_required, which
 * needs no authorization-server request. Remove when re-vendoring.
 */
const WITHDRAWN = new Map([['host-policy-issuer-metadata-destination-refused-challenge', 'withdrawn from spec 14d9eed; replaced in the next spec commit']]);
for (const vector of vectors.scope_decisions) {
  test(`shared scope decision: ${vector.id}`, { skip: skipFor(vector) || (WITHDRAWN.get(vector.id) ?? false) }, async () => {
    defined(vector, SCOPE_INPUT, SCOPE_EXPECT);
    compare(vector, await decideVector(vector.input));
  });
}

/** A token-endpoint answer for each error kind the vectors name. */
const tokenErrors = {
  ok: undefined,
  invalid_grant: () => Response.json({ error: 'invalid_grant' }, { status: 400 }),
  invalid_client: () => Response.json({ error: 'invalid_client' }, { status: 401 }),
  unauthorized_client: () => Response.json({ error: 'unauthorized_client' }, { status: 400 }),
  access_denied: () => Response.json({ error: 'access_denied' }, { status: 400 }),
  invalid_scope: () => Response.json({ error: 'invalid_scope' }, { status: 400 }),
  server_error: () => Response.json({ error: 'server_error' }, { status: 500 }),
  unreachable: () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); },
  not_found: () => new Response('not found', { status: 404 }),
  invalid_response: () => Response.json({ access_token: 'x', token_type: 'mac' }),
};

async function completeVector(input) {
  const source = input.client_source;
  const ceiling = sorted(input.stored_required ?? [], input.prepare_time_host_required ?? [], input.current_host_required ?? [], input.ceiling);
  const w = world({ flow: 'authorization_code_pkce', requested: ['read'], ceiling, source,
    required: input.stored_required ?? input.prepare_time_host_required ?? [],
    extra: { persistPendingLogins: true, ...(input.pending === 'expired' ? { loginLifetimeMs: 1 } : {}) } });
  const context = { backendId: 'backend', purpose: 'event', url: resource };
  const pending = await w.oauth.prepare(context, budget());
  const pendingKey = [...w.store.values.keys()].find(key => key.startsWith('ahp.oauth.pending:'));
  if (input.stored_required === null) {
    // A record written by an older release: no stored R; perhaps its prepare-time H.
    const { requiredScopes: _r, ...record } = w.store.values.get(pendingKey);
    const { requiredScopes: _h, ...client } = record.client;
    w.store.values.set(pendingKey, { ...record, client: input.prepare_time_host_required ? { ...client, requiredScopes: input.prepare_time_host_required } : client });
  }
  if (input.pending === 'expired') await new Promise(resolve => setTimeout(resolve, 5));
  if (input.pending === 'ended') await w.oauth.cancel(pending, budget());
  // Current host policy at completion.
  Object.assign(w.client, { allowedScopes: [...input.ceiling], scopes: ['read'], requiredScopes: input.current_host_required ?? input.stored_required ?? [] });
  if (!input.source_permitted) {
    // Host policy now selects another client source for this grant.
    if (source === 'preregistered') { delete w.client.clientId; w.client.registration = { clientName: 'vectors' }; }
    else { delete w.client.registration; delete w.client.clientMetadataDocument; w.client.clientId = 'client'; }
  }
  w.state.scope = input.granted.join(' ');
  w.state.hostError = input.host_error;
  const params = { state: pending.state };
  let url;
  switch (input.callback) {
    case 'valid': url = callbackFor(pending); break;
    case 'valid_with_server_params': url = callbackFor(pending, { session_state: 'opaque' }); break;
    case 'denied': url = callbackFor(pending, { code: undefined, error: 'access_denied' }); break;
    case 'denied_invalid_client': url = callbackFor(pending, { code: undefined, error: 'invalid_client' }); break;
    case 'redirect_mismatch': url = callbackFor(pending).replace('/callback', '/other'); break;
    case 'redirect_query_mismatch': url = callbackFor(pending).replace('app=1', 'app=2'); break;
    case 'state_duplicated': url = `${callbackFor(pending)}&state=${params.state}`; break;
    case 'iss_mismatch': url = callbackFor(pending, { iss: 'https://evil.example' }); break;
    case 'fragment': url = `${callbackFor(pending)}#fragment`; break;
    case 'userinfo': url = callbackFor(pending).replace('https://', 'https://user@'); break;
    case 'missing_code': url = callbackFor(pending, { code: undefined }); break;
    case 'code_and_error': url = callbackFor(pending, { error: 'access_denied' }); break;
    case 'duplicate_param': url = `${callbackFor(pending)}&code=again`; break;
    case 'unparseable': url = 'not a url'; break;
    default: assert.fail(`unknown callback ${input.callback}`);
  }
  if (input.pending === 'unknown') url = url.replace(pending.state, 'unknown-state');
  if (input.pending === 'absent') { const parsed = new URL(url); parsed.searchParams.delete('state'); url = parsed.href; }
  if (input.claim !== 'ok') {
    // The claim's store write fails; afterwards the login is gone, still pending, or unknowable.
    const { reread } = input.claim;
    w.store.failClaim = (key, value) => key === pendingKey && value === undefined ? (reread === 'gone' ? 'after' : 'before') : undefined;
    if (reread === 'undetermined') {
      let claimed = false;
      const fail = w.store.failClaim;
      w.store.failClaim = (key, value) => { const result = fail(key, value); if (result) claimed = true; return result; };
      w.store.failLoad = key => claimed && key === pendingKey;
    }
  }
  w.state.tokenError = tokenErrors[typeof input.exchange === 'string' ? input.exchange : 'ok'];
  const grantsBefore = grantKeys(w).length;
  const outcome = await settle(w.oauth.complete(url, budget()));
  const result = { grant_persisted: grantKeys(w).length > grantsBefore };
  if (!outcome.error) return { ...result, code: null };
  result.login_ended = outcome.error.loginEnded;
  return { ...result, ...errorFields(outcome.error) };
}

for (const vector of vectors.completions) {
  test(`shared completion: ${vector.id}`, { skip: skipFor(vector) }, async () => {
    defined(vector, COMPLETION_INPUT, COMPLETION_EXPECT);
    compare(vector, await completeVector(vector.input));
  });
}

/** A refresh (PKCE) or client-credentials grant whose token request fails with `error`. */
async function tokenErrorVector(input) {
  const refresh = input.grant_type === 'refresh';
  const w = world({ flow: refresh ? 'authorization_code_pkce' : 'client_credentials', requested: ['read'], ceiling: ['read'],
    source: input.client_source });
  const context = { backendId: 'backend', purpose: 'event', url: resource };
  if (refresh) {
    await w.oauth.complete(callbackFor(await w.oauth.prepare(context, budget())), budget());
    for (const key of grantKeys(w)) w.store.values.set(key, { ...w.store.values.get(key), expiresAt: Date.now() - 1 });
  }
  w.state.tokenError = tokenErrors[input.error];
  const outcome = await settle(refresh ? w.provider.credential(context) : w.oauth.prepare(context, budget()));
  assert.ok(outcome.error, 'the renewal fails');
  const result = errorFields(outcome.error);
  // A token_errors outcome never carries scopes.
  assert.equal(outcome.error.requiredScopes, undefined, 'no scopes');
  delete result.scopes;
  // The registrations sent after the first invalid_client, before the repeated one.
  if (!refresh && input.client_source === 'dcr' && input.error === 'invalid_client') result.reregistrations = (w.state.registrations ?? 0) - 1;
  return result;
}

for (const vector of vectors.token_errors) {
  test(`[renewal-token-errors-classified] shared token error: ${vector.id}`, { skip: skipFor(vector) }, async () => {
    defined(vector, TOKEN_ERROR_INPUT, TOKEN_ERROR_EXPECT);
    compare(vector, await tokenErrorVector(vector.input));
  });
}

/**
 * The same renewal against the legacy auth() provider (Hooks' default). It has
 * pre-registered clients only, so it runs the pre-registered vectors.
 */
async function legacyTokenErrorVector(input) {
  const refresh = input.grant_type === 'refresh';
  const legacyIssuer = 'https://identity.example.com', legacyResource = 'https://hooks.example.com/api';
  let failing = false, issued = 0;
  const provider = auth({ validateDestination() {}, resolveHostname: async () => ['93.184.216.34'],
    redirectUri: 'https://app.example/callback', authorize: request => `${request.redirectUri}?code=code&state=${request.state}`,
    selectClient: () => ({ issuer: legacyIssuer, resource: legacyResource, clientId: 'client', flow: refresh ? 'authorization_code_pkce' : 'client_credentials',
      scopes: ['read'] }),
    async fetch(url) {
      const target = String(url);
      if (target.includes('oauth-protected-resource')) return Response.json({ resource: legacyResource, authorization_servers: [legacyIssuer] });
      if (target.includes('well-known')) return Response.json({ issuer: legacyIssuer, token_endpoint: `${legacyIssuer}/token`,
        authorization_endpoint: `${legacyIssuer}/authorize`, code_challenge_methods_supported: ['S256'],
        grant_types_supported: ['client_credentials', 'authorization_code', 'refresh_token'] });
      if (failing) return tokenErrors[input.error]();
      issued++;
      return Response.json({ access_token: `legacy-${issued}`, token_type: 'Bearer', expires_in: 3600, scope: 'read',
        ...(refresh ? { refresh_token: `legacy-refresh-${issued}` } : {}) });
    } });
  const cache = new Map(), context = { url: `${legacyResource}/events`, cache };
  if (refresh) {
    await provider.authenticate({ ...context, challenged: true });
    for (const [key, value] of cache) cache.set(key, { ...value, expiresAt: 0 });
  }
  failing = true;
  const outcome = await settle(provider.authenticate({ ...context, ...(refresh ? {} : { challenged: true }) }));
  assert.ok(outcome.error, 'the renewal fails');
  // Hooks classifies whatever the provider throws; no scopes survive.
  const error = classifyAuthError(outcome.error);
  assert.equal(error.requiredScopes, undefined, 'no scopes');
  return { code: error.code };
}

for (const vector of vectors.token_errors.filter(vector => vector.input.client_source === 'preregistered')) {
  test(`[renewal-token-errors-classified] shared token error through legacy auth(): ${vector.id}`, { skip: skipFor(vector) }, async () => {
    defined(vector, TOKEN_ERROR_INPUT, TOKEN_ERROR_EXPECT);
    compare(vector, await legacyTokenErrorVector(vector.input));
  });
}

test('every shared vector names only known SDK features in requires', () => {
  for (const vector of Object.values(vectors).filter(Array.isArray).flat()) {
    assert.doesNotThrow(() => skipFor(vector), vector.id);
    for (const feature of vector.requires ?? []) assert.ok(KNOWN_FEATURES.includes(feature), `${vector.id}: ${feature}`);
  }
  assert.throws(() => skipFor({ id: 'x', requires: ['teleport'] }), /unknown SDK features: teleport/);
});

test('[complete-token-endpoint-errors-classified] token-endpoint errors after the claim are classified by client source, with no scopes', async () => {
  const base = { pending: 'pending', handle: 'none', source_permitted: true, callback: 'valid', claim: 'ok',
    stored_required: ['read', 'write'], granted: ['read', 'write'], ceiling: ['read', 'write'] };
  const expected = [
    ['preregistered', 'invalid_grant', 'interaction_required'], ['preregistered', 'invalid_client', 'credential_unavailable'],
    ['cimd', 'invalid_client', 'invalid_configuration'], ['dcr', 'invalid_client', 'interaction_required'],
    ...['unauthorized_client', 'access_denied', 'invalid_scope', 'server_error', 'unreachable', 'not_found', 'invalid_response']
      .map(exchange => ['preregistered', exchange, 'provider_failed']),
  ];
  for (const [client_source, exchange, code] of expected) {
    const result = await completeVector({ ...base, client_source, exchange });
    assert.equal(result.code, code, `${client_source} ${exchange}`);
    assert.equal(result.login_ended, true, `${client_source} ${exchange}`);
    assert.equal(result.grant_persisted, false, `${client_source} ${exchange}`);
    if ('scopes' in result) assert.deepEqual(result.scopes, [], `${client_source} ${exchange}`);
  }
});

test('the vector runner rejects unknown fields at every nesting level', () => {
  const base = vectors.scope_decisions.find(vector => vector.input.grant && vector.input.challenge && vector.input.host_error === undefined);
  const mutate = change => { const copy = structuredClone(base); change(copy); return copy; };
  for (const copy of [
    mutate(vector => { vector.extra = 1; }),
    mutate(vector => { vector.input.extra = 1; }),
    mutate(vector => { vector.expect.extra = 1; }),
    mutate(vector => { vector.input.grant.extra = 1; }),
    mutate(vector => { vector.input.challenge.extra = 1; }),
    mutate(vector => { vector.input.host_error = { callback: 'destination', extra: 1 }; }),
    mutate(vector => { vector.input.requested = [{ nested: true }]; }),
  ]) assert.throws(() => defined(copy, SCOPE_INPUT, SCOPE_EXPECT), /unknown field|unexpected object/);
  assert.doesNotThrow(() => defined(base, SCOPE_INPUT, SCOPE_EXPECT));
});
