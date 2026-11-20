// Executes the shared scope_decisions and completions vectors against managedOAuth at
// its real host boundaries (policyFetch, store, selectClient, checkDestination).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { managedOAuth } from '../dist/src/oauth/index.js';
import { AuthError } from '../dist/src/client/auth.js';
import { KNOWN_FEATURES, skipFor } from './fixtures/sdk-features.mjs';

const vectors = JSON.parse(readFileSync(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url), 'utf8'));
const budget = () => ({ signal: new AbortController().signal, deadline: Date.now() + 5000 });
const sorted = (...sets) => [...new Set(sets.flat())].sort();
const issuer = 'https://issuer.example', resource = 'https://api.example/events', redirect = 'https://app.example/callback';
const cimdUrl = 'https://app.example/client.json';

function memoryStore() {
  const values = new Map(), locks = new Map();
  return {
    values,
    async load(key, signal) { signal.throwIfAborted(); return structuredClone(values.get(key)); },
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

/**
 * One host and authorization server. `state.network` counts every policyFetch and
 * `state.authorizationServer` those to the issuer (metadata, registration, token).
 */
function world({ flow, requested, ceiling, required, source = 'preregistered', extra = {} }) {
  const store = memoryStore(), secrets = new Map();
  const state = { network: 0, authorizationServer: 0, tokens: [], scope: undefined, tokenError: undefined, n: 0,
    hostError: undefined, noRefresh: false };
  const client = { issuer, resource, flow, scopes: requested, allowedScopes: ceiling, requiredScopes: required, redirectUri: redirect,
    ...(source === 'preregistered' ? { clientId: 'client' } : {}),
    ...(source === 'preregistered' && flow === 'client_credentials' ? { clientSecret: 'secret' } : {}),
    ...(source === 'cimd' ? { clientMetadataDocument: { url: cimdUrl, redirectUris: [redirect] } } : {}),
    ...(source === 'dcr' ? { registration: { clientName: 'vectors' } } : {}) };
  const options = {
    namespace: 'vectors', store,
    secrets: { async put(ref, value) { secrets.set(ref, value); }, async get(ref) { return secrets.get(ref); }, async delete(ref) { secrets.delete(ref); } },
    selectClient: () => {
      if (state.hostError?.callback === 'client_selection') throw new AuthError(state.hostError.code, state.hostError.scopes);
      return structuredClone(client);
    },
    checkDestination: (_url, purpose) => {
      if (state.hostError?.callback === 'destination' && state.hostError.target === 'registration_endpoint' && purpose === 'registration') {
        throw new AuthError(state.hostError.code, state.hostError.scopes);
      }
    },
    async policyFetch(url, init) {
      state.network++;
      if (url.startsWith(issuer)) state.authorizationServer++;
      if (url === `${issuer}/register`) {
        const body = JSON.parse(String(init.body)), n = ++state.n;
        return Response.json({ client_id: `issued-${n}`, token_endpoint_auth_method: body.token_endpoint_auth_method,
          ...(body.token_endpoint_auth_method === 'none' ? {} : { client_secret: `issued-secret-${n}` }) }, { status: 201 });
      }
      if (url === `${issuer}/token`) {
        const body = new URLSearchParams(String(init.body));
        state.tokens.push(body);
        if (state.tokenError) return state.tokenError();
        const n = ++state.n;
        return Response.json({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: 3600,
          ...(flow === 'client_credentials' || state.noRefresh ? {} : { refresh_token: `refresh-${n}` }),
          scope: state.scope ?? body.get('scope') ?? '' });
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
const grants = w => [...w.store.values].filter(([key]) => key.startsWith('ahp.oauth.grant:')).map(([, value]) => value);
const settle = async promise => { try { return { value: await promise }; } catch (error) { return { error }; } };
const urlScopes = pending => sorted(new URL(pending.authorizationUrl).searchParams.get('scope').split(' '));
const callbackFor = (pending, params = {}) => {
  const url = new URL(redirect);
  url.search = new URLSearchParams({ code: 'code', state: pending.state, iss: issuer, ...params }).toString();
  return url.href;
};
/** Outcome fields comparable with a vector's `expect` (`required` is asserted through `scopes`). */
function observed(outcome) {
  if (!outcome.error) return { code: null };
  assert.ok(outcome.error instanceof AuthError, `not an AuthError: ${outcome.error?.stack ?? outcome.error}`);
  const { code } = outcome.error;
  return { code, ...(['access_denied', 'interaction_required'].includes(code) ? { scopes: [...(outcome.error.requiredScopes ?? [])] } : {}) };
}
function compare(expect, result) {
  for (const [key, want] of Object.entries(expect)) {
    if (key === 'required') continue;
    assert.deepEqual(result[key], want, `${key}: ${JSON.stringify(result)}`);
  }
}


async function decide(input) {
  const preset = input.preset_scopes ?? [], requested = sorted(input.requested), ceiling = input.ceiling ?? requested;
  const w = world({ flow: input.flow, requested, ceiling, required: [],
    source: input.host_error?.target === 'registration_endpoint' ? 'dcr' : 'preregistered' });
  const context = { backendId: 'backend', purpose: 'event', url: resource,
    ...(input.binding === 'preset' ? { authentication: { type: 'oauth', issuer, resource, clientId: 'client', flow: input.flow, scopes: preset } } : {}) };
  // Seed the stored binding (and the grant) through the real flows, with a valid configuration.
  const seeded = input.binding === 'stored' || (!['fresh', 'prepare'].includes(input.path) && input.granted !== null);
  if (seeded) {
    w.client.scopes = requested.filter(scope => ceiling.includes(scope));
    if (input.binding === 'preset') w.client.scopes = preset;
    w.state.scope = (input.granted ?? w.client.scopes).join(' ');
    if (input.flow === 'client_credentials') await w.oauth.prepare(context, budget());
    else await w.oauth.complete(callbackFor(await w.oauth.prepare(context, budget())), budget());
    if (input.granted === null) {
      for (const key of [...w.store.values.keys()]) if (/^ahp\.oauth\.(grant|registration)/.test(key)) w.store.values.delete(key);
    }
    w.client.scopes = requested;
    w.state.scope = undefined;
  }
  // A retired PKCE token is modelled without a refresh token.
  w.state.noRefresh = input.flow === 'authorization_code_pkce';
  for (const [key, grant] of w.store.values) if (key.startsWith('ahp.oauth.grant:') && w.state.noRefresh) w.store.values.set(key, { ...grant, refreshToken: undefined });
  w.client.requiredScopes = input.host_required;
  let sent;
  if (input.path === 'challenge' && input.granted !== null) {
    w.client.requiredScopes = [];
    sent = await w.provider.credential(context);
    w.client.requiredScopes = input.host_required;
  }
  w.state.hostError = input.host_error;
  const tokensBefore = w.state.tokens.length;
  w.state.network = 0; w.state.authorizationServer = 0;
  let outcome;
  if (input.path === 'prepare' || input.path === 'fresh') outcome = await settle(w.oauth.prepare(context, budget(), { requiredScopes: input.explicit }));
  else if (input.path === 'challenge') {
    const response = new Response(null, { status: input.challenge.status, headers: { 'www-authenticate': input.challenge.www_authenticate } });
    outcome = await settle(w.provider.challenge({ ...context, response, credential: sent }));
    // The transport's replay carries the challenge.
    if (!outcome.error) outcome = await settle(w.provider.credential({ ...context, challenged: true, challenge: input.challenge.www_authenticate }));
  } else outcome = await settle(w.provider.credential(context));
  const result = { ...observed(outcome), network_calls: w.state.network, authorization_server_requests: w.state.authorizationServer };
  if (sent) result.retired = grants(w)[0]?.token !== sent.token;
  if (!outcome.error) {
    const pending = outcome.value?.type === 'pending_login';
    result.action = pending ? 'login' : w.state.tokens.length > tokensBefore ? 'acquire' : 'use';
    if (pending) result.acquisition_scopes = urlScopes(outcome.value);
    else if (result.action === 'acquire') result.acquisition_scopes = sorted(w.state.tokens.at(-1).get('scope').split(' '));
  } else if (result.code === 'interaction_required') {
    // The next sign-in: host prepare with the error's scope set (and the challenge, for a 401 hint).
    w.state.hostError = undefined;
    const pending = await w.oauth.prepare({ ...context, ...(input.challenge ? { challenge: input.challenge.www_authenticate } : {}) },
      budget(), { requiredScopes: result.scopes });
    result.acquisition_scopes = urlScopes(pending);
  }
  return result;
}

for (const vector of vectors.scope_decisions) {
  test(`shared scope decision: ${vector.id}`, { skip: skipFor(vector) }, async () => {
    compare(vector.expect, await decide(vector.input));
  });
}

async function complete(input, source = input.client_source ?? 'preregistered') {
  const w = world({ flow: 'authorization_code_pkce', requested: ['read'], ceiling: sorted(input.stored_required, input.ceiling),
    required: input.stored_required, source, extra: input.pending === 'expired' ? { loginLifetimeMs: 1 } : {} });
  const context = { backendId: 'backend', purpose: 'event', url: resource };
  const pending = await w.oauth.prepare(context, budget());
  if (input.pending === 'expired') await new Promise(resolve => setTimeout(resolve, 5));
  if (input.pending === 'ended') await w.oauth.cancel(pending, budget());
  // The host's current ceiling at completion; the login keeps the R it was prepared with.
  w.client.allowedScopes = input.ceiling;
  w.state.scope = input.granted.join(' ');
  const params = { code: 'code', state: input.pending === 'unknown' ? 'unknown-state' : pending.state, iss: issuer };
  const url = new URL(redirect);
  switch (input.callback) {
    case 'denied': delete params.code; params.error = 'access_denied'; break;
    case 'redirect_mismatch': url.pathname = '/other'; break;
    case 'iss_mismatch': params.iss = 'https://evil.example'; break;
    case 'missing_code': delete params.code; break;
    case 'missing_state': delete params.state; break;
  }
  url.search = new URLSearchParams(params).toString();
  let callback = url.href;
  if (input.callback === 'fragment') callback += '#fragment';
  if (input.callback === 'userinfo') callback = callback.replace('https://', 'https://user@');
  if (input.callback === 'duplicate_param') callback += '&code=again';
  w.state.tokenError = {
    invalid_grant: () => Response.json({ error: 'invalid_grant' }, { status: 400 }),
    invalid_client: () => Response.json({ error: 'invalid_client' }, { status: 401 }),
    token_endpoint_failure: () => new Response('{}', { status: 503 }),
    invalid_response: () => Response.json({ access_token: 'x', token_type: 'mac' }),
  }[input.exchange];
  // A host callback failure before the claim (client selection reselects host client authentication).
  w.state.hostError = input.host_error;
  const outcome = await settle(w.oauth.complete(callback, budget()));
  const result = { ...observed(outcome), grant_persisted: grants(w).length > 0 };
  if (outcome.error) result.login_ended = outcome.error.loginEnded;
  if (input.host_error && result.login_ended === false) {
    // The login is still pending: once the host recovers, the same callback completes it.
    w.state.hostError = undefined;
    assert.equal((await w.oauth.complete(callback, budget())).type, 'ready', 'the login still completes');
  }
  return result;
}

for (const vector of vectors.completions) {
  test(`shared completion: ${vector.id}`, { skip: skipFor(vector) }, async () => {
    compare(vector.expect, await complete(vector.input));
  });
}

test('[complete-error-login-ended] a token-endpoint invalid_client after the claim fails by client source, login ended, no scopes', async () => {
  const input = { pending: 'pending', callback: 'valid', exchange: 'invalid_client', stored_required: ['read', 'write'], granted: ['read', 'write'], ceiling: ['read', 'write'] };
  const expected = { preregistered: 'credential_unavailable', cimd: 'invalid_configuration', dcr: 'interaction_required' };
  for (const [source, code] of Object.entries(expected)) {
    const result = await complete(input, source);
    assert.equal(result.code, code, source);
    assert.equal(result.login_ended, true, source);
    assert.equal(result.grant_persisted, false, source);
    if ('scopes' in result) assert.deepEqual(result.scopes, [], source);
  }
});

test('every shared vector names only known SDK features in requires', () => {
  const sections = Object.values(vectors).filter(Array.isArray);
  for (const vector of sections.flat()) {
    assert.doesNotThrow(() => skipFor(vector), vector.id);
    for (const feature of vector.requires ?? []) assert.ok(KNOWN_FEATURES.includes(feature), `${vector.id}: ${feature}`);
  }
  assert.throws(() => skipFor({ id: 'x', requires: ['teleport'] }), /unknown SDK features: teleport/);
});
