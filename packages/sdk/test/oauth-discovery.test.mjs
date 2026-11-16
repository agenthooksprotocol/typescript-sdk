import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveTarget } from '../dist/src/oauth/discovery.js';
import { acquireClientCredentials } from '../dist/src/oauth/protocol.js';


const operation = () => ({ signal: new AbortController().signal, deadline: Date.now() + 10_000 });
const issuer = 'https://issuer.example/tenant/';
const resource = 'https://resource.example/events';
const target = {
  client: { issuer, resource, clientId: 'client', clientSecret: 'secret', flow: 'client_credentials', scopes: ['deliver'] },
  metadata: { issuer, token_endpoint: 'https://issuer.example/token', grant_types_supported: ['client_credentials'] },
};
const options = policyFetch => ({ checkDestination() {}, policyFetch, selectClient: () => target.client });

for (const fallback of [false, true]) {
  test(`issuer lookup removes the trailing slash but preserves exact issuer identity (OIDC fallback: ${fallback})`, async () => {
    const requests = [];
    const expected = [
      'https://resource.example/.well-known/oauth-protected-resource/events',
      'https://issuer.example/.well-known/oauth-authorization-server/tenant',
      ...(fallback ? [
        'https://issuer.example/.well-known/openid-configuration/tenant',
        'https://issuer.example/tenant/.well-known/openid-configuration',
      ] : []),
    ];
    const resolved = await resolveTarget({ url: resource, challenged: true }, options(async url => {
      requests.push(url);
      if (url === expected[0]) return Response.json({ resource, authorization_servers: [issuer] });
      if (fallback && requests.length < expected.length) return new Response(null, { status: 404 });
      assert.equal(url, expected.at(-1), "only the conforming well-known endpoint serves metadata");
      return Response.json(target.metadata);
    }), operation());
    assert.equal(resolved.metadata.issuer, issuer);
    assert.deepEqual(requests, expected);
  });
}

for (const access_token of ['has;separator', 'tokené', 'pad=middle', '=']) {
  test(`rejects an access token outside RFC 6750 b64token grammar: ${access_token}`, async () => {
    await assert.rejects(acquireClientCredentials(target, options(async () => Response.json({
      access_token, token_type: 'Bearer', expires_in: 300,
    })), operation()), { code: 'provider_failed' });
  });
}

for (const scope of [' deliver', 'deliver ', 'deliver  deliver', '']) {
  test(`rejects a malformed token response scope: ${JSON.stringify(scope)}`, async () => {
    await assert.rejects(acquireClientCredentials(target, options(async () => Response.json({
      access_token: 'valid-token', token_type: 'Bearer', expires_in: 300, scope,
    })), operation()), { code: 'provider_failed' });
  });
}

test('accepts RFC 6750 token punctuation and optional padding', async () => {
  const credential = await acquireClientCredentials(target, options(async () => Response.json({
    access_token: 'a-Z_0.~+/==', token_type: 'Bearer', expires_in: 300, scope: 'deliver',
  })), operation());
  assert.equal(credential.token, 'a-Z_0.~+/==');
});

for (const endpoint of [
  'https://resource.example/events?tenant=one&aud=a%2Fb',
  'https://resource.example/?tenant=one',
  'https://resource.example/events?',
]) {
  test(`resource path discovery preserves query and exact source identity: ${endpoint}`, async () => {
    const requests = [];
    const source = new URL(endpoint);
    const query = endpoint.slice(endpoint.indexOf('?'));
    const specific = `${source.origin}/.well-known/oauth-protected-resource${source.pathname === '/' ? '' : source.pathname}${query}`;
    const config = { ...target.client, resource: endpoint };
    const resolved = await resolveTarget({ url: endpoint, challenged: true }, {
      ...options(async url => {
        requests.push(url);
        if (url === specific) return Response.json({ resource: endpoint, authorization_servers: [issuer] });
        assert.equal(url, 'https://issuer.example/.well-known/oauth-authorization-server/tenant');
        return Response.json(target.metadata);
      }),
      selectClient: () => config,
    }, operation());
    assert.equal(resolved.client.resource, endpoint);
    assert.equal(requests[0], specific);
    assert.equal(requests.length, 2);
  });
}

for (const returnedResource of [resource, `${resource}?tenant=two`, `${resource}?tenant=one&extra=1`]) {
  test(`query source rejects nonidentical metadata resource without fallback: ${returnedResource}`, async () => {
    const endpoint = `${resource}?tenant=one`, requests = [];
    await assert.rejects(resolveTarget({ url: endpoint, challenged: true }, options(async url => {
      requests.push(url);
      return Response.json({ resource: returnedResource, authorization_servers: [issuer] });
    }), operation()), { code: 'discovery_failed' });
    assert.deepEqual(requests, ['https://resource.example/.well-known/oauth-protected-resource/events?tenant=one']);
  });
}

test('query-specific 404 falls back to origin-root with origin source identity', async () => {
  const requests = [], endpoint = `${resource}?tenant=one`;
  const resolved = await resolveTarget({ url: endpoint, challenged: true }, {
    ...options(async url => {
      requests.push(url);
      if (url.endsWith('/events?tenant=one')) return new Response(null, { status: 404 });
      if (url === 'https://resource.example/.well-known/oauth-protected-resource') {
        return Response.json({ resource: 'https://resource.example', authorization_servers: [issuer] });
      }
      return Response.json(target.metadata);
    }),
    selectClient: () => ({ ...target.client, resource: 'https://resource.example' }),
  }, operation());
  assert.equal(resolved.client.resource, 'https://resource.example');
  assert.deepEqual(requests.slice(0, 2), [
    'https://resource.example/.well-known/oauth-protected-resource/events?tenant=one',
    'https://resource.example/.well-known/oauth-protected-resource',
  ]);
});

test('root fallback rejects the endpoint identifier in place of its origin source', async () => {
  const endpoint = `${resource}?tenant=one`, requests = [];
  await assert.rejects(resolveTarget({ url: endpoint, challenged: true }, options(async url => {
    requests.push(url);
    if (requests.length === 1) return new Response(null, { status: 404 });
    return Response.json({ resource: endpoint, authorization_servers: [issuer] });
  }), operation()), { code: 'discovery_failed' });
  assert.equal(requests.length, 2);
});

test('normalized issuer lookup does not normalize the metadata issuer identity', async () => {
  await assert.rejects(resolveTarget({ url: resource, challenged: true }, options(async url => {
    if (url.startsWith('https://resource.example/')) return Response.json({ resource, authorization_servers: [issuer] });
    assert.equal(url, 'https://issuer.example/.well-known/oauth-authorization-server/tenant');
    return Response.json({ ...target.metadata, issuer: issuer.slice(0, -1) });
  }), operation()), { code: 'discovery_failed' });
});

const preset = { type: 'oauth', ...target.client };
for (const flow of ['client_credentials', 'authorization_code_pkce']) {
  test(`configured ${flow} preset skips PRM but validates issuer metadata and scope policy`, async () => {
    const requests = [];
    const client = { ...target.client, flow, allowedScopes: ['deliver', 'extra'], requiredScopes: ['deliver'] };
    const metadata = { ...target.metadata, grant_types_supported: ['client_credentials', 'authorization_code'],
      authorization_endpoint: `${issuer}authorize`, code_challenge_methods_supported: ['S256'] };
    const resolved = await resolveTarget({ url: resource, authentication: { ...preset, flow },
      challenge: 'Bearer resource_metadata="https://attacker.example/metadata", scope="extra"' }, {
      ...options(async url => { requests.push(url); return Response.json(metadata); }), selectClient: () => client,
    }, operation());
    assert.deepEqual(requests, ['https://issuer.example/.well-known/oauth-authorization-server/tenant']);
    assert.deepEqual(resolved.client.scopes, ['deliver']);
    assert.deepEqual(resolved.client.allowedScopes, ['deliver', 'extra']);
    assert.deepEqual(resolved.client.requiredScopes, ['deliver', 'extra']);
    assert.ok(Object.isFrozen(resolved.client.requiredScopes));
  });
}

test('preset issuer mismatch fails without a protected-resource fallback', async () => {
  const requests = [];
  await assert.rejects(resolveTarget({ url: resource, authentication: preset }, options(async url => {
    requests.push(url); return Response.json({ ...target.metadata, issuer: 'https://other.example' });
  }), operation()), { code: 'discovery_failed' });
  assert.equal(requests.length, 1);
});

test('preset local principal mismatch fails before metadata I/O', async () => {
  await assert.rejects(resolveTarget({ url: resource, authentication: preset }, {
    ...options(() => assert.fail('no network for forbidden local principal')),
    selectClient: () => ({ ...target.client, clientId: 'different' }),
  }, operation()), { code: 'invalid_configuration' });
});

test('challenge requirement outside local ceiling fails before issuer I/O', async () => {
  await assert.rejects(resolveTarget({ url: resource, authentication: preset,
    challenge: 'Bearer error="insufficient_scope", scope="forbidden"' },
  options(() => assert.fail('forbidden scopes must not reach metadata')), operation()), { code: 'access_denied' });
});

test('discovery preserves native cancellation from an in-flight host selection', async () => {
  const controller = new AbortController(), reason = new DOMException('host cancellation', 'AbortError');
  await assert.rejects(resolveTarget({ url: resource, authentication: preset }, {
    ...options(() => assert.fail('cancelled selection must not fetch metadata')),
    selectClient: () => { controller.abort(reason); throw new Error('provider detail'); },
  }, { signal: controller.signal, deadline: Date.now() + 10_000 }), error => error === reason);
});

test('cached discovery revalidates local client policy and current secrets without metadata I/O', async () => {
  const resolved = await resolveTarget({ url: resource, authentication: preset }, {
    ...options(() => assert.fail('valid cached metadata must not require network')),
    selectClient: () => ({ ...target.client, scopes: ['deliver', 'deliver'], clientSecret: 'rotated-secret' }),
  }, operation(), target);
  assert.equal(resolved.client.clientSecret, 'rotated-secret');
  assert.deepEqual(resolved.client.scopes, ['deliver']);
});

test('cached discovery cannot bypass current local destination policy', async () => {
  await assert.rejects(resolveTarget({ url: 'https://other.example/events', authentication: preset },
    options(() => assert.fail('forbidden destination must not fetch metadata')), operation(), target), { code: 'discovery_failed' });
});
