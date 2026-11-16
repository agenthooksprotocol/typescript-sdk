import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveTarget } from '../dist/src/discovery.js';
import { acquireClientCredentials } from '../dist/src/protocol.js';


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

