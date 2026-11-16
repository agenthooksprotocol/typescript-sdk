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
  test(`issuer discovery preserves a trailing path slash (OIDC fallback: ${fallback})`, async () => {
    const requests = [];
    const expected = [
      'https://resource.example/.well-known/oauth-protected-resource/events',
      'https://issuer.example/.well-known/oauth-authorization-server/tenant/',
      ...(fallback ? [
        'https://issuer.example/.well-known/openid-configuration/tenant/',
        'https://issuer.example/tenant/.well-known/openid-configuration',
      ] : []),
    ];
    const resolved = await resolveTarget({ url: resource, challenged: true }, options(async url => {
      requests.push(url);
      if (url === expected[0]) return Response.json({ resource, authorization_servers: [issuer] });
      if (fallback && requests.length < expected.length) return new Response(null, { status: 404 });
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
