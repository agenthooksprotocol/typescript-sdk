import test from "node:test";
import assert from "node:assert/strict";
import { auth } from "agenthooksprotocol/client";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { classifyAuthError } from "agenthooksprotocol/client/auth";

// Default delegation uses context composition, not JavaScript call-site `this`.
test("default authenticate delegation preserves overrides and external token persistence", async () => {
  const saved = new Map();
  let writes = 0;
  const { provider, tokens } = fixture({
    authenticate(context, options) {
      return auth.authenticate(context, options);
    },
    getToken(key) {
      return saved.get(key);
    },
    setToken(key, token) {
      writes++;
      saved.set(key, token);
    },
    deleteToken(key) {
      saved.delete(key);
    },
  });
  const context = { url, authentication: binding };
  await provider.authenticate(context);
  await provider.authenticate(context);
  assert.equal(tokens.length, 1);
  assert.equal(writes, 1);
  assert.equal(saved.size, 1);
  const bearer = auth({
    authenticate(context) {
      return auth.authenticate(context);
    },
    resolveEnvironmentVariable() {
      return "composed";
    },
  });
  assert.equal(
    (
      await bearer.authenticate({
        url,
        authentication: { type: "bearer", tokenEnv: "A" },
      })
    ).token,
    "composed",
  );
  assert.equal(
    auth.resolveEnvironmentVariable(
      "AHP_TEST_NONEXISTENT_ENVIRONMENT_VARIABLE",
    ),
    undefined,
  );
});

test("DNS policy rejects private, mixed and empty resolution before fetching metadata", async () => {
  for (const addresses of [
    ["127.0.0.1"],
    ["::ffff:127.0.0.1"],
    ["10.0.0.1"],
    ["93.184.216.34", "169.254.169.254"],
    [],
  ]) {
    const { provider, requests } = fixture({
      resolveHostname: async () => addresses,
    });
    await assert.rejects(
      provider.authenticate({ url, authentication: binding }),
      /forbidden resolved destination/,
    );
    assert.equal(requests.length, 0);
  }
});

test("address policy checks IPv6-embedded IPv4 as IPv4, for resolved addresses and literals", async () => {
  const refused = [
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "::ffff:10.0.0.1", "::ffff:0:0",
    "::127.0.0.1", "::7f00:1", "::a00:1", "::", "::1",
    "64:ff9b::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:1",
    "2002:7f00:1::1", "2002:a9fe:a9fe::", "2002:c0a8:101::1", "2002:0a00:0001::",
    "64:ff9b:1::5db8:d822", "2001:db8::1", "2001:0:5db8:d822::1", "fe80::1", "fc00::1", "ff02::1",
    "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.18.0.1", "240.0.0.1",
  ];
  for (const address of refused) {
    const { provider, requests } = fixture({ resolveHostname: async () => [address] });
    await assert.rejects(provider.authenticate({ url, authentication: binding }), /forbidden resolved destination/, address);
    assert.equal(requests.length, 0);
  }
  for (const literal of ["[::ffff:127.0.0.1]", "[::ffff:a9fe:a9fe]", "[::127.0.0.1]", "[64:ff9b::a9fe:a9fe]", "[2002:a9fe:a9fe::1]", "[::ffff:10.0.0.1]"]) {
    const { provider, requests } = fixture();
    const issuerUrl = `https://${literal}/tenant`;
    await assert.rejects(
      provider.authenticate({ url, authentication: { ...binding, issuer: issuerUrl } }),
      /forbidden destination/, literal);
    assert.equal(requests.length, 0);
  }
  for (const address of ["::ffff:93.184.216.34", "::ffff:5db8:d822", "64:ff9b::5db8:d822", "2002:5db8:d822::1", "2606:2800:220:1::1", "93.184.216.34"]) {
    const { provider } = fixture({ resolveHostname: async () => [address] });
    assert.equal((await provider.authenticate({ url, authentication: binding })).token, "token-1", address);
  }
});

test("default transport permits explicitly trusted loopback and never follows token redirects", async () => {
  let origin,
    redirects = false,
    tokens = 0,
    leaked = false;
  const server = createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.url.includes("oauth-protected-resource"))
      response.end(
        JSON.stringify({
          resource: `${origin}/api`,
          authorization_servers: [origin],
        }),
      );
    else if (request.url.includes("well-known"))
      response.end(
        JSON.stringify({
          ...metadata,
          issuer: origin,
          token_endpoint: `${origin}/token`,
        }),
      );
    else if (request.url === "/token") {
      tokens++;
      if (redirects) {
        response.writeHead(302, { location: `${origin}/leaked` });
        response.end();
      } else
        response.end(
          JSON.stringify({
            access_token: "local",
            token_type: "bearer",
            expires_in: 60,
          }),
        );
    } else {
      leaked = true;
      response.end("{}");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const provider = auth({ allowedLoopbackOrigins: [origin] });
    const authentication = {
      ...binding,
      issuer: origin,
      resource: `${origin}/api`,
      scopes: [],
    };
    assert.equal(
      (
        await provider.authenticate({
          url: `${origin}/api/events`,
          authentication,
        })
      ).token,
      "local",
    );
    redirects = true;
    await assert.rejects(
      provider.authenticate({ url: `${origin}/api/uploads`, authentication }),
      /token request rejected/,
    );
    assert.equal(tokens, 2);
    assert.equal(leaked, false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

const issuer = "https://identity.example.com/tenant";
const resource = "https://hooks.example.com/api";
const url = `${resource}/events`;
const binding = {
  type: "oauth",
  issuer,
  resource,
  clientId: "client",
  flow: "client_credentials",
  scopes: ["hooks"],
};
const metadata = {
  issuer,
  token_endpoint: "https://identity.example.com/token",
  authorization_endpoint: "https://identity.example.com/authorize",
  grant_types_supported: [
    "client_credentials",
    "authorization_code",
    "refresh_token",
  ],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
};
function fixture(extra = {}) {
  const requests = [];
  const tokens = [];
  const options = {
    validateDestination() {},
    async resolveHostname() {
      return ["93.184.216.34"];
    },
    async fetch(input, init = {}) {
      const target = String(input);
      requests.push({ url: target, init });
      assert.equal(init.redirect, "error");
      if (target.includes("oauth-protected-resource"))
        return Response.json({ resource, authorization_servers: [issuer] });
      if (target.includes("well-known")) return Response.json(metadata);
      tokens.push(new URLSearchParams(init.body));
      return Response.json({
        access_token: `token-${tokens.length}`,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "refresh",
        scope: "hooks",
      });
    },
    ...extra,
  };
  return { provider: auth(options), options, requests, tokens };
}

test("auth exposes callable defaults and composes bearer resolution without discovery", async () => {
  assert.equal(typeof auth.authenticate, "function");
  assert.equal(typeof auth.exchangeAuthorizationCode, "function");
  const resolved = [];
  const provider = auth({
    resolveEnvironmentVariable(name) {
      resolved.push(name);
      return "env-token";
    },
    resolveCredentialReference(name) {
      resolved.push(name);
      return "ref-token";
    },
    discover() {
      throw new Error("must not discover");
    },
  });
  assert.deepEqual(
    await provider.authenticate({
      url,
      authentication: { type: "bearer", tokenEnv: "TOKEN" },
    }),
    { token: "env-token" },
  );
  assert.deepEqual(
    await provider.authenticate({
      url,
      challenge: "Bearer",
      authentication: { type: "bearer", tokenRef: "vault/key" },
    }),
    { token: "ref-token" },
  );
  assert.deepEqual(resolved, ["TOKEN", "vault/key"]);
  await assert.rejects(
    provider.authenticate({
      url,
      authentication: { type: "bearer", tokenEnv: "A", tokenRef: "B" },
    }),
    /exactly one/,
  );
  await assert.rejects(
    auth().authenticate({
      url,
      authentication: { type: "bearer", tokenRef: "missing" },
    }),
    /unavailable/,
  );
});

test("absent binding starts anonymous and discovers on a 401 without a challenge header", async () => {
  const { provider, tokens } = fixture({
    selectClient: () => ({ ...binding }),
  });
  assert.equal(await provider.authenticate({ url }), undefined);
  const credential = await provider.authenticate({ url, challenged: true });
  assert.equal(credential.token, "token-1");
  assert.equal(tokens[0].get("resource"), resource);
  assert.equal(tokens[0].get("scope"), "hooks");
  assert.equal(tokens[0].get("grant_type"), "client_credentials");
});

test("the built-in provider uses only pre-registered clients: none is credential_unavailable", async () => {
  const { provider, requests } = fixture({
    selectClient: () => { const { clientId: _clientId, ...rest } = binding; return rest; },
  });
  await assert.rejects(provider.authenticate({ url, challenged: true }), (error) => {
    assert.equal(error.code, "credential_unavailable");
    return true;
  });
  assert.ok(requests.every((request) => !String(request.url ?? request).includes("register")));
});

test("discovery requires explicit issuer selection but destination policy is an optional restriction", async () => {
  const { provider } = fixture({ validateDestination: undefined });
  await assert.rejects(
    provider.authenticate({ url, challenged: true }),
    /client selection required/,
  );
  assert.equal(
    (await provider.authenticate({ url, authentication: binding })).token,
    "token-1",
  );
  await assert.rejects(
    provider.authenticate(
      { url: `${resource}/uploads`, authentication: binding },
      {
        validateDestination() {
          throw new Error("host policy denied");
        },
      },
    ),
    /host policy denied/,
  );
});

test("automatic OAuth discovery survives spread contexts and remains scoped to the client cache", async () => {
  let now = 1000;
  const { provider, requests, tokens } = fixture({
    now: () => now,
    selectClient: () => ({ ...binding }),
  });
  const context = { url, cache: new Map() };
  assert.equal(await provider.authenticate({ ...context }), undefined);
  assert.equal(
    (await provider.authenticate({ ...context, challenged: true })).token,
    "token-1",
  );
  const discoveredRequests = requests.length;
  assert.equal((await provider.authenticate({ ...context })).token, "token-1");
  assert.equal(requests.length, discoveredRequests);
  now += 3_600_000;
  assert.equal((await provider.authenticate({ ...context })).token, "token-2");
  assert.equal(requests.length, discoveredRequests + 1);
  // Client credentials always reissue, even when the server sent a refresh token.
  assert.equal(tokens[1].get("grant_type"), "client_credentials");
  // Another Hooks instance may reuse the provider, but it supplies a fresh Map.
  const independent = { url, cache: new Map() };
  assert.equal(await provider.authenticate({ ...independent }), undefined);
  assert.equal(
    (await provider.authenticate({ ...independent, challenged: true })).token,
    "token-3",
  );
  assert.equal(tokens[2].get("grant_type"), "client_credentials");
  // An upload endpoint does not inherit the event endpoint's discovered identity.
  assert.equal(
    await provider.authenticate({ ...context, url: `${resource}/uploads` }),
    undefined,
  );
});

test("discovery honors quoted challenge metadata after realm and enforces scope policy", async () => {
  const { provider, requests } = fixture({
    selectClient: () => ({ ...binding }),
  });
  await provider.authenticate({
    url,
    challenge: `Bearer realm="hooks, events", resource_metadata="https://hooks.example.com/.well-known/oauth-protected-resource", scope="hooks"`,
  });
  assert.equal(
    requests[0].url,
    "https://hooks.example.com/.well-known/oauth-protected-resource",
  );
  await assert.rejects(
    provider.authenticate({
      url,
      authentication: binding,
      challenge: 'Bearer error="insufficient_scope", scope="admin"',
    }),
    { code: "access_denied", recovery: "none", requiredScopes: ["admin"] },
  );
});

test("well-known metadata falls back in standard order and issuer identity is exact", async () => {
  const attempts = [];
  const { provider } = fixture({
    selectClient: () => ({ ...binding }),
    async fetch(input) {
      const target = String(input);
      attempts.push(target);
      if (
        target ===
        "https://hooks.example.com/.well-known/oauth-protected-resource"
      )
        return Response.json({ resource, authorization_servers: [issuer] });
      if (
        target ===
        "https://identity.example.com/tenant/.well-known/openid-configuration"
      )
        return Response.json({ ...metadata, issuer: `${issuer}/` });
      return new Response(null, { status: 404 });
    },
  });
  await assert.rejects(
    provider.authenticate({ url, challenged: true }),
    /issuer mismatch/,
  );
  assert.deepEqual(attempts, [
    "https://hooks.example.com/.well-known/oauth-protected-resource/api/events",
    "https://hooks.example.com/.well-known/oauth-protected-resource",
    "https://identity.example.com/.well-known/oauth-authorization-server/tenant",
    "https://identity.example.com/.well-known/openid-configuration/tenant",
    "https://identity.example.com/tenant/.well-known/openid-configuration",
  ]);
});

test("PKCE validates host callback state and exchanges code through overridable default", async () => {
  let exchange;
  const { provider, tokens } = fixture({
    redirectUri: "http://127.0.0.1:9876/callback",
    async authorize(request) {
      const authorization = new URL(request.url);
      assert.equal(
        authorization.searchParams.get("code_challenge_method"),
        "S256",
      );
      assert.equal(authorization.searchParams.get("resource"), resource);
      assert.ok(authorization.searchParams.get("code_challenge").length >= 43);
      return `${request.redirectUri}?state=${request.state}&code=code`;
    },
    async exchangeAuthorizationCode(request, context, options) {
      exchange = request;
      return auth.exchangeAuthorizationCode(request, context, options);
    },
  });
  const credential = await provider.authenticate({
    url,
    authentication: { ...binding, flow: "authorization_code_pkce" },
  });
  assert.equal(credential.token, "token-1");
  assert.equal(tokens[0].get("code"), "code");
  assert.equal(tokens[0].get("code_verifier"), exchange.verifier);
  assert.equal(tokens[0].get("redirect_uri"), "http://127.0.0.1:9876/callback");
});

test("invalid or denied PKCE callbacks never reach the token endpoint", async () => {
  for (const callback of [
    (request) => `${request.redirectUri}?state=wrong&code=secret`,
    (request) =>
      `https://evil.example.com/callback?state=${request.state}&code=secret`,
    (request) =>
      `${request.redirectUri}?state=${request.state}&error=access_denied`,
    (request) =>
      `${request.redirectUri}?state=${request.state}&state=${request.state}&code=secret`,
  ]) {
    const { provider, tokens } = fixture({
      redirectUri: "https://client.example.com/callback",
      authorize: callback,
    });
    await assert.rejects(
      provider.authenticate({
        url,
        authentication: { ...binding, flow: "authorization_code_pkce" },
      }),
      /Authentication failed/,
    );
    assert.equal(tokens.length, 0);
  }
});

test("tokens refresh in their own endpoint cache and provider instances never share credentials", async () => {
  let now = 1000;
  const first = fixture({ now: () => now });
  const context = { url, authentication: binding, cache: new Map() };
  assert.equal((await first.provider.authenticate(context)).token, "token-1");
  assert.equal((await first.provider.authenticate(context)).token, "token-1");
  assert.equal(first.tokens.length, 1);
  now += 3_600_000;
  assert.equal((await first.provider.authenticate(context)).token, "token-2");
  // Client credentials always reissue, even when the server sent a refresh token.
  assert.equal(first.tokens[1].get("grant_type"), "client_credentials");
  await first.provider.authenticate({ ...context, url: `${resource}/uploads` });
  assert.equal(first.tokens[2].get("grant_type"), "client_credentials");
  const second = fixture();
  await second.provider.authenticate({ url, authentication: binding });
  assert.equal(second.tokens.length, 1);
});

test("interactive cancellation interrupts an unresponsive host callback", async () => {
  const controller = new AbortController();
  const { provider } = fixture({
    redirectUri: "https://client.example.com/callback",
    authorize() {
      controller.abort(new Error("cancelled"));
      return new Promise(() => {});
    },
  });
  await assert.rejects(
    provider.authenticate({
      url,
      signal: controller.signal,
      authentication: { ...binding, flow: "authorization_code_pkce" },
    }),
    /cancelled/,
  );
});

test("credential acquisition failures redact remote error bodies and reject private destinations", async () => {
  const { provider, options } = fixture();
  await assert.rejects(
    provider.authenticate(
      { url, authentication: binding },
      {
        ...options,
        fetch: async (input, init) =>
          String(input).includes("well-known")
            ? options.fetch(input, init)
            : new Response("secret token detail", { status: 400 }),
      },
    ),
    (error) =>
      !error.message.includes("secret token detail") &&
      /token request rejected/.test(error.message),
  );
  await assert.rejects(
    provider.authenticate({
      url,
      challenge: 'Bearer resource_metadata="https://127.0.0.1/private"',
    }),
    /forbidden destination/,
  );
});

const scopeVectors = JSON.parse(readFileSync(new URL("../testdata/sdk-auth-lifecycle.json", import.meta.url), "utf8"))
  .token_responses.filter((vector) => /^(?:initial|refresh)-(?:empty|whitespace|null|numeric|array|repeated-separator|leading-separator|tab-separator)-scope$/.test(vector.id));
for (const vector of scopeVectors) {
  test(`built-in auth applies the token-response scope rule: ${vector.id}`, async () => {
    const stored = [];
    const cached = vector.exchange === "refresh"
      ? { token: "old", expiresAt: 1, refreshToken: "previous-refresh", scopes: vector.previous_granted }
      : undefined;
    const { provider, tokens } = fixture({
      async fetch(input, init = {}) {
        const target = String(input);
        if (target.includes("oauth-protected-resource")) return Response.json({ resource, authorization_servers: [issuer] });
        if (target.includes("well-known")) return Response.json(metadata);
        tokens.push(new URLSearchParams(init.body));
        return Response.json(vector.response);
      },
      getToken: () => cached,
      setToken: (_key, value) => { stored.push(value); },
      deleteToken() {},
    });
    // A refresh is a PKCE grant's (client credentials always reissue).
    const authentication = { ...binding, ...(vector.exchange === "refresh" ? { flow: "authorization_code_pkce" } : {}),
      scopes: vector.requested.filter((scope) => vector.allowed.includes(scope)), allowedScopes: vector.allowed };
    const result = provider.authenticate({ url, authentication });
    if (vector.usable) {
      const credential = await result;
      assert.equal(credential.token, vector.response.access_token);
      assert.deepEqual([...credential.scopes].sort(), [...vector.granted].sort());
      assert.deepEqual([...stored.at(-1).scopes].sort(), [...vector.granted].sort());
    } else {
      await assert.rejects(result, (error) => {
        assert.match(error.message, /invalid token scope/);
        assert.equal(classifyAuthError(error).code, vector.error);
        return true;
      });
      assert.ok(stored.every((value) => value.token !== vector.response.access_token), "an invalid response is never dispatched");
    }
    assert.equal(tokens.length, 1);
    if (vector.exchange === "refresh") assert.equal(tokens[0].get("grant_type"), "refresh_token");
  });
}

test("built-in refresh with an omitted scope inherits the previous grant, not the current request", async () => {
  for (const scope of [undefined, null, "", " \r\n"]) {
    const stored = [];
    const { provider } = fixture({
      async fetch(input) {
        const target = String(input);
        if (target.includes("oauth-protected-resource")) return Response.json({ resource, authorization_servers: [issuer] });
        if (target.includes("well-known")) return Response.json(metadata);
        return Response.json({ access_token: "refreshed", token_type: "Bearer", ...(scope === undefined ? {} : { scope }) });
      },
      getToken: () => ({ token: "old", expiresAt: 1, refreshToken: "r", scopes: ["hooks", "admin"] }),
      setToken: (_key, value) => { stored.push(value); },
      deleteToken() {},
    });
    const credential = await provider.authenticate({ url, authentication: { ...binding, flow: "authorization_code_pkce", scopes: ["hooks"], allowedScopes: ["hooks"] } });
    assert.deepEqual(credential.scopes, ["hooks", "admin"], String(scope));
    assert.equal(stored[0].refreshToken, "r");
  }
});

// Initial exchanges with a host-selected ceiling: narrowing, broadening and required scopes.
const ceilingVectors = JSON.parse(readFileSync(new URL("../testdata/sdk-auth-lifecycle.json", import.meta.url), "utf8"))
  .token_responses.filter((vector) => ["allowed-added-scope", "narrowed-scope", "unallowed-added-scope-ignored", "required-scope-missing"].includes(vector.id));
for (const vector of ceilingVectors) {
  test(`built-in auth intersects initial grants with the selected ceiling: ${vector.id}`, async () => {
    const stored = [];
    const { provider, tokens } = fixture({
      async fetch(input, init = {}) {
        const target = String(input);
        if (target.includes("oauth-protected-resource")) return Response.json({ resource, authorization_servers: [issuer] });
        if (target.includes("well-known")) return Response.json(metadata);
        tokens.push(new URLSearchParams(init.body));
        return Response.json(vector.response);
      },
      selectClient: () => ({ ...binding, scopes: vector.requested, allowedScopes: vector.allowed, requiredScopes: vector.required }),
      setToken: (_key, value) => { stored.push(value); },
      getToken: () => undefined,
      deleteToken() {},
    });
    const result = provider.authenticate({ url, challenged: true });
    if (vector.usable) assert.equal((await result).token, vector.response.access_token);
    else await assert.rejects(result, (error) => classifyAuthError(error).code === vector.error);
    assert.equal(tokens.length, 1);
    assert.deepEqual([...tokens[0].get("scope").split(" ")].sort(), [...new Set([...vector.requested, ...vector.required])].sort());
    assert.deepEqual([...stored[0].scopes].sort(), [...vector.granted].sort());
  });
}
