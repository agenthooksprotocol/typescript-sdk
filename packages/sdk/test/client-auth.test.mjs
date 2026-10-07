import test from "node:test";
import assert from "node:assert/strict";
import { auth } from "@agenthooksprotocol/sdk/client";
import { createServer } from "node:http";

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
  assert.equal(tokens[1].get("grant_type"), "refresh_token");
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
      challenge: 'Bearer scope="admin"',
    }),
    /permitted scopes/,
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
  assert.equal(first.tokens[1].get("grant_type"), "refresh_token");
  assert.equal(first.tokens[1].get("refresh_token"), "refresh");
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
