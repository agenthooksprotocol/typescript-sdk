import test from "node:test";
import assert from "node:assert/strict";
import ts from "typescript";
import { fileURLToPath } from "node:url";
import { auth, Hooks } from "@agenthooksprotocol/sdk/client";
import { createHash } from "node:crypto";

test("delivery provider public types support registration context and opaque attempts", () => {
  const filename = fileURLToPath(
    new URL("./auth-provider-types.ts", import.meta.url),
  );
  const source = `
    import type {
      AuthContext, DeliveryAuthProvider, DeliveryCredential,
      DeliveryAuthContext, AuthChallengeContext,
    } from "../src/client/auth.js";
    const identity = {};
    const provider: DeliveryAuthProvider = {
      credential(context) {
        const backend: string = context.backendId;
        const purpose: "event" | "upload" = context.purpose;
        const binding = context.authentication;
        const signal: AbortSignal | undefined = context.signal;
        return { type: "bearer", token: "secret", attempt: identity };
      },
      async challenge(context) {
        const response: Response = context.response;
        const credential: DeliveryCredential | undefined = context.credential;
        const attempt: unknown = credential?.attempt;
      },
    };
    const asyncProvider: DeliveryAuthProvider = {
      async credential(context) { return undefined; },
      challenge(context) {},
    };
    const standalone: AuthContext = { url: "https://example.com" };
    const delivery: DeliveryAuthContext = {
      backendId: "backend", purpose: "upload", url: "https://example.com/upload",
    };
    const challenge: AuthChallengeContext = {
      ...delivery, response: new Response(null, { status: 401 }), credential: undefined,
    };
    // @ts-expect-error Delivery requires registration identity and purpose.
    const missingRegistration: DeliveryAuthContext = standalone;
    // @ts-expect-error Unsupported delivery mechanisms must not type-check.
    const unsupported: DeliveryCredential = { type: "basic", token: "secret" };
    provider.challenge(challenge);
    provider.credential(delivery);
  `;
  const options = {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
  };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (
    path,
    languageVersion,
    onError,
    shouldCreateNewSourceFile,
  ) =>
    path === filename
      ? ts.createSourceFile(path, source, languageVersion, true)
      : getSourceFile(
          path,
          languageVersion,
          onError,
          shouldCreateNewSourceFile,
        );
  const program = ts.createProgram(
    [
      filename,
      fileURLToPath(new URL("../../../node-shims.d.ts", import.meta.url)),
    ],
    options,
    host,
  );
  const diagnostics = ts.getPreEmitDiagnostics(program);
  assert.deepEqual(
    diagnostics.map((diagnostic) =>
      ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
    ),
    [],
  );
});

test("optional auth helpers preserve registration context and standalone use", async () => {
  const controller = new AbortController();
  const binding = { type: "bearer", tokenRef: "host-secret" };
  const seen = [];
  const provider = auth({
    resolveCredentialReference(reference, context) {
      assert.equal(reference, "host-secret");
      seen.push(context);
      return "resolved-secret";
    },
  });
  for (const purpose of ["event", "upload"]) {
    const credential = await provider.authenticate({
      backendId: "backend-a",
      purpose,
      authentication: binding,
      url: `https://example.com/${purpose}`,
      signal: controller.signal,
    });
    assert.equal(credential.token, "resolved-secret");
    const context = seen.at(-1);
    assert.equal(context.backendId, "backend-a");
    assert.equal(context.purpose, purpose);
    assert.equal(context.authentication, binding);
    assert.equal(context.url, `https://example.com/${purpose}`);
    assert.equal(context.signal, controller.signal);
  }
  assert.equal(
    await auth().authenticate({ url: "https://example.com" }),
    undefined,
  );
});

const eventUrl = "https://receiver.example/events";
const uploadUrl = "https://receiver.example/upload";
const toolInput = () => ({
  call: { id: "call" },
  path: "native",
  tool: { name: "test", origin: "native", input: { value: 1 } },
});
const success = (init) =>
  Response.json({
    jsonrpc: "2.0",
    id: JSON.parse(init.body).id,
    result: { protocolVersion: "draft", effects: [] },
  });
function deliveryFixture(provider, fetch, authentication, upload) {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "auth.backend",
          transport: { type: "http", url: eventUrl },
          ...(authentication ? { authentication } : {}),
          subscriptions: [
            {
              mode: "intercept",
              events: ["tool.before"],
              timeoutMs: 10000,
              failurePolicy: "fail-closed",
              content: { default: upload ? "body" : "metadata" },
              ...(upload ? { upload } : {}),
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:auth-provider",
      capabilities: { "tool.before": { effects: ["deny"] } },
      auth: provider,
      fetch,
    },
  );
}

const bindings = [
  { type: "bearer", tokenRef: "host-vault-entry" },
  { type: "bearer", tokenEnv: "HOST_TOKEN" },
  ...["client_credentials", "authorization_code_pkce"].map((flow) => ({
    type: "oauth",
    flow,
    issuer: "https://identity.example/tenant",
    resource: "https://receiver.example",
    clientId: "host-client",
    clientSecretRef: "host-client-secret",
    scopes: ["events"],
    hostExtension: { account: "selected-account" },
  })),
];
for (const binding of bindings) {
  test(`Hooks forwards complete ${binding.tokenRef ? "tokenRef" : binding.tokenEnv ? "tokenEnv" : binding.flow} binding to a minimal provider`, async () => {
    const contexts = [];
    const requests = [];
    const hooks = deliveryFixture(
      {
        credential(context) {
          contexts.push(context);
          return { type: "bearer", token: "host-owned-token" };
        },
        challenge() {
          assert.fail("unexpected challenge");
        },
      },
      async (url, init) => {
        requests.push({ url, init });
        return success(init);
      },
      binding,
    );
    try {
      const result = await hooks.dispatch("tool.before", toolInput());
      assert.deepEqual(result.errors, []);
      assert.equal(contexts.length, 1);
      assert.equal(contexts[0].backendId, "auth.backend");
      assert.equal(contexts[0].purpose, "event");
      assert.equal(contexts[0].url, eventUrl);
      assert.deepEqual(contexts[0].authentication, binding);
      assert.ok(contexts[0].signal instanceof AbortSignal);
      assert.equal(contexts[0].signal.aborted, false);
      assert.equal(requests.length, 1); // No SDK discovery or token endpoint requests.
      assert.equal(requests[0].url, eventUrl);
      assert.equal(
        new Headers(requests[0].init.headers).get("authorization"),
        "Bearer host-owned-token",
      );
    } finally {
      await hooks.close();
    }
  });
}

for (const finalStatus of [200, 401]) {
  test(`Hooks challenges exact credential and response; retry is bounded (final ${finalStatus})`, async () => {
    const credentials = [
      { type: "bearer", token: "old-secret", attempt: { generation: 1 } },
      { type: "bearer", token: "new-secret", attempt: Symbol("generation-2") },
    ];
    const requests = [],
      responses = [],
      challenges = [];
    let acquisitions = 0;
    const hooks = deliveryFixture(
      {
        credential() {
          return credentials[acquisitions++];
        },
        challenge(context) {
          challenges.push(context);
        },
      },
      async (url, init) => {
        requests.push({ url, init });
        const response =
          requests.length === 1 || finalStatus === 401
            ? new Response(null, {
                status: 401,
                headers: { "www-authenticate": 'Bearer error="invalid_token"' },
              })
            : success(init);
        responses.push(response);
        return response;
      },
      bindings[0],
    );
    try {
      const result = await hooks.dispatch("tool.before", toolInput());
      assert.equal(result.errors.length, finalStatus === 200 ? 0 : 1);
      assert.equal(acquisitions, 2);
      assert.equal(requests.length, 2);
      assert.equal(challenges.length, finalStatus === 200 ? 1 : 2);
      for (const [index, challenge] of challenges.entries()) {
        assert.equal(challenge.response, responses[index]);
        assert.equal(challenge.response.status, 401);
        assert.equal(
          challenge.response.headers.get("www-authenticate"),
          'Bearer error="invalid_token"',
        );
        assert.equal(challenge.credential, credentials[index]);
        assert.equal(challenge.credential.attempt, credentials[index].attempt);
        assert.deepEqual(challenge.authentication, bindings[0]);
        assert.equal(challenge.backendId, "auth.backend");
        assert.equal(challenge.purpose, "event");
        assert.equal(challenge.url, eventUrl);
      }
      assert.equal(requests[0].init.body, requests[1].init.body);
      assert.equal(
        JSON.parse(requests[0].init.body).id,
        JSON.parse(requests[1].init.body).id,
      );
      assert.equal(requests[0].init.method, requests[1].init.method);
      assert.equal(
        new Headers(requests[0].init.headers).get("authorization"),
        "Bearer old-secret",
      );
      assert.equal(
        new Headers(requests[1].init.headers).get("authorization"),
        "Bearer new-secret",
      );
      assert.doesNotMatch(
        JSON.stringify(result.errors),
        /old-secret|new-secret/,
      );
    } finally {
      await hooks.close();
    }
  });
}

for (const uploadAuth of [
  { type: "bearer", tokenRef: "upload-only" },
  undefined,
]) {
  test(`Hooks upload binding is independent (${uploadAuth ? "explicit" : "anonymous"})`, async () => {
    const contexts = [],
      requests = [];
    const hooks = deliveryFixture(
      {
        credential(context) {
          contexts.push(context);
          return context.authentication
            ? { type: "bearer", token: context.purpose }
            : undefined;
        },
        challenge() {
          assert.fail("unexpected challenge");
        },
      },
      async (url, init) => {
        requests.push({
          url,
          authorization: new Headers(init.headers).get("authorization"),
        });
        if (url === eventUrl) return success(init);
        const bytes = Buffer.from(await new Response(init.body).arrayBuffer());
        return Response.json(
          {
            ref: "urn:test:uploaded",
            size: bytes.length,
            sha256: createHash("sha256").update(bytes).digest("hex"),
          },
          { status: 201 },
        );
      },
      bindings[0],
      {
        endpoint: uploadUrl,
        maxBytes: 1000,
        timeoutMs: 10000,
        ...(uploadAuth ? { auth: uploadAuth } : {}),
      },
    );
    try {
      const input = toolInput();
      input.items = [
        {
          id: "content",
          kind: "text",
          mediaType: "text/plain",
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("payload"));
              controller.close();
            },
          }),
        },
      ];
      const result = await hooks.dispatch("tool.before", input);
      assert.deepEqual(result.errors, []);
      assert.deepEqual(
        contexts.map((context) => context.purpose),
        ["upload", "event"],
      );
      assert.deepEqual(contexts[0].authentication, uploadAuth);
      assert.deepEqual(contexts[1].authentication, bindings[0]);
      assert.equal(contexts[0].backendId, "auth.backend");
      assert.equal(contexts[0].url, uploadUrl);
      assert.ok(contexts[0].signal instanceof AbortSignal);
      assert.deepEqual(requests, [
        { url: uploadUrl, authorization: uploadAuth ? "Bearer upload" : null },
        { url: eventUrl, authorization: "Bearer event" },
      ]);
    } finally {
      await hooks.close();
    }
  });
}

test("Hooks allows provider-owned recovery from an anonymous challenge", async () => {
  let challenged = false;
  const requests = [];
  const rejection = new Response(null, { status: 401 });
  const hooks = deliveryFixture(
    {
      credential(context) {
        assert.equal(context.authentication, undefined);
        return challenged
          ? { type: "bearer", token: "discovered-by-host" }
          : undefined;
      },
      challenge(context) {
        assert.equal(context.response, rejection);
        assert.equal(context.credential, undefined);
        challenged = true;
      },
    },
    async (url, init) => {
      requests.push(init);
      return requests.length === 1 ? rejection : success(init);
    },
  );
  try {
    assert.deepEqual(
      (await hooks.dispatch("tool.before", toolInput())).errors,
      [],
    );
    assert.equal(requests.length, 2);
    assert.equal(new Headers(requests[0].headers).get("authorization"), null);
    assert.equal(
      new Headers(requests[1].headers).get("authorization"),
      "Bearer discovered-by-host",
    );
    assert.equal(requests[0].body, requests[1].body);
  } finally {
    await hooks.close();
  }
});

for (const binding of bindings) {
  test(`Hooks fails closed when configured ${binding.flow ?? binding.tokenRef ?? binding.tokenEnv} credentials are missing`, async () => {
    let deliveries = 0;
    const hooks = deliveryFixture(
      { credential() {}, challenge() {} },
      async () => {
        deliveries++;
        throw new Error("must not deliver anonymously");
      },
      binding,
    );
    try {
      const result = await hooks.dispatch("tool.before", toolInput());
      assert.equal(deliveries, 0);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0].syntheticDenial, true);
    } finally {
      await hooks.close();
    }
  });
}

for (const phase of ["credential", "challenge"]) {
  test(
    `Hooks cancellation bounds an unresponsive provider ${phase} wait`,
    { timeout: 3000 },
    async () => {
      const controller = new AbortController();
      let entered;
      const ready = new Promise((resolve) => {
        entered = resolve;
      });
      let providerSignal;
      let deliveries = 0;
      const wait = (context) => {
        providerSignal = context.signal;
        entered();
        return new Promise(() => {}); // Deliberately ignores cancellation.
      };
      const hooks = deliveryFixture(
        {
          credential:
            phase === "credential"
              ? wait
              : () => ({ type: "bearer", token: "secret" }),
          challenge: phase === "challenge" ? wait : () => {},
        },
        async () => {
          deliveries++;
          return new Response(null, { status: 401 });
        },
        bindings[0],
      );
      try {
        const pending = hooks.dispatch("tool.before", toolInput(), {
          signal: controller.signal,
        });
        await ready;
        assert.ok(providerSignal instanceof AbortSignal);
        assert.equal(providerSignal.aborted, false);
        const start = performance.now();
        controller.abort(new Error("caller cancelled"));
        const result = await pending;
        assert.ok(performance.now() - start < 1000);
        assert.equal(providerSignal.aborted, true);
        assert.equal(result.interrupted, true);
        assert.equal(deliveries, phase === "credential" ? 0 : 1);
        assert.ok(result.errors.some((error) => error.code === "INTERRUPTED"));
      } finally {
        controller.abort();
        await hooks.close();
      }
    },
  );
}

test("Hooks never retries a challenge anonymously when the provider still has no credential", async () => {
  let deliveries = 0,
    challenges = 0,
    acquisitions = 0;
  const hooks = deliveryFixture(
    {
      credential() {
        acquisitions++;
        return undefined;
      },
      challenge() {
        challenges++;
      },
    },
    async () => {
      deliveries++;
      return new Response(null, { status: 401 });
    },
  );
  try {
    const result = await hooks.dispatch("tool.before", toolInput());
    assert.equal(deliveries, 1);
    assert.equal(challenges, 1);
    assert.equal(acquisitions, 2);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].syntheticDenial, true);
  } finally {
    await hooks.close();
  }
});

test("Hooks cannot substitute event credentials for missing configured upload credentials", async () => {
  const purposes = [];
  let deliveries = 0;
  const hooks = deliveryFixture(
    {
      credential(context) {
        purposes.push(context.purpose);
        return context.purpose === "event"
          ? { type: "bearer", token: "event-secret" }
          : undefined;
      },
      challenge() {
        assert.fail("unexpected challenge");
      },
    },
    async () => {
      deliveries++;
      throw new Error("unexpected delivery");
    },
    bindings[0],
    {
      endpoint: uploadUrl,
      timeoutMs: 10000,
      maxBytes: 1000,
      auth: { type: "bearer", tokenRef: "missing-upload-secret" },
    },
  );
  try {
    const input = toolInput();
    input.items = [
      {
        id: "content",
        kind: "text",
        mediaType: "text/plain",
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("payload"));
            controller.close();
          },
        }),
      },
    ];
    const result = await hooks.dispatch("tool.before", input);
    assert.deepEqual(purposes, ["upload"]);
    assert.equal(deliveries, 0);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].phase, "preparation");
    assert.equal(result.errors[0].syntheticDenial, true);
  } finally {
    await hooks.close();
  }
});
