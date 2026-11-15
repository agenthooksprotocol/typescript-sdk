import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { inspect } from "node:util";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { auth, AuthError, normalizeAuthTarget, Hooks, Attachment } from "agenthooksprotocol/client";

// Scenario labels match /tmp/ahp-auth-parity-cases.json; no runtime dependency on /tmp.
const bearer = { type: "bearer", tokenRef: "vault/events" };
const oauth = {
  type: "oauth", issuer: "https://identity.example", resource: "https://receiver.example",
  clientId: "host-client", flow: "client_credentials", scopes: ["events"],
};
const context = (authentication = bearer, extra = {}) => ({
  backendId: "routing.backend", purpose: "event", url: "https://receiver.example/events",
  ...(authentication ? { authentication } : {}), ...extra,
});
const rejected = (code) => (error) => {
  assert.ok(error instanceof AuthError);
  assert.equal(error.code, code);
  return true;
};
const provider = (credential, challenge = () => {}) => ({ credential, challenge });
const input = () => ({ call: { id: "call" }, path: "native", tool: { name: "test", origin: "native", input: {} } });
function hooksFor(url, routing, { authentication = bearer, headers, upload } = {}) {
  return new Hooks({ protocolVersion: "draft", hooks: [{
    id: "routing.backend", transport: { type: "http", url, ...(headers ? { headers } : {}) },
    ...(authentication ? { authentication } : {}),
    subscriptions: [{ mode: "intercept", events: ["tool.before"], timeoutMs: 10000,
      failurePolicy: "fail-closed", content: { default: upload ? "body" : "metadata" },
      ...(upload ? { upload } : {}),
    }],
  }] }, { source: "urn:test:auth-routing", harness: { name: "test", version: "1" },
    capabilities: { toolBefore: { intercept: { deny: true } } }, auth: routing });
}
async function withServer(handle, run) {
  const requests = [];
  const server = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      requests.push({ path: request.url, authorization: request.headers.authorization, body });
      await handle(request, response, body);
    } catch (error) {
      response.statusCode = 500;
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await run(`http://127.0.0.1:${server.address().port}`, requests); }
  finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}
function success(response, body) {
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ jsonrpc: "2.0", id: JSON.parse(body).id,
    result: { protocolVersion: "draft", effects: [] } }));
}

test("mixed-bearer-oauth: native reference resolver remains additive with custom OAuth", async () => {
  const seen = [];
  const routing = auth.compose({
    bearer: auth.bearer({ resolveCredentialReference(reference, ctx) {
      seen.push([reference, ctx.backendId, ctx.purpose]); return "reference-token";
    } }),
    oauth: provider((ctx) => { seen.push(ctx.authentication); return { type: "bearer", token: "oauth-token" }; }),
    discover: provider(() => assert.fail("configured binding must not discover")),
  });
  assert.equal((await routing.credential(context())).token, "reference-token");
  assert.equal((await routing.credential(context(oauth))).token, "oauth-token");
  assert.deepEqual(seen, [["vault/events", "routing.backend", "event"], oauth]);
  const environment = auth.bearer({ resolveEnvironmentVariable: (name) => name === "EVENT_TOKEN" ? "environment-token" : undefined });
  assert.equal((await environment.credential(context({ type: "bearer", tokenEnv: "EVENT_TOKEN" }))).token, "environment-token");
});

test("missing-bearer-secret / oauth-no-credential: configured routes fail closed without fallback", async () => {
  let alternate = 0;
  const routing = auth.compose({
    bearer: auth.bearer({ resolveCredentialReference: () => undefined }),
    oauth: provider(() => { alternate++; return undefined; }),
    discover: provider(() => assert.fail("no fallback discovery")),
  });
  await assert.rejects(routing.credential(context()), rejected("credential_unavailable"));
  assert.equal(alternate, 0);
  await assert.rejects(routing.credential(context(oauth)), rejected("credential_unavailable"));
  assert.equal(alternate, 1);
  for (const flow of ["authorization_code_pkce", "client_credentials"]) {
    await assert.rejects(auth.compose({}).credential(context({ ...oauth, flow })), rejected("unsupported_binding"));
  }
  await withServer((req, res, body) => success(res, body), async (origin, requests) => {
    const hooks = hooksFor(`${origin}/events`, routing);
    try {
      const result = await hooks.dispatch("tool.before", input());
      assert.equal(requests.length, 0, "missing secret must not send anonymous HTTP");
      assert.ok(result.diagnostics.some((d) => d.phase !== "observation"));
    } finally { await hooks.close(); }
  });
});

test("explicit-authorization: real HTTP bypasses all routes even on 401", async () => {
  const fail = provider(() => assert.fail("explicit header must bypass credential"), () => assert.fail("explicit header must bypass challenge"));
  await withServer((_req, res) => { res.writeHead(401, { "www-authenticate": "Bearer" }); res.end(); }, async (origin, requests) => {
    const hooks = hooksFor(`${origin}/events`, auth.compose({ bearer: fail, oauth: fail, discover: fail }), {
      authentication: oauth, headers: { Authorization: "Bearer explicit-token" },
    });
    try {
      await hooks.dispatch("tool.before", input());
      assert.equal(requests.length, 1);
      assert.equal(requests[0].authorization, "Bearer explicit-token");
    } finally { await hooks.close(); }
  });
});

test("purpose-isolation: real upload and event requests resolve independent bindings", async () => {
  const seen = [];
  const routing = auth.compose({
    bearer: auth.bearer({ resolveCredentialReference(ref, ctx) {
      seen.push([ctx.purpose, ref]); return ref === "vault/upload" ? "upload-token" : "event-token";
    } }),
  });
  await withServer((req, res, body) => {
    if (req.url === "/events") return success(res, body);
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ ref: "urn:test:uploaded", size: body.length,
      sha256: createHash("sha256").update(body).digest("hex") }));
  }, async (origin, requests) => {
    const hooks = hooksFor(`${origin}/events`, routing, { upload: {
      endpoint: `${origin}/upload`, maxBytes: 1000, timeoutMs: 10000,
      auth: { type: "bearer", tokenRef: "vault/upload" },
    } });
    try {
      const result = await hooks.toolBefore({ callId: "call", path: "native", name: "test", origin: "native", input: {},
        items: [{ id: "content", kind: "attachment", mediaType: "application/octet-stream", selection: "body",
          body: Attachment.bytes(new Uint8Array([0, 1, 2])) }],
      });
      assert.deepEqual(result.diagnostics.filter((d) => d.phase !== "observation"), []);
      assert.deepEqual(seen, [["upload", "vault/upload"], ["event", "vault/events"]]);
      assert.deepEqual(requests.map((r) => [r.path, r.authorization]), [["/upload", "Bearer upload-token"], ["/events", "Bearer event-token"]]);
      await result.content?.close();
    } finally { await hooks.close(); }
  });
});

test("stale-401: challenge restores original opaque attempt to its owning provider", async () => {
  const store = { generation: 1, invalidated: [] };
  const originals = [];
  const owner = provider(() => {
    const credential = { type: "bearer", token: `generation-${store.generation}`, attempt: { generation: store.generation } };
    originals.push(credential); return credential;
  }, (ctx) => {
    assert.equal(ctx.credential, originals[0]);
    if (ctx.credential.attempt.generation === store.generation) store.invalidated.push(store.generation);
  });
  const routing = auth.compose({ oauth: owner, bearer: provider(() => assert.fail("wrong owner"), () => assert.fail("wrong challenge owner")) });
  const old = await routing.credential(context(oauth));
  assert.notEqual(old.attempt, originals[0].attempt);
  store.generation = 2;
  const latest = await routing.credential(context(oauth));
  assert.equal(latest.token, "generation-2");
  await routing.challenge({ ...context(bearer), credential: old, response: new Response(null, { status: 401 }) });
  assert.deepEqual(store.invalidated, [], "stale rejection must not invalidate newer host state");
});

test("purpose-isolation / destination-isolation: foreign attempt never reaches host store", async () => {
  let challenges = 0;
  const routing = auth.compose({ bearer: provider(() => ({ type: "bearer", token: "event-token", attempt: {} }), () => challenges++) });
  const credential = await routing.credential(context());
  for (const changed of [{ purpose: "upload" }, { backendId: "other" }, { url: "https://receiver.example/other" }]) {
    await assert.rejects(routing.challenge({ ...context(bearer, changed), credential,
      response: new Response(null, { status: 401 }) }), rejected("invalid_configuration"));
  }
  await assert.rejects(routing.challenge({ ...context(), credential: { ...credential, attempt: {} },
    response: new Response(null, { status: 401 }) }), rejected("invalid_configuration"));
  assert.equal(challenges, 0);
});

test("unconfigured-challenge: real HTTP discovery starts only after no-binding 401", async () => {
  const calls = [];
  const routing = auth.compose({ discover: provider((ctx) => {
    assert.equal(ctx.challenged, true);
    assert.equal(ctx.challenge, "Bearer");
    calls.push("credential"); return { type: "bearer", token: "discovered-token" };
  }, (ctx) => { assert.equal(ctx.credential, undefined); calls.push("challenge"); }) });
  await withServer((req, res, body) => {
    if (!req.headers.authorization) { res.writeHead(401, { "www-authenticate": "Bearer" }); res.end(); }
    else success(res, body);
  }, async (origin, requests) => {
    const unconfigured = hooksFor(`${origin}/events`, routing, { authentication: null });
    try {
      assert.equal(await routing.credential(context(null)), undefined);
      assert.deepEqual(calls, []);
      const result = await unconfigured.dispatch("tool.before", input());
      assert.deepEqual(result.diagnostics.filter((d) => d.phase !== "observation"), []);
      assert.deepEqual(calls, ["challenge", "credential"]);
      assert.deepEqual(requests.map((r) => r.authorization), [undefined, "Bearer discovered-token"]);
    } finally { await unconfigured.close(); }
  });
});

test("deadline-cancel: cancellation identity survives credential and challenge waits", async () => {
  for (const phase of ["credential", "challenge", "discovery"]) {
    const controller = new AbortController();
    const reason = new DOMException("host cancelled", "AbortError");
    let started;
    const ready = new Promise((resolve) => { started = resolve; });
    const pending = () => { started(); return new Promise(() => {}); };
    const route = provider(phase !== "challenge" ? pending : () => ({ type: "bearer", token: "token" }), pending);
    const routing = auth.compose(phase === "discovery" ? { discover: route } : { bearer: route });
    const ctx = context(phase === "discovery" ? null : bearer, { signal: controller.signal, ...(phase === "discovery" ? { challenged: true } : {}) });
    const credential = phase === "challenge" ? await routing.credential(ctx) : undefined;
    const operation = phase !== "challenge" ? routing.credential(ctx) : routing.challenge({ ...ctx, credential, response: new Response(null, { status: 401 }) });
    await ready;
    controller.abort(reason);
    await assert.rejects(operation, (error) => error === reason);
    await assert.rejects(routing.credential(ctx), (error) => error === reason);
  }
});

test("redaction: provider messages, nested causes and forged error codes never escape", async () => {
  const secret = "secret-refresh-token-callback-url-body";
  for (const phase of ["credential", "challenge"]) {
    const fail = () => { throw new Error(secret, { cause: new Error(secret) }); };
    const routing = auth.compose({ bearer: provider(phase === "credential" ? fail : () => ({ type: "bearer", token: "token" }), fail) });
    const credential = phase === "challenge" ? await routing.credential(context()) : undefined;
    const operation = phase === "credential" ? routing.credential(context()) : routing.challenge({ ...context(), credential, response: new Response(null, { status: 401 }) });
    await assert.rejects(operation, (error) => {
      rejected("provider_failed")(error);
      assert.equal(error.recovery, "retry");
      assert.equal(error.cause, undefined);
      assert.doesNotMatch([String(error), error.stack, JSON.stringify(error), inspect(error)].join("\n"), new RegExp(secret));
      return true;
    });
  }
  const forged = new AuthError(secret);
  assert.equal(forged.code, "provider_failed");
  assert.doesNotMatch(inspect(forged), new RegExp(secret));
});

test("normalizeAuthTarget validates bindings and preserves immutable destination identity", () => {
  const ctx = context(oauth);
  const target = normalizeAuthTarget(ctx);
  assert.deepEqual(target, { backendId: ctx.backendId, purpose: "event", url: ctx.url, ...oauth });
  assert.ok(Object.isFrozen(target));
  assert.ok(Object.isFrozen(target.scopes));
  oauth.scopes.push("later");
  assert.deepEqual(target.scopes, ["events"]);
  oauth.scopes.pop();
  const reference = normalizeAuthTarget(context());
  assert.deepEqual(reference.source, { type: "reference", reference: "vault/events" });
  assert.ok(Object.isFrozen(reference.source));
  assert.equal(normalizeAuthTarget(context(null)).type, "discover");
  for (const invalid of [context(bearer, { purpose: "other" }), context(bearer, { backendId: " " }),
    context(bearer, { url: "https://user:password@example.com" }), context(bearer, { url: "https://example.com/#fragment" }),
    context(bearer, { url: "file:///secret" }), context({ type: "bearer" }),
    context({ type: "bearer", tokenRef: "ref", tokenEnv: "ENV" }), context({ ...oauth, scopes: [""] })]) {
    assert.throws(() => normalizeAuthTarget(invalid), rejected("invalid_configuration"));
  }
  assert.throws(() => normalizeAuthTarget(context({ type: "basic" })), rejected("unsupported_binding"));
  assert.throws(() => normalizeAuthTarget(context({ ...oauth, flow: "implicit" })), rejected("unsupported_binding"));
  assert.equal(new AuthError("interaction_required").recovery, "login");
  assert.equal(new AuthError("credential_unavailable").recovery, "configure");
});

test("package auth subpath exports the same routing helpers", async () => {
  const subpath = await import("agenthooksprotocol/client/auth");
  assert.equal(subpath.auth, auth);
  assert.equal(subpath.AuthError, AuthError);
  assert.equal(subpath.normalizeAuthTarget, normalizeAuthTarget);
  assert.equal(typeof subpath.auth.compose, "function");
  assert.equal(typeof subpath.auth.bearer, "function");
  const native = subpath.auth.bearer({ resolveCredentialReference: () => undefined });
  await assert.rejects(native.credential(context()), rejected("credential_unavailable"));
});

test("public AuthTarget is readonly and discriminated through client and auth subpaths", () => {
  const filename = fileURLToPath(new URL("./auth-routing-types.ts", import.meta.url));
  const source = `
    import { auth, AuthError, normalizeAuthTarget } from "agenthooksprotocol/client/auth";
    import type { AuthTarget, AuthCompositionOptions, DeliveryAuthProvider } from "agenthooksprotocol/client/auth";
    import type { AuthTarget as ClientTarget } from "agenthooksprotocol/client";
    function narrow(target: AuthTarget): ClientTarget {
      const backend: string = target.backendId;
      const purpose: "event" | "upload" = target.purpose;
      // @ts-expect-error Destination identity is readonly.
      target.backendId = "other";
      // @ts-expect-error Purpose is readonly.
      target.purpose = "upload";
      // @ts-expect-error URL is readonly.
      target.url = "https://other.example";
      switch (target.type) {
        case "bearer": {
          // @ts-expect-error Bearer source is readonly.
          target.source = { type: "reference", reference: "other" };
          if (target.source.type === "reference") {
            const reference: string = target.source.reference;
            // @ts-expect-error Reference is readonly.
            target.source.reference = "other";
            // @ts-expect-error Reference source has no environment name.
            target.source.name;
          } else {
            const name: string = target.source.name;
            // @ts-expect-error Environment source name is readonly.
            target.source.name = "OTHER";
            // @ts-expect-error Environment source has no reference.
            target.source.reference;
          }
          // @ts-expect-error Bearer target has no OAuth issuer.
          target.issuer;
          break;
        }
        case "oauth": {
          const flow: "authorization_code_pkce" | "client_credentials" = target.flow;
          const scopes: readonly string[] = target.scopes;
          // @ts-expect-error OAuth scopes cannot be appended.
          target.scopes.push("other");
          // @ts-expect-error OAuth scope elements are readonly.
          target.scopes[0] = "other";
          // @ts-expect-error OAuth issuer is readonly.
          target.issuer = "https://other.example";
          // @ts-expect-error OAuth target has no bearer source.
          target.source;
          break;
        }
        case "discover":
          // @ts-expect-error Discovery does not imply a client identity.
          target.clientId;
          break;
        default: {
          const exhaustive: never = target;
          return exhaustive;
        }
      }
      return target;
    }
    const options: AuthCompositionOptions = { bearer: auth.bearer() };
    const composed: DeliveryAuthProvider = auth.compose(options);
    const target: ClientTarget = normalizeAuthTarget({ backendId: "backend", purpose: "event", url: "https://example.com" });
    const safeError = new AuthError("credential_unavailable");
  `;
  const options = { noEmit: true, strict: true, skipLibCheck: true,
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (path, languageVersion, onError, shouldCreateNewSourceFile) =>
    path === filename ? ts.createSourceFile(path, source, languageVersion, true)
      : getSourceFile(path, languageVersion, onError, shouldCreateNewSourceFile);
  const program = ts.createProgram([filename,
    fileURLToPath(new URL("../../../node-shims.d.ts", import.meta.url))], options, host);
  assert.deepEqual(ts.getPreEmitDiagnostics(program).map((diagnostic) =>
    ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")), []);
});
