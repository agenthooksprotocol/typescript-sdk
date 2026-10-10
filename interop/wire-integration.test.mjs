import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:http";
import {
  createServer as createSecureServer,
  request as httpsRequest,
} from "node:https";
import { createHmac } from "node:crypto";
import { listen } from "./common.mjs";
import { createRequire } from "node:module";
import { Readable } from "node:stream";
import { authorize } from "./security.mjs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { digest } from "./content-upload.mjs";
const cwd = fileURLToPath(new URL("..", import.meta.url));
const clock = 1893456000,
  issuer = "urn:ahp:interop:local-issuer",
  audience = "urn:ahp:interop:local-server";
function auth(mode, role) {
  const cfg = { mode };
  if (mode === "bearer") cfg.token = "TEST-ONLY-event-token";
  if (["oauth", "workload"].includes(mode)) {
    const encode = (v) => Buffer.from(JSON.stringify(v)).toString("base64url"),
      value =
        encode({ alg: "HS256", typ: "JWT" }) +
        "." +
        encode({
          iss: issuer,
          aud: audience,
          purpose: mode,
          exp: clock + 3600,
        });
    const signingKey = `TEST-ONLY-ahp-interop-${mode}-signing-key`;
    Object.assign(cfg, {
      issuer,
      audience,
      purpose: mode,
      clock,
      signingKey,
      assertion:
        value +
        "." +
        createHmac("sha256", signingKey).update(value).digest("base64url"),
    });
  }
  if (mode === "mtls") {
    const path = resolve(cwd, "../agent-hooks-protocol/interop/fixtures");
    Object.assign(cfg, {
      caFile: join(path, "ca.pem"),
      certFile: join(path, role + ".pem"),
      keyFile: join(path, role + "-key.pem"),
    });
  }
  return cfg;
}
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, auth: sdkAuth } = await import(
  require.resolve("agenthooksprotocol/client")
);
const { hooks: serverHooks, attachments } = await import(
  require.resolve("agenthooksprotocol/server")
);

/** TLS transport adapter for this real local peer; never fabricates AHP responses. */
async function mutualTlsFetch(tls, origin) {
  const identity = {
    ca: await readFile(tls.caFile),
    cert: await readFile(tls.certFile),
    key: await readFile(tls.keyFile),
  };
  /** @type {typeof globalThis.fetch} */
  const fetchWithIdentity = async (input, init) => {
    const request = new Request(input, init);
    assert.equal(new URL(request.url).origin, origin);
    const body = Buffer.from(await request.arrayBuffer());
    return new Promise((resolve, reject) => {
      const outgoing = httpsRequest(
        request.url,
        {
          ...identity,
          method: request.method,
          headers: Object.fromEntries(request.headers),
          signal: request.signal,
        },
        (incoming) => {
          const headers = new Headers();
          for (let index = 0; index < incoming.rawHeaders.length; index += 2)
            headers.append(
              incoming.rawHeaders[index],
              incoming.rawHeaders[index + 1],
            );
          resolve(
            new Response(
              incoming.statusCode === 204 ? null : Readable.toWeb(incoming),
              {
                status: incoming.statusCode,
                headers,
              },
            ),
          );
        },
      );
      outgoing.on("error", reject);
      outgoing.end(body);
    });
  };
  return fetchWithIdentity;
}

for (const [transport, mode, authenticatedUpload] of [
  ...["none", "bearer", "oauth", "workload", "mtls"].map((mode) => [
    "http",
    mode,
  ]),
  ["stdio", "none"],
].flatMap(([transport, mode]) =>
  [true, false].map((authenticatedUpload) => [
    transport,
    mode,
    authenticatedUpload,
  ]),
))
  test(
    `public SDK ${transport} ${mode} ${authenticatedUpload ? "authenticated" : "anonymous"} uploads settle binary observations and interrupt boundaries`,
    { timeout: 20000 },
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "ahp-public-wire-"));
      const bytes = Buffer.from([0, 255, 128, 10]);
      const received = [],
        observed = [],
        uploads = [],
        stored = new Map();
      const credentials = auth(mode, "server");
      let client,
        origin,
        tokenRequests = 0;
      const controller = new AbortController();
      /** @param {import("agenthooksprotocol/server").Message} message */
      async function policy(message) {
        const event = message.params.event;
        assert.ok(event);
        const descriptor = event.items[0].body;
        assert.deepEqual(stored.get(descriptor.ref), bytes);
        assert.deepEqual(Object.keys(descriptor), ["ref"]);
        assert.equal(event.source, "urn:typescript:wire");
        if (message.method === "hooks/observe") {
          // hooks.handle has already validated this canonical notification.
          assert.equal(message.jsonrpc, "2.0");
          assert.equal(Object.hasOwn(message.params, "disposition"), false);
          observed.push(message);
          return;
        }
        assert.equal(message.method, "hooks/intercept");
        assert.equal(message.id, event.id);
        received.push(message);
        if (event.id === "interrupted") {
          controller.abort();
          await delay(50);
        }
        return {
          effects: [
            {
              type: "modify",
              target: "input",
              operation: "merge",
              value: { task: 2 },
            },
            ...(event.id === "denied"
              ? [{ type: "deny", reason: "policy" }]
              : event.id === "stopped"
                ? [{ type: "flow", operation: "stop", reason: "done" }]
                : []),
          ],
        };
      }
      const handler = async (incoming, outgoing) => {
        try {
          const request = new Request(`${origin}${incoming.url}`, {
            method: incoming.method,
            headers: incoming.headers,
            body: Readable.toWeb(incoming),
            duplex: "half",
          });
          let response;
          if (incoming.url === "/token") {
            const parameters = new URLSearchParams(await request.text());
            assert.equal(parameters.get("grant_type"), "client_credentials");
            assert.equal(parameters.get("client_id"), "test-client");
            assert.equal(
              parameters.get("client_secret"),
              "TEST-ONLY-client-secret",
            );
            tokenRequests++;
            response = Response.json({
              access_token: credentials.assertion,
              token_type: "Bearer",
              expires_in: 3600,
            });
          } else if (incoming.url === "/upload") {
            assert.equal(
              incoming.headers.authorization,
              authenticatedUpload ? "Bearer TEST-ONLY-upload-token" : undefined,
            );
            const upload = attachments.parse(request);
            const content = Buffer.from(
              await new Response(upload.body).arrayBuffer(),
            );
            const ref = `stored-${stored.size}`;
            stored.set(ref, content);
            uploads.push(ref);
            response = attachments.response({
              ref,
              size: upload.size,
              sha256: upload.sha256,
            });
          } else if (incoming.url === "/policy" && transport === "stdio") {
            // Application policy RPC for the child; the child invokes hooks.handle
            // before this callback. This route never receives unvalidated AHP frames.
            response = Response.json(
              (await policy(await request.json())) ?? null,
            );
          } else if (!authorize(incoming, credentials)) {
            response = new Response(null, { status: 401 });
          } else {
            response = await serverHooks.handle(request, policy);
          }
          outgoing.writeHead(
            response.status,
            Object.fromEntries(response.headers),
          );
          outgoing.end(new Uint8Array(await response.arrayBuffer()));
        } catch {
          outgoing.writeHead(500).end();
        }
      };
      const server =
        mode === "mtls"
          ? createSecureServer(
              {
                ca: await readFile(credentials.caFile),
                cert: await readFile(credentials.certFile),
                key: await readFile(credentials.keyFile),
                requestCert: true,
                rejectUnauthorized: true,
              },
              handler,
            )
          : createServer(handler);
      try {
        origin = await listen(server, mode === "mtls" ? "https" : "http");
        const peer = join(dir, "peer.mjs");
        if (transport === "stdio")
          await writeFile(
            peer,
            `
      import { createInterface } from 'node:readline';
      import { hooks } from ${JSON.stringify(pathToFileURL(require.resolve("agenthooksprotocol/server")).href)};
      for await (const line of createInterface({ input: process.stdin })) {
        const response = await hooks.handle(new Request('http://localhost/hooks', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: line,
        }), async message => {
          const result = await fetch(${JSON.stringify(origin + "/policy")}, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(message),
          });
          if (!result.ok) throw Error('Policy failed');
          const value = await result.json();
          return value === null ? undefined : value;
        });
        const text = await response.text();
        if (text) process.stdout.write(text + '\\n');
        else if (response.status !== 204) process.exit(1);
      }
    `,
          );
        const provider = sdkAuth({
          async authenticate(context, options) {
            if (context.purpose === "upload")
              return sdkAuth.authenticate(context, options);
            assert.equal(context.purpose, "event");
            if (mode === "none" || mode === "mtls") return undefined;
            if (mode === "workload") return { token: credentials.assertion };
            return sdkAuth.authenticate(context, options);
          },
          resolveEnvironmentVariable(name) {
            assert.equal(name, "AHP_TEST_UPLOAD_TOKEN");
            return "TEST-ONLY-upload-token";
          },
          resolveCredentialReference(name) {
            return name === "event"
              ? credentials.token
              : "TEST-ONLY-client-secret";
          },
          async discover() {
            return {
              client: {
                issuer: origin,
                resource: origin,
                clientId: "test-client",
                clientSecretRef: "secret",
                flow: "client_credentials",
              },
              metadata: {
                issuer: origin,
                token_endpoint: origin + "/token",
                grant_types_supported: ["client_credentials"],
                token_endpoint_auth_methods_supported: ["client_secret_post"],
              },
            };
          },
          allowedLoopbackOrigins: [origin],
        });
        const upload = {
          endpoint: origin + "/upload",
          timeoutMs: 5000,
          maxBytes: 1024,
          ...(authenticatedUpload
            ? { auth: { type: "bearer", tokenEnv: "AHP_TEST_UPLOAD_TOKEN" } }
            : {}),
        };
        // Host-owned TLS socket adapter only: Hooks still owns protocol framing,
        // correlation, upload publication, retries, cancellation and auth headers.
        const tls = mode === "mtls" ? auth("mtls", "client") : undefined;
        const transportFetch = tls
          ? await mutualTlsFetch(tls, origin)
          : undefined;
        client = new Hooks(
          {
            protocolVersion: "draft",
            hooks: [
              {
                id: "test.wire",
                transport:
                  transport === "stdio"
                    ? {
                        type: "stdio",
                        command: process.execPath,
                        args: [peer],
                        lifecycle: "persistent",
                      }
                    : { type: "http", url: origin + "/hooks" },
                ...(mode === "bearer"
                  ? { authentication: { type: "bearer", tokenRef: "event" } }
                  : mode === "oauth"
                    ? {
                        authentication: {
                          type: "oauth",
                          issuer: "https://identity.example",
                          resource: "https://hooks.example",
                          clientId: "test-client",
                          clientSecretRef: "secret",
                          flow: "client_credentials",
                        },
                      }
                    : {}),
                subscriptions: [
                  {
                    mode: "intercept",
                    events: ["tool.before"],
                    content: { default: "body" },
                    upload,
                    timeoutMs: 5000,
                    failurePolicy: "fail-closed",
                  },
                  {
                    mode: "observe",
                    events: ["tool.before"],
                    content: { default: "body" },
                    upload,
                  },
                ],
              },
            ],
          },
          {
            source: "urn:typescript:wire",
            auth: provider,
            ...(transportFetch ? { fetch: transportFetch } : {}),
            capabilities: {
              "tool.before": {
                modes: ["intercept", "observe"],
                capabilities: {
                  effects: ["modify", "allow", "deny", "flow"],
                  modify: { input: { merge: true, replace: true } },
                  flow: { operations: ["stop"] },
                },
              },
            },
          },
        );
        // Deliberate unauthorized/malformed negative bypass, never a positive sender.
        if (transport === "http" && mode !== "none" && mode !== "mtls") {
          const response = await fetch(origin + "/hooks", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{}",
          });
          assert.equal(response.status, 401);
        }
        for (const status of ["normal", "denied", "stopped", "interrupted"]) {
          /** @type {import("agenthooksprotocol/client").BoundaryInput<"tool.before">} */
          const input = {
            id: status,
            time: "2026-01-01T00:00:00Z",
            session: { id: "s" },
            call: { id: status },
            path: "native",
            tool: {
              origin: "native",
              name: "task",
              kind: "task",
              input: { task: 1 },
            },
            items: [
              {
                id: "item-" + status,
                kind: "attachment",
                mediaType: "application/octet-stream",
                body: new ReadableStream({
                  start(stream) {
                    stream.enqueue(bytes);
                    stream.close();
                  },
                }),
              },
            ],
          };
          const result = await client.dispatch(
            "tool.before",
            input,
            status === "interrupted" ? { signal: controller.signal } : {},
          );
          assert.deepEqual(await result.observations, []);
          assert.equal(result.interrupted, status === "interrupted");
          if (status === "interrupted") {
            assert.ok(
              result.errors.some((error) => error.code === "INTERRUPTED"),
            );
            assert.equal(result.event.tool.input.task, 1);
          } else {
            assert.deepEqual(result.errors, []);
            assert.equal(result.event.tool.input.task, 2);
            assert.equal(
              result.response.result.effects.some(
                (effect) => effect.type === "deny",
              ),
              status === "denied",
            );
            assert.equal(
              result.response.result.effects.some(
                (effect) => effect.type === "flow",
              ),
              status === "stopped",
            );
          }
          if (status === "interrupted") {
            // Cancellation retires this operation: no new observer upload or
            // notification may start, even for skipped interceptors.
            assert.equal(
              observed.some((note) => note.params.event.id === status),
              false,
            );
            continue;
          }
          if (transport !== "stdio")
            assert.ok(
              observed.some((note) => note.params.event.id === status),
              "HTTP observers complete before the boundary returns",
            );
          // stdio observation completion means frame write; wait for application receipt.
          for (
            let attempt = 0;
            attempt < 200 &&
            !observed.some((note) => note.params.event.id === status);
            attempt++
          )
            await delay(10);
          const note = observed.find((note) => note.params.event.id === status);
          assert.ok(note);
          assert.equal(note.params.event.tool.input.task, 2);
          assert.ok(uploads.includes(note.params.event.items[0].body.ref));
          assert.notEqual(
            note.params.event.items[0].body.ref,
            received.find((message) => message.id === status).params.event
              .items[0].body.ref,
          );
        }
        assert.equal(received.length, 4);
        // Normal and short-circuited operations own observer completion;
        // interruption does not launch fresh best-effort work.
        assert.deepEqual(
          observed.map((note) => note.params.event.id),
          ["normal", "denied", "stopped"],
        );
        // The interrupted call also preuploads its authorized observer body.
        assert.equal(stored.size, 8);
        if (mode === "oauth") assert.ok(tokenRequests > 0);
      } finally {
        await client?.close();
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        await rm(dir, { recursive: true, force: true });
      }
    },
  );
