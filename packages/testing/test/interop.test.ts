import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import process from "node:process";
import { Hooks } from "agenthooksprotocol/client";
import { createAuth, clientAuth } from "../src/interop/auth.js";
import { atomicScenarios } from "../src/interop/atomic-client.js";
import {
  runInterop,
  resolveCredential,
  request,
} from "../src/interop/client.js";

test("synthetic interop: real concurrent stdio, HTTP, TLS and explicit auth matrix", async () => {
  const nativeFetch = globalThis.fetch;
  const report = await runInterop();
  assert.equal(globalThis.fetch, nativeFetch);
  assert.equal(
    report.ok,
    true,
    JSON.stringify(report.results.filter((row) => row.status === "failed")),
  );
  assert.equal(report.results.length, 34);
  assert.equal(
    report.results.filter((row) => row.status === "inapplicable").length,
    4,
  );
  assert.ok(
    report.results.some(
      (row) => row.id === "stdio-repeat" && row.actual === "no-effect",
    ),
  );
  // The report is language neutral, with no wire bodies, tokens or authorization headers.
  for (const row of report.results)
    assert.deepEqual(Object.keys(row).sort(), [
      "actual",
      "auth",
      "expected",
      "id",
      "status",
      "transport",
    ]);
});
test("public auth resolves credential references outside protocol payloads and fails closed", async () => {
  const provider = clientAuth("bearer", "http://127.0.0.1:1");
  const credentials = createAuth().credentials;
  for (const binding of [
    { type: "bearer" as const, tokenEnv: "AHP_TEST_BEARER" },
    { type: "bearer" as const, tokenRef: "bearer" },
  ]) {
    const credential = await provider.authenticate({
      url: "http://127.0.0.1:1/bearer",
      authentication: binding,
    });
    assert.equal(credential?.token, credentials.bearer);
  }
  for (const binding of [
    { type: "bearer" as const, tokenEnv: "MISSING" },
    { type: "bearer" as const, tokenRef: "MISSING" },
  ]) {
    let rejected = false;
    try {
      await provider.authenticate({
        url: "http://127.0.0.1:1/bearer",
        authentication: binding,
      });
    } catch {
      rejected = true;
    }
    assert.equal(rejected, true);
  }
  // Raw adversarial-wire helpers still reject unsupported reference syntax.
  for (const reference of ["literal:secret", "malformed"]) {
    let rejected = false;
    try {
      resolveCredential(reference, {}, {});
    } catch {
      rejected = true;
    }
    assert.equal(rejected, true);
  }
});

test("HTTP authorization is independent of JSON-RPC correlation and event identifiers", async () => {
  const child = spawn(
    process.execPath,
    [new URL("../src/interop/server.js", import.meta.url).pathname],
    { stdio: ["pipe", "pipe", "pipe", "ipc"], shell: false },
  );
  child.stdout.resume();
  child.stderr.resume();
  const exited = new Promise<void>((resolve) =>
    child.once("exit", () => resolve()),
  );
  const deadline = setTimeout(() => child.kill(), 15000);
  try {
    const ready = await new Promise<{ httpPort: number }>((resolve, reject) => {
      child.once("message", (message: any) =>
        message.type === "ready"
          ? resolve(message)
          : reject(Error("Missing readiness")),
      );
      child.once("error", reject);
      child.once("exit", () => reject(Error("Server exited")));
    });
    const auth = createAuth();
    for (const id of ["unrelated-correlation", "another-event"]) {
      const wire = structuredClone(
        atomicScenarios()[0]!.expected.requests[0],
      ) as any;
      wire.id = id;
      wire.params.event.id = id;
      const body = JSON.stringify(wire);
      const accepted = await request(
        ready.httpPort,
        "/bearer",
        body,
        `Bearer ${auth.credentials.bearer}`,
      );
      assert.equal(accepted.status, 200);
      assert.equal(JSON.parse(accepted.body).id, id);
      assert.equal(
        (await request(ready.httpPort, "/bearer", body, `Bearer ${id}`)).status,
        401,
      );
      assert.equal(
        (await request(ready.httpPort, "/bearer", body)).status,
        401,
      );
    }
    // Public client upload -> attachments helpers -> committed reference -> hooks.handle.
    const origin = `http://127.0.0.1:${ready.httpPort}`;
    const hooks = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "interop.upload",
            transport: { type: "http", url: `${origin}/bearer` },
            authentication: { type: "bearer", tokenRef: "bearer" },
            subscriptions: [
              {
                mode: "intercept",
                events: ["user.message.inbound"],
                failurePolicy: "fail-closed",
                timeoutMs: 5000,
                content: { default: "body" },
                upload: {
                  endpoint: `${origin}/attachments`,
                  maxBytes: 1024,
                  timeoutMs: 5000,
                  auth: { type: "bearer", tokenRef: "bearer" },
                },
              },
            ],
          },
        ],
      },
      {
        source: "urn:interop:upload",
        capabilities: { "user.message.inbound": { effects: [] } },
        auth: clientAuth("bearer", origin),
      },
    );
    try {
      const result = await hooks.dispatch("user.message.inbound", {
        message: {
          channel: "chat",
          sender: "user",
          messages: [{ id: "upload-message", role: "user", parts: [
            {
              id: "upload-text",
              kind: "attachment",
              mediaType: "application/octet-stream",
              body: new ReadableStream<Uint8Array>({
                start(controller) {
                  controller.enqueue(
                    new TextEncoder().encode("verified Unicode 🚀"),
                  );
                  controller.close();
                },
              }),
            },
          ] }],
        },
      });
      assert.deepEqual(result.errors, []);
      assert.deepEqual(await result.observations, []);
      assert.equal(result.interrupted, false);
      assert.deepEqual(result.response.result.effects, []);
    } finally {
      await hooks.close();
    }
    // Authentication happens before JSON-RPC decoding, even for malformed input.
    assert.equal((await request(ready.httpPort, "/bearer", "{")).status, 401);
  } finally {
    clearTimeout(deadline);
    child.kill();
    await exited;
  }
});
