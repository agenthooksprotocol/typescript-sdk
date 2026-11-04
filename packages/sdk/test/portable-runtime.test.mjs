import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  Hooks,
  Permission,
  state,
} from "agenthooksprotocol/client";

const client = new URL("../dist/src/client/index.js", import.meta.url).href;

// A host that refuses `eval` and `new Function` (a sandboxed plugin runtime)
// still loads the client and intercepts: validators are precompiled.
test("the client validates and intercepts with code generation disallowed", () => {
  const script = `
    const { Hooks, Permission, state } = await import(${JSON.stringify(client)});
    assert(() => new Function("return 1"));
    const hooks = new Hooks({
      protocolVersion: "draft",
      hooks: [{
        id: "org.example.policy",
        transport: { type: "http", url: "https://hooks.example/intercept" },
        subscriptions: [{ mode: "intercept", events: ["tool.before"], timeoutMs: 1000,
          failurePolicy: "fail-closed", content: { default: "body" } }],
      }],
    }, {
      source: "urn:example:sandbox",
      harness: { name: "sandbox", version: "1" },
      capabilities: { toolBefore: { intercept: { deny: true } } },
      fetch: async (_url, init) => {
        const request = JSON.parse(init.body);
        return Response.json({ jsonrpc: "2.0", id: request.id,
          result: { protocolVersion: "draft", effects: [{ type: "deny", reason: "no" }] } });
      },
    });
    const result = await hooks.toolBefore(
      { callId: "c", name: "read_file", origin: "native", path: "native", input: { path: "x" } },
      { initialState: state.initial(Permission.None) },
    );
    await hooks.close();
    if (result.state.permission !== Permission.Deny) throw new Error("expected deny");
    function assert(generate) {
      try { generate(); } catch { return; }
      throw new Error("code generation was not disallowed");
    }
  `;
  const run = spawnSync(process.execPath, [
    "--disallow-code-generation-from-strings",
    "--input-type=module",
    "-e",
    script,
  ], { encoding: "utf8", cwd: fileURLToPath(new URL("..", import.meta.url)) });
  assert.equal(run.status, 0, run.stderr);
});

test("contracts validate without generated code where the runtime refuses it", () => {
  const script = `
    const { contract, Type } = await import(${JSON.stringify(client)});
    const codec = contract(Type.Object({ path: Type.String({ minLength: 1 }) }));
    codec.decode({ path: "README.md" });
    let refused = false;
    try { codec.decode({ path: "" }); } catch { refused = true; }
    if (!refused) throw new Error("expected the contract to refuse an empty path");
  `;
  const run = spawnSync(process.execPath, [
    "--disallow-code-generation-from-strings",
    "--input-type=module",
    "-e",
    script,
  ], { encoding: "utf8", cwd: fileURLToPath(new URL("..", import.meta.url)) });
  assert.equal(run.status, 0, run.stderr);
});

test("contracts behave the same compiled and interpreted", () => {
  const script = `
    const { contract, Type } = await import(${JSON.stringify(client)});
    const schemas = [
      Type.String({ maxLength: 1 }),
      Type.String({ minLength: 2 }),
      Type.String({ pattern: "^.$" }),
      Type.String({ format: "email" }),
      Type.String({ format: "uri", maxLength: 3 }),
      Type.Object({ list: Type.Array(Type.String({ maxLength: 1 })) }),
      Type.Union([Type.Number(), Type.String({ maxLength: 1 })]),
      Type.Optional(Type.String({ minLength: 2 })),
    ];
    const values = ["😀", "ab", "a@b.co", { list: ["😀"] }, { list: ["ab"] }, 1, null];
    console.log(JSON.stringify(schemas.map((schema) => {
      const codec = contract(schema);
      return values.map((value) => {
        try { codec.decode(value); return true; } catch { return false; }
      });
    })));
  `;
  const run = (...flags) => {
    const result = spawnSync(process.execPath, [...flags, "--input-type=module", "-e", script],
      { encoding: "utf8", cwd: fileURLToPath(new URL("..", import.meta.url)) });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };
  const compiled = run();
  assert.deepEqual(compiled[0].slice(0, 2), [true, false]);
  assert.deepEqual(compiled[1].slice(0, 2), [false, true]);
  assert.deepEqual(run("--disallow-code-generation-from-strings"), compiled);
});

test("stdio runs through an injected launcher without Buffer", () => {
  const script = `
    const { BackendTransport } = await import(${JSON.stringify(new URL("../dist/src/client/transport.js", import.meta.url).href)});
    delete globalThis.Buffer;
    let killed = 0;
    const transport = new BackendTransport(
      { id: "org.example.stdio", transport: { type: "stdio", command: "policy", lifecycle: "per_event" } },
      async () => { throw new Error("no fetch"); },
      { environment: {}, spawn() {
        const listeners = { stdout: [], close: [] };
        return {
          write(data, end, callback) {
            callback();
            const { id } = JSON.parse(data);
            const reply = JSON.stringify({ jsonrpc: "2.0", id, result: { text: "😀" } }) + "\\n";
            const bytes = new TextEncoder().encode(reply);
            queueMicrotask(() => {
              // Split inside the multi-byte character: frames span chunks.
              for (const listener of listeners.stdout) {
                listener(bytes.subarray(0, reply.indexOf("😀") + 1));
                listener(bytes.subarray(reply.indexOf("😀") + 1));
              }
              for (const listener of listeners.close) listener(0);
            });
          },
          onStdout: (listener) => listeners.stdout.push(listener),
          onError() {},
          onClose: (listener) => listeners.close.push(listener),
          kill() { killed++; },
        };
      } },
    );
    const response = await transport.request({ jsonrpc: "2.0", id: "1", method: "hooks/intercept", params: {} });
    await transport.close();
    if (response.result.text !== "😀") throw new Error("frame was not decoded");
  `;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script],
    { encoding: "utf8", cwd: fileURLToPath(new URL("..", import.meta.url)) });
  assert.equal(run.status, 0, run.stderr);
});

test("an injected spawner runs per_event stdio backends", async () => {
  const written = [];
  const hooks = new Hooks({
    protocolVersion: "draft",
    hooks: [{
      id: "org.example.stdio",
      transport: { type: "stdio", command: "policy", args: ["--json"], lifecycle: "per_event" },
      subscriptions: [{ mode: "intercept", events: ["tool.before"], timeoutMs: 1000,
        failurePolicy: "fail-closed", content: { default: "body" } }],
    }],
  }, {
    source: "urn:example:spawn",
    harness: { name: "spawn", version: "1" },
    capabilities: { toolBefore: { intercept: { deny: true } } },
    environment: { PATH: "/bin", SECRET: "kept out" },
    spawn: (request) => {
      written.push(request);
      const listeners = { stdout: [], close: [] };
      return {
        write(data, end, callback) {
          assert.equal(end, true);
          const message = JSON.parse(data);
          callback();
          queueMicrotask(() => {
            const reply = JSON.stringify({ jsonrpc: "2.0", id: message.id,
              result: { protocolVersion: "draft", effects: [{ type: "deny", reason: "stdio" }] } }) + "\n";
            for (const listener of listeners.stdout) listener(new TextEncoder().encode(reply));
            for (const listener of listeners.close) listener(0);
          });
        },
        onStdout: (listener) => listeners.stdout.push(listener),
        onError: () => {},
        onClose: (listener) => listeners.close.push(listener),
        kill: () => {},
      };
    },
  });
  try {
    const result = await hooks.toolBefore(
      { callId: "c", name: "read_file", origin: "native", path: "native", input: {} },
      { initialState: state.initial(Permission.None) },
    );
    assert.equal(result.state.permission, Permission.Deny);
    assert.equal(written.length, 1);
    assert.equal(written[0].command, "policy");
    assert.deepEqual(written[0].args, ["--json"]);
    assert.deepEqual(written[0].env, { PATH: "/bin" });
  } finally {
    await hooks.close();
  }
});
