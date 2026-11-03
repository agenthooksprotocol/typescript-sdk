import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  Hooks,
  Permission,
  contract,
  state,
  Type,
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
  const codec = contract(Type.Object({ path: Type.String({ minLength: 1 }) }));
  assert.deepEqual(codec.decode({ path: "README.md" }), { path: "README.md" });
  assert.throws(() => codec.decode({ path: "" }));
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
