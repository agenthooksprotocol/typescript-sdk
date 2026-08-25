import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ToolBeforeRunner, type HookBackend, type ToolBeforeInput } from "@agenthooksprotocol/sdk";
import { fakeBackendEntrypoint } from "@agenthooksprotocol/testing";
import { runConformance } from "../src/index.js";

const temp = (): string => mkdtempSync(join(tmpdir(), "ahp-ts-"));
const fake = (mode: string, extra: string[] = [], overrides: Partial<HookBackend> = {}): HookBackend => ({
  command: "node",
  args: [fakeBackendEntrypoint, "--mode", mode, ...extra],
  timeoutMs: 500,
  failurePolicy: "fail-closed",
  ...overrides,
});
const input: ToolBeforeInput = {
  source: "urn:agenthooksprotocol:tests:runner",
  eventId: "event-stable",
  time: "2026-01-02T03:04:05.678Z",
  session: { id: "session-stable", cwd: "/workspace", workspaceRoots: ["/workspace", "/shared"], model: "model-1", agent: { id: "agent-1", type: "subagent" } },
  tool: { callId: "call-stable", name: "write_工具", kind: "file_write", input: { text: "Zażółć 🚀" } },
  native: { provider: "fixture", eventName: "PreToolUse", payload: { original: true } },
  extensions: { "com.example.trace": "trace-1" },
};

async function failureCodeFor(badInput: ToolBeforeInput): Promise<string | undefined> {
  const runner = new ToolBeforeRunner();
  try { await runner.intercept(badInput); return undefined; } catch (error) { return error instanceof Error && "code" in error ? String((error as { code: unknown }).code) : "UNKNOWN"; } finally { runner.close(); }
}

test("emits the exact canonical intercept request shape", async () => {
  const record = join(temp(), "request.ndjson");
  const runner = new ToolBeforeRunner({ idGenerator: (kind) => `${kind}-generated` });
  runner.register(fake("no-effect", ["--record-file", record]));
  const result = await runner.intercept(input);
  runner.close();
  const line = readFileSync(record, "utf8").trim();
  const request = JSON.parse(line.slice(line.indexOf("\t") + 1)) as unknown;
  assert.deepEqual(request, {
    jsonrpc: "2.0",
    id: "event-stable",
    method: "hooks/intercept",
    params: {
      protocolVersion: "0.1",
      event: {
        id: "event-stable", source: "urn:agenthooksprotocol:tests:runner", type: "tool.before", time: "2026-01-02T03:04:05.678Z",
        session: { id: "session-stable", cwd: "/workspace", workspaceRoots: ["/workspace", "/shared"], model: "model-1", agent: { id: "agent-1", type: "subagent" } },
        tool: { callId: "call-stable", name: "write_工具", kind: "file_write", input: { text: "Zażółć 🚀" } },
        native: { provider: "fixture", eventName: "PreToolUse", payload: { original: true } }, extensions: { "com.example.trace": "trace-1" },
      },
      capabilities: { effects: ["deny"] },
    },
  });
  assert.equal(result.decision, "continue");
});

test("requires tool.input to be a JSON object and rejects unknown tool kinds", async () => {
  const scalar = { ...input, tool: { ...input.tool, input: "not-an-object" } } as unknown as ToolBeforeInput;
  const array = { ...input, tool: { ...input.tool, input: [] } } as unknown as ToolBeforeInput;
  const unknownKind = { ...input, tool: { ...input.tool, kind: "future-kind" } } as unknown as ToolBeforeInput;
  assert.equal(await failureCodeFor(scalar), "MALFORMED_JSON_RPC");
  assert.equal(await failureCodeFor(array), "MALFORMED_JSON_RPC");
  assert.equal(await failureCodeFor(unknownKind), "MALFORMED_JSON_RPC");
});

test("composes backends serially in registration order", async () => {
  const record = join(temp(), "order.ndjson");
  const runner = new ToolBeforeRunner();
  runner.register(fake("no-effect", ["--delay-ms", "80", "--record-file", record, "--record-label", "first"]));
  runner.register(fake("no-effect", ["--record-file", record, "--record-label", "second"]));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.decision, "continue");
  assert.deepEqual(readFileSync(record, "utf8").trim().split("\n").map((line) => line.split("\t")[0]), ["first", "second"]);
});

test("deadline covers the full exchange and bounds all retries", async () => {
  const runner = new ToolBeforeRunner();
  runner.register(fake("timeout", ["--delay-ms", "150"], { timeoutMs: 35, retries: 1, failurePolicy: "fail-open" }));
  const started = Date.now();
  const result = await runner.intercept(input);
  const elapsed = Date.now() - started;
  runner.close();
  assert.equal(result.decision, "continue");
  assert.equal(result.failures[0]?.code, "TIMEOUT");
  assert.ok(elapsed >= 25 && elapsed < 250, `unexpected elapsed time ${elapsed}ms`);
});

test("classifies malformed output and explicitly fails open", async () => {
  const runner = new ToolBeforeRunner();
  runner.register(fake("malformed-json", [], { failurePolicy: "fail-open" }));
  runner.register(fake("deny", ["--reason", "second backend"]));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.failures[0]?.code, "MALFORMED_JSON");
  assert.equal(result.decision, "deny");
  assert.equal(result.denial?.reason, "second backend");
});

test("ignores unknown fields in otherwise valid responses", async () => {
  const runner = new ToolBeforeRunner();
  runner.register(fake("unknown-fields"));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.decision, "deny");
  assert.equal(result.denial?.reason, "Unknown fields tolerated");
  assert.equal(result.denial?.code, "com.example.denied");
  assert.deepEqual(result.denial?.extensions, { "com.example.detail": true });
  assert.deepEqual(result.failures, []);
});

test("rejects a deny effect with an empty reason", async () => {
  const runner = new ToolBeforeRunner();
  runner.register(fake("malformed-deny", [], { failurePolicy: "fail-open" }));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.decision, "continue");
  assert.equal(result.failures[0]?.code, "MALFORMED_JSON_RPC");
});

test("explicit fail-closed stops composition on operational failure", async () => {
  const record = join(temp(), "not-called.ndjson");
  const runner = new ToolBeforeRunner();
  runner.register(fake("json-rpc-error"));
  runner.register(fake("no-effect", ["--record-file", record]));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.decision, "deny");
  assert.equal(result.denial?.operational, true);
  assert.equal(result.failures[0]?.code, "JSON_RPC_ERROR");
  assert.equal(existsSync(record), false);
});

test("a protocol denial short-circuits later registrations", async () => {
  const record = join(temp(), "not-called.ndjson");
  const runner = new ToolBeforeRunner();
  runner.register(fake("deny", ["--reason", "policy"]));
  runner.register(fake("no-effect", ["--record-file", record]));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.decision, "deny");
  assert.equal(result.denial?.operational, false);
  assert.equal(result.denial?.reason, "policy");
  assert.equal(existsSync(record), false);
});

test("bounded retries preserve byte-identical requests and all IDs", async () => {
  const record = join(temp(), "retries.ndjson");
  let serial = 0;
  const runner = new ToolBeforeRunner({ idGenerator: (kind) => `${kind}-${++serial}` });
  runner.register(fake("malformed-json", ["--record-file", record], { retries: 2, failurePolicy: "fail-open" }));
  const result = await runner.intercept({ source: "urn:agenthooksprotocol:tests:runner", time: "2026-01-02T03:04:05Z", session: {}, tool: { name: "stable", kind: "other", input: {} } });
  runner.close();
  const requests = readFileSync(record, "utf8").trim().split("\n").map((line) => line.slice(line.indexOf("\t") + 1));
  assert.equal(requests.length, 3);
  assert.ok(requests.every((line) => line === requests[0]));
  const request = JSON.parse(requests[0] as string) as { id: string; params: { event: { id: string; session: { id: string }; tool: { callId: string } } } };
  assert.equal(request.id, "event-3");
  assert.equal(request.params.event.id, "event-3");
  assert.equal(request.params.event.session.id, "session-1");
  assert.equal(request.params.event.tool.callId, "call-2");
  assert.equal(result.event.id, "event-3");
});

test("NDJSON framing preserves Unicode across one-byte chunks", async () => {
  const record = join(temp(), "unicode.ndjson");
  const runner = new ToolBeforeRunner();
  runner.register(fake("deny", ["--reason", "拒否 🚫", "--chunk-size", "1", "--record-file", record], { lifecycle: "persistent" }));
  const result = await runner.intercept(input);
  runner.close();
  assert.equal(result.denial?.reason, "拒否 🚫");
  assert.match(readFileSync(record, "utf8"), /Zażółć 🚀/);
});

test("unsupported, multiple, incompatible, and mismatched semantics are operational failures", async () => {
  const cases = [["unsupported-effect", "UNSUPPORTED_EFFECT"], ["multiple-effects", "MULTIPLE_EFFECTS"], ["incompatible-version", "INCOMPATIBLE_VERSION"], ["id-mismatch", "ID_MISMATCH"]] as const;
  for (const [mode, code] of cases) {
    const runner = new ToolBeforeRunner();
    runner.register(fake(mode, [], { failurePolicy: "fail-open" }));
    const result = await runner.intercept(input);
    runner.close();
    assert.equal(result.decision, "continue");
    assert.equal(result.failures[0]?.code, code);
  }
});

test("black-box conformance runner drives a persistent target command", async () => {
  const report = await runConformance({ command: "node", args: [fakeBackendEntrypoint, "--mode", "no-effect"] });
  assert.equal(report.ok, true);
  assert.equal(report.checks.length, 2);
});
