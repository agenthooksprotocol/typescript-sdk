import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as rootSdk from "agenthooksprotocol";
import { Hooks, type ToolBeforeInput } from "agenthooksprotocol/client";
import { fakeBackendEntrypoint } from "@agenthooksprotocol/testing";
import { runConformance } from "../src/index.js";

type Fixture = {
  mode: string;
  args?: string[];
  timeoutMs?: number;
  failurePolicy?: "fail-open" | "fail-closed";
};
const temp = (): string => mkdtempSync(join(tmpdir(), "ahp-ts-"));
const input: ToolBeforeInput = {
  id: "event-stable",
  time: "2026-01-02T03:04:05.678Z",
  callId: "call-stable",
  path: "native",
  name: "write_工具",
  origin: "native",
  input: { text: "Zażółć 🚀" },
};
const client = (...fixtures: Fixture[]) => new Hooks({
  protocolVersion: "draft",
  hooks: fixtures.map((fixture, index) => ({
    id: `fixture.backend${index}`,
    transport: {
      type: "stdio",
      command: "node",
      args: [fakeBackendEntrypoint, "--mode", fixture.mode, ...(fixture.args ?? [])],
      lifecycle: "persistent",
    },
    subscriptions: [{
      mode: "intercept",
      events: ["tool.before"],
      timeoutMs: fixture.timeoutMs ?? 5000,
      failurePolicy: fixture.failurePolicy ?? "fail-closed",
      content: { default: "metadata" },
    }],
  })),
}, {
  source: "urn:agenthooksprotocol:tests:runner",
  harness: { name: "test", version: "1" },
  capabilities: { toolBefore: { intercept: { deny: true } } },
});
async function exchange(...fixtures: Fixture[]) {
  const hooks = client(...fixtures);
  try { return await hooks.toolBefore(input); }
  finally { await hooks.close(); }
}

test("emits the canonical tool.before shape without legacy tool identity or kind fields", async () => {
  const record = join(temp(), "request.ndjson");
  const result = await exchange({ mode: "no-effect", args: ["--record-file", record] });
  assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
  assert.deepEqual(result.diagnostics.filter(d => d.phase === "observation"), []);
  const line = readFileSync(record, "utf8").trim();
  const request = JSON.parse(line.slice(line.indexOf("\t") + 1));
  assert.equal(request.method, "hooks/intercept");
  assert.equal(request.id, input.id);
  assert.equal(request.params.protocolVersion, "draft");
  assert.equal(request.params.event.source, "urn:agenthooksprotocol:tests:runner");
  assert.deepEqual(request.params.event.call, { id: "call-stable" });
  assert.deepEqual(request.params.event.tool, {
    name: "write_工具", origin: "native", input: { text: "Zażółć 🚀" },
  });
  assert.equal(request.params.event.tool.callId, undefined);
  assert.equal(request.params.event.tool.kind, undefined);
  assert.deepEqual(request.params.capabilities.effects, ["deny"]);
  assert.equal(result.event.id, input.id);
});

test("composes canonical backends serially in registration order", async () => {
  const record = join(temp(), "order.ndjson");
  const result = await exchange(...["first", "second"].map(label => ({
    mode: "no-effect", args: ["--record-file", record, "--record-label", label],
  })));
  assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
  assert.deepEqual(readFileSync(record, "utf8").trim().split("\n").map(line => line.split("\t")[0]), ["first", "second"]);
});

test("deadline covers the full canonical exchange", async () => {
  const started = Date.now();
  const result = await exchange({ mode: "timeout", args: ["--delay-ms", "150"], timeoutMs: 35, failurePolicy: "fail-open" });
  assert.ok(Date.now() - started < 1000);
  assert.equal(result.diagnostics.filter(d => d.phase !== "observation")[0]?.code, "deadline_exceeded");
  assert.equal(result.interrupted, false);
});

test("malformed output fails open and subsequent denial is accepted", async () => {
  const result = await exchange(
    { mode: "malformed-json", failurePolicy: "fail-open" },
    { mode: "deny", args: ["--reason", "second backend"] },
  );
  assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
  assert.equal(result.state.permission, "deny");
  assert.deepEqual(result.effects, [{ type: "deny", reason: "second backend" }]);
});

test("unknown envelope fields survive canonical acceptance", async () => {
  const result = await exchange({ mode: "unknown-fields" });
  assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
  assert.equal(result.state.permission, "deny");
  assert.equal(result.acceptedResponses[0]?.ignoredRoot, true);
});

for (const mode of ["malformed-deny", "unsupported-effect", "multiple-effects", "incompatible-version", "id-mismatch"] as const) {
  test(`canonical validation rejects fault injection: ${mode}`, async () => {
    const result = await exchange({ mode, failurePolicy: "fail-open" });
    assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
    assert.deepEqual(result.acceptedResponses, []);
    assert.deepEqual(result.effects, []);
  });
}

test("fail-closed operational failure stops later registrations", async () => {
  const record = join(temp(), "not-called.ndjson");
  const result = await exchange(
    { mode: "json-rpc-error" },
    { mode: "no-effect", args: ["--record-file", record] },
  );
  assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
  assert.equal(result.state.permission, "deny");
  assert.equal(existsSync(record), false);
});

test("protocol denial short-circuits later registrations", async () => {
  const record = join(temp(), "not-called.ndjson");
  const result = await exchange(
    { mode: "deny", args: ["--reason", "policy"] },
    { mode: "no-effect", args: ["--record-file", record] },
  );
  assert.equal(result.state.permission, "deny");
  assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
  assert.equal(existsSync(record), false);
});

test("strict NDJSON framing preserves Unicode across one-byte chunks", async () => {
  const result = await exchange({ mode: "deny", args: ["--reason", "拒否 🚫", "--chunk-size", "1"] });
  assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
  assert.deepEqual(result.effects, [{ type: "deny", reason: "拒否 🚫" }]);
});

test("black-box conformance runner drives a persistent canonical target", async () => {
  const report = await runConformance({
    command: "node",
    args: [fakeBackendEntrypoint, "--mode", "no-effect", "--chunk-size", "3"],
    timeoutMs: 5000,
  });
  assert.deepEqual(report, { ok: true, checks: [
    { name: "valid tool.before exchange", ok: true },
    { name: "persistent sequential exchange", ok: true },
  ] });
});


test("root entrypoint exposes independent JSON helpers, not an alternate protocol API", () => {
  for (const name of ["ToolBeforeRunner", "parseInterceptRequest", "parseInterceptResponse", "PROTOCOL_VERSION", "INTERCEPT_METHOD", "TOOL_KINDS", "asOperationalError"]) {
    assert.equal(name in rootSdk, false, `root.${name}`);
  }
  const json = rootSdk.parseJson('{"integer":9007199254740993}');
  rootSdk.assertJsonObject(json);
  assert.equal(json.integer, 9007199254740993n);
  rootSdk.assertJsonValue({ nested: [null, true, 3.5, 9007199254740993n] });
  const rejects = (value: unknown) => {
    let rejected = false;
    try { rootSdk.assertJsonValue(value); } catch { rejected = true; }
    assert.equal(rejected, true);
  };
  rejects({ value: undefined });
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  rejects(cycle);
});
