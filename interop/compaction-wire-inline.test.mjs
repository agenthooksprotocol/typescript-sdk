import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compactionCapabilities, textParts, inlineText } from "./compaction.mjs";

const adapter = new URL("./compaction-wire.mjs", import.meta.url).pathname;
const modify = (target, value) => ({ type: "modify", target, operation: "replace", value });
const part = (id, text) => ({ ...textParts(text)[0], id });

async function command(mode, input) {
  const child = spawn(process.execPath, [adapter, mode], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  child.stdin.end(JSON.stringify(input));
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

async function fixture(config, run) {
  const store = await mkdtemp(join(tmpdir(), "ahp-compaction-inline-"));
  const configPath = join(store, "subscriptions.json");
  await writeFile(configPath, JSON.stringify(config));
  const plan = {
    transport: "stdio",
    endpoint: "http://127.0.0.1:1",
    credentials: Object.fromEntries(Object.keys(config).map(sub => [sub, {
      token: "event:" + sub, uploadToken: "upload:" + sub,
    }])),
    receiverCommand: [process.execPath, adapter, "unused-schema", store, configPath],
  };
  try { await run(plan, store); }
  finally { await rm(store, { recursive: true, force: true }); }
}

for (const boundary of ["before", "after"]) {
  test(`wire call preserves ordered inline ${boundary} parts and receiver evidence`, { timeout: 15000 }, async () => {
    await fixture({ watch: { effects: [] } }, async (plan, store) => {
      const parts = [part("first", "one"), part("second", ":two")];
      const snapshot = {
        boundary, instructions: parts, summary: parts, candidate: null,
        capabilities: compactionCapabilities(boundary),
      };
      const run = await command("call", { plan, sub: "watch", name: "parts", snapshot });
      assert.equal(run.code, 0, run.stderr);
      const result = JSON.parse(run.stdout);
      assert.equal(result.failed, false);
      assert.deepEqual(result.effects, []);
      const target = boundary === "before" ? "instructions" : "summary";
      assert.deepEqual(result.wire.request.params.event[target], parts);
      assert.equal(result.wire.request.method, "hooks/intercept");
      assert.equal(Object.hasOwn(result.wire.request.params, "subscriptionId"), false);
      const receipt = JSON.parse((await readFile(join(store, "receipts.jsonl"), "utf8")).trim());
      assert.deepEqual(receipt.request, result.wire.request);
      assert.deepEqual(receipt.response, result.wire.response);
      assert.equal(receipt.bodies[target], "one:two");
      assert.equal(JSON.stringify(result.wire).includes("event:watch"), false);
      assert.equal(JSON.stringify(result.wire).includes("upload:watch"), false);
    });
  });
}

test("wire host reports canonical arrays without leaking compound effects or supplier provenance", { timeout: 30000 }, async () => {
  const accepted = [part("left", "base"), part("right", ":accepted")];
  const config = {
    edit: { effects: [modify("instructions", accepted)] },
    cache: { effects: [{ type: "return", value: "cached" }] },
    beforeBad: { bypass: true, effects: [modify("instructions", textParts("leaked")), { type: "message", text: "leaked" }, modify("summary", textParts("wrong"))] },
    beforeWatch: { effects: [] },
    redact: { kind: "append", target: "summary", suffix: ":safe" },
    afterBad: { bypass: true, effects: [modify("summary", textParts("leaked")), { type: "message", text: "leaked" }, modify("instructions", textParts("wrong"))] },
    afterWatch: { effects: [] },
  };
  await fixture(config, async (plan, store) => {
    const row = (supplier, failurePolicy = "fail-closed") => ({ supplier, failurePolicy });
    plan.cases = [{ name: "atomic", before: [row("edit"), row("cache"), row("beforeBad", "fail-open"), row("beforeWatch")], after: [row("redact"), row("afterBad", "fail-open"), row("afterWatch")] }];
    const run = await command("host", plan);
    assert.equal(run.code, 0, run.stderr);
    const [out] = JSON.parse(run.stdout);
    assert.deepEqual(out.result.instructions, accepted);
    assert.equal(inlineText(out.result.summary), "cached:safe");
    assert.deepEqual(out.result.provenance, { kind: "supplied", supplier: "cache" });
    assert.equal(out.result.generated, false);
    assert.equal(out.result.applied, true);
    assert.equal(out.result.failures.length, 2);
    assert.deepEqual(out.result.messages, []);
    assert.deepEqual(out.downstream, ["cached:safe"]);
    const seen = out.trace.map(entry => {
      const event = entry.request.params.event;
      if (event.type.endsWith(".after")) assert.deepEqual(event.execution, { status: "skipped", reason: "supplied_result" });
      return inlineText(event.instructions ?? event.summary);
    });
    assert.deepEqual(seen, ["base", "base:accepted", "base:accepted", "base:accepted", "cached", "cached:safe", "cached:safe"]);
    const receipts = (await readFile(join(store, "receipts.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
    assert.equal(receipts.length, out.trace.length);
    for (const entry of out.trace) {
      const receipt = receipts.find(receipt => receipt.subscription === entry.subscription);
      assert.deepEqual(receipt.request, entry.request);
      assert.deepEqual(receipt.response, entry.response);
    }
  });
});

test("wire call requires independently supplied event and upload credentials", { timeout: 15000 }, async () => {
  await fixture({ watch: { effects: [] } }, async (plan) => {
    delete plan.credentials.watch.uploadToken;
    const run = await command("call", {
      plan, sub: "watch", name: "credentials",
      snapshot: { boundary: "before", instructions: textParts("base"), capabilities: compactionCapabilities("before") },
    });
    assert.notEqual(run.code, 0);
    assert.match(run.stderr, /Missing independent compaction credentials/);
  });
});
