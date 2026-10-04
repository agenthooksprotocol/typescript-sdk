import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import test from "node:test";
import { sdkDraft } from "./common.mjs";
import {
  lifecycleWireGate,
  maliciousLifecycleObservation,
} from "./lifecycle-common.mjs";
const { validateInterceptResponse } = sdkDraft;
const uploadSubscriptions = {
  body: {
    scope: "default",
    auth: { type: "bearer", tokenEnv: "AHP_TEST_BODY" },
  },
  metadata: {
    authorized: false,
    auth: { type: "bearer", tokenEnv: "AHP_TEST_METADATA" },
  },
};
const uploadPolicies = Object.fromEntries(
  Object.entries(uploadSubscriptions).map(([name, policy]) => [
    name,
    { auth: policy.auth },
  ]),
);
const env = {
  ...process.env,
  AHP_TEST_BODY: "TEST-ONLY-body",
  AHP_TEST_METADATA: "TEST-ONLY-metadata",
  AHP_INTEROP_UNAUTHORIZED_UPLOAD_TOKEN: "TEST-ONLY-unauthorized",
};
const cwd = fileURLToPath(new URL("..", import.meta.url));
const central = JSON.parse(
  await readFile(
    cwd + "/../agent-hooks-protocol/interop/lifecycle-scenarios.json",
    "utf8",
  ),
).scenarios;
// Only these named duplicate-response probes use raw replay. Repeated IDs in
// any other scenario must still exercise the public client, not bypass it.
const replayProbes = new Set([
  "duplicate-reply-ignored",
  "first-staged-response-wins",
]);
for (const row of central) {
  if (!replayProbes.has(row.id)) continue;
  const replay = row.steps.find(
    (step) =>
      step.op === "send" && step.key === "a" && step.slot === "duplicate",
  );
  assert.ok(replay, row.id);
  replay.bypassSDK = true;
}
// These schedules require two outstanding requests at the same foreign peer.
// Exercise their unchanged steps and expected reports over HTTP: persistent
// stdio permits only one outstanding intercept in this revision.
const concurrentPeerScenarios = new Set([
  "late-old-while-next-pending",
  "request-specific-acceptance",
  "two-staged-reverse-acceptance",
]);
const askBoundary = central.find((row) => row.id === "ask-boundary-observed");
test("ask lifecycle fixture uses strict canonical fields and rejects added reason", () => {
  const response = askBoundary.responses.a;
  assert.equal(validateInterceptResponse(response).ok, true);
  const malformed = structuredClone(response);
  malformed.result.effects[0].reason = "confirm";
  assert.equal(validateInterceptResponse(malformed).ok, false);
});
function validateFixtureResponses(rows) {
  for (const row of rows) {
    const responses = [
      ...Object.entries(row.responses),
      ...Object.entries(row.responseSequences ?? {}).flatMap(([key, values]) =>
        values.map((value, index) => [`${key}[${index}]`, value]),
      ),
    ];
    for (const [key, response] of responses) {
      const checked = validateInterceptResponse(response);
      assert.equal(
        checked.ok,
        true,
        `Invalid canonical lifecycle response: scenario=${row.id}, response=${key}`,
      );
    }
  }
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    const timer = setTimeout(() => child.kill("SIGKILL"), 1000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
async function run(rows, transport, inspect, observationReply) {
  const dir = await mkdtemp("/tmp/ts-lifecycle-check-");
  let server, client, foreignReplyProxy;
  try {
    const scenarioFile = dir + "/fixture.json",
      selected = rows.filter(
        (row) => !row.transports || row.transports.includes(transport),
      );
    validateFixtureResponses(selected);
    await writeFile(
      scenarioFile,
      JSON.stringify({ version: 1, scenarios: selected }),
    );
    const config = {
      uploadPolicies,
      uploadSubscriptions,
      serverConfig: { uploadSubscriptions },
      transport,
      scenarioFile,
      auth: { mode: "none" },
      reportFile: dir + "/report.json",
      childPidFile: dir + "/pid.json",
      serverCommand: ["node", "interop/lifecycle-server.mjs"],
      serverCwd: cwd,
    };
    if (transport === "http") {
      const ready = dir + "/ready.json";
      await writeFile(
        dir + "/server.json",
        JSON.stringify({ ...config, readinessFile: ready }),
      );
      server = spawn(
        "node",
        ["interop/lifecycle-server.mjs", "--config", dir + "/server.json"],
        { cwd, env, stdio: "inherit" },
      );
      const deadline = Date.now() + 10000;
      for (;;) {
        try {
          Object.assign(config, JSON.parse(await readFile(ready, "utf8")));
          break;
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          if (Date.now() > deadline || server.exitCode !== null)
            throw Error("Readiness");
          await delay(10);
        }
      }
    }
    if (observationReply) {
      assert.equal(transport, "http");
      const endpoint = config.endpoint;
      // A deliberately noncompliant foreign-wire stand-in. The real compliant
      // TS server still owns fixture receipts; the proxy only injects the exact
      // legacy foreign observer response after real notification delivery.
      foreignReplyProxy = createServer(async (req, res) => {
        try {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const response = await fetch(new URL(req.url, endpoint), {
            method: req.method,
            headers: { "content-type": "application/json" },
            body: Buffer.concat(chunks),
          });
          const bytes = Buffer.from(await response.arrayBuffer());
          if (req.url === "/observe") {
            res.writeHead(observationReply.status, {
              "content-type": "application/json",
            });
            res.end(
              observationReply.body === undefined
                ? undefined
                : JSON.stringify(observationReply.body),
            );
          } else {
            res.writeHead(response.status, {
              "content-type":
                response.headers.get("content-type") ?? "application/json",
            });
            res.end(bytes);
          }
        } catch (error) {
          res.writeHead(502).end(String(error));
        }
      });
      await new Promise((resolve) =>
        foreignReplyProxy.listen(0, "127.0.0.1", resolve),
      );
      config.endpoint = `http://127.0.0.1:${foreignReplyProxy.address().port}`;
    }
    await writeFile(dir + "/client.json", JSON.stringify(config));
    client = spawn(
      "node",
      ["interop/lifecycle-client.mjs", "--config", dir + "/client.json"],
      { cwd, env, stdio: "inherit" },
    );
    const code = await new Promise((resolve, reject) => {
      // Whole-adapter budget includes many fresh SDK processes and schema startup.
      // Protocol deadlines and cancellation probes retain their original budgets.
      const timer = setTimeout(() => {
        client.kill("SIGTERM");
        reject(Error("Client watchdog"));
      }, 120000);
      client.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      client.on("exit", (code) => {
        clearTimeout(timer);
        resolve(code);
      });
    });
    if (code !== 0) {
      let failures = "report unavailable";
      try {
        const report = JSON.parse(await readFile(config.reportFile, "utf8"));
        failures = JSON.stringify(
          (report.results ?? [])
            .filter((result) => result.status === "failed")
            .map((result) => result.id),
        );
      } catch {}
      assert.equal(
        code,
        0,
        `Lifecycle client failed (${transport}); failed scenario IDs: ${failures}`,
      );
    }
    if (transport === "stdio")
      assert.ok(
        JSON.parse(await readFile(config.childPidFile, "utf8")).pid > 0,
      );
    const report = JSON.parse(await readFile(config.reportFile, "utf8"));
    assert.equal(report.results.length, selected.length);
    for (const result of report.results)
      assert.deepEqual(
        result.actual,
        selected.find((row) => row.id === result.id).expected,
        result.id,
      );
    if (inspect) await inspect(config);
    return report;
  } finally {
    await stop(client);
    await stop(server);
    if (foreignReplyProxy) {
      foreignReplyProxy.closeAllConnections();
      await new Promise((resolve) => foreignReplyProxy.close(resolve));
    }
    await rm(dir, { recursive: true, force: true });
  }
}
function fixture(id, keys = ["a"]) {
  const requests = {},
    responses = {};
  for (const key of keys) {
    const request = structuredClone(central[0].requests.a);
    request.id = `local-${id}:${key}`;
    request.params.event.id = request.id;
    request.params.event.call = { id: request.id };
    requests[key] = request;
    responses[key] = {
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: "draft",
        effects: [
          {
            type: "modify",
            target: "input",
            operation: "replace",
            value: { value: key },
          },
          { type: "message", text: key },
        ],
      },
    };
  }
  return {
    id: `local-${id}`,
    requests,
    responses,
    steps: [],
    expected: {
      published: [],
      cancelled: [],
      ignored: [],
      states: {},
      observations: [],
      uploadStatuses: [],
    },
  };
}
const send = (key) => [
  { op: "send", key, slot: key },
  { op: "wait", key },
];
const receive = (key) => [
  { op: "receive", slot: key },
  { op: "accept", key },
];
function accepted(row, key) {
  const id = row.requests[key].id;
  row.expected.published.push(id);
  row.expected.states[id] = {
    decision: "allow",
    executed: true,
    input: { value: key },
    messages: [key],
  };
}
const duplicate = fixture("first");
duplicate.responseSequences = {
  a: [
    duplicate.responses.a,
    {
      ...duplicate.responses.a,
      result: {
        protocolVersion: "draft",
        effects: [{ type: "deny", reason: "must not replace first" }],
      },
    },
  ],
};
duplicate.steps = [
  ...send("a"),
  { op: "release", key: "a" },
  { op: "receive", slot: "a" },
  { op: "send", key: "a", slot: "retry", bypassSDK: true },
  { op: "wait", key: "a", count: 2 },
  { op: "receive", slot: "retry" },
  { op: "accept", key: "a" },
];
accepted(duplicate, "a");
duplicate.expected.ignored = ["retry"];
const interrupted = fixture("interrupted");
interrupted.steps = [
  ...send("a"),
  { op: "release", key: "a" },
  ...receive("a"),
  { op: "cancel", key: "a" },
  { op: "failOpen", key: "a" },
  { op: "accept", key: "a" },
  { op: "observe", key: "a", subscription: "metadata" },
];
accepted(interrupted, "a");
interrupted.expected.cancelled = [interrupted.requests.a.id];
interrupted.expected.observations = [
  {
    eventId: interrupted.requests.a.id,
    subscription: "metadata",
    input: { value: "a" },
  },
];
const unmatched = fixture("unmatched");
unmatched.transports = ["stdio"];
const stray = {
  jsonrpc: "2.0",
  id: "local-unknown",
  result: {
    protocolVersion: "draft",
    effects: [{ type: "deny", reason: "stray" }],
  },
};
unmatched.steps = [
  ...send("a"),
  { op: "emit", response: stray },
  { op: "release", key: "a" },
  ...receive("a"),
];
accepted(unmatched, "a");
unmatched.expected.ignored = ["unsolicited:local-unknown"];
const empty = fixture("empty", []);
empty.steps = [
  {
    op: "upload",
    subscription: "body",
    ref: "",
    size: 0,
    sha256: createHash("sha256").update("").digest("hex"),
    text: "",
  },
];
empty.expected.uploadStatuses = [201];
for (const transport of ["stdio", "http"])
  test(`central exact reports and focused lifecycle regressions: ${transport}`, async () => {
    const report = await run(
      [
        ...central.filter(
          (row) =>
            transport !== "stdio" || !concurrentPeerScenarios.has(row.id),
        ),
        duplicate,
        interrupted,
        unmatched,
        empty,
      ],
      transport,
    );
    const entries = report.receipts.entries;
    for (const row of central.filter((row) => replayProbes.has(row.id))) {
      const id = row.requests.a.id;
      const result = report.results.find((result) => result.id === row.id);
      assert.ok(result.actual.ignored.includes("duplicate"), row.id);
      assert.equal(
        report.sdkDeliveries.filter(
          (delivery) => delivery.eventId === row.requests.a.params.event.id,
        ).length,
        1,
        row.id,
      );
      assert.equal(
        entries.filter((entry) => entry.kind === "accepted" && entry.id === id)
          .length,
        1,
        row.id,
      );
      assert.equal(
        entries.filter((entry) => entry.kind === "acquired" && entry.id === id)
          .length,
        1,
        row.id,
      );
    }
    const acquired = entries.filter(
      (e) => e.kind === "acquired" && e.id === duplicate.requests.a.id,
    );
    assert.equal(acquired.length, 1);
    const observed = entries.find(
      (e) =>
        e.kind === "observed" &&
        e.eventId === interrupted.requests.a.params.event.id,
    );
    assert.equal(Object.hasOwn(observed.message.params, "disposition"), false);
    assert.equal(
      entries.some((e) => e.kind === "view"),
      false,
    );
    if (transport === "stdio")
      assert.ok(
        entries.findIndex(
          (e) => e.kind === "discarded" && e.id === "local-unknown",
        ) <
          entries.findIndex(
            (e) => e.kind === "acquired" && e.id === unmatched.requests.a.id,
          ),
      );
  });
test("HTTP correlates concurrent foreign replies released in reverse order", async () => {
  const row = central.find((row) => row.id === "two-staged-reverse-acceptance");
  const report = await run([row], "http");
  for (const request of Object.values(row.requests)) {
    assert.ok(
      report.sdkDeliveries.some(
        (delivery) => delivery.eventId === request.params.event.id,
      ),
    );
    assert.ok(
      report.receipts.sdkCalls.some(
        (call) => call.eventId === request.params.event.id,
      ),
    );
  }
});

for (const transport of ["stdio", "http"])
  test(`positive lifecycle boundaries use public client and server: ${transport}`, async () => {
    const names = [
      "settled-observer-effects-ignored",
      "denied-boundary-observed",
      "stopped-boundary-observed",
      "ask-boundary-observed",
      "intercept-content-upload-before-send",
      "observation-chain-deny",
    ];
    const rows = central.filter(
      (row) => names.includes(row.id) || (row.chain && !row.chain.interrupt),
    );
    const report = await run(rows, transport);
    for (const row of rows) {
      const eventId = row.requests.a.params.event.id;
      const publicCalls = report.receipts.sdkCalls.filter(
        (entry) => entry.eventId === eventId,
      );
      if (
        !row.chain ||
        row.chain.subscriptions.some((sub) => sub.mode === "intercept")
      )
        assert.ok(
          publicCalls.some((entry) => entry.method === "hooks/intercept"),
          row.id,
        );
      const received = report.receipts.entries.filter(
        (entry) => entry.kind === "received" && entry.id === eventId,
      );
      for (const receipt of received) {
        assert.equal(receipt.message.id, receipt.message.params.event.id);
        assert.equal(receipt.message.params.protocolVersion, "draft");
        if (!row.chain)
          assert.deepEqual(
            receipt.message.params.state,
            row.requests.a.params.state,
          );
      }
      if (row.steps?.some((step) => step.op === "observe") || row.chain)
        assert.ok(
          publicCalls.some((entry) => entry.method === "hooks/observe"),
          row.id,
        );
    }
  });

test("application rejects unavailable content before public observe handling", async () => {
  await run([askBoundary], "http", async (config) => {
    const event = structuredClone(askBoundary.requests.a.params.event);
    event.id = "reference-status-check";
    const post = () =>
      fetch(new URL("/observe", config.endpoint), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "hooks/observe",
          params: { protocolVersion: "draft", event },
        }),
      });
    const okay = await post();
    assert.equal(okay.status, 204);
    assert.equal(await okay.text(), "");
    event.items = [
      {
        id: "missing",
        kind: "text",
        mediaType: "text/plain",
        selection: "body",
        body: {
          ref: "urn:missing:content",
          size: 0,
          sha256: createHash("sha256").update("").digest("hex"),
        },
      },
    ];
    const rejected = await post();
    assert.equal(rejected.status, 409);
    await rejected.arrayBuffer();
  });
});

test("multi-send and cancellation retain actual public boundary results over HTTP", async () => {
  const names = [
    "cancel-before-reply",
    "cancel-after-reply-before-acceptance",
    "late-old-while-next-pending",
    "request-specific-acceptance",
    "two-staged-reverse-acceptance",
  ];
  const rows = central.filter((row) => names.includes(row.id));
  const report = await run(rows, "http");
  for (const row of rows) {
    for (const request of Object.values(row.requests)) {
      assert.ok(
        report.sdkDeliveries.some(
          (delivery) => delivery.eventId === request.params.event.id,
        ),
      );
      assert.ok(
        report.receipts.sdkCalls.some(
          (call) => call.eventId === request.params.event.id,
        ),
      );
    }
  }
  const cancelled = rows.find((row) => row.id === "cancel-before-reply");
  assert.equal(
    report.sdkDeliveries.find(
      (delivery) => delivery.eventId === cancelled.requests.a.params.event.id,
    ).interrupted,
    true,
  );
});

test("cached Hooks associate concurrent upload confirmations with exact deliveries", async () => {
  const row = fixture("concurrent-content", ["a", "b"]);
  const uploads = [];
  for (const key of ["a", "b"]) {
    // Equal bytes deliberately cannot identify the operation or source alias.
    const bytes = Buffer.from("same concurrent content");
    const descriptor = {
      ref: `concurrent-${key}`,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    row.requests[key].params.event.items = [
      {
        id: `item-${key}`,
        kind: "text",
        mediaType: "text/plain",
        selection: "body",
        body: descriptor,
      },
    ];
    uploads.push({
      op: "upload",
      subscription: "body",
      ...descriptor,
      bodyBase64: bytes.toString("base64"),
    });
  }
  row.steps = [
    ...uploads,
    { op: "send", key: "a", slot: "a" },
    { op: "send", key: "b", slot: "b" },
    { op: "wait", key: "a" },
    { op: "wait", key: "b" },
    { op: "release", key: "b" },
    { op: "release", key: "a" },
    ...receive("b"),
    ...receive("a"),
  ];
  accepted(row, "b");
  accepted(row, "a");
  row.expected.uploadStatuses = [201, 201];
  const report = await run([row], "http");
  assert.equal(report.contentUploads.length, 2);
  const entries = report.receipts.entries;
  const explicitUploads = entries
    .filter((entry) => entry.kind === "upload")
    .slice(0, 2);
  for (const [index, key] of ["a", "b"].entries()) {
    const confirmation = report.contentUploads.find(
      (entry) => entry.eventId === row.requests[key].id,
    );
    assert.equal(confirmation.method, "hooks/intercept");
    assert.equal(confirmation.sourceRef, explicitUploads[index].ref);
    const received = entries.findIndex(
      (entry) => entry.kind === "received" && entry.id === row.requests[key].id,
    );
    assert.deepEqual(
      entries[received].message.params.event.items[0].body,
      confirmation.descriptor,
    );
    assert.ok(
      entries
        .slice(0, received)
        .some(
          (entry) =>
            entry.kind === "upload" &&
            entry.ref === confirmation.descriptor.ref,
        ),
    );
  }
});

for (const transport of ["http", "stdio"])
  test(`cancel after real response acquisition interrupts SDK settlement: ${transport}`, async () => {
    const row = fixture("cancel-acquired-valid");
    row.steps = [
      ...send("a"),
      { op: "release", key: "a" },
      { op: "receive", slot: "a" },
      { op: "cancel", key: "a" },
      { op: "accept", key: "a" },
    ];
    row.expected.cancelled = [row.requests.a.id];
    const report = await run([row], transport);
    const delivery = report.sdkDeliveries.find(
      (entry) => entry.eventId === row.requests.a.id,
    );
    assert.equal(delivery.wireAcquired, true);
    assert.equal(delivery.wireRelease, "abort");
    assert.equal(delivery.interrupted, true);
    assert.ok(delivery.errors.every((error) => error.code === "INTERRUPTED"));
    assert.deepEqual(report.results[0].actual.published, []);
    const entries = report.receipts.entries;
    const acquired = entries.findIndex((entry) => entry.kind === "acquired");
    const cancelled = entries.findIndex((entry) => entry.kind === "cancelled");
    assert.ok(acquired >= 0 && cancelled > acquired);
  });

test("wire acquisition gate is bounded and never releases timed-out bytes", async () => {
  const gate = lifecycleWireGate(undefined, 20);
  let delivered = false;
  const held = gate.hold().then(() => {
    delivered = true;
  });
  await gate.acquired;
  assert.equal(delivered, false);
  await assert.rejects(held, /Wire acquisition watchdog/);
  assert.equal(gate.releaseReason, "timeout");
  gate.release();
  assert.equal(delivered, false);
});

test("explicit foreign malicious observer response preserves actual SDK errors and settled decision", async () => {
  const row = central.find(
    (item) => item.id === "settled-observer-effects-ignored",
  );
  const report = await run([row], "http", undefined, {
    status: 200,
    body: maliciousLifecycleObservation,
  });
  const observations = report.sdkDeliveries.filter(
    (delivery) => delivery.mode === "observe",
  );
  assert.equal(observations.length, 2);
  for (const delivery of observations) {
    assert.equal(delivery.maliciousObservation, true);
    assert.deepEqual(delivery.observationErrors, [
      {
        backendId: "interop.lifecycle",
        subscriptionIndex: 0,
        phase: "observation",
        code: "DELIVERY_FAILED",
        syntheticDenial: false,
      },
    ]);
  }
  assert.equal(
    report.results[0].actual.states[row.requests.a.id].decision,
    "allow",
  );
  assert.equal(
    report.results[0].actual.states[row.requests.a.id].executed,
    true,
  );
});

for (const status of [202, 204])
  test(`valid empty observer HTTP ${status} remains error-free`, async () => {
    const row = central.find(
      (item) => item.id === "settled-observer-effects-ignored",
    );
    const report = await run([row], "http", undefined, { status });
    for (const delivery of report.sdkDeliveries.filter(
      (item) => item.mode === "observe",
    )) {
      assert.equal(delivery.maliciousObservation, false);
      assert.deepEqual(delivery.observationErrors, []);
    }
  });

test("unexpected foreign observer response remains fatal", async () => {
  const row = central.find(
    (item) => item.id === "settled-observer-effects-ignored",
  );
  const unknown = structuredClone(maliciousLifecycleObservation);
  unknown.result.effects[0].reason = "not the declared malicious fixture";
  await assert.rejects(
    run([row], "http", undefined, { status: 200, body: unknown }),
    /Lifecycle client failed/,
  );
});
