import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  catalogueManifest,
  evaluateRegistration,
  catalogueEvents,
} from "./catalogue.mjs";
import { sdkDraft, sdkServer, fixtureCapabilities } from "./common.mjs";
const { validateCapabilitiesResponse } = sdkDraft;
import { TaskLineage } from "./task-lineage.mjs";
const registration = (overrides = {}) => ({
  protocolVersion: "draft",
  hooks: [
    {
      id: "com.example.test",
      transport: { type: "http", url: "https://policy.invalid/hooks" },
      subscriptions: [
        {
          events: ["tool.before"],
          mode: "intercept",
          timeoutMs: 500,
          failurePolicy: "fail-closed",
          content: { default: "metadata" },
        },
      ],
      ...overrides,
    },
  ],
});
test("catalogue manifest advertises typed observations without invented managed enforcement", () => {
  assert.equal(catalogueEvents.length, 22);
  assert.equal(
    validateCapabilitiesResponse({
      jsonrpc: "2.0",
      id: "discovery",
      result: { protocolVersion: "draft", manifest: catalogueManifest },
    }).ok,
    true,
  );
  assert.equal(
    catalogueManifest.events.some((e) => e.event === "hook.failure"),
    false,
  );
  assert.deepEqual(catalogueManifest.managedPolicy, {
    scopes: ["user", "project"],
    disableable: true,
  });
});
test("registration uses discovered capabilities and trusted credential resolution", async () => {
  const evaluate = async (
    r,
    requirements = [],
    context = { interactive: true, environment: {} },
  ) =>
    (await evaluateRegistration(r, catalogueManifest, requirements, context))
      .accepted;
  assert.equal(await evaluate(registration()), true);
  const requirement = {
    event: "tool.before",
    mode: "intercept",
    effects: ["modify"],
    modify: { input: { merge: true } },
  };
  assert.equal(await evaluate(registration(), [requirement]), true);
  assert.equal(
    await evaluate(registration(), [
      { ...requirement, modify: { workspace: { replace: true } } },
    ]),
    false,
  );
  assert.equal(
    await evaluate(
      registration(),
      [{ event: "tool.before", mode: "intercept", effects: ["ask"] }],
      { interactive: false, environment: {} },
    ),
    false,
  );
  assert.equal(
    await evaluate(
      registration({ authentication: { type: "bearer", tokenEnv: "TOKEN" } }),
    ),
    false,
  );
  assert.equal(
    await evaluate(
      registration({ authentication: { type: "bearer", tokenEnv: "TOKEN" } }),
      [],
      { interactive: true, environment: { TOKEN: "TEST-ONLY" } },
    ),
    true,
  );
  const duplicate = registration();
  duplicate.hooks.push(structuredClone(duplicate.hooks[0]));
  assert.equal(await evaluate(duplicate), false);
  const managed = registration();
  managed.hooks[0].subscriptions[0].scope = "managed";
  managed.hooks[0].subscriptions[0].disableable = false;
  assert.equal(await evaluate(managed), false);
  const observed = registration();
  observed.hooks[0].subscriptions[0].mode = "observe";
  assert.equal(await evaluate(observed), false);
});
test("catalogue native payloads and lineage negatives run through public server hooks", async () => {
  const { scenarios } = JSON.parse(
    await readFile(
      "../agent-hooks-protocol/interop/catalogue-scenarios.json",
      "utf8",
    ),
  );
  const lineage = new TaskLineage();
  for (const row of scenarios)
    for (const step of row.steps) {
      if (step.op !== "notify" && step.op !== "rawNotify") continue;
      // Normalize positive legacy catalogue fixtures at the producer boundary.
      // Raw negative probes remain unchanged.
      if (step.op === "notify") {
        const event = step.message.params.event;
        for (const [slot, role] of [["delta", "assistant"], ["partialOutput", "tool"]]) {
          const part = event[slot];
          if (part && !part.parts) {
            event[slot] = {
              id: `${part.id}:message`, role,
              parts: [{ id: part.id, kind: "text", mediaType: "text/plain", selection: part.selection }],
            };
          }
        }
        if (event.summary && !Array.isArray(event.summary)) {
          const part = event.summary;
          event.summary = [{ id: part.id, kind: "text", mediaType: "text/plain", selection: part.selection }];
        }
      }
      const response = await sdkServer.hooks.handle(
        new Request("http://localhost/observe", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(step.message),
        }),
        (message) => {
          lineage.accept(message);
        },
      );
      if (step.op === "notify") assert.equal(response.status, 204, row.id);
      else assert.notEqual(response.status, 204, row.id);
    }
});

test("unknown configuration/auth/upload fields are tolerated, recognized fields still validate", async () => {
  const r = registration({
    futureBackend: { enabled: true },
    authentication: {
      type: "bearer",
      tokenEnv: "EVENT_TOKEN",
      futureAuth: true,
    },
  });
  r.futureConfig = true;
  const sub = r.hooks[0].subscriptions[0];
  sub.futureSubscription = { version: 2 };
  sub.upload = {
    endpoint: "https://uploads.example.test/bytes",
    timeoutMs: 500,
    maxBytes: 0,
    auth: { type: "bearer", tokenEnv: "UPLOAD_TOKEN", futureAuth: true },
    futureUpload: true,
  };
  const context = {
    interactive: true,
    environment: { EVENT_TOKEN: "event", UPLOAD_TOKEN: "upload" },
  };
  assert.equal(
    (await evaluateRegistration(r, catalogueManifest, [], context)).accepted,
    true,
  );
  for (const mutate of [
    (r) => {
      r.hooks[0].authentication.tokenEnv = "bad-name";
    },
    (r) => {
      r.hooks[0].subscriptions[0].upload.maxBytes = -1;
    },
    (r) => {
      r.hooks[0].subscriptions[0].upload.timeoutMs = "500";
    },
    (r) => {
      r.hooks[0].subscriptions[0].upload.auth.tokenEnv = "bad-name";
    },
  ]) {
    const bad = structuredClone(r);
    mutate(bad);
    assert.equal(
      (await evaluateRegistration(bad, catalogueManifest, [], context))
        .accepted,
      false,
    );
  }
});

test("core fixture capability union retains every occurrence advertisement", async () => {
  const { scenarios } = JSON.parse(
    await readFile("../agent-hooks-protocol/interop/scenarios.json", "utf8"),
  );
  const caps = fixtureCapabilities(scenarios);
  for (const { request } of scenarios) {
    const actual = caps[request.params.event.type];
    assert.equal(sdkDraft.validateCapabilities(actual).ok, true);
    for (const effect of request.params.capabilities.effects)
      assert.ok(actual.effects.includes(effect));
  }
  assert.ok(caps["tool.before"].effects.includes("inject"));
  assert.ok(caps["tool.before"].effects.includes("return"));
});
