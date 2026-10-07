import test from "node:test";
import assert from "node:assert/strict";
import { sdkDraft } from "./common.mjs";

// Supplemental validator unit coverage; positive delivery coverage uses Hooks
// and hooks.handle in the adapter and client/server integration suites.
test("public notification and registration validators retain canonical strictness", () => {
  const notification = {
    jsonrpc: "2.0",
    method: "hooks/observe",
    params: {
      protocolVersion: "draft",
      event: {
        type: "tool.before",
        id: "event",
        source: "urn:fixture:validation",
        time: "2026-01-01T00:00:00Z",
        call: { id: "call" },
        path: "native",
        tool: { name: "fixture", origin: "native", input: {} },
      },
    },
  };
  assert.equal(sdkDraft.validateObserveNotification(notification).ok, true);
  assert.equal(
    sdkDraft.validateObserveNotification({ ...notification, id: "forbidden" })
      .ok,
    false,
  );
  const malformed = structuredClone(notification);
  malformed.params.event.time = "not-a-time";
  assert.equal(sdkDraft.validateObserveNotification(malformed).ok, false);
  const registration = {
    protocolVersion: "draft",
    hooks: [
      {
        id: "fixture.validation",
        transport: { type: "http", url: "https://hooks.example.test" },
        subscriptions: [
          {
            mode: "observe",
            events: ["tool.before"],
            content: { default: "metadata" },
          },
        ],
      },
    ],
  };
  assert.equal(sdkDraft.validateRegistration(registration).ok, true);
  assert.equal(
    sdkDraft.validateRegistration({ ...registration, protocolVersion: "wrong" })
      .ok,
    false,
  );
  const nonJson = structuredClone(registration);
  nonJson.extension = NaN;
  assert.equal(sdkDraft.validateRegistration(nonJson).ok, false);
});
