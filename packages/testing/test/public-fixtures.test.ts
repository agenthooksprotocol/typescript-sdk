import test from "node:test";
import process from "node:process";
import assert from "node:assert/strict";
import { Hooks, auth } from "@agenthooksprotocol/sdk/client";
import { fakeBackendEntrypoint } from "../src/index.js";

for (const mode of ["no-effect", "deny"] as const) {
  test(`public Hooks reaches the canonical fake backend: ${mode}`, async () => {
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "public.fixture",
            transport: {
              type: "stdio",
              command: process.execPath,
              args: [
                fakeBackendEntrypoint,
                "--mode",
                mode,
                "--chunk-size",
                "7",
              ],
              lifecycle: "persistent",
            },
            subscriptions: [
              {
                mode: "intercept",
                events: ["tool.before"],
                timeoutMs: 2000,
                failurePolicy: "fail-closed",
                content: { default: "metadata" },
              },
            ],
          },
        ],
      },
      {
        source: "urn:testing:public-fixture",
        capabilities: { "tool.before": { effects: ["deny"] } },
        auth: auth(),
      },
    );
    try {
      for (let occurrence = 0; occurrence < 2; occurrence++) {
        const result = await client.toolBefore({
          id: `occurrence-${occurrence}`,
          call: { id: `call-${occurrence}` },
          path: "native",
          tool: {
            name: "read_工具",
            origin: "native",
            input: { text: "Zażółć 🚀" },
          },
        });
        assert.deepEqual(result.errors, []);
        assert.deepEqual(await result.observations, []);
        assert.equal(result.interrupted, false);
        assert.equal(result.event.id, `occurrence-${occurrence}`);
        assert.deepEqual(
          result.response.result.effects,
          mode === "deny"
            ? [{ type: "deny", reason: "Denied by fake backend" }]
            : [],
        );
      }
    } finally {
      await client.close();
    }
  });
}
