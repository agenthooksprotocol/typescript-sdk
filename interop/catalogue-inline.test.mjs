import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { catalogueContentSelection } from "./catalogue.mjs";

const text = (id, value, extra = {}) => ({
  id, kind: "text", mediaType: "text/plain", selection: "body", text: value, ...extra,
});
const event = (id, items) => ({
  id, source: "urn:ahp:catalogue-test", type: "model.request.before",
  time: "2026-09-15T12:00:00Z", model: { id: "example", provider: "example" },
  attempt: { id: "example", number: 1 }, params: {}, items,
});
const inline = event("inline", [
  { id: "inline:user", role: "user", parts: [
    text("inline:user:text", "First line.\nUnicode: café 🌍"),
    { id: "inline:user:image", kind: "attachment", mediaType: "image/png", selection: "metadata" },
    text("inline:user:tail", "Last part."),
  ] },
  { id: "inline:assistant", role: "assistant", parts: [
    text("inline:assistant:reasoning", "Consider the input.", { category: "reasoning" }),
    text("inline:assistant:empty", ""),
  ] },
]);

test("catalogue policy selects canonical parts without traversing opaque params", () => {
  assert.deepEqual(catalogueContentSelection(inline), {
    default: "metadata", text: "body", images: "metadata", reasoning: "body",
  });
  assert.deepEqual(catalogueContentSelection({ ...event("opaque", []), params: { items: inline.items } }), {
    default: "metadata",
  });
});

for (const transport of ["http", "stdio"]) {
  test(`catalogue ${transport} preserves inline parts after a metadata-only cached client`, { timeout: 20000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), "ahp-catalogue-inline-"));
    const processes = [];
    let diagnostics = "";
    const start = (file, config) => {
      const child = spawn(process.execPath, [file, "--config", config], {
        cwd: new URL("../", import.meta.url), stdio: ["ignore", "pipe", "pipe"],
      });
      processes.push(child);
      child.stdout.on("data", chunk => { diagnostics += chunk; });
      child.stderr.on("data", chunk => { diagnostics += chunk; });
      return child;
    };
    try {
      const messages = [event("metadata", []), inline].map(event => ({
        jsonrpc: "2.0", method: "hooks/observe", params: { protocolVersion: "draft", event },
      }));
      const scenarioFile = join(directory, "scenarios.json");
      const readinessFile = join(directory, "ready.json");
      const reportFile = join(directory, "report.json");
      const serverConfig = join(directory, "server.json");
      const clientConfig = join(directory, "client.json");
      await writeFile(scenarioFile, JSON.stringify({ version: 1, scenarios: messages.map(message => ({
        id: message.params.event.id, requests: {}, responses: {},
        steps: [{ op: "notify", message }],
      })) }));
      await writeFile(serverConfig, JSON.stringify({ suite: "catalogue", transport, scenarioFile, readinessFile, auth: { mode: "none" } }));
      const config = { suite: "catalogue", transport, scenarioFile, reportFile, auth: { mode: "none" } };
      if (transport === "http") {
        const server = start("interop/lifecycle-server.mjs", serverConfig);
        const deadline = Date.now() + 5000;
        for (;;) {
          try {
            const ready = JSON.parse(await readFile(readinessFile, "utf8"));
            config.endpoint = ready.endpoint;
            config.controlEndpoint = ready.controlEndpoint;
            break;
          } catch (error) {
            if (error.code !== "ENOENT") throw error;
            assert.equal(server.exitCode, null, diagnostics);
            assert.ok(Date.now() < deadline, diagnostics);
            await delay(10);
          }
        }
      } else {
        config.serverCommand = [process.execPath, "interop/lifecycle-server.mjs"];
        config.serverCwd = new URL("../", import.meta.url).pathname;
        config.serverConfig = serverConfig;
        config.childPidFile = join(directory, "child.json");
      }
      await writeFile(clientConfig, JSON.stringify(config));
      const client = start("interop/lifecycle-client.mjs", clientConfig);
      const code = await new Promise((resolve, reject) => {
        client.once("error", reject);
        client.once("exit", resolve);
      });
      assert.equal(code, 0, diagnostics);
      const report = JSON.parse(await readFile(reportFile, "utf8"));
      assert.deepEqual(report.results.map(row => row.actual.sent[0]), messages);
      // These are independent receiver records, not the sender's claimed sent data.
      assert.deepEqual(report.receipts.entries.filter(entry => entry.kind !== "discovery"), messages.map(message => ({
        kind: "observed", eventId: message.params.event.id, event: message.params.event, message,
      })));
    } finally {
      for (const child of processes) {
        if (child.exitCode === null) {
          const exited = new Promise(resolve => child.once("exit", resolve));
          child.kill("SIGKILL");
          await exited;
        }
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
}
