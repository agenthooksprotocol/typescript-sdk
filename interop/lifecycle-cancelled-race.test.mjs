import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

test(
  "cancelled HTTP receive waits for the released old reply while next request stays pending",
  { timeout: 15000 },
  async (t) => {
    const rows = JSON.parse(
      await readFile(
        new URL(
          "../../agent-hooks-protocol/interop/lifecycle-scenarios.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ).scenarios;
    const row = rows.find((row) => row.id === "late-old-while-next-pending");
    const a = row.requests.a.id,
      b = row.requests.b.id;
    const entries = [],
      responses = new Map(),
      timers = new Set();
    const server = createServer(async (request, response) => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
      const reply = (value) => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
      };
      if (request.url === "/intercept") {
        entries.push({ kind: "received", id: body.id });
        responses.set(body.id, response);
        return;
      }
      if (request.url === "/wait") {
        while (
          entries.filter(
            (entry) => entry.kind === "received" && entry.id === body.id,
          ).length < body.count
        )
          await delay(1);
      } else if (request.url === "/release") {
        const send = () => {
          entries.push({ kind: "replied", id: body.id });
          const pending = responses.get(body.id);
          pending.writeHead(200, { "content-type": "application/json" });
          pending.end(JSON.stringify(row.responses[body.id === a ? "a" : "b"]));
        };
        // Release acknowledges permission to reply, not completion. Delay only
        // the cancelled reply to expose the client's missing receive rendezvous.
        if (body.id === a) {
          const timer = setTimeout(() => {
            timers.delete(timer);
            send();
          }, 100);
          timers.add(timer);
        } else send();
      } else if (request.url === "/mark") entries.push(body);
      reply(request.url === "/receipts" ? { entries } : {});
    });
    const directory = await mkdtemp(join(tmpdir(), "ahp-cancel-race-"));
    let child;
    t.after(async () => {
      for (const timer of timers) clearTimeout(timer);
      if (child && child.exitCode === null) child.kill("SIGKILL");
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const scenarioFile = join(directory, "scenarios.json"),
      reportFile = join(directory, "report.json"),
      configFile = join(directory, "config.json");
    await writeFile(
      scenarioFile,
      JSON.stringify({ version: 1, scenarios: [row] }),
    );
    await writeFile(
      configFile,
      JSON.stringify({
        transport: "http",
        endpoint,
        controlEndpoint: endpoint,
        scenarioFile,
        reportFile,
      }),
    );
    child = spawn(
      process.execPath,
      [
        new URL("./lifecycle-client.mjs", import.meta.url).pathname,
        "--config",
        configFile,
      ],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const code = await new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("close", resolve);
    });
    assert.equal(code, 0, stderr);
    const report = JSON.parse(await readFile(reportFile, "utf8"));
    assert.deepEqual(report.results[0].actual, row.expected);
    const recorded = report.receipts.entries;
    const index = (kind, id) =>
      recorded.findIndex((entry) => entry.kind === kind && entry.id === id);
    assert.ok(
      index("cancelled", a) < index("received", b),
      "cancellation must settle before starting b",
    );
    assert.ok(
      index("received", b) < index("replied", a),
      "a must reply while b is pending",
    );
    assert.ok(
      index("replied", a) < index("replied", b),
      "receive of cancelled a must precede release of b",
    );
  },
);
