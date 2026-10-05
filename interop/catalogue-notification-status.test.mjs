import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { catalogueManifest } from "./catalogue.mjs";

// Raw catalogue probes can be accepted too (for example a new source-local
// lineage). Their HTTP success statuses must match normal notifications.
for (const status of [202, 204, 400, 409, 500]) {
  test(
    `catalogue raw notification HTTP ${status}`,
    { timeout: 10000 },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "ahp-catalogue-status-"));
      const message = {
        jsonrpc: "2.0",
        method: "hooks/observe",
        params: {
          protocolVersion: "draft",
          event: {
            id: "event",
            source: "urn:catalogue-status",
            time: "2026-01-01T00:00:00Z",
            type: "turn.start",
            turn: { id: "turn" },
            trigger: "user",
            items: [],
          },
        },
      };
      const observed = [];
      const server = createServer(async (request, response) => {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : null;
        if (request.url === "/observe") {
          observed.push(body);
          response.writeHead(status).end();
          return;
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify(
            request.url === "/capabilities"
              ? {
                  jsonrpc: "2.0",
                  id: body.id,
                  result: {
                    protocolVersion: "draft",
                    manifest: catalogueManifest,
                  },
                }
              : {},
          ),
        );
      });
      let child;
      try {
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        const endpoint = `http://127.0.0.1:${server.address().port}`;
        const scenarioFile = join(directory, "scenarios.json");
        const reportFile = join(directory, "report.json");
        const configFile = join(directory, "config.json");
        await writeFile(
          scenarioFile,
          JSON.stringify({
            version: 1,
            scenarios: [
              {
                id: "raw-notification",
                requests: {},
                responses: {},
                steps: [{ op: "rawNotify", message }],
              },
            ],
          }),
        );
        await writeFile(
          configFile,
          JSON.stringify({
            suite: "catalogue",
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
          child.once("error", reject);
          child.once("exit", resolve);
        });
        assert.deepEqual(observed, [message]);
        if (status === 500) {
          assert.notEqual(code, 0);
          assert.match(stderr, /Catalogue event transport failed: 500/);
        } else {
          assert.equal(code, 0, stderr);
          const report = JSON.parse(await readFile(reportFile, "utf8"));
          assert.deepEqual(report.results, [
            {
              id: "raw-notification",
              status: "passed",
              actual: { sent: [message], registrations: [] },
            },
          ]);
        }
      } finally {
        if (child && child.exitCode === null) child.kill("SIGKILL");
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
}
