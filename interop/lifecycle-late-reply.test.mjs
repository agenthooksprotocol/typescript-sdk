import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const names = [
  "cancel-before-reply",
  "cancel-after-reply-before-acceptance",
  "cancelled-boundary-observed",
  "observation-chain-fail-open",
  "observation-chain-fail-closed",
];
const canonical = JSON.parse(
  await readFile(
    new URL(
      "../../agent-hooks-protocol/interop/lifecycle-scenarios.json",
      import.meta.url,
    ),
    "utf8",
  ),
).scenarios;

for (const transport of ["http", "stdio"]) {
  test(
    `late invalid lifecycle replies remain explicit wire probes: ${transport}`,
    { timeout: 15000 },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "ahp-late-reply-"));
      const rows = structuredClone(
        canonical.filter((row) => names.includes(row.id)),
      );
      // Identical unsupported effects on an ordinary send must still be rejected.
      const ordinary = structuredClone(rows[0]);
      ordinary.id = "ordinary-unsupported-reply";
      ordinary.requests.a.id = ordinary.requests.a.params.event.id =
        ordinary.id;
      ordinary.responses.a.id = ordinary.id;
      rows.push(ordinary);
      const readyFile = join(directory, "ready.json");
      const scenarioFile = join(directory, "scenarios.json");
      const configFile = join(directory, "config.json");
      await writeFile(
        scenarioFile,
        JSON.stringify({ version: 1, scenarios: rows }),
      );
      await writeFile(
        configFile,
        JSON.stringify({ transport, scenarioFile, readinessFile: readyFile }),
      );
      const child = spawn(
        process.execPath,
        [
          new URL("./lifecycle-server.mjs", import.meta.url).pathname,
          "--config",
          configFile,
        ],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      const lines = createInterface({ input: child.stdout });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      try {
        let ready;
        const deadline = Date.now() + 5000;
        while (!ready) {
          try {
            ready = JSON.parse(await readFile(readyFile, "utf8"));
          } catch (error) {
            if (error.code !== "ENOENT") throw error;
            assert.ok(child.exitCode === null && Date.now() < deadline, stderr);
            await delay(10);
          }
        }
        const control = async (path, value) => {
          const response = await fetch(new URL(path, ready.controlEndpoint), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(value),
          });
          assert.equal(response.status, 200);
          return response.json();
        };
        const send = async (request) => {
          if (transport === "http") {
            const response = await fetch(
              new URL("/intercept", ready.endpoint),
              {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(request),
              },
            );
            assert.equal(response.status, 200);
            return response.json();
          }
          const next = once(lines, "line");
          child.stdin.write(JSON.stringify(request) + "\n");
          return JSON.parse((await next)[0]);
        };
        for (const row of rows) {
          await control("/release", { id: row.requests.a.id });
          const reply = await send(row.requests.a);
          if (names.includes(row.id)) {
            assert.deepEqual(
              reply,
              row.responseSequences?.a?.[0] ?? row.responses.a,
              row.id,
            );
            // Only the first send occurrence is a named adversarial reply.
            const repeated = await send(row.requests.a);
            if (row.chain)
              assert.deepEqual(
                repeated,
                row.responseSequences.a[1] ?? row.responses.a,
              );
            else assert.equal(repeated.error.code, -32004);
          } else assert.equal(reply.error.code, -32004);
        }
        const receipts = await control("/receipts", {});
        for (const row of rows)
          assert.equal(
            receipts.sdkCalls.filter(
              (call) => call.eventId === row.requests.a.params.event.id,
            ).length,
            1,
          );
      } finally {
        lines.close();
        child.kill("SIGTERM");
        if (child.exitCode === null) await once(child, "exit");
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
}
