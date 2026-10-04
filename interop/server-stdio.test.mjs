import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";

async function until(read) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const value = await read();
    if (value) return value;
    await delay(10);
  }
  throw Error("Fixture did not become ready");
}

test(
  "stdio fixture keeps control available and only bypasses explicit negative replies",
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "ahp-server-stdio-"));
    let child;
    let lines;
    try {
      const { scenarios } = JSON.parse(
        await readFile(
          "../agent-hooks-protocol/interop/scenarios.json",
          "utf8",
        ),
      );
      const ordinary = structuredClone(scenarios[0]);
      delete ordinary.request.params.state;
      ordinary.barrier = "release-stdio";
      const negative = structuredClone(ordinary);
      delete negative.barrier;
      negative.id =
        negative.request.id =
        negative.request.params.event.id =
          "negative";
      negative.expectError = true;
      negative.response = { deliberately: "not a JSON-RPC response" };
      const scenarioFile = join(directory, "scenarios.json");
      const readinessFile = join(directory, "ready.json");
      const configFile = join(directory, "config.json");
      await writeFile(
        scenarioFile,
        JSON.stringify({ version: 1, scenarios: [ordinary, negative] }),
      );
      await writeFile(
        configFile,
        JSON.stringify({
          transport: "stdio",
          scenarioFile,
          readinessFile,
          auth: { mode: "none" },
        }),
      );
      child = spawn(
        process.execPath,
        ["interop/server.mjs", "--config", configFile],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      let stderr = "";
      child.stderr.setEncoding("utf8").on("data", (text) => {
        stderr += text;
      });
      lines = createInterface({ input: child.stdout });
      const ready = await until(async () => {
        try {
          return JSON.parse(await readFile(readinessFile, "utf8"));
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      });
      const reply = once(lines, "line");
      child.stdin.write(JSON.stringify(ordinary.request) + "\n");
      await until(async () => {
        const health = await (
          await fetch(ready.controlEndpoint + "/health")
        ).json();
        return health.requests.length === 1;
      });
      const released = await fetch(ready.controlEndpoint + "/release", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ barrier: ordinary.barrier }),
      });
      assert.equal(released.status, 200);
      const [line] = await reply;
      assert.deepEqual(JSON.parse(line), ordinary.response);
      const malformedReply = once(lines, "line");
      child.stdin.write("{\n");
      const [malformed] = await malformedReply;
      assert.equal(JSON.parse(malformed).error.code, -32700);
      const negativeReply = once(lines, "line");
      child.stdin.write(JSON.stringify(negative.request) + "\n");
      const [raw] = await negativeReply;
      assert.deepEqual(JSON.parse(raw), negative.response);
      const exited = once(child, "exit");
      child.stdin.end();
      const [code] = await exited;
      assert.equal(code, 0, stderr);
    } finally {
      lines?.close();
      if (child && child.exitCode === null) {
        const exited = once(child, "exit");
        child.kill("SIGKILL");
        await exited;
      }
      await rm(directory, { recursive: true, force: true });
    }
  },
);
