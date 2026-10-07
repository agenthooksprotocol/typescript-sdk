import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, rm, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UploadStore } from "./content-upload.mjs";
import { compactionCapabilities } from "./compaction.mjs";

// Python/Rust's legacy receivers omit the media type; Go's encoder defaults
// to text/plain. Neither is a canonical AHP HTTP response. Test the actual
// fixture command so a wire-contract failure cannot be repaired by its adapter.
for (const mediaType of [
  undefined,
  "text/plain; charset=utf-8",
  "application/json",
]) {
  test(
    `compaction HTTP response media type ${mediaType ?? "absent"}`,
    { timeout: 10000 },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "ahp-compaction-http-"));
      const uploads = new UploadStore(() => "scope");
      const effects = [
        {
          type: "modify",
          target: "instructions",
          operation: "replace",
          value: "base:one",
        },
      ];
      const server = createServer(async (request, response) => {
        if (request.url === "/upload") {
          const result = await uploads.receive(request);
          response.writeHead(result.status, {
            "content-type": "application/json",
          });
          response.end(
            JSON.stringify({
              ref: result.ref,
              size: result.size,
              sha256: result.sha256,
            }),
          );
          return;
        }
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const message = JSON.parse(Buffer.concat(chunks));
        const reply = {
          jsonrpc: "2.0",
          id: message.id,
          result: { protocolVersion: "draft", effects },
        };
        await appendFile(
          join(directory, "receipts.jsonl"),
          JSON.stringify({
            subscription: "before",
            request: message,
            response: reply,
          }) + "\n",
        );
        response.writeHead(200, mediaType ? { "content-type": mediaType } : {});
        response.end(JSON.stringify(reply));
      });
      let child;
      try {
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        child = spawn(
          process.execPath,
          [new URL("./compaction-wire.mjs", import.meta.url).pathname, "call"],
          { stdio: ["pipe", "pipe", "pipe"] },
        );
        let stdout = "",
          stderr = "";
        child.stdout.on("data", (chunk) => {
          stdout += chunk;
        });
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        child.stdin.end(
          JSON.stringify({
            plan: {
              transport: "http",
              endpoint: `http://127.0.0.1:${server.address().port}`,
              credentials: {
                before: { token: "event", uploadToken: "upload" },
              },
              receiverCommand: ["unused", directory, "unused"],
            },
            sub: "before",
            name: "chain",
            snapshot: {
              boundary: "before",
              instructions: "base",
              capabilities: compactionCapabilities("before"),
            },
          }),
        );
        const code = await new Promise((resolve, reject) => {
          child.once("error", reject);
          child.once("exit", resolve);
        });
        assert.equal(code, 0, stderr);
        const result = JSON.parse(stdout);
        assert.deepEqual(result.wire.response.result.effects, effects);
        assert.equal(result.failed, mediaType !== "application/json");
        if (mediaType === "application/json")
          assert.deepEqual(result.effects, effects);
        else
          assert.equal(
            result.effects.some((effect) => effect.type === "modify"),
            false,
          );
      } finally {
        if (child && child.exitCode === null) child.kill("SIGKILL");
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
}
