import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const ts = require("typescript");

test("documented Hooks example loads JSON, preserves typed original arguments, and honors denial", async () => {
  const readme = await readFile(
    new URL("../README.md", import.meta.url),
    "utf8",
  );
  const section = readme
    .split("## Intercept a tool call with `Hooks`")[1]
    .split("## Legacy")[0];
  const config = JSON.parse(section.match(/```json\n([\s\S]*?)```/)[1]);
  const source = await readFile(
    new URL("../packages/sdk/test/client-example.ts", import.meta.url),
    "utf8",
  );
  assert.equal(section.match(/```ts\n([\s\S]*?)```/)[1].trim(), source.trim());
  const emitted = ts
    .transpileModule(source, {
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ES2022,
      },
    })
    .outputText.replace(
      "@agenthooksprotocol/sdk/client",
      pathToFileURL(require.resolve("@agenthooksprotocol/sdk/client")).href,
    );
  const directory = await mkdtemp(join(tmpdir(), "ahp-client-example-"));
  let denied = false;
  const requests = [];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const message = JSON.parse(Buffer.concat(chunks));
    requests.push(message);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "draft",
          effects: denied ? [{ type: "deny", reason: "Policy" }] : [],
        },
      }),
    );
  });
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    config.hooks[0].transport.url = `http://127.0.0.1:${server.address().port}/intercept`;
    await writeFile(join(directory, "hooks.json"), JSON.stringify(config));
    await writeFile(
      join(directory, "README.md"),
      "typed original path was used",
    );
    await writeFile(join(directory, "example.mjs"), emitted);
    for (denied of [false, true]) {
      const child = spawn(process.execPath, ["example.mjs"], {
        cwd: directory,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "",
        stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      const code = await new Promise((resolve, reject) => {
        child.on("error", reject);
        child.on("close", resolve);
      });
      if (denied) {
        assert.notEqual(code, 0);
        assert.equal(stdout, "");
        assert.match(stderr, /interrupted or denied/);
      } else {
        assert.equal(code, 0, stderr);
        assert.equal(stdout.trim(), "typed original path was used");
      }
    }
    assert.equal(requests.length, 2);
    for (const request of requests) {
      assert.deepEqual(request.params.state, {
        permission: "none",
        candidate: null,
      });
      assert.equal(Object.hasOwn(request.params, "initialState"), false);
      assert.deepEqual(request.params.capabilities, { effects: ["deny"] });
      assert.deepEqual(request.params.event.tool.input, { path: "README.md" });
    }
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
