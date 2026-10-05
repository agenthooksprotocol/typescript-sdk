import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { fileURLToPath } from "node:url";

const fixture = (name) =>
  fileURLToPath(
    new URL(`../packages/testing/interop/fixtures/${name}`, import.meta.url),
  );
const securityURL = new URL("./security.mjs", import.meta.url).href;

// Use a separate process: an assertion on Response.body alone misses an unread
// IncomingMessage retaining its TLS socket after the caller has finished.
const client = `
  import assert from 'node:assert/strict';
  const { fixtureFetch } = await import(process.argv[1]);
  const [endpoint, scenario, caFile, certFile, keyFile] = process.argv.slice(2);
  const fetch = fixtureFetch({ mode: 'mtls', caFile, certFile, keyFile }, endpoint);
  const response = await fetch(endpoint, { method: scenario === 'HEAD' ? 'HEAD' : 'POST' });
  if (scenario === 'stream') {
    assert.equal(response.status, 202);
    const reader = response.body.getReader();
    const first = await reader.read();
    assert.equal(first.done, false);
    let body = Buffer.from(first.value).toString();
    // The server withholds the rest until consumption has actually begun.
    process.send('reading');
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      body += Buffer.from(chunk.value).toString();
    }
    assert.equal(body, 'prefix:' + 'x'.repeat(256 * 1024) + ':suffix');
  } else if (scenario === 'cancel') {
    assert.equal(response.status, 202);
    const reader = response.body.getReader();
    assert.equal((await reader.read()).done, false);
    await reader.cancel();
  } else {
    assert.equal(response.status, scenario === 'HEAD' ? 200 : Number(scenario));
    assert.equal(response.body, null);
    assert.equal(await response.text(), '');
  }
  console.log('caller finished');
  process.disconnect();
  // No process.exit(), agent destruction, or socket cleanup: exit is the test.
`;

for (const scenario of ["204", "205", "304", "HEAD", "stream", "cancel"]) {
  test(
    `fixtureFetch mTLS ${scenario}: caller completes and process exits`,
    { timeout: 5000 },
    async () => {
      let pendingResponse;
      let cancelled = false;
      const server = createServer(
        {
          ca: readFileSync(fixture("ca.pem")),
          cert: readFileSync(fixture("server.pem")),
          key: readFileSync(fixture("server-key.pem")),
          requestCert: true,
          rejectUnauthorized: true,
        },
        (req, res) => {
          assert.equal(req.socket.authorized, true);
          req.resume();
          if (scenario === "stream" || scenario === "cancel") {
            pendingResponse = res;
            res.writeHead(202);
            res.write("prefix:");
            res.on("close", () => {
              cancelled = !res.writableEnded;
            });
          } else {
            res.writeHead(scenario === "HEAD" ? 200 : Number(scenario));
            res.end();
          }
        },
      );
      // An unread response must not be rescued by the server's idle timeout.
      server.keepAliveTimeout = 60000;
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const endpoint = `https://127.0.0.1:${server.address().port}/event`;
      const child = spawn(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          client,
          securityURL,
          endpoint,
          scenario,
          fixture("ca.pem"),
          fixture("client.pem"),
          fixture("client-key.pem"),
        ],
        { stdio: ["ignore", "pipe", "pipe", "ipc"] },
      );
      let stdout = "",
        stderr = "",
        timedOut = false;
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("message", (message) => {
        if (message === "reading")
          pendingResponse.end("x".repeat(256 * 1024) + ":suffix");
      });
      const exited = once(child, "close");
      const deadline = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, 2500);
      try {
        const [code, signal] = await exited;
        assert.equal(
          timedOut,
          false,
          `child retained a TLS handle after response: ${stdout}${stderr}`,
        );
        assert.equal(signal, null, stderr);
        assert.equal(code, 0, stderr);
        assert.match(stdout, /caller finished/);
        if (scenario === "cancel")
          assert.equal(
            cancelled,
            true,
            "cancelling the body closes the unfinished response",
          );
      } finally {
        clearTimeout(deadline);
        if (child.exitCode === null && child.signalCode === null)
          child.kill("SIGKILL");
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
      }
    },
  );
}
