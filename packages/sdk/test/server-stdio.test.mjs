import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { PassThrough, Readable, Writable } from "node:stream";
import { setImmediate } from "node:timers/promises";
import { hooks } from "@agenthooksprotocol/sdk/server";
import { serveStdio } from "@agenthooksprotocol/sdk/server/stdio";

function capture(options = {}) {
  const chunks = [];
  const stream = new Writable({
    ...options,
    write(chunk, encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return { stream, text: () => chunks.join("") };
}
function intercept(id = "é🪝") {
  return {
    jsonrpc: "2.0",
    id,
    method: "hooks/intercept",
    params: {
      protocolVersion: "draft",
      capabilities: { effects: ["deny"] },
      event: {
        id,
        source: "urn:test",
        time: "2026-01-01T00:00:00Z",
        type: "tool.before",
        call: { id: "call" },
        path: "native",
        tool: { name: "read", origin: "native", input: {} },
      },
    },
  };
}

test("stdio composes hooks.handle: correlation, parse errors, and silent notifications", async () => {
  const notification = intercept();
  delete notification.id;
  delete notification.params.capabilities;
  notification.method = "hooks/observe";
  const output = capture();
  const seen = [];
  const bytes = Buffer.from(
    [
      JSON.stringify(intercept()),
      "{",
      JSON.stringify(notification),
      JSON.stringify(intercept("next")),
    ].join("\n"),
  );
  await serveStdio(
    (request) => {
      assert.equal(request.method, "POST");
      assert.equal(request.headers.get("content-type"), "application/json");
      return hooks.handle(request, (message) => {
        seen.push(message.method);
        if (message.method === "hooks/observe") return;
        return { effects: [{ type: "deny", reason: "é🪝" }] };
      });
    },
    {
      stdin: Readable.from([...bytes].map((byte) => Buffer.from([byte]))),
      stdout: output.stream,
    },
  );
  const replies = output.text().trimEnd().split("\n").map(JSON.parse);
  assert.deepEqual(replies[0], {
    jsonrpc: "2.0",
    id: "é🪝",
    result: {
      protocolVersion: "draft",
      effects: [{ type: "deny", reason: "é🪝" }],
    },
  });
  assert.equal(replies[1].id, null);
  assert.equal(replies[1].error.code, -32700);
  assert.equal(replies[2].id, "next");
  assert.equal(replies.length, 3);
  assert.deepEqual(seen, [
    "hooks/intercept",
    "hooks/observe",
    "hooks/intercept",
  ]);
  assert.equal(output.stream.writableEnded, false);
  assert.equal(output.stream.destroyed, false);
  assert.equal(output.stream.listenerCount("error"), 0);
  assert.equal(output.stream.listenerCount("close"), 0);
  output.stream.end();
});

test("raw lines, CRLF, EOF, statuses and multiline response framing", async () => {
  const seen = [];
  const output = capture();
  await serveStdio(
    async (request) => {
      seen.push(await request.text());
      if (seen.length === 2) return new Response(null, { status: 500 });
      return new Response('{\n  "error": true\r\n}', { status: 400 });
    },
    { stdin: Readable.from(["first\r\n\nlast"]), stdout: output.stream },
  );
  assert.deepEqual(seen, ["first\r", "", "last"]);
  assert.equal(output.text(), '{   "error": true  }\n{   "error": true  }\n');
  output.stream.end();
});

test("empty input invokes no handler and writes nothing", async () => {
  const output = capture();
  await serveStdio(() => assert.fail("no request"), {
    stdin: Readable.from([]),
    stdout: output.stream,
  });
  assert.equal(output.text(), "");
  output.stream.end();
});

test("notification handler failures remain silent through the shim", async () => {
  const message = intercept();
  delete message.id;
  delete message.params.capabilities;
  message.method = "hooks/observe";
  const output = capture();
  await serveStdio(
    (request) =>
      hooks.handle(request, () => {
        throw Error("policy failed");
      }),
    {
      stdin: Readable.from([JSON.stringify(message) + "\n"]),
      stdout: output.stream,
    },
  );
  assert.equal(output.text(), "");
  output.stream.end();
});

test(
  "backpressure blocks the next handler and EOF waits for the final write",
  { timeout: 5000 },
  async () => {
    const writes = [];
    let calls = 0;
    let completed = false;
    const output = new Writable({
      highWaterMark: 1,
      write(chunk, encoding, callback) {
        writes.push({ text: chunk.toString(), callback });
      },
    });
    const serving = serveStdio(() => new Response(String(++calls)), {
      stdin: Readable.from(["a\nb\n"]),
      stdout: output,
    }).then(() => {
      completed = true;
    });
    await setImmediate();
    assert.equal(calls, 1);
    assert.equal(completed, false);
    writes[0].callback();
    await setImmediate();
    assert.equal(calls, 2);
    assert.equal(completed, false);
    writes[1].callback();
    await serving;
    assert.deepEqual(
      writes.map(({ text }) => text),
      ["1\n", "2\n"],
    );
    assert.equal(output.writableEnded, false);
    output.end();
  },
);

for (const kind of ["handler", "response", "input", "output"]) {
  test(
    `stdio propagates ${kind} errors without fabricated replies`,
    { timeout: 5000 },
    async () => {
      const failure = Error(`${kind} failed`);
      const captured = capture();
      const output =
        kind === "output"
          ? new Writable({
              write(chunk, encoding, callback) {
                callback(failure);
              },
            })
          : captured.stream;
      const input =
        kind === "input"
          ? new Readable({
              read() {
                this.destroy(failure);
              },
            })
          : Readable.from(["request\n"]);
      const serving = serveStdio(
        () => {
          if (kind === "handler") throw failure;
          if (kind === "response")
            return new Response(
              new ReadableStream({
                start(controller) {
                  controller.error(failure);
                },
              }),
            );
          return new Response("reply");
        },
        { stdin: input, stdout: output },
      );
      await assert.rejects(serving, (error) => error === failure);
      assert.equal(input.destroyed, true);
      assert.equal(output.destroyed, true);
      assert.equal(captured.text(), "");
      if (!output.destroyed) output.end();
    },
  );
}

test("abort tears down idle input and output", { timeout: 5000 }, async () => {
  const input = new PassThrough();
  const output = capture().stream;
  const controller = new AbortController();
  const serving = serveStdio(() => new Response("unused"), {
    stdin: input,
    stdout: output,
    signal: controller.signal,
  });
  controller.abort();
  await assert.rejects(serving, { name: "AbortError" });
  assert.equal(input.destroyed, true);
  assert.equal(output.destroyed, true);
});

test(
  "abort reaches an active handler's Request signal",
  { timeout: 5000 },
  async () => {
    const input = new PassThrough();
    const output = capture();
    const controller = new AbortController();
    const entered = new PassThrough();
    const ready = once(entered, "data");
    const serving = serveStdio(
      async (request) => {
        const aborted = once(request.signal, "abort");
        entered.write("ready");
        await aborted;
        request.signal.throwIfAborted();
        return new Response("unreachable");
      },
      { stdin: input, stdout: output.stream, signal: controller.signal },
    );
    input.write("request\n");
    await ready;
    controller.abort();
    await assert.rejects(serving, { name: "AbortError" });
    assert.equal(output.text(), "");
    entered.destroy();
  },
);

test("output errors interrupt an idle input", { timeout: 5000 }, async () => {
  const failure = Error("output closed");
  const input = new PassThrough();
  const output = capture().stream;
  const serving = serveStdio(() => new Response("unused"), {
    stdin: input,
    stdout: output,
  });
  output.destroy(failure);
  await assert.rejects(serving, (error) => error === failure);
  assert.equal(input.destroyed, true);
});

test("abort interrupts output backpressure", { timeout: 5000 }, async () => {
  const input = new PassThrough();
  const output = new PassThrough({ highWaterMark: 1 });
  const controller = new AbortController();
  const serving = serveStdio(() => new Response("reply"), {
    stdin: input,
    stdout: output,
    signal: controller.signal,
  });
  input.write("request\n");
  await setImmediate();
  assert.equal(output.writableNeedDrain, true);
  controller.abort();
  await assert.rejects(serving, { name: "AbortError" });
  assert.equal(input.destroyed, true);
  output.destroy();
});

test(
  "EOF waits for an accepted write's callback even without drain",
  { timeout: 5000 },
  async () => {
    let release;
    let completed = false;
    const output = new Writable({
      write(chunk, encoding, callback) {
        release = callback;
      },
    });
    const serving = serveStdio(() => new Response("reply"), {
      stdin: Readable.from(["request\n"]),
      stdout: output,
    }).then(() => {
      completed = true;
    });
    await setImmediate();
    assert.equal(output.writableNeedDrain, false);
    assert.equal(completed, false);
    release();
    await serving;
    output.end();
  },
);

test(
  "an already-aborted signal invokes no handler",
  { timeout: 5000 },
  async () => {
    const input = new PassThrough();
    const output = capture().stream;
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      serveStdio(() => assert.fail("aborted"), {
        stdin: input,
        stdout: output,
        signal: controller.signal,
      }),
      { name: "AbortError" },
    );
    assert.equal(input.destroyed, true);
    assert.equal(output.destroyed, true);
  },
);
