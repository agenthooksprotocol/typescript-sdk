import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { PassThrough, Readable, Writable } from "node:stream";
import { setImmediate } from "node:timers/promises";
import { NdjsonDecoder } from "agenthooksprotocol";
import { serveStdio } from "agenthooksprotocol/server/stdio";

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
        source: "urn:test", harness: { name: 'test', version: '1' },
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
    {
      intercept: {
        toolBefore(ctx) {
          seen.push(ctx.request.method);
          return { effects: [{ type: "deny", reason: "é🪝" }] };
        },
      },
      observe: {
        toolBefore(ctx) {
          seen.push(ctx.notification.method);
        },
      },
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

// Root framing is independent from server admission and typed dispatch.
test("root NDJSON preserves split UTF-8 and CRLF and requires complete frames", () => {
  const decoder = new NdjsonDecoder();
  const text = JSON.stringify(intercept());
  const frames = [];
  for (const byte of Buffer.from(text + "\r\n")) {
    frames.push(...decoder.push(Buffer.from([byte])));
  }
  assert.deepEqual(frames, [text]);
  decoder.end();
  const incomplete = new NdjsonDecoder();
  assert.deepEqual(incomplete.push(Buffer.from(text)), []);
  assert.throws(() => incomplete.end(), /incomplete NDJSON frame/);
  assert.throws(() => new NdjsonDecoder().push(Buffer.from("\n")), /Empty NDJSON frame/);
  assert.throws(() => new NdjsonDecoder().push(Buffer.from([0xff, 0x0a])), /valid UTF-8/);
});

test("empty input invokes no handler and writes nothing", async () => {
  const output = capture();
  await serveStdio({ intercept: { toolBefore() { assert.fail("no request"); } } }, {
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
    { observe: { toolBefore() { throw Error("policy failed"); } } },
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
    const serving = serveStdio({ intercept: { toolBefore() { calls++; return { effects: [] }; } } }, {
      stdin: Readable.from([JSON.stringify(intercept("a")) + "\n" + JSON.stringify(intercept("b")) + "\n"]),
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
      writes.map(({ text }) => JSON.parse(text).id),
      ["a", "b"],
    );
    assert.equal(output.writableEnded, false);
    output.end();
  },
);

for (const kind of ["input", "output"]) {
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
          : Readable.from([JSON.stringify(intercept()) + "\n"]);
      const serving = serveStdio(
        { intercept: { toolBefore() { return { effects: [] }; } } },
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
  const serving = serveStdio({ intercept: { toolBefore() { return { effects: [] }; } } }, {
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
  "abort reaches an active handler's context signal",
  { timeout: 5000 },
  async () => {
    const input = new PassThrough();
    const output = capture();
    const controller = new AbortController();
    const entered = new PassThrough();
    const ready = once(entered, "data");
    const serving = serveStdio(
      { intercept: { async toolBefore(ctx) {
        const aborted = once(ctx.signal, "abort");
        entered.write("ready");
        await aborted;
        ctx.signal.throwIfAborted();
        return { effects: [] };
      } } },
      { stdin: input, stdout: output.stream, signal: controller.signal },
    );
    input.write(JSON.stringify(intercept()) + "\n");
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
  const serving = serveStdio({ intercept: { toolBefore() { return { effects: [] }; } } }, {
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
  const serving = serveStdio({ intercept: { toolBefore() { return { effects: [] }; } } }, {
    stdin: input,
    stdout: output,
    signal: controller.signal,
  });
  input.write(JSON.stringify(intercept()) + "\n");
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
    const serving = serveStdio({ intercept: { toolBefore() { return { effects: [] }; } } }, {
      stdin: Readable.from([JSON.stringify(intercept()) + "\n"]),
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
      serveStdio({ intercept: { toolBefore() { assert.fail("aborted"); } } }, {
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
