import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { ContentManager } = await import(
  require.resolve("agenthooksprotocol/client")
);
import { createHash } from "node:crypto";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const upload = {
  endpoint: "https://uploads.example/custom?tenant=one",
  timeoutMs: 1000,
  maxBytes: 100,
};
const attachment = (body, extra = {}) => ({
  id: "p",
  kind: "attachment",
  mediaType: "application/octet-stream",
  body,
  ...extra,
});
const text = (value, extra = {}) => ({
  id: "p",
  kind: "text",
  mediaType: "text/plain",
  text: value,
  ...extra,
});
const selectedAttachment = (selection) => {
  const { body, ...metadata } = attachment(undefined, { selection });
  return metadata;
};
const message = (...parts) => ({ id: "i", role: "assistant", parts });
const item = (body, extra = {}) => message(attachment(body, extra));
function source(bytes = new Uint8Array([0, 255, 128])) {
  let reads = 0,
    cancelled = false;
  return {
    stream: new ReadableStream(
      {
        pull(controller) {
          reads++;
          controller.enqueue(bytes);
          controller.close();
        },
        cancel() {
          cancelled = true;
        },
      },
      { highWaterMark: 0 },
    ),
    get reads() {
      return reads;
    },
    get cancelled() {
      return cancelled;
    },
  };
}
function sender(calls = [], ref = "receiver-ref") {
  return async (endpoint, init, config) => {
    calls.push({ endpoint, init, config });
    return new Response(
      JSON.stringify({
        ref,
        size: init.body.byteLength,
        sha256: hash(init.body),
      }),
      { status: 201, headers: { "content-type": "application/json" } },
    );
  };
}

test("content metadata and omit are lazy cloned views", async () => {
  const manager = new ContentManager();
  const content = source();
  const event = { type: "model.response.after", items: [item(content.stream)], nested: { untouched: [1] } };
  for (const mode of ["metadata", "omit"]) {
    const wire = await manager.prepare(
      event,
      { default: mode },
      undefined,
      () => {
        throw Error("must not upload");
      },
    );
    assert.equal(wire.items[0].parts[0].selection, mode);
    assert.equal("body" in wire.items[0].parts[0], false);
    assert.equal(wire.items[0].role, "assistant");
    assert.deepEqual(wire.nested, event.nested);
    assert.notEqual(wire.items[0], event.items[0]);
    assert.equal(content.reads, 0);
    assert.equal(content.stream.locked, false);
  }
  assert.equal(event.items[0].parts[0].body, content.stream);
  await manager.close();
  assert.equal(content.cancelled, true);
});

test("raw snapshot is consumed once, validated and uploaded independently per receiver", async () => {
  const bytes = new Uint8Array([0, 255, 128]);
  const content = source(bytes);
  const manager = new ContentManager();
  const event = {
    type: "model.response.after",
    items: [item(content.stream, { size: 3, sha256: hash(bytes) })],
  };
  const calls = [];
  const one = await manager.prepare(
    event,
    { default: "body" },
    upload,
    sender(calls, "one"),
  );
  calls[0].init.body.fill(42); // Request callbacks cannot mutate retained content.
  const receiverTwo = {
    ...upload,
    endpoint: "https://other.example/raw",
    auth: { type: "bearer", tokenEnv: "UPLOAD_ONLY" },
  };
  const two = await manager.prepare(
    event,
    { default: "body" },
    receiverTwo,
    sender(calls, "two"),
  );
  assert.equal(content.reads, 1);
  assert.equal(one.items[0].parts[0].body.ref, "one");
  assert.equal(two.items[0].parts[0].body.ref, "two");
  assert.deepEqual(calls[1].init.body, bytes);
  assert.equal(calls[0].endpoint, upload.endpoint);
  assert.equal(calls[1].config, receiverTwo);
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.headers["content-length"], "3");
  assert.equal(calls[0].init.headers["ahp-content-sha256"], hash(bytes));
  assert.equal(calls[0].init.headers.authorization, undefined);
  await manager.close();
});

test("reasoning category overrides text media type; explicit category overrides binary media type", async () => {
  const manager = new ContentManager();
  const b = source(), c = source();
  const wire = await manager.prepare(
    {
      type: "model.response.after",
      items: [
        message(text("private reasoning", { category: "reasoning" })),
        item(b.stream, { category: "custom" }),
        item(c.stream, { mediaType: "image/png" }),
        message(text("visible text")),
      ],
    },
    { default: "body", reasoning: "omit", custom: "metadata", images: "metadata" },
    undefined,
    () => { throw Error("must not upload inline text or unselected attachments"); },
  );
  assert.deepEqual(wire.items.map((x) => x.parts[0].selection),
    ["omit", "metadata", "metadata", "body"]);
  assert.equal("text" in wire.items[0].parts[0], false);
  assert.equal(wire.items[3].parts[0].text, "visible text");
  assert.equal(b.reads + c.reads, 0);
  await manager.close();
});

test("length, digest, memory and upload limits fail without publishing a reference", async () => {
  for (const extra of [{ size: 4 }, { sha256: "0".repeat(64) }]) {
    const manager = new ContentManager();
    await assert.rejects(
      manager.prepare(
        { type: "model.response.after", items: [item(source().stream, extra)] },
        { default: "body" },
        upload,
        () => {
          throw Error("unexpected upload");
        },
      ),
      /mismatch/,
    );
    await manager.close();
  }
  const manager = new ContentManager({ maxSnapshotBytes: 2 });
  const content = source();
  await assert.rejects(
    manager.prepare(
      { type: "model.response.after", items: [item(content.stream)] },
      { default: "body" },
      upload,
      sender(),
    ),
    /memory limit/,
  );
  await manager.close();
  const other = new ContentManager();
  await assert.rejects(
    other.prepare(
      { type: "model.response.after", items: [item(source().stream)] },
      { default: "body" },
      { ...upload, maxBytes: 2 },
      sender(),
    ),
    /maxBytes/,
  );
  await other.close();
});

test("only a validated 201 confirmation is accepted", async () => {
  const manager = new ContentManager();
  const event = { type: "model.response.after", items: [item(source().stream)] };
  for (const [status, ref, type] of [
    [
      202,
      { ref: "x", size: 3, sha256: hash(new Uint8Array([0, 255, 128])) },
      "application/json",
    ],
    [201, { ref: "x", size: 4, sha256: "0".repeat(64) }, "application/json"],
    [201, { size: 3, sha256: "0".repeat(64) }, "application/json"],
    [201, {}, "text/plain"],
  ]) {
    await assert.rejects(
      manager.prepare(
        event,
        { default: "body" },
        upload,
        async () =>
          new Response(JSON.stringify(ref), {
            status,
            headers: { "content-type": type },
          }),
      ),
    );
  }
  await manager.close();
});

test("close cancels active readers and blocks future preparation", async () => {
  let cancelled = false;
  const stream = new ReadableStream(
    {
      pull() {
        return new Promise(() => {});
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const manager = new ContentManager();
  const preparation = manager.prepare(
    { type: "model.response.after", items: [item(stream)] },
    { default: "body" },
    upload,
    sender(),
  );
  const rejected = assert.rejects(preparation, /closed/);
  await new Promise((resolve) => setTimeout(resolve, 5));
  await manager.close();
  await rejected;
  assert.equal(cancelled, true);
  await assert.rejects(
    manager.prepare({}, { default: "omit" }, undefined, sender()),
    /closed/,
  );
});

test("empty snapshots retain exact zero framing and unsafe endpoints fail before reads", async () => {
  const manager = new ContentManager();
  const calls = [];
  const empty = await manager.prepare(
    { type: "model.response.after", items: [item(source(new Uint8Array()).stream)] },
    { default: "body" },
    upload,
    sender(calls),
  );
  assert.deepEqual(empty.items[0].parts[0].body, { ref: "receiver-ref" });
  assert.equal(calls[0].init.headers["content-length"], "0");
  const content = source();
  for (const endpoint of [
    "http://remote.example/raw",
    "https://user:pass@example.com/raw",
    "https://example.com/raw#fragment",
  ]) {
    await assert.rejects(
      manager.prepare(
        { type: "model.response.after", items: [item(content.stream)] },
        { default: "body" },
        { ...upload, endpoint },
        sender(),
      ),
      /Unsafe/,
    );
  }
  assert.equal(content.reads, 0);
  await manager.close();
});

test("readBody reuses preparation snapshots and returns independent byte copies", async () => {
  const manager = new ContentManager();
  const content = source();
  const event = { type: "model.response.after", items: [item(content.stream)] };
  await manager.prepare(event, { default: "body" }, upload, sender());
  const first = await manager.readBody(content.stream);
  assert.deepEqual(first, new Uint8Array([0, 255, 128]));
  first.fill(17);
  const second = await manager.readBody(content.stream);
  assert.deepEqual(second, new Uint8Array([0, 255, 128]));
  assert.notEqual(first, second);
  assert.equal(content.reads, 1);
  await manager.close();
});

test("readBody before preparation and composed replacement streams share the manager budget", async () => {
  const manager = new ContentManager({ maxSnapshotBytes: 6 });
  const original = source();
  assert.deepEqual(
    await manager.readBody(original.stream),
    new Uint8Array([0, 255, 128]),
  );
  const calls = [];
  await manager.prepare(
    { type: "model.response.after", items: [item(original.stream)] },
    { default: "body" },
    upload,
    sender(calls),
  );
  assert.equal(original.reads, 1);
  const replacement = source(new Uint8Array([1, 2, 3]));
  const wire = await manager.prepare(
    { type: "model.response.after", items: [item(replacement.stream)] },
    { default: "body" },
    upload,
    sender(calls),
  );
  assert.deepEqual(wire.items[0].parts[0].body, { ref: "receiver-ref" });
  assert.equal(calls.at(-1).init.headers["ahp-content-sha256"], hash(new Uint8Array([1, 2, 3])));
  assert.deepEqual(
    await manager.readBody(replacement.stream),
    new Uint8Array([1, 2, 3]),
  );
  await assert.rejects(
    manager.readBody(source(new Uint8Array([4])).stream),
    /memory limit/,
  );
  await assert.rejects(
    manager.readBody({
      ref: "untrusted",
      size: 0,
      sha256: hash(new Uint8Array()),
    }),
    /raw ReadableStream/,
  );
  await manager.close();
});

test("readBody honors pre-abort, in-flight abort, and manager close", async () => {
  const manager = new ContentManager();
  const untouched = source();
  const alreadyAborted = new AbortController();
  alreadyAborted.abort(new Error("already aborted"));
  await assert.rejects(
    manager.readBody(untouched.stream, alreadyAborted.signal),
    /already aborted/,
  );
  assert.equal(untouched.reads, 0);
  for (const action of ["abort", "close"]) {
    let cancelled = false;
    const stream = new ReadableStream(
      {
        pull() {
          return new Promise(() => {});
        },
        cancel() {
          cancelled = true;
        },
      },
      { highWaterMark: 0 },
    );
    const controller = new AbortController();
    const pending = manager.readBody(stream, controller.signal);
    const rejected = assert.rejects(
      pending,
      action === "abort" ? /read cancelled/ : /closed/,
    );
    if (action === "abort") controller.abort(new Error("read cancelled"));
    else await manager.close();
    await rejected;
    assert.equal(cancelled, action === "close");
  }
  await assert.rejects(manager.readBody(untouched.stream), /closed/);
});

test("close never waits for producer cancellation and pending reads release their locks", async () => {
  const manager = new ContentManager();
  let cancellations = 0;
  const makeStream = () =>
    new ReadableStream(
      {
        pull() {
          return new Promise(() => {});
        },
        cancel() {
          cancellations++;
          return new Promise(() => {});
        },
      },
      { highWaterMark: 0 },
    );
  const unread = makeStream(),
    active = makeStream();
  await manager.prepare(
    { type: "model.response.after", items: [item(unread)] },
    { default: "metadata" },
    undefined,
    sender(),
  );
  const read = manager.readBody(active);
  const rejected = assert.rejects(read, /Content manager closed/);
  const closing = manager.close();
  assert.equal(manager.close(), closing);
  let timer;
  try {
    await Promise.race([
      Promise.all([closing, rejected]),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(Error("close waited for producer cancellation")),
          100,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
  assert.equal(cancellations, 2);
  assert.equal(active.locked, false);
  assert.equal(unread.locked, false);
});

test("caller abort releases its wait; manager close releases the pending reader without awaiting producer cancellation", async () => {
  const manager = new ContentManager();
  const stream = new ReadableStream(
    {
      pull() {
        return new Promise(() => {});
      },
      cancel() {
        return new Promise(() => {});
      },
    },
    { highWaterMark: 0 },
  );
  const controller = new AbortController();
  const reading = manager.readBody(stream, controller.signal);
  const rejected = assert.rejects(reading, /caller stopped/);
  controller.abort(new Error("caller stopped"));
  await rejected;
  assert.equal(stream.locked, true);
  await manager.close();
  assert.equal(stream.locked, false);
});

test("upload timeout and caller abort bound even an uncooperative callback", async () => {
  const manager = new ContentManager();
  await assert.rejects(
    manager.prepare(
      { type: "model.response.after", items: [item(source().stream)] },
      { default: "body" },
      { ...upload, timeoutMs: 10 },
      () => new Promise(() => {}),
    ),
    /timed out/,
  );
  const controller = new AbortController();
  controller.abort(new Error("caller cancelled"));
  await assert.rejects(
    manager.prepare(
      {},
      { default: "omit" },
      undefined,
      sender(),
      controller.signal,
    ),
    /caller cancelled/,
  );
  await manager.close();
});

test("file.changed attachments upload once per receiver from reusable snapshots", async () => {
  const manager = new ContentManager();
  const before = source(new Uint8Array([1])),
    after = source(new Uint8Array([2, 3]));
  const event = {
    type: "file.changed",
    changes: [
      {
        operation: "update",
        path: "file.txt",
        agentCaused: true,
        before: attachment(before.stream),
        after: attachment(after.stream),
      },
    ],
  };
  const calls = [];
  const one = await manager.prepare(
    event,
    { default: "omit", files: "body" },
    upload,
    sender(calls, "scope-one"),
  );
  const secondUpload = { ...upload, endpoint: "https://second.example/upload" };
  const two = await manager.prepare(
    event,
    { default: "body" },
    secondUpload,
    sender(calls, "scope-two"),
  );
  assert.equal(before.reads, 1);
  assert.equal(after.reads, 1);
  assert.equal(calls.length, 4);
  for (const key of ["before", "after"]) {
    assert.equal(one.changes[0][key].body.ref, "scope-one");
    assert.equal(two.changes[0][key].body.ref, "scope-two");
    assert.deepEqual(Object.keys(two.changes[0][key].body), ["ref"]);
  }
  assert.deepEqual(calls.slice(2).map((call) => call.init.headers["ahp-content-sha256"]).sort(), [hash(new Uint8Array([1])), hash(new Uint8Array([2, 3]))].sort());
  assert.deepEqual(calls.slice(2).map((call) => call.init.headers["content-length"]).sort(), ["1", "2"]);
  assert.equal(two.changes[0].path, "file.txt");
  assert.equal(event.changes[0].before.body, before.stream);
  await manager.close();
});

test("file.changed metadata and omitted attachments exclude bodies without reading and are cancelled on close", async () => {
  const manager = new ContentManager();
  const before = source(),
    after = source();
  const event = {
    type: "file.changed",
    changes: [{ path: "file", before: attachment(before.stream), after: attachment(after.stream) }],
  };
  for (const mode of ["metadata", "omit"]) {
    const wire = await manager.prepare(
      event,
      { default: "body", files: mode },
      undefined,
      () => {
        throw Error("unexpected upload");
      },
    );
    assert.deepEqual(wire, {
      type: "file.changed",
      changes: [{
        path: "file",
        before: selectedAttachment(mode),
        after: selectedAttachment(mode),
      }],
    });
  }
  assert.equal(before.reads + after.reads, 0);
  await manager.close();
  assert.equal(before.cancelled, true);
  assert.equal(after.cancelled, true);
});

test("file.changed never forwards a receiver's existing attachment reference", async () => {
  const manager = new ContentManager();
  const ref = { ref: "other-scope" };
  const event = {
    type: "file.changed",
    changes: [{ path: "file", before: attachment(ref), after: attachment(ref) }],
  };
  await assert.rejects(
    manager.prepare(event, { default: "body" }, upload, sender()),
    /not a receiver reference/,
  );
  for (const mode of ["metadata", "omit"]) {
    assert.deepEqual(
      await manager.prepare(event, { default: mode }, undefined, sender()),
      {
        type: "file.changed",
        changes: [{ path: "file", before: selectedAttachment(mode), after: selectedAttachment(mode) }],
      },
    );
  }
  assert.equal(event.changes[0].before.body, ref);
  await manager.close();
});

test("only canonical content paths are projected, never opaque descriptor-shaped data", async () => {
  const manager = new ContentManager();
  const opaque = {
    id: "ordinary",
    kind: "message",
    mediaType: "text/plain",
    body: "opaque string",
    selection: "body",
  };
  for (const mode of ["metadata", "body"]) {
    const event = {
      tool: { input: opaque },
      native: opaque,
      params: opaque,
      config: opaque,
      workspace: opaque,
      extensions: { items: [opaque] },
      nested: { items: [opaque] },
    };
    assert.deepEqual(
      await manager.prepare(event, { default: mode }, undefined, () => {
        throw Error("unexpected upload");
      }),
      event,
    );
  }
  const stream = () => attachment(source().stream);
  const cases = [
    ["model.response.after", { items: [message(stream())] }, (wire) => wire.items[0].parts],
    ["context.compact.before", { instructions: [text("instructions")] }, (wire) => wire.instructions],
    ["context.compact.after", { summary: [text("summary")] }, (wire) => wire.summary],
    ["tool.progress", { partialOutput: message(stream()) }, (wire) => wire.partialOutput.parts],
    ["turn.progress", { delta: message(stream()) }, (wire) => wire.delta.parts],
    ["user.attention", { attention: { title: [text("title")], message: [text("message")] } }, (wire) => [...wire.attention.title, ...wire.attention.message]],
    ["user.message.inbound", { message: { messages: [message(text("inbound"))], payload: opaque } }, (wire) => wire.message.messages[0].parts],
    ["user.elicitation.request", { elicitation: { request: text("request") } }, (wire) => [wire.elicitation.request]],
    ["user.elicitation.result", { elicitation: { result: text("result") } }, (wire) => [wire.elicitation.result]],
    ["tool.after", { fileChanges: [{ before: stream(), after: stream(), path: "file" }], changes: [{ before: { ref: "existing" } }] }, (wire) => [wire.fileChanges[0].before, wire.fileChanges[0].after]],
  ];
  for (const [type, fields, descriptors] of cases) {
    const event = { type, ...fields, native: opaque, extensions: { items: [opaque] } };
    const wire = await manager.prepare(event, { default: "metadata" }, undefined, sender());
    for (const descriptor of descriptors(wire)) {
      assert.equal(descriptor.selection, "metadata", type);
      assert.equal("body" in descriptor, false);
      assert.equal("text" in descriptor, false);
    }
    assert.deepEqual(Object.keys(wire).sort(), Object.keys(event).sort());
    assert.deepEqual(wire.native, opaque);
    assert.deepEqual(wire.extensions, event.extensions);
    if (event.changes) assert.deepEqual(wire.changes, event.changes);
    if (event.message?.payload) assert.deepEqual(wire.message.payload, opaque);
  }
  await manager.close();
});

test("upload confirmations are bounded, strict UTF-8 JSON and always release readers", async () => {
  const manager = new ContentManager();
  const event = { type: "model.response.after", items: [item(source().stream)] };
  for (const [bytes, status, pattern] of [
    [new Uint8Array(1024 * 1024 + 1), 201, /1 MiB/],
    [new Uint8Array([255]), 201, /encoded data|encoding/i],
    [new TextEncoder().encode("{broken"), 201, /JSON|property/i],
    [new Uint8Array([1]), 403, /HTTP 201/],
  ]) {
    let cancelled = false;
    const body = new ReadableStream(
      {
        start(c) {
          c.enqueue(bytes);
          if (bytes.length < 10 && status === 201) c.close();
        },
        cancel() {
          cancelled = true;
          return new Promise(() => {});
        },
      },
      { highWaterMark: 0 },
    );
    await assert.rejects(
      manager.prepare(
        event,
        { default: "body" },
        upload,
        async () =>
          new Response(body, {
            status,
            headers: { "content-type": "application/json" },
          }),
      ),
      pattern,
    );
    assert.equal(body.locked, false);
    if (bytes.length > 10 || status !== 201) assert.equal(cancelled, true);
  }
  let cancelled = false;
  const stalled = new ReadableStream(
    {
      pull() {
        return new Promise(() => {});
      },
      cancel() {
        cancelled = true;
        return new Promise(() => {});
      },
    },
    { highWaterMark: 0 },
  );
  await assert.rejects(
    manager.prepare(
      event,
      { default: "body" },
      { ...upload, timeoutMs: 10 },
      async () =>
        new Response(stalled, {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    ),
    /timed out/,
  );
  assert.equal(cancelled, true);
  assert.equal(stalled.locked, false);
  await manager.close();
});
