import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ContentManager, ContentSource } from "@agenthooksprotocol/sdk/client";

function fixture(stalled = false) {
  const state = { pulls: 0, cancels: 0 };
  const stream = new ReadableStream(
    {
      pull(controller) {
        state.pulls++;
        if (!stalled) {
          controller.enqueue(new TextEncoder().encode("hello"));
          controller.close();
        }
      },
      cancel() {
        state.cancels++;
      },
    },
    { highWaterMark: 0 },
  );
  const source = new ContentSource(stream);
  return {
    state,
    stream,
    source,
    event: {
      instructions: {
        id: "i",
        kind: "text",
        mediaType: "text/plain",
        body: source,
      },
    },
  };
}
const upload = {
  endpoint: "https://receiver.example/upload",
  maxBytes: 100,
  timeoutMs: 1000,
};
const unexpected = () => {
  throw new Error("unexpected upload");
};

for (const mode of ["metadata", "omit"]) {
  test(`lazy source ${mode} selection never reads bytes`, async () => {
    const { source, stream, state, event } = fixture();
    assert.equal(source.stream, stream);
    assert.equal(stream.locked, false);
    await Promise.resolve();
    assert.equal(state.pulls, 0);
    const manager = new ContentManager();
    try {
      const prepared = await manager.prepare(
        event,
        { default: mode },
        undefined,
        unexpected,
      );
      assert.equal(prepared.instructions.body, undefined);
      assert.equal(prepared.instructions.mediaType, "text/plain");
      assert.equal(prepared.instructions.selection, mode);
      assert.equal(state.pulls, 0);
    } finally {
      await manager.close();
    }
    assert.equal(state.cancels, 1);
  });
}

test("unmatched sources and raw streams are owned without consumption", async () => {
  const first = fixture(),
    second = fixture();
  const manager = new ContentManager();
  const event = { opaque: { source: first.source }, hidden: [second.stream] };
  event.self = event;
  manager.own(event);
  const closed = manager.close();
  assert.equal(manager.close(), closed);
  await closed;
  for (const { state } of [first, second])
    assert.deepEqual(state, { pulls: 0, cancels: 1 });
});

test("concurrent body fanout shares one snapshot and independent receiver uploads", async () => {
  const { stream, state, event } = fixture();
  const manager = new ContentManager();
  const digest = createHash("sha256").update("hello").digest("hex");
  const seen = [];
  const send = async (endpoint, init) => {
    const ref = `receiver-${seen.length}`;
    seen.push(new TextDecoder().decode(init.body));
    assert.equal(init.headers["ahp-content-sha256"], digest);
    init.body.fill(0); // Must not mutate the manager's reusable snapshot.
    return Response.json({ ref, size: 5, sha256: digest }, { status: 201 });
  };
  try {
    const results = await Promise.all([
      manager.prepare(event, { default: "body" }, upload, send),
      manager.prepare(
        { instructions: { ...event.instructions, body: stream } },
        { default: "body" },
        upload,
        send,
      ),
    ]);
    assert.equal(state.pulls, 1);
    assert.deepEqual(seen, ["hello", "hello"]);
    assert.notEqual(
      results[0].instructions.body.ref,
      results[1].instructions.body.ref,
    );
    assert.equal(
      new TextDecoder().decode(await manager.readBody(event.instructions.body)),
      "hello",
    );
  } finally {
    await manager.close();
  }
  assert.equal(stream.locked, false);
});

for (const cancel of ["signal", "close"]) {
  test(`${cancel} cancels a pending selected body and releases ownership`, async () => {
    const { state, stream, event } = fixture(true);
    const manager = new ContentManager();
    const controller = new AbortController();
    const pending = manager.prepare(
      event,
      { default: "body" },
      upload,
      unexpected,
      controller.signal,
    );
    const rejected = assert.rejects(pending);
    while (state.pulls === 0) await Promise.resolve();
    if (cancel === "signal") controller.abort(new Error("cancelled"));
    else await manager.close();
    await rejected;
    await manager.close();
    assert.equal(state.cancels, 1);
    assert.equal(stream.locked, false);
  });
}

test("pre-aborted operations still register unused sources for cleanup", async () => {
  const { state, event } = fixture();
  const manager = new ContentManager();
  await assert.rejects(
    manager.prepare(
      event,
      { default: "body" },
      upload,
      unexpected,
      AbortSignal.abort(),
    ),
  );
  await manager.close();
  assert.deepEqual(state, { pulls: 0, cancels: 1 });
});
