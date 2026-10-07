import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { attachments, UploadError } = await import(
  require.resolve("agenthooksprotocol/server")
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const bytes = new Uint8Array([0, 255, 128, 10]);
function request(body = bytes, headers = {}, method = "POST") {
  return new Request("https://receiver.test/upload", {
    method,
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(bytes.length),
      "ahp-content-sha256": hash(bytes),
      ...headers,
    },
    ...(body === null ? {} : { body, duplex: "half" }),
  });
}
async function read(body) {
  return new Uint8Array(await new Response(body).arrayBuffer());
}
function source(chunks) {
  let reads = 0,
    cancelled;
  return {
    stream: new ReadableStream(
      {
        pull(c) {
          reads++;
          const b = chunks.shift();
          if (b) c.enqueue(b);
          else c.close();
        },
        cancel(reason) {
          cancelled = reason;
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

test("attachments lazily validate binary chunks and emit canonical 201 descriptor", async () => {
  const input = source([bytes.slice(0, 2), bytes.slice(2)]);
  const upload = attachments.parse(request(input.stream));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(input.reads, 0);
  assert.equal(upload.size, 4);
  assert.equal(upload.sha256, hash(bytes));
  const reader = upload.body.getReader();
  assert.deepEqual((await reader.read()).value, bytes.slice(0, 2));
  assert.equal(input.reads, 1);
  assert.deepEqual((await reader.read()).value, bytes.slice(2));
  assert.equal(input.reads, 2);
  assert.equal((await reader.read()).done, true);
  const response = attachments.response({
    ref: "opaque-receiver-ref",
    size: upload.size,
    sha256: upload.sha256,
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.deepEqual(await response.json(), {
    ref: "opaque-receiver-ref",
    size: 4,
    sha256: hash(bytes),
  });
});

test("zero-byte body including absent Web Request body verifies the empty digest", async () => {
  for (const body of [null, new Uint8Array(), source([]).stream]) {
    const upload = attachments.parse(
      request(body, {
        "content-length": "0",
        "ahp-content-sha256": hash(new Uint8Array()),
      }),
    );
    assert.deepEqual(await read(upload.body), new Uint8Array());
  }
});

test("malformed upload framing fails synchronously before consuming bytes", () => {
  for (const headers of [
    { "content-type": "application/json" },
    { "content-type": "application/octet-stream; charset=utf-8" },
    { "content-length": "-1" },
    { "content-length": "1.0" },
    { "content-length": "4, 4" },
    { "content-length": "9007199254740992" },
    { "ahp-content-sha256": "A".repeat(64) },
    { "ahp-content-sha256": "x" },
    { "content-encoding": "identity" },
    { "transfer-encoding": "chunked" },
  ]) {
    const input = source([bytes]);
    assert.throws(
      () => attachments.parse(request(input.stream, headers)),
      UploadError,
    );
    assert.equal(input.reads, 0);
  }
  for (const name of ["content-type", "content-length", "ahp-content-sha256"]) {
    const req = request();
    req.headers.delete(name);
    assert.throws(() => attachments.parse(req), UploadError);
  }
  assert.throws(() => attachments.parse(request(null, {}, "GET")), UploadError);
});

test("long bodies reject the first oversized chunk and cancel upstream immediately", async () => {
  const input = source([bytes, bytes]);
  const reader = attachments
    .parse(request(input.stream, { "content-length": "3" }))
    .body.getReader();
  await assert.rejects(
    reader.read(),
    (error) => error instanceof UploadError && error.status === 400,
  );
  assert.equal(input.reads, 1);
});

test("short and wrong-hash bodies reject at EOF, never successful EOF", async () => {
  for (const headers of [
    { "content-length": "5" },
    { "ahp-content-sha256": "0".repeat(64) },
  ]) {
    const reader = attachments
      .parse(request(source([bytes]).stream, headers))
      .body.getReader();
    assert.deepEqual((await reader.read()).value, bytes);
    await assert.rejects(reader.read(), UploadError);
  }
  await assert.rejects(
    read(attachments.parse(request(null)).body),
    UploadError,
  );
});

test("cancellation propagates with no eager read, before and after one chunk", async () => {
  for (const started of [false, true]) {
    const input = source([bytes, bytes]);
    const reader = attachments.parse(request(input.stream)).body.getReader();
    if (started) await reader.read();
    await reader.cancel("storage aborted");
    assert.equal(input.cancelled, "storage aborted");
    assert.equal(input.reads, started ? 1 : 0);
  }
});

test("upstream read failures are sanitized and response validates whole descriptor", async () => {
  const body = new ReadableStream(
    {
      pull(c) {
        c.error(new Error("Bearer SECRET"));
      },
    },
    { highWaterMark: 0 },
  );
  await assert.rejects(
    read(attachments.parse(request(body)).body),
    (e) => e instanceof UploadError && !e.message.includes("SECRET"),
  );
  for (const descriptor of [
    { ref: "", size: 0, sha256: hash(bytes) },
    { ref: "x", size: -1, sha256: hash(bytes) },
    { ref: "x", size: 0, sha256: "X" },
    { ref: "x", size: 4, sha256: hash(bytes), extra: true },
  ])
    assert.throws(() => attachments.response(descriptor), UploadError);
});
