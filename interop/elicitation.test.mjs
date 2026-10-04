import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const bytes = Buffer.from(
  JSON.stringify({
    message: "Name?",
    requestedSchema: { type: "object", properties: {} },
  }),
);
const descriptor = {
  ref: "urn:test:original",
  size: bytes.length,
  sha256: createHash("sha256").update(bytes).digest("hex"),
};
const item = () => ({
  id: "request",
  kind: "text",
  role: "user",
  mediaType: "application/json",
  selection: "body",
  body: { ...descriptor },
});
function message() {
  return {
    jsonrpc: "2.0",
    id: "request",
    method: "hooks/intercept",
    params: {
      protocolVersion: "draft",
      capabilities: { effects: [], elicitation: { form: {} } },
      event: {
        id: "request",
        source: "urn:test:elicitation",
        type: "user.elicitation.request",
        time: "2026-01-01T00:00:00Z",
        elicitation: { mode: "form", server: "test", request: item() },
      },
    },
  };
}
function run(plan, args = ["client"]) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["interop/elicitation.mjs", ...args],
      {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, AHP_ELICITATION_TOKEN: "test-token" },
      },
    );
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(plan));
  });
}

test("elicitation sender hydrates exact sources and reports real upload confirmations; bypass stays raw", async () => {
  const uploads = [],
    messages = [];
  const confirmed = { ...descriptor, ref: "urn:test:confirmed" };
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    res.setHeader("content-type", "application/json");
    if (req.url === "/upload") {
      uploads.push(body);
      assert.equal(req.headers.authorization, "Bearer upload-secret");
      res.writeHead(201).end(JSON.stringify(confirmed));
    } else if (req.url === "/hooks/intercept") {
      const incoming = JSON.parse(body);
      messages.push(incoming);
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: incoming.id,
          result: { protocolVersion: "draft", effects: [] },
        }),
      );
    } else {
      res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const plan = {
    endpoint: `http://127.0.0.1:${server.address().port}`,
    token: "event-secret",
    uploadToken: "upload-secret",
    contentSources: [{ descriptor, bytes: bytes.toString("base64") }],
    steps: [
      {
        path: "/hooks/intercept",
        bytes: Buffer.from(JSON.stringify(message())).toString("base64"),
      },
    ],
  };
  try {
    const positive = await run(plan);
    assert.equal(positive.code, 0, positive.stderr);
    assert.deepEqual(JSON.parse(positive.stdout)[0].contentUploads, [
      { sourceRef: descriptor.ref, descriptor: confirmed },
    ]);
    assert.deepEqual(uploads, [bytes]);
    assert.deepEqual(
      messages[0].params.event.elicitation.request.body,
      confirmed,
    );
    const raw = await run({
      ...plan,
      contentSources: [],
      steps: [{ ...plan.steps[0], bypass: true }],
    });
    assert.equal(raw.code, 0, raw.stderr);
    assert.equal(JSON.parse(raw.stdout)[0].contentUploads, undefined);
    assert.deepEqual(
      messages[1].params.event.elicitation.request.body,
      descriptor,
    );
    assert.equal(uploads.length, 1);
    for (const contentSources of [
      [],
      [
        {
          descriptor: { ...descriptor, size: descriptor.size + 1 },
          bytes: bytes.toString("base64"),
        },
      ],
      [{ descriptor, bytes: Buffer.from("wrong bytes").toString("base64") }],
    ]) {
      const invalid = await run({ ...plan, contentSources });
      assert.notEqual(invalid.code, 0);
      assert.equal(messages.length, 2);
      assert.equal(uploads.length, 1);
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("atomic elicitation presentation uses SDK effects and never disguises presentation failure as rejection", async () => {
  const request = message();
  request.params.capabilities.effects = ["return", "deny"];
  const base = {
    op: "apply",
    request,
    result: null,
    uploads: [{ ref: descriptor.ref, bytes: bytes.toString("base64") }],
  };
  const returned = { type: "return", value: { action: "decline" } };
  const denied = { type: "deny", reason: "Policy" };
  const args = [
    "check",
    "../agent-hooks-protocol/schema/draft",
    "test-principal",
  ];
  const result = await run(
    [
      { ...base, effects: [returned] },
      { ...base, effects: [denied] },
      { ...base, effects: [returned, denied] },
    ],
    args,
  );
  assert.equal(result.code, 0, result.stderr);
  const rows = JSON.parse(result.stdout);
  assert.deepEqual(
    rows.map((row) => row.accepted),
    [true, true, false],
  );
  assert.ok(rows.every((row) => row.inputUnchanged));
  for (const row of rows.slice(0, 2))
    assert.deepEqual(row.summary.result, { action: "decline" });
  assert.deepEqual(rows[0].summary.provenance, {
    kind: "hook",
    authenticatedSource: "test-principal",
    effects: ["return"],
  });
  assert.equal(rows[2].summary, undefined);
  // No terminal means there is nothing for this atomic fixture formatter to
  // present. SDK acceptance must remain visible as an adapter failure, not false.
  const malformedPresentation = await run([{ ...base, effects: [] }], args);
  assert.notEqual(malformedPresentation.code, 0);
  assert.equal(malformedPresentation.stdout, "");
});
