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
  body: { ref: descriptor.ref },
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
      { ref: confirmed.ref },
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
      { ref: descriptor.ref },
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

test("atomic elicitation preserves absent, empty, and other-mode AHP grants", async () => {
  const answerBytes = Buffer.from(
    JSON.stringify({ action: "accept", content: {} }),
  );
  const answerDescriptor = {
    ref: "urn:test:answer",
    size: answerBytes.length,
    sha256: createHash("sha256").update(answerBytes).digest("hex"),
  };
  const rows = [];
  for (const effect of [
    { type: "return", value: { action: "decline" } },
    { type: "deny", reason: "Policy" },
    { type: "modify", target: "content", operation: "replace", value: {} },
  ]) {
    for (const grant of [null, {}, { url: {} }, { form: {} }]) {
      const request = message();
      request.params.event.session = { id: "atomic-mode" };
      const result = structuredClone(request);
      result.id = result.params.event.id = "result";
      result.params.event.parentEventId = request.id;
      result.params.event.type = "user.elicitation.result";
      result.params.event.elicitation = {
        mode: "form",
        server: "test",
        action: "accept",
        result: { ...item(), id: "answer", body: { ref: answerDescriptor.ref } },
      };
      const boundary = effect.type === "modify" ? result : request;
      boundary.params.capabilities = {
        effects: [effect.type],
        ...(effect.type === "modify"
          ? { modify: { content: { replace: true, merge: false } } }
          : {}),
        ...(grant === null ? {} : { elicitation: grant }),
      };
      rows.push({
        op: "apply",
        request,
        result: effect.type === "modify" ? result : null,
        effects: [effect],
        uploads: [
          { ref: descriptor.ref, bytes: bytes.toString("base64") },
          { ref: answerDescriptor.ref, bytes: answerBytes.toString("base64") },
        ],
      });
    }
  }
  const result = await run(rows, [
    "check",
    "../agent-hooks-protocol/schema/draft",
    "test-principal",
  ]);
  assert.equal(result.code, 0, result.stderr);
  const outputs = JSON.parse(result.stdout);
  assert.deepEqual(
    outputs.map((row) => row.accepted),
    [
      false,
      false,
      false,
      true,
      false,
      false,
      false,
      true,
      false,
      false,
      false,
      true,
    ],
  );
  assert.ok(outputs.every((row) => row.inputUnchanged));
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

test("actual elicitation endpoint rejects forbidden ref metadata before resolving stored bytes", { timeout: 15000 }, async () => {
  const child = spawn(process.execPath, ["interop/elicitation.mjs", "server", "../agent-hooks-protocol/schema/draft", "test-principal"], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, AHP_ELICITATION_TOKEN: "event-secret", AHP_ELICITATION_UPLOAD_TOKEN: "upload-secret" },
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    const endpoint = await new Promise((resolve, reject) => {
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk;
        if (output.includes("\n")) resolve(JSON.parse(output.split("\n")[0]).endpoint);
      });
      child.once("error", reject);
      child.once("exit", () => reject(Error(stderr || "Receiver exited before ready")));
    });
    const uploaded = await fetch(endpoint + "/upload", {
      method: "POST",
      headers: { authorization: "Bearer upload-secret", "content-type": "application/octet-stream", "content-length": String(bytes.length), "ahp-content-sha256": descriptor.sha256 },
      body: bytes,
    });
    assert.equal(uploaded.status, 201);
    const receipt = await uploaded.json();
    const send = (wire) => fetch(endpoint + "/hooks/intercept", {
      method: "POST", headers: { authorization: "Bearer event-secret", "content-type": "application/json" }, body: JSON.stringify(wire),
    });
    for (const extra of [{ sha256: "0".repeat(64) }, { sha256: null }, { size: bytes.length }, { size: null }]) {
      const wire = message();
      wire.params.event.elicitation.request.body = { ref: receipt.ref, ...extra };
      const rejected = await send(wire);
      assert.equal(rejected.status, 400);
      await rejected.arrayBuffer();
    }
    const receipts = await fetch(endpoint + "/receipts", { headers: { authorization: "Bearer event-secret" } });
    assert.deepEqual(await receipts.json(), []);
    const valid = message();
    valid.params.event.elicitation.request.body = { ref: receipt.ref };
    const accepted = await send(valid);
    assert.equal(accepted.status, 200);
    assert.deepEqual((await accepted.json()).result.effects, []);
  } finally {
    child.kill();
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else child.once("exit", resolve);
    });
  }
});
