import { spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import { runCompaction, compactionCapabilities, inlineText, textParts } from "./compaction.mjs";
const modify = (target, value) => ({
  type: "modify",
  target,
  operation: "replace",
  value: textParts(value),
});
const hook = (supplier, run, failurePolicy = "fail-closed") => ({
  supplier,
  run,
  failurePolicy,
});
test("compaction callbacks and generator see accepted inputs and results", async () => {
  const generated = [];
  const r = await runCompaction(
    "old",
    [
      hook("edit", (snapshot) => {
        snapshot.instructions = "leak";
        return [modify("instructions", "new")];
      }),
    ],
    [
      hook("redact", (snapshot) => [
        modify("summary", inlineText(snapshot.summary) + ":redacted"),
      ]),
      hook("watch", (snapshot) => {
        assert.equal(
          inlineText(snapshot.summary),
          "generated:new:redacted",
        );
        return [];
      }),
    ],
    {
      generate: (instructions) => {
        generated.push(instructions);
        return "generated:" + instructions;
      },
    },
  );
  assert.deepEqual(generated, ["new"]);
  assert.deepEqual(r.failures, []);
  assert.equal(r.applied, true);
  assert.equal(r.seen[1].summary[0].id, "summary-1");
  assert.equal(r.summary[0].id, "text");
  assert.notEqual(inlineText(r.seen[1].summary), inlineText(r.summary));
  assert.equal(inlineText(r.seen[1].summary), "generated:new");
});
test("failed compound preserves candidate, messages and input; supplied summary still redacted", async () => {
  const r = await runCompaction(
    "old",
    [
      hook("cache", () => [{ type: "return", value: "cached" }]),
      hook(
        "bad",
        () => [
          modify("instructions", "leak"),
          { type: "message", text: "leak" },
          modify("summary", "wrong"),
        ],
        "fail-open",
      ),
    ],
    [hook("redact", () => [modify("summary", "safe")])],
    {
      generate: () => {
        throw Error("generator must not run");
      },
    },
  );
  assert.equal(inlineText(r.instructions), "old");
  assert.deepEqual(r.messages, []);
  assert.equal(inlineText(r.summary), "safe");
  assert.deepEqual(r.provenance, { kind: "supplied", supplier: "cache" });
  assert.equal(r.applied, true);
});
test("after failure prevents delivery; observation does not advertise control", async () => {
  const r = await runCompaction(
    "old",
    [],
    [
      hook("bad", () => [
        modify("summary", "leak"),
        modify("instructions", "wrong"),
      ]),
    ],
  );
  assert.equal(r.applied, false);
  assert.equal(inlineText(r.summary).includes("leak"), false);
  assert.deepEqual(compactionCapabilities("after", true), {
    effects: [],
    modify: {},
  });
});

test(
  "blocked observers complete within compaction without changing settled content",
  { timeout: 5000 },
  async () => {
    let start, release, finish, failed;
    const entered = new Promise((resolve) => {
      start = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const finished = new Promise((resolve) => {
      finish = resolve;
    });
    const rejected = new Promise((resolve) => {
      failed = resolve;
    });
    let snapshot;
    let returned = false;
    try {
      const work = runCompaction("base", [], [], {
        observeOnly: true,
        observers: [
          {
            supplier: "slow",
            run: async (s) => {
              snapshot = s;
              start();
              await gate;
              s.bodies = {};
              s.instructions = "mutation";
              finish();
              return [modify("summary", "forbidden")];
            },
          },
          {
            supplier: "throw",
            run: async () => {
              failed();
              throw Error("observer rejected");
            },
          },
        ],
      }).then((result) => {
        returned = true;
        return result;
      });
      await entered;
      await rejected;
      assert.equal(
        returned,
        false,
        "compaction returned while an observer was blocked",
      );
      assert.equal(snapshot.applied, true);
      assert.deepEqual(snapshot.capabilities, { effects: [], modify: {} });
      release();
      const r = await work;
      await finished;
      const downstream = r.applied ? [inlineText(r.summary)] : [];
      assert.deepEqual(downstream, ["summary:base"]);
      assert.deepEqual(r.failures, []);
      const saved = structuredClone(r);
      snapshot.summary[0].text = "late mutation";
      snapshot.summary = "forbidden";
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(r, saved);
    } finally {
      release();
    }
  },
);

test(
  "observe-only legacy after callbacks complete inline without applying effects",
  { timeout: 5000 },
  async () => {
    let returned = false,
      snapshot,
      notify,
      release;
    const entered = new Promise((resolve) => {
      notify = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    try {
      const work = runCompaction(
        "base",
        [],
        [
          hook("legacy", async (value) => {
            snapshot = value;
            notify();
            await gate;
            value.summary[0].text = "mutation";
            return [modify("summary", "forbidden")];
          }),
        ],
        { observeOnly: true },
      ).then((result) => {
        returned = true;
        return result;
      });
      await entered;
      assert.equal(
        returned,
        false,
        "compaction returned before its callback completed",
      );
      assert.equal(snapshot.applied, true);
      assert.deepEqual(snapshot.capabilities, { effects: [], modify: {} });
      release();
      const r = await work;
      const downstream = r.applied ? [inlineText(r.summary)] : [];
      assert.deepEqual(downstream, ["summary:base"]);
      assert.deepEqual(r.failures, []);
      assert.equal(inlineText(r.summary), "summary:base");
      const saved = structuredClone(r);
      snapshot.summary = "late mutation";
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(r, saved);
    } finally {
      release();
    }
  },
);

test(
  "wire receiver scopes attachment uploads and inline-text events by independent credentials, never correlation IDs",
  { timeout: 15000 },
  async () => {
    const { spawn } = await import("node:child_process");
    const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { createInterface } = await import("node:readline");
    const { createHash } = await import("node:crypto");
    const directory = mkdtempSync(join(tmpdir(), "ahp-compaction-test-"));
    const configPath = join(directory, "subscriptions.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        one: { kind: "append", target: "instructions", suffix: ":one" },
        two: { kind: "append", target: "instructions", suffix: ":two" },
      }),
    );
    const child = spawn(
      process.execPath,
      [
        new URL("./compaction-wire.mjs", import.meta.url).pathname,
        "server",
        "unused-schema",
        directory,
        configPath,
      ],
      {
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          AHP_COMPACTION_TOKENS: JSON.stringify({
            "event-one": "one",
            "event-two": "two",
          }),
          AHP_COMPACTION_UPLOAD_TOKENS: JSON.stringify({
            "upload-one": "one",
            "upload-two": "two",
          }),
        },
      },
    );
    child.stderr.resume();
    const exited = new Promise((resolve) => child.once("exit", resolve));
    const lines = createInterface({ input: child.stdout });
    try {
      const { endpoint } = await new Promise((resolve, reject) => {
        lines.once("line", (line) => {
          try {
            resolve(JSON.parse(line));
          } catch (error) {
            reject(error);
          }
        });
        child.once("error", reject);
        child.once("exit", () =>
          reject(Error("Receiver exited before readiness")),
        );
      });
      const bytes = Buffer.from("base"),
        sha256 = createHash("sha256").update(bytes).digest("hex");
      const upload = (token) =>
        fetch(endpoint + "/upload", {
          method: "POST",
          headers: {
            authorization: "Bearer " + token,
            "content-type": "application/octet-stream",
            "content-length": String(bytes.length),
            "ahp-content-sha256": sha256,
          },
          body: bytes,
        });
      for (const token of ["event-one", "unknown"]) {
        const denied = await upload(token);
        assert.equal(denied.status, 401);
        await denied.arrayBuffer();
      }
      const uploaded = await upload("upload-one");
      assert.equal(uploaded.status, 201);
      const descriptor = await uploaded.json();
      assert.deepEqual(Object.keys(descriptor).sort(), [
        "ref",
        "sha256",
        "size",
      ]);
      assert.equal(descriptor.sha256, sha256);
      const event = {
        id: "same-correlation",
        source: "urn:ahp:compaction-test",
        time: "2026-09-15T12:00:00Z",
        session: { id: "test" },
        type: "context.compact.before",
        trigger: "manual",
        items: [],
        instructions: textParts("base"),
      };
      const request = {
        jsonrpc: "2.0",
        id: event.id,
        method: "hooks/intercept",
        params: {
          protocolVersion: "draft",
          event,
          capabilities: compactionCapabilities("before"),
        },
      };
      const send = (token, wire = request) =>
        fetch(endpoint + "/hooks/intercept", {
          method: "POST",
          headers: {
            authorization: "Bearer " + token,
            "content-type": "application/json",
          },
          body: JSON.stringify(wire),
        });
      for (const token of ["upload-one", "same-correlation"]) {
        const denied = await send(token);
        assert.equal(denied.status, 401);
        await denied.arrayBuffer();
      }
      const accepted = await (await send("event-one")).json();
      assert.equal(inlineText(accepted.result.effects[0].value), "base:one");
      const legacy = structuredClone(request);
      legacy.params.event.instructions = {
        id: "instructions",
        kind: "instructions",
        mediaType: "text/plain",
        role: "system",
        selection: "body",
        body: { ref: descriptor.ref },
      };
      const rejectedLegacy = await (await send("event-one", legacy)).json();
      assert.equal(rejectedLegacy.error.code, -32602);
      const crossScope = await (await send("event-two")).json();
      assert.equal(inlineText(crossScope.result.effects[0].value), "base:two");
      const second = await upload("upload-two");
      assert.equal(second.status, 201);
      const secondDescriptor = await second.json();
      assert.notEqual(secondDescriptor.ref, descriptor.ref);
      const other = structuredClone(request);
      other.params.event.instructions = textParts("base");
      const scoped = await (await send("event-two", other)).json();
      assert.equal(inlineText(scoped.result.effects[0].value), "base:two");
      other.id = "unrelated-id";
      other.params.event.id = other.id;
      const correlated = await (await send("event-two", other)).json();
      assert.equal(correlated.id, other.id);
      assert.equal(inlineText(correlated.result.effects[0].value), "base:two");
    } finally {
      lines.close();
      child.kill();
      await exited;
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test("wire sender refuses plans missing independent upload credentials", () => {
  const result = spawnSync(
    process.execPath,
    [new URL("./compaction-wire.mjs", import.meta.url).pathname, "call"],
    {
      input: JSON.stringify({
        plan: { credentials: { one: { token: "event-only" } } },
        sub: "one",
        name: "case",
        snapshot: {},
      }),
      encoding: "utf8",
      timeout: 5000,
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Missing independent compaction credentials/);
});

test("empty hook plans still use a valid public Hooks registration", async () => {
  const result = await runCompaction("base");
  assert.equal(result.applied, true);
  assert.equal(inlineText(result.summary), "summary:base");
  assert.deepEqual(result.seen, []);
  assert.deepEqual(result.failures, []);
});

test("explicit malformed-response bypass exercises SDK rejection", async () => {
  const result = await runCompaction("base", [
    {
      supplier: "malformed",
      failurePolicy: "fail-open",
      bypass: true,
      run: () => ({ type: "deny" }),
    },
  ]);
  assert.deepEqual(result.failures, [
    { boundary: "before", supplier: "malformed" },
  ]);
  assert.equal(result.applied, true);
  assert.equal(inlineText(result.summary), "summary:base");
});


test("compaction composes all inline text parts before generation", async () => {
  const result = await runCompaction("base", [
    hook("parts", () => [{
      type: "modify",
      target: "instructions",
      operation: "replace",
      value: [
        { ...textParts("first")[0], id: "first" },
        { ...textParts(":second")[0], id: "second" },
      ],
    }]),
    hook("watch", (snapshot) => {
      assert.equal(inlineText(snapshot.instructions), "first:second");
      return [];
    }),
  ]);
  assert.deepEqual(result.failures, []);
  assert.equal(inlineText(result.summary), "summary:first:second");
});


test("canonical instruction identities preserve a supplied candidate across a no-change edit", async () => {
  const instructions = [{ ...textParts("base")[0], id: "fixture:text" }];
  const result = await runCompaction(instructions, [
    hook("cache", () => [{ type: "return", value: "cached" }]),
    hook("same", snapshot => [{ type: "modify", target: "instructions", operation: "replace", value: structuredClone(snapshot.instructions) }]),
  ], [hook("watch", snapshot => {
    assert.ok(Array.isArray(snapshot.instructions));
    assert.ok(Array.isArray(snapshot.summary));
    assert.equal(snapshot.instructions[0].id, "fixture:text");
    return [];
  })], { generate() { throw Error("same-input modification must preserve supplied candidate"); } });
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.instructions, instructions);
  assert.equal(inlineText(result.summary), "cached");
  assert.equal(result.generated, false);
  assert.deepEqual(result.provenance, { kind: "supplied", supplier: "cache" });
});


test("rejected equal-valued return cannot overwrite the accepted supplier", async () => {
  const result = await runCompaction(textParts("base"), [
    hook("cache", () => [{ type: "return", value: "cached" }]),
    hook("rejected", () => [{ type: "return", value: "cached" }, modify("summary", "leak")], "fail-open"),
  ]);
  assert.equal(result.failures.length, 1);
  assert.equal(result.generated, false);
  assert.equal(inlineText(result.summary), "cached");
  assert.deepEqual(result.provenance, { kind: "supplied", supplier: "cache" });
});

test("multipart supplied summaries retain canonical order, identities, and supplier", async () => {
  const supplied = [{ ...textParts("first")[0], id: "supplied:first" }, { ...textParts(":second")[0], id: "supplied:second" }];
  const result = await runCompaction(textParts("base"), [
    hook("cache", () => [{ type: "return", value: supplied }]),
    hook("watch", snapshot => {
      assert.deepEqual(snapshot.candidate.body, supplied);
      assert.equal(snapshot.candidate.supplier, "cache");
      return [];
    }),
  ], [hook("after", snapshot => { assert.deepEqual(snapshot.summary, supplied); return []; })],
  { generate() { throw Error("supplied canonical summary must skip generation"); } });
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.summary, supplied);
  assert.deepEqual(result.provenance, { kind: "supplied", supplier: "cache" });
});
