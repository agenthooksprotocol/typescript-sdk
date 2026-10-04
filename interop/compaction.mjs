// @ts-check
// Host execution is local; all hook composition crosses the public SDK boundary.
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
/** @type {typeof import("@agenthooksprotocol/sdk/client")} */
const { Hooks, auth } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
/** @type {typeof import("@agenthooksprotocol/sdk/server")} */
const { hooks, attachments } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);
/** @param {import("node:http").Server} server */
export function port(server) {
  const address = server.address();
  if (!address || typeof address === "string")
    throw Error("Missing TCP listener");
  return address.port;
}
export function compactionCapabilities(boundary, observeOnly = false) {
  return observeOnly
    ? { effects: [], modify: {} }
    : {
        effects: [
          "modify",
          "message",
          ...(boundary === "before" ? ["return", "deny"] : []),
        ],
        modify: {
          [boundary === "before" ? "instructions" : "summary"]: {
            replace: true,
            merge: false,
          },
        },
      };
}
/** @param {string} id @param {string} kind @param {string} text @param {string} role */
export function contentItem(id, kind, text, role) {
  return {
    id,
    kind,
    mediaType: "text/plain",
    role,
    body: new Blob([text]).stream(),
  };
}
export async function runCompaction(
  instructions,
  before = [],
  after = [],
  options = {},
) {
  const itemId = options.itemId ?? "summary-1";
  const state = {
    instructions,
    candidate: null,
    summary: null,
    bodies: {},
    messages: [],
    denied: false,
  };
  const seen = [],
    failures = [],
    uploads = new Map(),
    suppliers = new Map();
  let generated = false,
    applied = false,
    provenance = null;
  function summary(text) {
    const ref = "urn:ahp:compaction:utf8:" + Buffer.from(text).toString("hex");
    state.bodies[ref] = text;
    return { id: itemId, ref };
  }
  const rows = [
    ...before.map((row) => ({ ...row, boundary: "before" })),
    ...after.map((row) => ({ ...row, boundary: "after" })),
    ...(options.observers ?? []).map((row) => ({ ...row, boundary: "after" })),
  ];
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const request = new Request(endpoint + req.url, {
        method: req.method,
        headers: Object.fromEntries(
          Object.entries(req.headers)
            .filter(([, value]) => value !== undefined)
            .map(([key, value]) => [
              key,
              Array.isArray(value) ? value.join(", ") : value,
            ]),
        ),
        body: Buffer.concat(chunks),
      });
      let response;
      if (req.url === "/upload") {
        if (req.headers.authorization !== "Bearer fixture-upload") {
          res.writeHead(401).end();
          return;
        }
        const upload = attachments.parse(request);
        const bytes = Buffer.from(
          await new Response(upload.body).arrayBuffer(),
        );
        const ref =
          "urn:fixture:" + createHash("sha256").update(bytes).digest("hex");
        uploads.set(ref, bytes.toString());
        response = attachments.response({
          ref,
          size: bytes.length,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        });
      } else {
        if (req.headers.authorization !== "Bearer fixture-event") {
          res.writeHead(401).end();
          return;
        }
        const row = rows[Number(req.url.slice(1))];
        const invoke = async (message) => {
          const event = message.params.event;
          const snapshot = structuredClone(state);
          if (row.boundary === "before") {
            snapshot.instructions = uploads.get(event.instructions.body.ref);
            const candidate = message.params.state?.candidate;
            snapshot.candidate = candidate
              ? {
                  body: candidate.value,
                  supplier: suppliers.get(candidate.value),
                }
              : null;
          } else {
            snapshot.summary = summary(uploads.get(event.summary.body.ref));
            snapshot.bodies = structuredClone(state.bodies);
          }
          Object.assign(snapshot, {
            boundary: row.boundary,
            capabilities: compactionCapabilities(
              row.boundary,
              options.observeOnly && row.boundary === "after",
            ),
          });
          if (options.observeOnly && row.boundary === "after")
            Object.assign(snapshot, { applied: true, generated, provenance });
          seen.push(structuredClone(snapshot));
          const effects = await row.run(snapshot);
          // This fixture compacts plain text. JSON-valued canonical content is
          // valid elsewhere but is outside this application's text contract.
          if (
            row.bypass !== true &&
            Array.isArray(effects) &&
            effects.some(
              (effect) =>
                (effect.type === "modify" || effect.type === "return") &&
                typeof effect.value !== "string",
            )
          )
            throw Error("Text compaction requires text effects");
          for (const effect of Array.isArray(effects) ? effects : [])
            if (effect.type === "return")
              suppliers.set(effect.value, row.supplier);
          return message.method === "hooks/observe" ? undefined : { effects };
        };
        // Explicit adversarial fixture escape hatch, never a positive response path.
        if (row.bypass === true) {
          const message = await request.json();
          response = Response.json({
            jsonrpc: "2.0",
            id: message.id,
            result: { protocolVersion: "draft", ...(await invoke(message)) },
          });
        } else response = await hooks.handle(request, invoke);
      }
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      res.writeHead(500).end();
    }
  });
  await new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve(undefined)),
  );
  const endpoint = "http://127.0.0.1:" + port(server);
  const registrationRows = rows.length
    ? rows
    : [{ supplier: "unused", boundary: "session.end" }];
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: registrationRows.map((row, i) => ({
        id: "fixture.hook" + i,
        transport: { type: "http", url: endpoint + "/" + i },
        authentication: { type: "bearer", tokenEnv: "EVENT" },
        subscriptions: [
          {
            events: [
              rows.length ? "context.compact." + row.boundary : "session.end",
            ],
            mode:
              !rows.length || (options.observeOnly && row.boundary === "after")
                ? "observe"
                : "intercept",
            ...(!rows.length ||
            (options.observeOnly && row.boundary === "after")
              ? {}
              : {
                  failurePolicy: row.failurePolicy ?? "fail-closed",
                  timeoutMs: 15000,
                }),
            content: { default: "body" },
            upload: {
              timeoutMs: 15000,
              maxBytes: 1048576,
              endpoint: endpoint + "/upload",
              auth: { type: "bearer", tokenEnv: "UPLOAD" },
            },
          },
        ],
      })),
    },
    {
      source: "urn:ahp:compaction-host",
      capabilities: {
        "context.compact.before": compactionCapabilities("before"),
        "context.compact.after": compactionCapabilities("after"),
      },
      auth: auth({
        resolveEnvironmentVariable: (name) =>
          name === "UPLOAD" ? "fixture-upload" : "fixture-event",
      }),
    },
  );
  /**
   * @param {"before" | "after"} boundary
   * @param {import("@agenthooksprotocol/sdk/client").BoundaryInput<"context.compact.before" | "context.compact.after">} input
   */
  async function settle(boundary, input) {
    const result = await client.dispatch(
      boundary === "before"
        ? "context.compact.before"
        : "context.compact.after",
      input,
    );
    failures.push(
      ...result.errors.map((error) => ({
        boundary,
        supplier: rows[Number(error.backendId.split("hook")[1])].supplier,
      })),
    );
    const effects = result.response.result.effects;
    // Enact accepted effects on host-owned data: original body streams in the
    // effective event have transferred ownership and cannot be consumed again.
    for (const effect of effects) {
      if (effect.type === "modify") {
        if (boundary === "before") state.instructions = effect.value;
        else state.summary = summary(effect.value);
      } else if (effect.type === "message") state.messages.push(effect.text);
    }
    const candidate = effects.find((effect) => effect.type === "return");
    if (boundary === "before")
      state.candidate = candidate
        ? { body: candidate.value, supplier: suppliers.get(candidate.value) }
        : null;
    state.denied = effects.some((effect) => effect.type === "deny");
    return result;
  }
  const close = async () => {
    await client.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  };
  let detached = false;
  try {
    await settle("before", {
      id: "compaction:before",
      session: { id: "compaction" },
      trigger: "manual",
      items: [contentItem("context", "user", "conversation", "user")],
      instructions: contentItem(
        "instructions",
        "instructions",
        instructions,
        "system",
      ),
    });
    if (!state.denied) {
      const body =
        state.candidate?.body ??
        (options.generate ?? ((value) => "summary:" + value))(
          state.instructions,
        );
      generated = state.candidate === null;
      provenance = generated
        ? { kind: "generated" }
        : { kind: "supplied", supplier: state.candidate.supplier };
      state.summary = summary(body);
      const result = await settle("after", {
        id: "compaction:after",
        session: { id: "compaction" },
        parentEventId: "compaction:before",
        summary: contentItem(itemId, "summary", body, "assistant"),
        removed: [{ id: "context" }],
        execution: generated
          ? { status: "executed" }
          : { status: "skipped", reason: "supplied_result" },
      });
      applied = !state.denied;
      if (options.observeOnly) {
        detached = true;
        void result.observations.finally(close);
      }
    }
    return structuredClone({
      ...state,
      seen,
      failures,
      generated,
      provenance,
      applied,
    });
  } finally {
    if (!detached) await close();
  }
}
async function receive(request) {
  try {
    if (request.jsonrpc !== "2.0" || request.method !== "compaction/run")
      throw Error("invalid request");
    const p = request.params;
    const hooks = (boundary) =>
      (p[boundary] ?? []).map((row) => ({
        supplier: row.supplier,
        bypass: row.bypass === true,
        failurePolicy: row.failurePolicy ?? "fail-closed",
        run: () => {
          if (row.throw) throw Error("hook failed");
          return row.effects;
        },
      }));
    const result = await runCompaction(
      p.instructions,
      hooks("before"),
      hooks("after"),
      { itemId: p.itemId, observeOnly: p.observeOnly },
    );
    return { jsonrpc: "2.0", id: request.id ?? null, result };
  } catch {
    return {
      jsonrpc: "2.0",
      id: request.id ?? null,
      error: { code: -32602, message: "invalid request" },
    };
  }
}
const mode =
  process.argv[1] &&
  pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url
    ? process.argv[2]
    : undefined;
if (mode === "stdio") {
  for await (const line of createInterface({ input: process.stdin }))
    console.log(JSON.stringify(await receive(JSON.parse(line))));
} else if (mode === "server") {
  const server = createServer(async (req, res) => {
    if (
      req.headers.authorization !==
      "Bearer " + process.env.AHP_COMPACTION_TOKEN
    ) {
      res.writeHead(401);
      res.end();
      return;
    }
    let raw = "";
    for await (const chunk of req) raw += chunk;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(await receive(JSON.parse(raw))));
  });
  server.listen(0, "127.0.0.1", () =>
    console.log(
      JSON.stringify({ endpoint: "http://127.0.0.1:" + port(server) }),
    ),
  );
} else if (mode === "client") {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  const plan = JSON.parse(raw);
  let replies;
  if (plan.transport === "stdio") {
    const out = spawnSync(
      plan.command[0],
      [...plan.command.slice(1), "stdio"],
      {
        input: plan.requests.map((r) => JSON.stringify(r) + "\n").join(""),
        encoding: "utf8",
        timeout: 60000,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    if (out.status !== 0) throw Error(out.stderr || String(out.error));
    replies = out.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
  } else {
    replies = [];
    for (const request of plan.requests) {
      const res = await fetch(plan.endpoint, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + plan.token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(20000),
      });
      if (!res.ok) throw Error("HTTP " + res.status);
      replies.push(await res.json());
    }
  }
  console.log(JSON.stringify(replies));
} else if (mode !== undefined) throw Error("unknown mode");
