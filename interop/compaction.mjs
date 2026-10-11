// @ts-check
// Host execution is local; all hook composition crosses the public SDK boundary.
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
/** @type {typeof import("agenthooksprotocol/client")} */
const { Hooks, auth } = await import(
  require.resolve("agenthooksprotocol/client")
);
/** @type {typeof import("agenthooksprotocol/server")} */
const { hooks } = await import(
  require.resolve("agenthooksprotocol/server")
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
/** @param {string} text */
export function textParts(text, id = "text") {
  return [
    { id, kind: "text", mediaType: "text/plain", selection: "body", text },
  ];
}
/** @param {string} id @param {string} text @param {string} role */
export function contentItem(id, text, role) {
  return { id, role, parts: textParts(text) };
}
/** @param {{kind: string, text?: string}[]} parts */
export function inlineText(parts) {
  if (
    !Array.isArray(parts) ||
    parts.some((part) => part.kind !== "text" || typeof part.text !== "string")
  )
    throw Error("Text compaction requires inline text parts");
  return parts.map((part) => part.text).join("");
}
export async function runCompaction(
  instructions,
  before = [],
  after = [],
  options = {},
) {
  if (options.observeOnly && after.length)
    throw new TypeError("observeOnly requires explicit observers, not after interceptors");
  const itemId = options.itemId ?? "summary-1";
  const state = {
    instructions: typeof instructions === "string" ? textParts(instructions) : structuredClone(instructions),
    candidate: null,
    summary: null,
    messages: [],
    denied: false,
  };
  const seen = [],
    failures = [],
    suppliers = new Map();
  let generated = false,
    applied = false,
    provenance = null;
  function summary(text) {
    return typeof text === "string" ? textParts(text, itemId) : structuredClone(text);
  }
  const rows = [
    ...before.map((row) => ({ ...row, boundary: "before" })),
    ...after.map((row) => ({ ...row, boundary: "after" })),
    ...(options.observers ?? []).map((row) => ({ ...row, boundary: "after", observation: true })),
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
      {
        if (req.headers.authorization !== "Bearer fixture-event") {
          res.writeHead(401).end();
          return;
        }
        const row = rows[Number(req.url.slice(1))];
        const invoke = async (message) => {
          const event = message.params.event;
          const snapshot = structuredClone(state);
          if (row.boundary === "before") {
            snapshot.instructions = structuredClone(event.instructions);
            const candidate = message.params.state?.candidate;
            snapshot.candidate = candidate
              ? {
                  body: structuredClone(candidate.value),
                  supplier: suppliers.get(JSON.stringify(candidate.value)),
                }
              : null;
          } else {
            snapshot.summary = structuredClone(event.summary);
          }
          Object.assign(snapshot, {
            boundary: row.boundary,
            capabilities: compactionCapabilities(
              row.boundary,
              row.observation === true,
            ),
          });
          if (row.observation === true)
            Object.assign(snapshot, { applied: true, generated, provenance });
          seen.push(structuredClone(snapshot));
          const effects = await row.run(snapshot);
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
        // Attribute only an authenticated, valid emitted response. A rejected
        // compound must not overwrite the supplier of an equal earlier value.
        if (row.bypass !== true && response.ok) {
          const emitted = await response.clone().json().catch(() => null);
          for (const effect of emitted?.result?.effects ?? [])
            if (effect.type === "return")
              suppliers.set(JSON.stringify(effect.value), row.supplier);
        }
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
              !rows.length || (row.observation === true)
                ? "observe"
                : "intercept",
            ...(!rows.length ||
            (row.observation === true)
              ? {}
              : {
                  failurePolicy: row.failurePolicy ?? "fail-closed",
                  timeoutMs: 15000,
                }),
            content: { default: "body" },
          },
        ],
      })),
    },
    {
      source: "urn:ahp:compaction-host",
      capabilities: {
        "context.compact.before": compactionCapabilities("before"),
        "context.compact.after": {
          modes: options.observeOnly ? ["observe"] : ["intercept", "observe"],
          ...(!options.observeOnly ? { capabilities: compactionCapabilities("after") } : {}),
        },
        "session.end": { modes: ["observe"] },
      },
      auth: auth({
        resolveEnvironmentVariable: (name) =>
          name === "UPLOAD" ? "fixture-upload" : "fixture-event",
      }),
    },
  );
  /**
   * @param {"before" | "after"} boundary
   * @param {import("agenthooksprotocol/client").BoundaryInput<"context.compact.before" | "context.compact.after">} input
   */
  async function settle(boundary, input) {
    const result = await (boundary === "before"
      ? client.contextCompactBefore(/** @type {import("agenthooksprotocol/client").BoundaryInput<"context.compact.before">} */ (input))
      : client.contextCompactAfter(/** @type {import("agenthooksprotocol/client").BoundaryInput<"context.compact.after">} */ (input)));
    failures.push(
      ...result.diagnostics.filter(d => d.phase !== "observation").map((error) => ({
        boundary,
        supplier: rows[Number(error.backendId.split("hook")[1])].supplier,
      })),
    );
    const effects = result.effects;
    // Event modifications are already committed; residual effects are host actions.
    if (boundary === "before") state.instructions = structuredClone(result.event.instructions);
    else state.summary = structuredClone(result.event.summary);
    for (const effect of effects) {
      if (effect.type === "message") state.messages.push(effect.text);
    }
    const candidate = result.state.candidate;
    if (boundary === "before")
      state.candidate = candidate
        ? { body: candidate.value, supplier: suppliers.get(JSON.stringify(candidate.value)) }
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
      items: [contentItem("context", "conversation", "user")],
      instructions: structuredClone(state.instructions),
    });
    if (!state.denied) {
      const body =
        state.candidate?.body ??
        (options.generate ?? ((value) => "summary:" + value))(
          inlineText(state.instructions),
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
        summary: structuredClone(state.summary),
        removed: [{ id: "context" }],
        execution: generated
          ? { status: "executed" }
          : { status: "skipped", reason: "supplied_result" },
      });
      applied = !state.denied;
      if (options.observeOnly) {
        detached = true;
        await close();
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
