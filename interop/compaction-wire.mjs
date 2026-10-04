// @ts-check
// Actual canonical AHP request/response traffic; scheduling stays local.
import { authorize } from "./security.mjs";
import { UploadStore } from "./content-upload.mjs";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";
import { runCompaction, contentItem, port } from "./compaction.mjs";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
/** @type {typeof import("@agenthooksprotocol/sdk/client")} */
const { Hooks, auth } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
/** @type {typeof import("@agenthooksprotocol/sdk/server")} */
const { hooks } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);
const digest = (b) => createHash("sha256").update(b).digest("hex");
const location = (store, sub, ref) =>
  store + "/" + digest(Buffer.from(sub + "\0" + ref));
// These canonical matrix cases deliberately return unsupported compound effects.
// The explicit names (or action.bypass) are the only server-validation escape hatch.
const malformedResponses = new Set([
  "before-atomic-before-1",
  "after-atomic-after-1",
  "after-closed-after-0",
  "before-closed-before-0",
  "before-open-before-0",
  "after-open-after-0",
]);
async function receive(request, sub, config, store) {
  let bodies = {};
  const evaluate = (message) => {
    const event = message.params.event;
    const items = [
      ...(event.items ?? []),
      ...["instructions", "summary"]
        .filter((k) => k in event)
        .map((k) => event[k]),
    ];
    for (const item of items) {
      const ref = item.body,
        raw = readFileSync(location(store, sub, ref.ref));
      if (raw.length !== ref.size || digest(raw) !== ref.sha256)
        throw Error("integrity");
      bodies[item.id] = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    }
    const action = config[sub];
    return {
      effects:
        action.kind === "append"
          ? [
              {
                type: "modify",
                target: action.target,
                operation: "replace",
                value: bodies[event[action.target].id] + action.suffix,
              },
            ]
          : action.effects,
    };
  };
  let response;
  if (config[sub]?.bypass === true || malformedResponses.has(sub)) {
    // Invalid requests still pass the public receiver boundary; only the response bypasses it.
    const checked = await hooks.handle(
      new Request("http://fixture/hooks/intercept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      }),
      (message) => {
        evaluate(message);
        return { effects: [] };
      },
    );
    response = await checked.json();
    if (!response.error)
      response = {
        jsonrpc: "2.0",
        id: request.id,
        result: { protocolVersion: "draft", ...evaluate(request) },
      };
  } else {
    const handled = await hooks.handle(
      new Request("http://fixture/hooks/intercept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      }),
      evaluate,
    );
    response = await handled.json();
  }
  if (response.error?.code === -32004)
    response.error = { code: -32602, message: "Invalid compaction request" };
  if (!response.error)
    appendFileSync(
      store + "/receipts.jsonl",
      JSON.stringify({ subscription: sub, request, response, bodies }) + "\n",
    );
  return response;
}
async function exchange(plan, sub, name, snapshot) {
  const credentials = Object.hasOwn(plan.credentials ?? {}, sub)
    ? plan.credentials[sub]
    : undefined;
  if (
    !credentials ||
    typeof credentials.token !== "string" ||
    !credentials.token ||
    typeof credentials.uploadToken !== "string" ||
    !credentials.uploadToken
  )
    throw Error("Missing independent compaction credentials");
  const common = {
    id: name + ":" + snapshot.boundary,
    time: "2026-09-15T12:00:00Z",
    session: { id: name },
  };
  /** @type {import("@agenthooksprotocol/sdk/client").BoundaryInput<"context.compact.before" | "context.compact.after">} */
  const event =
    snapshot.boundary === "before"
      ? {
          ...common,
          trigger: "manual",
          items: [
            contentItem(name + ":context", "user", "conversation", "user"),
          ],
          instructions: contentItem(
            name + ":instructions",
            "instructions",
            snapshot.instructions,
            "system",
          ),
        }
      : {
          ...common,
          parentEventId: name + ":before",
          summary: contentItem(
            snapshot.summary.id,
            "summary",
            snapshot.bodies[snapshot.summary.ref],
            "assistant",
          ),
          removed: [{ id: name + ":context" }],
          execution:
            snapshot.candidate === null
              ? { status: "executed" }
              : { status: "skipped", reason: "supplied_result" },
        };
  const type =
    snapshot.boundary === "before"
      ? "context.compact.before"
      : "context.compact.after";
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "fixture.compaction",
          ...(plan.transport === "http"
            ? { authentication: { type: "bearer", tokenEnv: "EVENT" } }
            : {}),
          transport:
            plan.transport === "http"
              ? { type: "http", url: plan.endpoint + "/hooks/intercept" }
              : {
                  type: "stdio",
                  command: plan.receiverCommand[0],
                  args: [...plan.receiverCommand.slice(1), "stdio", sub],
                  lifecycle: "per_event",
                },
          subscriptions: [
            {
              events: [type],
              mode: "intercept",
              timeoutMs: 15000,
              failurePolicy: "fail-closed",
              content: { default: "body" },
              upload: {
                endpoint: plan.endpoint + "/upload",
                auth: { type: "bearer", tokenEnv: "UPLOAD" },
                timeoutMs: 15000,
                maxBytes: 1048576,
              },
            },
          ],
        },
      ],
    },
    {
      source: "urn:ahp:compaction-host",
      capabilities: { [type]: snapshot.capabilities },
      auth: auth({
        resolveEnvironmentVariable: (name) =>
          name === "UPLOAD" ? credentials.uploadToken : credentials.token,
      }),
    },
  );
  try {
    const result = await client.dispatch(type, event);
    // Receipts are independent receiver evidence, not reconstructed SDK envelopes.
    // The fixture command's final arguments are schema, shared store, and config.
    const store = plan.receiverCommand.at(-2);
    const receipt = readFileSync(store + "/receipts.jsonl", "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .findLast(
        (row) => row.subscription === sub && row.request.id === event.id,
      );
    if (!receipt) throw Error("Missing receiver receipt");
    return {
      effects: result.response.result.effects,
      failed: result.errors.length > 0,
      wire: {
        subscription: sub,
        request: receipt.request,
        response: receipt.response,
      },
    };
  } finally {
    await client.close();
  }
}

let args = process.argv.slice(2);
if (!["host", "server", "stdio", "call"].includes(args[0]))
  args = [args[3], ...args.slice(0, 3), ...args.slice(4)];
const mode = args[0];
if (mode === "host" || mode === "call") {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  const input = JSON.parse(raw);
  if (mode === "call") {
    console.log(
      JSON.stringify(
        await exchange(input.plan, input.sub, input.name, input.snapshot),
      ),
    );
  } else {
    const plan = input,
      out = [];
    for (const row of plan.cases) {
      const trace = [];
      const hooks = (boundary) =>
        row[boundary].map((h) => ({
          supplier: h.supplier,
          failurePolicy: h.failurePolicy,
          run: async (snapshot) => {
            const r = await exchange(plan, h.supplier, row.name, snapshot);
            trace.push(r.wire);
            if (r.failed) throw Error("Rejected compaction response");
            return r.effects;
          },
        }));
      const result = await runCompaction(
          "base",
          hooks("before"),
          hooks("after"),
          {
            itemId: row.name + ":summary",
          },
        ),
        downstream = [];
      if (result.applied) downstream.push(result.bodies[result.summary.ref]);
      out.push({ name: row.name, result, trace, downstream });
    }
    console.log(JSON.stringify(out));
  }
} else {
  const [, schema, store, configPath, sub] = args,
    config = JSON.parse(readFileSync(configPath, "utf8"));
  if (mode === "stdio")
    for await (const line of createInterface({ input: process.stdin }))
      console.log(
        JSON.stringify(await receive(JSON.parse(line), sub, config, store)),
      );
  else if (mode === "server") {
    const eventTokens = JSON.parse(process.env.AHP_COMPACTION_TOKENS ?? "{}");
    const uploadTokens = JSON.parse(
      process.env.AHP_COMPACTION_UPLOAD_TOKENS ?? "{}",
    );
    const scopeFor = (tokens, authorization) => {
      if (
        typeof authorization !== "string" ||
        !authorization.startsWith("Bearer ")
      )
        return undefined;
      const token = authorization.slice(7),
        scope = Object.hasOwn(tokens, token) ? tokens[token] : undefined;
      return typeof scope === "string" && Object.hasOwn(config, scope)
        ? scope
        : undefined;
    };
    const uploads = new UploadStore(
      (authorization) => scopeFor(uploadTokens, authorization) ?? 401,
    );
    const server = createServer(async (req, res) => {
      try {
        if (req.url === "/upload") {
          const result = await uploads.receive(req);
          if (result.status === 201) {
            const scope = scopeFor(uploadTokens, req.headers.authorization);
            writeFileSync(
              location(store, scope, result.ref),
              uploads.resolve(scope, result),
            );
          }
          res.writeHead(result.status, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify(
              result.status === 201
                ? { ref: result.ref, size: result.size, sha256: result.sha256 }
                : {},
            ),
          );
          return;
        }
        const sub = scopeFor(eventTokens, req.headers.authorization);
        if (
          sub === undefined ||
          !authorize(req, {
            mode: "bearer",
            token: req.headers.authorization.slice(7),
          })
        ) {
          res.writeHead(401);
          res.end();
          return;
        }
        if (req.method !== "POST" || req.url !== "/hooks/intercept") {
          res.writeHead(404);
          res.end();
          return;
        }
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const raw = Buffer.concat(chunks);
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify(
            await receive(JSON.parse(raw.toString()), sub, config, store),
          ),
        );
      } catch {
        res.writeHead(400);
        res.end();
      }
    });
    server.listen(0, "127.0.0.1", () =>
      console.log(
        JSON.stringify({
          endpoint: "http://127.0.0.1:" + port(server),
        }),
      ),
    );
  } else throw Error("unknown mode");
}
