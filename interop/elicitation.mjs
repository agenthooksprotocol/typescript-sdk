// @ts-check
// Offline HTTP adapter. Inputs describe bytes to send, never expected semantics.
import { authorize } from "./security.mjs";
import {
  UploadStore,
  uploadBytes,
  createContentAdapter,
} from "./content-upload.mjs";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const {
  validateElicitationExchange,
  readSelectedElicitation,
  validateElicitationMode,
} = await import(require.resolve("agenthooksprotocol"));
const { Hooks, auth } = await import(
  require.resolve("agenthooksprotocol/client")
);
const { hooks } = await import(
  require.resolve("agenthooksprotocol/server")
);

// Raw probes explicitly opt out of client normalization and retain arbitrary bytes.
/**
 * @param {string} endpoint
 * @param {import("agenthooksprotocol/client").EventType[]} events
 * @param {"body" | "metadata" | "omit"} content
 * @returns {import("agenthooksprotocol/client").Registration}
 */
const registration = (endpoint, events, content = "body") => ({
  protocolVersion: "draft",
  hooks: [
    {
      id: "fixture.elicitation",
      transport: { type: "http", url: endpoint + "/hooks/intercept" },
      subscriptions: [
        {
          mode: "intercept",
          events,
          timeoutMs: 10000,
          failurePolicy: "fail-closed",
          content: { default: content },
          upload: {
            endpoint: endpoint + "/upload",
            timeoutMs: 10000,
            maxBytes: 4194304,
          },
        },
      ],
    },
  ],
});
/**
 * @param {string} source
 * @param {import("agenthooksprotocol/client").EventCapabilities} capabilities
 * @param {string} token
 * @param {string} [uploadToken]
 * @returns {import("agenthooksprotocol/client").HooksOptions}
 */
const clientOptions = (source, capabilities, token, uploadToken) => ({
  source,
  capabilities,
  auth: auth({
    authenticate: async (context, options) =>
      context.purpose === "upload"
        ? uploadToken
          ? { token: uploadToken }
          : auth.authenticate(context, options)
        : { token },
  }),
});
/**
 * @param {import("agenthooksprotocol/client").Hooks} client
 * @param {{ params: { event: ({ type: import("agenthooksprotocol/client").EventType, source: string } & import("agenthooksprotocol/client").BoundaryInput<import("agenthooksprotocol/client").EventType>) } }} message
 */
const dispatch = async (client, message) => {
  const { type, source, ...event } = message.params.event;
  const result = await client.dispatch(type, event);
  if (result.errors.length || (await result.observations).length)
    throw Error("SDK delivery rejected: " + JSON.stringify(result.errors));
  return result;
};

const { Ajv2020 } = require(require.resolve("ajv/dist/2020.js"));
const addFormats = require(require.resolve("ajv-formats"));
const input = async () => {
  let data = "";
  for await (const b of process.stdin) data += b;
  return JSON.parse(data);
};
if (process.argv[2] === "client") {
  const plan = await input(),
    results = [];
  for (const step of plan.steps) {
    const bytes = Buffer.from(step.bytes, "base64"),
      upload = step.path === "/upload";
    const headers = upload
      ? {
          ...(plan.uploadToken
            ? { Authorization: "Bearer " + plan.uploadToken }
            : {}),
          ...step.headers,
        }
      : { Authorization: "Bearer " + plan.token, ...step.headers };
    // A supplied mismatched Authorization header is an explicit adversarial
    // input, even in canonical runners that predate the bypass flag. Preserve
    // its bytes rather than silently replacing it with the positive credential.
    const suppliedHeaders = new Headers(step.headers);
    const uploadAuthProbe =
      upload &&
      suppliedHeaders.has("authorization") &&
      suppliedHeaders.get("authorization") !==
        (plan.uploadToken ? "Bearer " + plan.uploadToken : null);
    if (
      upload &&
      !uploadAuthProbe &&
      step.bypass !== true &&
      plan.bypass !== true
    ) {
      const result = await uploadBytes(
        {
          endpoint: plan.endpoint + step.path,
          auth: { type: "bearer", tokenEnv: "UPLOAD" },
        },
        bytes,
        { allowLoopback: true, env: { UPLOAD: plan.uploadToken } },
      );
      results.push({
        status: result.status,
        body: JSON.stringify(result.body),
      });
      continue;
    }
    if (
      step.path === "/hooks/intercept" &&
      step.bypass !== true &&
      plan.bypass !== true
    ) {
      const message = JSON.parse(bytes.toString("utf8"));
      if (message.id !== message.params.event.id)
        throw Error("ID mismatch; use bypass for malformed probes");
      const event = message.params.event;
      const selection =
        event.elicitation.request?.selection ??
        event.elicitation.result?.selection ??
        "omit";
      const config = registration(plan.endpoint, [event.type], selection);
      const adapter = createContentAdapter(plan.contentSources ?? [], fetch, [
        config.hooks[0].subscriptions[0].upload.endpoint,
      ]);
      // The shared helper hydrates content items in place; elicitation carries
      // those same items under named request/result slots rather than items.
      adapter.hydrate({
        items: [event.elicitation.request, event.elicitation.result].filter(
          Boolean,
        ),
      });
      const client = new Hooks(config, {
        ...clientOptions(
          event.source,
          { [event.type]: message.params.capabilities },
          plan.token,
          plan.uploadToken,
        ),
        fetch: adapter.fetch,
      });
      try {
        const result = await dispatch(client, message);
        results.push({
          status: 200,
          body: JSON.stringify(result.response),
          contentUploads: adapter.contentUploads,
        });
      } finally {
        await client.close();
      }
      continue;
    }
    const r = await fetch(plan.endpoint + step.path, {
        method: "POST",
        headers: uploadAuthProbe
          ? new Headers({
              ...Object.fromEntries(new Headers(headers)),
              authorization: suppliedHeaders.get("authorization"),
            })
          : headers,
        body: bytes,
        redirect: "error",
        signal: AbortSignal.timeout(10000),
      }),
      body = await r.text();
    if (upload && r.status === 201) {
      const descriptor = JSON.parse(body);
      if (
        r.headers.get("content-type")?.split(";")[0].trim() !==
          "application/json" ||
        !descriptor ||
        typeof descriptor.ref !== "string" ||
        !descriptor.ref ||
        descriptor.size !== bytes.length ||
        descriptor.sha256 !== createHash("sha256").update(bytes).digest("hex")
      )
        throw Error("Invalid upload confirmation");
    }
    results.push({ status: r.status, body });
  }
  console.log(JSON.stringify(results));
} else {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  for (const name of readdirSync(process.argv[3]).filter((x) =>
    x.endsWith(".schema.json"),
  ))
    ajv.addSchema(
      JSON.parse(readFileSync(process.argv[3] + "/" + name, "utf8")),
    );
  const validate = (name, value) => {
    if (name === "form-answer") {
      if (!ajv.compile(value.schema)(value.value))
        throw Error("Submitted form rejected");
      return;
    }
    const [file, def] = name.split("#");
    const fn = ajv.getSchema(
      "https://agenthooksprotocol.org/schemas/draft/" +
        file +
        ".schema.json" +
        (def ? "#/$defs/" + def : ""),
    );
    if (!fn || !fn(value)) throw Error("Schema rejected");
  };
  const token = process.env.AHP_ELICITATION_TOKEN,
    principal = process.argv[4];
  if (!token || !principal) throw Error("Missing auth");
  const store = new Map(),
    pending = new Map(),
    receipts = [];
  const hash = (b) => createHash("sha256").update(b).digest("hex");
  const resolve = (ref) => {
    validate("content-reference", ref);
    const b = store.get(ref.ref);
    if (!b || b.length !== ref.size || hash(b) !== ref.sha256)
      throw Error("Upload integrity");
    return b;
  };
  if (process.argv[2] === "check") {
    // Offline cases still traverse a real HTTP client/server boundary. Storage,
    // principal scope and MCP answer validation remain application-owned.
    let effects = [],
      target;
    const uploadToken = token + "-upload";
    const uploads = new UploadStore((authorization) =>
      authorization === `Bearer ${uploadToken}` ? principal : 401,
    );
    const receiver = createServer(async (req, res) => {
      try {
        if (req.url === "/upload") {
          const value = await uploads.receive(req);
          if (value.status === 201)
            store.set(value.ref, uploads.resolve(principal, value));
          res.writeHead(value.status, { "content-type": "application/json" });
          res.end(
            JSON.stringify(
              value.status === 201
                ? { ref: value.ref, size: value.size, sha256: value.sha256 }
                : {},
            ),
          );
          return;
        }
        if (!authorize(req, { mode: "bearer", token })) {
          res.writeHead(401).end();
          return;
        }
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const response = await hooks.handle(
          new Request("http://localhost/hooks/intercept", {
            method: "POST",
            headers: Object.fromEntries(
              Object.entries(req.headers)
                .filter(([, value]) => value !== undefined)
                .map(([key, value]) => [
                  key,
                  Array.isArray(value) ? value.join(", ") : value,
                ]),
            ),
            body: Buffer.concat(chunks),
          }),
          (message) => ({
            effects: message.params.event.type === target ? effects : [],
          }),
        );
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(new Uint8Array(await response.arrayBuffer()));
      } catch {
        res.writeHead(400).end();
      }
    });
    await new Promise((resolve) =>
      receiver.listen(0, "127.0.0.1", () => resolve(undefined)),
    );
    const address = receiver.address();
    if (!address || typeof address === "string")
      throw Error("Missing HTTP address");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const exercise = async (c) => {
      const messages = [c.request, c.result].filter(Boolean);
      const capabilities = Object.fromEntries(
        messages.map((message) => [
          message.params.event.type,
          message.params.capabilities,
        ]),
      );
      effects = c.op === "apply" ? c.effects : [];
      target = messages.at(-1).params.event.type;
      const selection =
        c.request.params.event.elicitation.request?.selection ?? "omit";
      const client = new Hooks(
        registration(
          endpoint,
          messages.map((message) => message.params.event.type),
          selection,
        ),
        clientOptions(
          c.request.params.event.source,
          capabilities,
          token,
          uploadToken,
        ),
      );
      try {
        const results = [];
        for (const message of messages) {
          const hydrated = structuredClone(message);
          for (const stage of ["request", "result"]) {
            const item = hydrated.params.event.elicitation[stage];
            if (item?.body) {
              const bytes = resolve(item.body);
              item.body = new ReadableStream({
                start(controller) {
                  controller.enqueue(bytes);
                  controller.close();
                },
              });
            }
          }
          results.push(await dispatch(client, hydrated));
        }
        return results;
      } finally {
        await client.close();
      }
    };
    // Presentation only: request bytes are host-owned fixture snapshots; result
    // bodies and decisions come from the actual accepted SDK boundary. No second
    // effect interpreter or semantic validator participates in acceptance.
    const presentAtomic = async (c, accepted) => {
      const acceptedEffects = accepted.response.result.effects;
      const result = c.result
        ? await new Response(accepted.event.elicitation.result.body).json()
        : acceptedEffects.some((effect) => effect.type === "deny")
          ? { action: "decline" }
          : acceptedEffects.find((effect) => effect.type === "return").value;
      return {
        request: JSON.parse(
          store
            .get(c.request.params.event.elicitation.request.body.ref)
            .toString("utf8"),
        ),
        result,
        provenance: {
          kind: "hook",
          authenticatedSource: principal,
          effects: acceptedEffects.map((effect) => effect.type),
        },
        externalCompletion: false,
      };
    };
    /** @type {{ accepted: boolean, summary?: unknown, inputUnchanged?: boolean }[]} */
    const outputs = [];
    for (const c of await input()) {
      const snapshot = JSON.stringify(c);
      store.clear();
      for (const u of c.uploads ?? [])
        store.set(u.ref, Buffer.from(u.bytes, "base64"));
      let sdkAccepted = false;
      try {
        const before = JSON.stringify(c);
        let summary;
        try {
          // Never label a positive composition case accepted without SDK delivery.
          const acceptedResults =
            c.op === "capability" ? null : await exercise(c);
          sdkAccepted = c.op === "apply";
          if (c.op === "capability") {
            const modes = validateElicitationMode(
              c.mode,
              c.capabilities,
              c.origin ?? "ahp",
            );
            effects = [];
            target = "user.elicitation.request";
            const client = new Hooks(
              registration(endpoint, ["user.elicitation.request"], "omit"),
              clientOptions(
                "urn:fixture:elicitation",
                {
                  "user.elicitation.request": {
                    effects: [],
                    elicitation: modes,
                  },
                },
                token,
              ),
            );
            try {
              const result = await client.dispatch("user.elicitation.request", {
                session: { id: "capability" },
                elicitation: { mode: c.mode, server: "fixture" },
              });
              if (result.errors.length || (await result.observations).length)
                throw Error("SDK capability delivery rejected");
            } finally {
              await client.close();
            }
          }
          summary =
            c.op === "capability"
              ? validateElicitationMode(
                  c.mode,
                  c.capabilities,
                  c.origin ?? "ahp",
                )
              : c.op === "apply"
                ? await presentAtomic(c, acceptedResults.at(-1))
                : validateElicitationExchange(
                    c.request,
                    c.result,
                    resolve,
                    validate,
                    principal,
                    c.effect,
                  );
        } finally {
          if (JSON.stringify(c) !== before) throw Error("Input mutated");
        }
        outputs.push({ accepted: true, summary });
      } catch (error) {
        // A presentation bug must fail the adapter, never disguise an accepted
        // SDK response as a successful negative conformance result.
        if (sdkAccepted) throw error;
        outputs.push({ accepted: false });
      }
      if (c.op === "apply")
        outputs[outputs.length - 1].inputUnchanged =
          JSON.stringify(c) === snapshot;
    }
    receiver.closeAllConnections();
    await new Promise((resolve) => receiver.close(resolve));
    console.log(JSON.stringify(outputs));
  } else {
    const uploads = new UploadStore((authorization) =>
      process.env.AHP_ELICITATION_UPLOAD_TOKEN &&
      authorization === `Bearer ${process.env.AHP_ELICITATION_UPLOAD_TOKEN}`
        ? principal
        : 401,
    );
    const server = createServer(async (req, res) => {
      if (req.url === "/upload") {
        const result = await uploads.receive(req);
        if (result.status === 201)
          store.set(result.ref, uploads.resolve(principal, result));
        res.writeHead(result.status, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            result.status === 201
              ? { ref: result.ref, size: result.size, sha256: result.sha256 }
              : {},
          ),
        );
        return;
      }
      if (!authorize(req, { mode: "bearer", token })) {
        res.writeHead(401);
        res.end();
        return;
      }
      try {
        const chunks = [];
        let size = 0;
        for await (const b of req) {
          size += b.length;
          if (size > 4194304) throw Error("Size limit");
          chunks.push(b);
        }
        const raw = Buffer.concat(chunks);
        if (req.url === "/receipts") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(receipts));
          return;
        }
        if (req.url !== "/hooks/intercept") throw Error("Unknown endpoint");
        let rejected = false;
        const response = await hooks.handle(
          new Request("http://localhost/hooks/intercept", {
            method: "POST",
            headers: Object.fromEntries(
              Object.entries(req.headers)
                .filter(([, value]) => value !== undefined)
                .map(([key, value]) => [
                  key,
                  Array.isArray(value) ? value.join(", ") : value,
                ]),
            ),
            body: raw,
          }),
          async (message) => {
            try {
              validate("intercept-request", message);
              const event = message.params.event,
                meta = event.elicitation;
              const parent =
                event.type === "user.elicitation.request"
                  ? event.id
                  : event.parentEventId;
              if (typeof parent !== "string") throw Error("Missing parent");
              const key = JSON.stringify([event.source, parent]);
              if (message.id !== event.id) throw Error("ID mismatch");
              let body, summary;
              if (event.type === "user.elicitation.request") {
                if (pending.has(key))
                  throw Error("Duplicate pending request identity");
                validateElicitationMode(meta.mode, { form: {}, url: {} });
                const payload = readSelectedElicitation(
                  meta,
                  "request",
                  resolve,
                  validate,
                );
                body =
                  payload === null
                    ? Buffer.alloc(0)
                    : resolve(meta.request.body);
                pending.set(key, message);
                summary =
                  payload === null
                    ? { selection: meta.request?.selection ?? "omit" }
                    : { request: payload };
              } else if (event.type === "user.elicitation.result") {
                summary = validateElicitationExchange(
                  pending.get(key),
                  message,
                  resolve,
                  validate,
                  principal,
                );
                body = meta.result?.body
                  ? resolve(meta.result.body)
                  : Buffer.alloc(0);
                pending.delete(key);
              } else throw Error("Not elicitation");
              receipts.push({
                message,
                bytes: body.toString("base64"),
                summary,
              });
              return { effects: [] };
            } catch (error) {
              rejected = true;
              throw error;
            }
          },
        );
        if (rejected) throw Error("Rejected elicitation");
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(new Uint8Array(await response.arrayBuffer()));
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "rejected" }));
      }
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string")
        throw Error("Missing HTTP address");
      console.log(
        JSON.stringify({ endpoint: "http://127.0.0.1:" + address.port }),
      );
    });
  }
}
