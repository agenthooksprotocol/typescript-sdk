// @ts-check
import { UploadStore, authorizeUpload } from "./content-upload.mjs";
import { TaskLineage } from "./task-lineage.mjs";
import { createServer } from "node:http";
import { createServer as tlsServer } from "node:https";
import { readFileSync } from "node:fs";
import { sdkDraft, sdkServer, sdkStdio } from "./common.mjs";
const {
  validateInterceptRequest,
  validateInterceptResponse,
  validateCapabilities,
  validateCapabilitiesRequest,
  validateCapabilitiesResponse,
} = sdkDraft;
import { authorize } from "./security.mjs";
import {
  config,
  scenarios,
  atomic,
  body,
  reply,
  listen,
  discovery,
  manifest,
} from "./common.mjs";
const cfg = await config(),
  rows = await scenarios(cfg.scenarioFile),
  receipts = [],
  barriers = new Map(),
  released = new Set();
const uploads = new UploadStore((authorization) =>
  authorizeUpload(cfg, authorization),
);
const lineage = new TaskLineage();
let tlsRejections = 0,
  tlsClientErrors = 0;
const tlsClientErrorCodes = {};
const tlsRejectionCodes = {};
if (!validateCapabilities(discovery).ok)
  throw Error("Invalid discovery capabilities");
// All ordinary messages use the same public Web handler on either transport.
const handleRequest = (request) =>
  sdkServer.hooks.handle(request, async (message) => {
    if (message.method === "hooks/capabilities") return { manifest };
    if (message.method === "hooks/observe") return;
    const decoded = validateInterceptResponse(await fixtureResult(message));
    if (!decoded.ok) throw Error("Invalid fixture result");
    const { protocolVersion, ...fields } = decoded.value.result;
    return fields;
  });
/** @param {unknown} request */
async function handleMessage(request) {
  const response = await handleRequest(
    new Request("http://localhost/intercept", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    }),
  );
  return response.json();
}
const wait = (name) =>
  released.has(name)
    ? Promise.resolve()
    : new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Error("Barrier watchdog")),
          15000,
        );
        const callbacks = barriers.get(name) ?? [];
        callbacks.push(() => {
          clearTimeout(timer);
          resolve();
        });
        barriers.set(name, callbacks);
      });
async function fixtureResult(request) {
  if (!validateInterceptRequest(request).ok)
    throw Error("Invalid canonical request");
  for (const item of request.params.event.items ?? [])
    if (item.body) uploads.resolve(cfg.contentScope ?? "default", item.body);
  lineage.accept(request);
  const row = rows.find((s) => s.id === request.params.event.id);
  if (!row) throw Error("Unknown scenario");
  receipts.push(structuredClone(request));
  if (row.barrier) await wait(row.barrier);
  if (!row.expectError && !validateInterceptResponse(row.response).ok)
    throw Error("Invalid canonical response");
  return row.response;
}
async function intercept(request) {
  // Deliberately malformed negative fixtures must not be repaired by the SDK.
  const row = rows.find((row) => row.id === request?.params?.event?.id);
  if (row?.expectError) return fixtureResult(request);
  return handleMessage(request);
}
const handler = async (req, res) => {
  try {
    if (cfg.uploadPath && req.url === cfg.uploadPath) {
      const result = await uploads.receive(req);
      reply(
        res,
        result.status,
        result.status === 201
          ? { ref: result.ref, size: result.size, sha256: result.sha256 }
          : {},
      );
      return;
    }
    if (!authorize(req, cfg.auth ?? { mode: "none" }))
      return reply(res, 401, { error: "unauthorized" });
    if (req.method === "GET" && req.url === "/capabilities")
      return reply(res, 200, discovery);
    if (req.method === "POST" && req.url === "/intercept")
      return reply(res, 200, await intercept(await body(req)));
    reply(res, 404, {});
  } catch {
    reply(res, 400, { error: "invalid request" });
  }
};
const api =
  cfg.auth?.mode === "mtls"
    ? tlsServer(
        {
          ca: readFileSync(cfg.auth.caFile),
          cert: readFileSync(cfg.auth.certFile),
          key: readFileSync(cfg.auth.keyFile),
          requestCert: true,
          rejectUnauthorized: true,
        },
        handler,
      )
    : createServer(handler);
api.on("tlsClientError", (error, socket) => {
  tlsClientErrors++;
  const rawCode =
    typeof error.code === "string" && /^[A-Z0-9_]{1,100}$/.test(error.code)
      ? error.code
      : "TLS_HANDSHAKE_ERROR";
  tlsClientErrorCodes[rawCode] = (tlsClientErrorCodes[rawCode] ?? 0) + 1;
  // Count only certificate/authentication TLS failures, not arbitrary resets.
  const code =
    typeof socket?.authorizationError === "string"
      ? socket.authorizationError
      : typeof error.code === "string"
        ? error.code
        : "";
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|UNKNOWN_CA/.test(code)) {
    tlsRejections++;
    const redacted = /^[A-Z0-9_]{1,100}$/.test(code)
      ? code
      : "TLS_CERTIFICATE_REJECTED";
    tlsRejectionCodes[redacted] = (tlsRejectionCodes[redacted] ?? 0) + 1;
  }
});
const control = createServer(async (req, res) => {
  try {
    if (cfg.uploadPath && req.url === cfg.uploadPath) {
      const result = await uploads.receive(req);
      reply(
        res,
        result.status,
        result.status === 201
          ? { ref: result.ref, size: result.size, sha256: result.sha256 }
          : {},
      );
      return;
    }
    if (req.method === "GET" && req.url === "/health")
      return reply(res, 200, {
        ready: true,
        tlsRejections,
        tlsRejectionCodes,
        tlsClientErrors,
        tlsClientErrorCodes,
        requests: structuredClone(receipts),
      });
    if (req.method === "GET" && req.url === "/receipts")
      return reply(res, 200, { requests: receipts });
    if (req.method === "POST" && req.url === "/release") {
      const { barrier } = await body(req);
      released.add(barrier);
      for (const release of barriers.get(barrier) ?? []) release();
      barriers.delete(barrier);
      return reply(res, 200, { released: true });
    }
    if (req.method === "POST" && req.url === "/shutdown") {
      reply(res, 200, { stopped: true });
      setImmediate(() => process.exit(0));
      return;
    }
    reply(res, 404, {});
  } catch {
    reply(res, 400, { error: "invalid control request" });
  }
});
const controlEndpoint = await listen(control);
const endpoint =
  cfg.transport === "http"
    ? await listen(api, cfg.auth?.mode === "mtls" ? "https" : "http")
    : "stdio";
if (cfg.transport === "stdio") {
  // Start without awaiting so the independent HTTP control plane stays ready.
  void sdkStdio
    .serveStdio(async (request) => {
      let message;
      try {
        message = await request.clone().json();
      } catch {
        // The public handler, not fixture routing, owns malformed input replies.
        return handleRequest(request);
      }
      const row = rows.find((row) => row.id === message?.params?.event?.id);
      // Only explicit adversarial fixtures bypass validation. Preserve their reply.
      if (message?.method === "hooks/intercept" && row?.expectError)
        return new Response(JSON.stringify(await fixtureResult(message)));
      return handleRequest(request);
    })
    .then(
      () => process.exit(0),
      (error) => {
        console.error(error);
        process.exit(1);
      },
    );
}
await atomic(cfg.readinessFile, {
  endpoint,
  controlEndpoint,
  pid: process.pid,
});
