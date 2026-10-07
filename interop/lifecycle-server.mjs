#!/usr/bin/env node
import { createServer } from "node:http";
import { createServer as tlsServer } from "node:https";
import { readFileSync } from "node:fs";
import { authorize } from "./security.mjs";
import { createInterface } from "node:readline";
import { catalogueManifest } from "./catalogue.mjs";
import { TaskLineage } from "./task-lineage.mjs";
import { UploadStore, authorizeUpload } from "./content-upload.mjs";
import { config, atomic, body, reply, listen } from "./common.mjs";
import { sdkDraft } from "./common.mjs";
const {
  validateInterceptRequest,
  validateInterceptResponse,
  validateCapabilitiesRequest,
  validateCapabilitiesResponse,
} = sdkDraft;
import {
  lifecycleScenarios as scenarios,
  validateObserve,
  serverHooks,
  control as fixtureControl,
} from "./lifecycle-common.mjs";
const cfg = await config(),
  rows = await scenarios(cfg.scenarioFile);
if (cfg.suite !== undefined && !["lifecycle", "catalogue"].includes(cfg.suite))
  throw Error("Unknown suite");
const auth = cfg.auth ?? { mode: "none" };
if (
  !["none", "bearer", "oauth", "workload", "mtls"].includes(auth.mode) ||
  (cfg.transport === "stdio" && auth.mode !== "none")
)
  throw Error("Unsupported lifecycle authentication");
const sequences = new Map(),
  occurrences = new Map();
const responses = new Map(),
  entries = [],
  sdkCalls = [],
  delivered = new Set(),
  released = new Set(),
  waits = new Set();
for (const row of rows)
  for (const [key, request] of Object.entries(row.requests)) {
    responses.set(request.id, row.responses[key]);
    sequences.set(request.id, row.responseSequences?.[key] ?? []);
  }
for (const row of rows)
  if (row.chain?.holdObservers)
    sequences.set(row.requests.a.id + ":observers", []);
// These cancellation probes deliberately stage unsupported flow.continue
// effects. Their original reply must reach the client unchanged so discard,
// rather than a server-generated RPC error, is what the schedule exercises.
const lateReplyProbes = new Set([
  "cancel-before-reply",
  "cancel-after-reply-before-acceptance",
  "cancelled-boundary-observed",
]);
// Bypass selection is per send occurrence, never per scenario/event family.
const rawAttempts = new Map();
const chainFailureProbes = new Set([
  "observation-chain-fail-open",
  "observation-chain-fail-closed",
]);
for (const row of rows) {
  // The first chain reply deliberately returns an unadvertised effect. Keep
  // that canonical response intact so the client exercises its failure policy.
  if (chainFailureProbes.has(row.id))
    rawAttempts.set(row.requests.a.id, new Set([0]));
  const counts = new Map();
  for (const step of row.steps ?? []) {
    if (step.op !== "send") continue;
    const id = row.requests[step.key].id;
    const occurrence = counts.get(id) ?? 0;
    counts.set(id, occurrence + 1);
    if (
      step.bypassSDK === true ||
      (lateReplyProbes.has(row.id) && step.key === "a" && occurrence === 0)
    ) {
      const attempts = rawAttempts.get(id) ?? new Set();
      attempts.add(occurrence);
      rawAttempts.set(id, attempts);
    }
  }
}
const rawNotifications = new Set(
  rows.flatMap((row) =>
    (row.steps ?? [])
      .filter((step) => step.op === "rawNotify")
      .map((step) => JSON.stringify(step.message)),
  ),
);
function isRawProbe(message) {
  return (
    (message.method === "hooks/intercept" &&
      rawAttempts.get(message.id)?.has(occurrences.get(message.id) ?? 0) ===
        true) ||
    rawNotifications.has(JSON.stringify(message))
  );
}
const uploads = new UploadStore((authorization) =>
  authorizeUpload(cfg, authorization),
);
function resolveContent(request) {
  for (const item of request.params.event.items ?? [])
    if (item.body) uploads.resolve(cfg.contentScope ?? "default", item.body);
}
const lineage = new TaskLineage();
let stopping = false;
function wake() {
  for (const check of [...waits]) check();
}
function record(entry) {
  entries.push(entry);
  wake();
}
function until(predicate) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => done(Error("Barrier watchdog")), 15000);
    function done(error) {
      clearTimeout(timer);
      waits.delete(check);
      error ? reject(error) : resolve();
    }
    function check() {
      if (stopping) done(Error("Shutdown"));
      else if (predicate()) done();
    }
    waits.add(check);
    check();
  });
}
const malicious = {
  jsonrpc: "2.0",
  id: "unsolicited-observer",
  result: {
    protocolVersion: "draft",
    effects: [{ type: "deny", reason: "observer must not decide" }],
  },
};
async function dispatch(request) {
  if (cfg.suite === "catalogue" && request.method === "hooks/capabilities") {
    if (!validateCapabilitiesRequest(request).ok)
      throw Error("Invalid canonical discovery request");
    const response = {
      jsonrpc: "2.0",
      id: request.id,
      result: { protocolVersion: "draft", manifest: catalogueManifest },
    };
    if (!validateCapabilitiesResponse(response).ok)
      throw Error("Invalid canonical discovery response");
    record({
      kind: "discovery",
      request: structuredClone(request),
      response: structuredClone(response),
    });
    return response;
  }

  if (request.method === "hooks/observe") {
    try {
      validateObserve(request);
    } catch (error) {
      if (cfg.suite === "catalogue")
        record({
          kind: "rejected",
          eventId: request.params?.event?.id,
          message: request,
          errorKind: "schema",
        });
      throw Object.assign(error, { status: 400, rejected: true });
    }
    const { event } = request.params;
    resolveContent(request);
    try {
      lineage.accept(request);
    } catch (error) {
      if (cfg.suite === "catalogue")
        record({
          kind: "rejected",
          eventId: event.id,
          message: request,
          errorKind: "lineage",
        });
      throw Object.assign(error, { status: 409, rejected: true });
    }
    const gate = event.id + ":observers";
    if (sequences.has(gate)) record({ kind: "observer-blocked", id: event.id });
    record({ kind: "observed", eventId: event.id, event, message: request });
    if (sequences.has(gate)) await until(() => released.has(gate));
    return cfg.suite === "catalogue" ? undefined : malicious;
  }
  if (!validateInterceptRequest(request).ok)
    throw Error("Invalid canonical request");
  resolveContent(request);
  lineage.accept(request);
  if (!responses.has(request.id)) throw Error("Unknown request ID");
  const occurrence = occurrences.get(request.id) ?? 0;
  occurrences.set(request.id, occurrence + 1);
  const response =
    sequences.get(request.id)[occurrence] ?? responses.get(request.id);
  record({
    kind: "received",
    id: request.id,
    message: structuredClone(request),
  });
  await until(() => released.has(request.id));
  if (!validateInterceptResponse(response).ok)
    throw Error("Invalid canonical response");
  record({ kind: "replied", id: request.id });
  return response;
}
// The application supplies fixture decisions; public helpers own canonical
// envelope validation, correlation, safe errors, and notification suppression.
async function publicDispatch(request) {
  const handled = await serverHooks.handle(
    new Request("http://localhost/hooks", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    }),
    async (message) => {
      const response = cfg.fixtureEndpoint
        ? await fixtureControl(cfg.fixtureEndpoint, "/evaluate", {
            message,
            deliveryId: cfg.deliveryId,
          })
        : await dispatch(message);
      if (message.method === "hooks/observe") return;
      const { protocolVersion, ...result } = response.result;
      return result;
    },
  );
  const text = await handled.text();
  return { status: handled.status, value: text ? JSON.parse(text) : undefined };
}
const protocolHandler = async (req, res) => {
  try {
    if (!authorize(req, auth))
      return reply(res, 401, { error: "unauthorized" });
    if (
      req.method !== "POST" ||
      ![
        "/intercept",
        "/observe",
        "/hooks",
        ...(cfg.suite === "catalogue" ? ["/capabilities"] : []),
      ].includes(req.url)
    )
      return reply(res, 404, {});
    const message = await body(req);
    if (!isRawProbe(message)) {
      // Reference authorization/storage availability is application routing policy,
      // not a backend evaluation failure. Preserve its HTTP status before handing
      // a canonically valid message to the protocol helper.
      if (
        (message.method === "hooks/intercept" &&
          validateInterceptRequest(message).ok) ||
        (message.method === "hooks/observe" &&
          sdkDraft.validateObserveNotification(message).ok)
      )
        resolveContent(message);
      sdkCalls.push({
        method: message.method,
        eventId: message.params?.event?.id,
      });
      const response = await publicDispatch(message);
      if (response.status === 204) {
        res.writeHead(204).end();
        return;
      }
      return reply(res, response.status, response.value);
    }
    // Raw fixture probes intentionally exercise unsupported effects and unsolicited replies.
    reply(res, 200, await dispatch(message));
  } catch (error) {
    reply(res, error.status ?? 400, { error: error.message });
  }
};
const protocol =
  auth.mode === "mtls"
    ? tlsServer(
        {
          ca: readFileSync(auth.caFile),
          cert: readFileSync(auth.certFile),
          key: readFileSync(auth.keyFile),
          requestCert: true,
          rejectUnauthorized: true,
        },
        protocolHandler,
      )
    : createServer(protocolHandler);
const control = createServer(async (req, res) => {
  try {
    const path = req.url;
    if (path === "/health") return reply(res, 200, { ready: true });
    if (path === "/receipts") return reply(res, 200, { entries, sdkCalls });
    if (path === (cfg.uploadPath ?? "/upload")) {
      const result = await uploads.receive(req);
      record({ kind: "upload", ...result });
      reply(
        res,
        result.status,
        result.status === 201
          ? { ref: result.ref, size: result.size, sha256: result.sha256 }
          : {},
      );
      return;
    }
    const value = await body(req);
    if (path === "/evaluate") {
      sdkCalls.push({
        method: value.message.method,
        eventId: value.message.params?.event?.id,
      });
      const result = await dispatch(value.message);
      delivered.add(value.deliveryId);
      wake();
      return reply(res, 200, result ?? null);
    }
    if (path === "/wait-delivered") await until(() => delivered.has(value.id));
    else if (path === "/wait")
      await until(
        () =>
          entries.filter((e) => e.kind === "received" && e.id === value.id)
            .length >= (value.count ?? 1),
      );
    else if (path === "/wait-observed")
      await until(
        () =>
          entries.filter(
            (e) =>
              (e.kind === "observed" || e.kind === "rejected") &&
              e.eventId === value.eventId,
          ).length >= value.count,
      );
    else if (path === "/release") {
      released.add(value.id);
      wake();
    } else if (path === "/emit") {
      if (
        cfg.transport !== "stdio" ||
        !validateInterceptResponse(value.response).ok
      )
        return reply(res, 400, { error: "Invalid stdio emission" });
      await output(value.response, { kind: "emitted", id: value.response.id });
    } else if (path === "/mark")
      record({ kind: value.kind, id: value.id, scenario: value.scenario });
    else if (path === "/shutdown") {
      reply(res, 200, { ok: true });
      shutdown();
      return;
    } else return reply(res, 404, {});
    reply(res, 200, { ok: true });
  } catch (error) {
    reply(res, 400, { error: error.message });
  }
});
// Serialize all stdout frames, including control emissions. Resolve after write flush.
let outputTail = Promise.resolve();
function output(value, receipt) {
  const task = outputTail.then(
    () =>
      new Promise((resolve, reject) => {
        if (receipt) record(receipt);
        process.stdout.write(JSON.stringify(value) + "\n", (error) =>
          error ? reject(error) : resolve(),
        );
      }),
  );
  outputTail = task.catch(() => {});
  return task;
}
let lines;
function shutdown() {
  stopping = true;
  wake();
  lines?.close();
  protocol.close();
  control.close();
  setImmediate(() => process.exit());
}
const controlEndpoint = await listen(control);
const endpoint =
  cfg.transport === "http"
    ? await listen(protocol, auth.mode === "mtls" ? "https" : "http")
    : null;
if (cfg.transport === "stdio") {
  lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    Promise.resolve()
      .then(async () => {
        const request = JSON.parse(line);
        if (!isRawProbe(request))
          sdkCalls.push({
            method: request.method,
            eventId: request.params?.event?.id,
          });
        return cfg.fixtureEndpoint || !isRawProbe(request)
          ? (await publicDispatch(request)).value
          : dispatch(request);
      })
      .then((value) => (value === undefined ? undefined : output(value)))
      .catch((error) => {
        if (cfg.suite === "catalogue" && error.rejected) return;
        console.error(error);
        process.exit(1);
      });
  });
  lines.on("close", () => {
    if (!stopping) shutdown();
  });
}
process.on("SIGTERM", shutdown);
await atomic(cfg.readinessFile, {
  endpoint,
  controlEndpoint,
  uploadEndpoint: new URL(cfg.uploadPath ?? "/upload", controlEndpoint).href,
  pid: process.pid,
});
