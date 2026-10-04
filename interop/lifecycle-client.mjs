#!/usr/bin/env node
import { runChain } from "./observation-chain.mjs";
import { evaluateRegistration } from "./catalogue.mjs";
import { TaskLineage } from "./task-lineage.mjs";
import { effectiveEvent } from "./settlement.mjs";
import {
  uploadBytes,
  rawUploadBytes,
  createContentAdapter,
} from "./content-upload.mjs";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  accessToken,
  fixtureAuth,
  fixtureFetch,
  sendStatus,
} from "./security.mjs";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { config, atomic } from "./common.mjs";
import { sdkDraft } from "./common.mjs";
const {
  validateInterceptRequest,
  validateCapabilitiesRequest,
  validateCapabilitiesResponse,
} = sdkDraft;
import { summarizeAccepted } from "./lifecycle-evaluator.mjs";
import {
  lifecycleScenarios as scenarios,
  validateObserve,
  control,
  lifecycleHooks,
  lifecycleFetch,
  lifecycleWireGate,
  isMaliciousLifecycleObservation,
  dispatchLifecycle,
  BackendTransport,
} from "./lifecycle-common.mjs";
const cfg = await config(),
  rows = await scenarios(cfg.scenarioFile),
  results = [];
if (cfg.suite !== undefined && !["lifecycle", "catalogue"].includes(cfg.suite))
  throw Error("Unknown suite");
const auth = cfg.auth ?? { mode: "none" };
if (
  !["none", "bearer", "oauth", "workload", "mtls"].includes(auth.mode) ||
  (cfg.transport === "stdio" && auth.mode !== "none")
)
  throw Error("Unsupported lifecycle authentication");
const token = cfg.transport === "http" ? await accessToken(auth) : undefined;
let child, temp, lines, transportError;
const confirmed = new Map();
const contentBytes = new Map();
const sdkClients = new Map();
const sdkDeliveries = [];
const contentUploads = [];
const contentOperations = new AsyncLocalStorage();
let bridge;
const bridgeSockets = new Set();
// Bridge subprocesses are SDK transport endpoints, but all share one foreign
// stdio backend. Serialize at that actual peer as well. Cancellation kills a
// bridge, not the foreign peer: drain its reply before forwarding another call.
const peerQueue = [];
let peerPending;
function flushPeerQueue() {
  if (peerPending || transportError) return;
  while (peerQueue.length) {
    const message = peerQueue.shift();
    if ("id" in message) {
      const timer = setTimeout(() => {
        fail(Error("Foreign stdio reply drain watchdog"));
        child.kill("SIGKILL");
      }, 15000);
      peerPending = { id: message.id, timer };
    }
    child.stdin.write(JSON.stringify(message) + "\n");
    if (peerPending) break;
  }
}
const wireAttempts = new Map();
const wireGates = new Set();
const activeWireGates = new Map();
async function rawSend(endpoint, path, message, authentication, credential) {
  const response = await sendStatus(
    endpoint,
    path,
    message,
    authentication,
    credential,
  );
  if (response.status !== 200)
    throw Error(`Raw fixture HTTP ${response.status}`);
  return response.value;
}
function eventEndpoints() {
  return cfg.endpoint
    ? ["/intercept", "/observe", "/capabilities"].map(
        (path) => new URL(path, cfg.endpoint).href,
      )
    : [];
}
async function sdkTransport(mode = "intercept") {
  return {
    transport:
      cfg.transport === "stdio"
        ? {
            type: "stdio",
            command: process.execPath,
            args: [
              fileURLToPath(new URL("./lifecycle-common.mjs", import.meta.url)),
              "--lifecycle-bridge",
              String(bridge.address().port),
            ],
            lifecycle: "persistent",
          }
        : { type: "http", url: new URL(`/${mode}`, cfg.endpoint).href },
  };
}
// Raw paths are limited to adversarial wire/lifecycle probes. Positive calls use
// Hooks; stdio bytes go to the unchanged configured executable.
async function sdkCall(
  message,
  subscription,
  signal,
  gate,
  allowMaliciousObservation = false,
) {
  const event = structuredClone(message.params.event);
  const mode = message.method === "hooks/observe" ? "observe" : "intercept";
  const bodySelected = (event.items ?? []).some(
    (item) => item.selection === "body",
  );
  const upload = bodySelected
    ? {
        endpoint: new URL("/upload", cfg.controlEndpoint).href,
        timeoutMs: 5000,
        maxBytes: 1048576,
        ...cfg.upload,
        ...cfg.uploadPolicies?.[subscription ?? "body"],
      }
    : undefined;
  let maliciousObservation = false;
  const baseNetwork = lifecycleFetch(
    fixtureFetch(auth, eventEndpoints()),
    cfg.endpoint,
  );
  const network = async (input, init) => {
    const response = await baseNetwork(input, init);
    const url = input instanceof Request ? input.url : String(input);
    if (
      allowMaliciousObservation &&
      mode === "observe" &&
      cfg.transport === "http" &&
      url === new URL("/observe", cfg.endpoint).href
    )
      maliciousObservation = await isMaliciousLifecycleObservation(response);
    if (
      gate &&
      cfg.transport === "http" &&
      url === new URL("/intercept", cfg.endpoint).href
    ) {
      // Acquire the complete foreign response without consuming or changing the
      // Response supplied to the SDK. SDK validation starts only after release.
      await response.clone().arrayBuffer();
      await gate.hold();
    }
    return response;
  };
  const sources = [
    ...(cfg.contentSources ?? []),
    ...[...contentBytes.entries()]
      .filter(
        ([key]) =>
          subscription === undefined || JSON.parse(key)[0] === subscription,
      )
      .map(([, source]) => source),
  ];
  const adapter = createContentAdapter(
    sources,
    network,
    upload ? [upload.endpoint] : [],
  );
  adapter.hydrate(event);
  const key = JSON.stringify([
    event.source,
    event.type,
    mode,
    bodySelected,
    subscription,
    message.params.capabilities,
  ]);
  const { transport } = await sdkTransport(mode);
  let client = sdkClients.get(key);
  if (!client) {
    client = lifecycleHooks({
      source: event.source,
      event: event.type,
      mode,
      bodySelected,
      capabilities:
        mode === "intercept" ? message.params.capabilities : undefined,
      transport,
      ...(upload ? { upload } : {}),
      auth: fixtureAuth(auth),
      // Async context binds a cached client to this operation's exact source
      // descriptors and confirmation collector, including concurrent uploads.
      fetch: (input, init) => {
        const operation = contentOperations.getStore();
        if (!operation) throw Error("SDK fetch outside lifecycle operation");
        return operation.fetch(input, init);
      },
    });
    sdkClients.set(key, client);
  }
  return contentOperations.run(adapter, async () => {
    const result = await dispatchLifecycle(
      client,
      event,
      message.params.state,
      signal,
    );
    const observations = await result.observations;
    const confirmations = adapter.contentUploads.map((confirmation) => ({
      ...confirmation,
      method: message.method,
      eventId: event.id,
    }));
    contentUploads.push(...confirmations);
    sdkDeliveries.push({
      eventId: event.id,
      mode,
      errors: result.errors,
      observationErrors: observations,
      maliciousObservation,
      interrupted: result.interrupted,
      contentUploads: confirmations,
      ...(gate
        ? { wireAcquired: gate.seen, wireRelease: gate.releaseReason }
        : {}),
    });
    if (
      mode === "observe" &&
      (result.response.result.effects.length !== 0 ||
        !isDeepStrictEqual(result.event.tool, event.tool) ||
        !isDeepStrictEqual(result.event.input, event.input))
    )
      throw Error("Observer changed the settled event or decision");
    const expectedObservationError = [
      {
        backendId: "interop.lifecycle",
        subscriptionIndex: 0,
        phase: "observation",
        code: "DELIVERY_FAILED",
        syntheticDenial: false,
      },
    ];
    if (
      maliciousObservation &&
      !isDeepStrictEqual(observations, expectedObservationError)
    )
      throw Error("Malicious observer response was not rejected by the SDK");
    if (!signal?.aborted && observations.length && !maliciousObservation)
      throw Error(
        `SDK lifecycle delivery failed (${event.id}): ${JSON.stringify([...result.errors, ...observations])}`,
      );
    return result;
  });
}

function ready(event, subscription) {
  for (const item of event.items ?? [])
    if (item.body) {
      const matches = [...confirmed.entries()].filter(
        ([key]) => JSON.parse(key)[1] === item.body.ref,
      );
      const body =
        subscription === undefined
          ? matches.length === 1
            ? matches[0][1]
            : undefined
          : confirmed.get(JSON.stringify([subscription, item.body.ref]));
      if (
        !body ||
        body.size !== item.body.size ||
        body.sha256 !== item.body.sha256
      )
        throw Error("Content not confirmed before event dispatch");
      item.body = structuredClone(body);
    }
}
const pending = new Map(),
  discarded = new Map(),
  discardWaits = new Set();
function waitDiscard(id, count) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => done(Error("Unsolicited drain watchdog")),
      15000,
    );
    function done(error) {
      clearTimeout(timer);
      discardWaits.delete(check);
      error ? reject(error) : resolve();
    }
    function check() {
      if (transportError) done(transportError);
      else if ((discarded.get(id) ?? 0) >= count) done();
    }
    discardWaits.add(check);
    check();
  });
}
function fail(error) {
  transportError = error;
  for (const queue of pending.values())
    for (const item of queue) item.reject(error);
  pending.clear();
  for (const check of [...discardWaits]) check();
}
function rawStdioCall(request) {
  if (transportError) return Promise.reject(transportError);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("Response watchdog")), 15000);
    const queue = pending.get(request.id) ?? [];
    const attempt = {
      id: request.id,
      resolve: (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      reject: (error) => {
        clearTimeout(timer);
        reject(error);
      },
    };
    queue.push(attempt);
    pending.set(request.id, queue);
    child.stdin.write(JSON.stringify(request) + "\n");
  });
}
try {
  if (cfg.transport === "stdio") {
    temp = await mkdtemp(join(tmpdir(), "ahp-ts-lifecycle-"));
    const serverConfig =
      typeof cfg.serverConfig === "string"
        ? JSON.parse(await readFile(cfg.serverConfig, "utf8"))
        : (cfg.serverConfig ?? {});
    const readinessFile = join(temp, "ready.json"),
      path = join(temp, "server.json");
    await atomic(path, {
      ...serverConfig,
      suite: cfg.suite,
      transport: "stdio",
      scenarioFile: cfg.scenarioFile,
      auth: cfg.auth,
      readinessFile,
    });
    child = spawn(
      cfg.serverCommand[0],
      [...cfg.serverCommand.slice(1), "--config", path],
      { cwd: cfg.serverCwd, stdio: ["pipe", "pipe", "pipe"] },
    );
    child.stderr.on("data", (data) => process.stderr.write(data));
    child.on("error", fail);
    child.on("exit", () => fail(Error("Server exited")));
    child.stdin.on("error", fail);
    bridge = createServer((socket) => {
      bridgeSockets.add(socket);
      const input = createInterface({ input: socket });
      input.on("line", (line) => {
        try {
          const message = JSON.parse(line);
          if (!("id" in message)) {
            // Notifications do not create another outstanding intercept. In
            // particular, cancellation observations need not await a late reply.
            child.stdin.write(JSON.stringify(message) + "\n");
          } else {
            peerQueue.push(message);
            flushPeerQueue();
          }
        } catch (error) {
          fail(error);
        }
      });
      socket.on("close", () => input.close());
      const disconnected = (error) => {
        // SDK cancellation kills its bridge. The foreign request is still
        // drained by peerPending; a closed return socket is not a peer failure.
        if (error.code !== "ECONNRESET" && error.code !== "EPIPE") fail(error);
      };
      input.on("error", disconnected);
      socket.on("error", disconnected);
      socket.on("close", () => bridgeSockets.delete(socket));
    });
    await new Promise((resolve, reject) => {
      bridge.once("error", reject);
      bridge.listen(0, "127.0.0.1", resolve);
    });
    let buffered = Buffer.alloc(0);
    const forward = (bytes) => {
      for (const socket of bridgeSockets)
        if (!socket.destroyed) socket.write(bytes);
    };
    child.stdout.on("data", (bytes) => {
      buffered = Buffer.concat([buffered, bytes]);
      for (;;) {
        const newline = buffered.indexOf(10);
        if (newline < 0) break;
        const frame = buffered.subarray(0, newline + 1);
        buffered = buffered.subarray(newline + 1);
        try {
          const message = JSON.parse(frame.toString("utf8"));
          if (peerPending && message.id === peerPending.id) {
            clearTimeout(peerPending.timer);
            peerPending = undefined;
            flushPeerQueue();
          }
          const attempts = wireAttempts.get(message.id);
          const attempt = attempts?.shift();
          if (attempts?.length === 0) wireAttempts.delete(message.id);
          // Adversarial replay bytes also reach the real SDK reader. If the
          // original reply is held, retain original-before-duplicate ordering.
          const gate = attempt?.gate ?? activeWireGates.get(message.id);
          if (gate) gate.hold().then(() => forward(frame), fail);
          else forward(frame);
        } catch (error) {
          fail(error);
        }
      }
    });
    lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      try {
        const response = JSON.parse(line);
        // Unsolicited observer effects never enter the pending boundary pipeline.
        if (response.id === "unsolicited-observer") return;
        const queue = pending.get(response.id);
        if (queue?.length) {
          const attempt = queue.shift();
          if (!queue.length) pending.delete(response.id);
          attempt.resolve(response);
        } else {
          discarded.set(response.id, (discarded.get(response.id) ?? 0) + 1);
          for (const check of [...discardWaits]) check();
        }
      } catch (error) {
        fail(error);
      }
    });
    if (cfg.childPidFile && child.pid)
      await atomic(cfg.childPidFile, { pid: child.pid });
    const deadline = Date.now() + 15000;
    for (;;) {
      if (transportError) throw transportError;
      try {
        const ready = JSON.parse(await readFile(readinessFile, "utf8"));
        cfg.controlEndpoint = ready.controlEndpoint;
        cfg.upload = {
          ...cfg.upload,
          endpoint: cfg.upload?.endpoint ?? ready.uploadEndpoint,
        };
        break;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      if (Date.now() > deadline) throw Error("Readiness watchdog");
      await delay(10);
    }
  }
  if (cfg.suite === "catalogue") {
    const request = {
      jsonrpc: "2.0",
      id: "catalogue-discovery",
      method: "hooks/capabilities",
      params: { protocolVersion: "draft" },
    };
    if (!validateCapabilitiesRequest(request).ok)
      throw Error("Invalid discovery request");
    const { transport } = await sdkTransport("capabilities");
    const network = fixtureFetch(auth, eventEndpoints());
    const discoveryTransport = new BackendTransport(
      { id: "interop.discovery", transport, subscriptions: [] },
      async (url, init) => {
        const headers = new Headers(init.headers);
        if (token) headers.set("authorization", `Bearer ${token}`);
        return network(url, { ...init, headers });
      },
    );
    let discovery;
    try {
      discovery = await discoveryTransport.request(
        request,
        AbortSignal.timeout(15000),
      );
    } finally {
      await discoveryTransport.close();
    }
    if (
      !validateCapabilitiesResponse(discovery).ok ||
      discovery.id !== request.id
    )
      throw Error("Invalid correlated discovery");
    const lineage = new TaskLineage(),
      counts = new Map();
    for (const row of rows) {
      const actual = { sent: [], registrations: [] };
      for (const step of row.steps) {
        if (transportError) throw transportError;
        if (step.op === "register") {
          actual.registrations.push(
            await evaluateRegistration(
              step.registration,
              discovery.result.manifest,
              step.requirements,
              step.context,
            ),
          );
        } else if (step.op === "notify" || step.op === "rawNotify") {
          const message = structuredClone(step.message);
          if (step.op === "notify") {
            validateObserve(message);
            ready(message.params.event, step.subscription);
            lineage.accept(message);
          }
          if (step.op === "notify") await sdkCall(message, step.subscription);
          else if (child) child.stdin.write(JSON.stringify(message) + "\n");
          else {
            const response = await sendStatus(
              cfg.endpoint,
              "/observe",
              message,
              auth,
              token,
            );
            if (
              step.op === "notify"
                ? response.status !== 200
                : ![200, 400, 409].includes(response.status)
            )
              throw Error(
                `Catalogue event transport failed: ${response.status}`,
              );
          }
          actual.sent.push(message);
          const eventId = message.params.event.id,
            count = (counts.get(eventId) ?? 0) + 1;
          counts.set(eventId, count);
          await control(cfg.controlEndpoint, "/wait-observed", {
            eventId,
            count,
          });
        } else throw Error(`Unknown catalogue operation ${step.op}`);
      }
      results.push({ id: row.id, status: "passed", actual });
    }
    const receipts = await control(cfg.controlEndpoint, "/receipts");
    await atomic(cfg.reportFile, {
      language: "typescript",
      discovery,
      results,
      receipts,
    });
  } else {
    const observedCounts = new Map();
    for (const row of rows) {
      if (row.chain) {
        const { transport } = await sdkTransport();
        const actual = await runChain(row, {
          transport,
          auth: fixtureAuth(auth),
          fetch: lifecycleFetch(
            fixtureFetch(auth, eventEndpoints()),
            cfg.endpoint,
          ),
          control: (path, value) => control(cfg.controlEndpoint, path, value),
        });
        results.push({ id: row.id, actual });
        continue;
      }
      const actual = {
        published: [],
        cancelled: [],
        ignored: [],
        states: {},
        observations: [],
        uploadStatuses: [],
      };
      const slots = new Map(),
        settlements = new Map();
      async function settled(attempt) {
        const { value, error } = await attempt.promise;
        if (error) throw error;
        if (!attempt.bypassSDK) settlements.set(attempt.request.id, value);
        return value;
      }
      async function publish(request) {
        // Publication is a host action, not a second protocol acceptance pass.
        // Release actual bytes, then enact only the SDK's actual settled result.
        if (actual.published.includes(request.id)) return;
        const attempt = [...slots.values()].find(
          (item) => item.request.id === request.id && !item.bypassSDK,
        );
        if (!attempt) throw Error("Publication requires a public SDK boundary");
        if (!attempt.received && !attempt.controller.signal.aborted) return;
        attempt.gate.release();
        const boundary = await settled(attempt);
        if (boundary.interrupted) return;
        actual.states[request.id] = summarizeAccepted(request, boundary);
        actual.published.push(request.id);
        await control(cfg.controlEndpoint, "/mark", {
          scenario: row.id,
          kind: "accepted",
          id: request.id,
        });
      }
      for (const step of row.steps) {
        if (transportError) throw transportError;
        const request = row.requests[step.key],
          id = request?.id;
        switch (step.op) {
          case "send": {
            if (step.bypassSDK !== true) {
              if (!validateInterceptRequest(request).ok)
                throw Error("Invalid canonical request");
              ready(request.params.event, step.subscription);
            }
            if (slots.has(step.slot)) throw Error("Duplicate slot");
            const controller = new AbortController();
            const gate =
              step.bypassSDK === true
                ? undefined
                : lifecycleWireGate(controller.signal);
            if (gate) {
              wireGates.add(gate);
              activeWireGates.set(id, gate);
            }
            if (child) {
              const attempts = wireAttempts.get(id) ?? [];
              attempts.push({ gate, bypassSDK: step.bypassSDK === true });
              wireAttempts.set(id, attempts);
            }
            const promise = (
              step.bypassSDK === true
                ? child
                  ? rawStdioCall(request)
                  : rawSend(cfg.endpoint, "/intercept", request, auth, token)
                : sdkCall(request, step.subscription, controller.signal, gate)
            ).then(
              (value) => ({ value }),
              (error) => ({ error }),
            );
            slots.set(step.slot, {
              request,
              promise,
              controller,
              gate,
              bypassSDK: step.bypassSDK === true,
            });
            break;
          }
          case "wait":
            await control(cfg.controlEndpoint, "/wait", {
              id,
              count: step.count ?? 1,
            });
            break;
          case "release":
            await control(cfg.controlEndpoint, "/release", { id });
            break;
          case "receive": {
            const attempt = slots.get(step.slot);
            if (!attempt) throw Error("Unknown slot");
            if (attempt.bypassSDK) {
              await settled(attempt);
              actual.ignored.push(step.slot);
              break;
            }
            if (attempt.controller.signal.aborted) {
              const boundary = await settled(attempt);
              if (
                !boundary.interrupted &&
                !actual.published.includes(attempt.request.id)
              )
                throw Error("Cancellation did not interrupt the SDK boundary");
              actual.ignored.push(step.slot);
              break;
            }
            await attempt.gate.acquired;
            if (attempt.received) {
              actual.ignored.push(step.slot);
              break;
            }
            attempt.received = true;
            await control(cfg.controlEndpoint, "/mark", {
              scenario: row.id,
              kind: "acquired",
              id: attempt.request.id,
            });
            break;
          }
          case "cancel": {
            for (const attempt of slots.values()) {
              if (attempt.request.id !== id || attempt.bypassSDK) continue;
              attempt.controller.abort();
              const boundary = await settled(attempt);
              if (!actual.published.includes(id) && !boundary.interrupted)
                throw Error("Cancellation occurred after SDK settlement");
            }
            actual.cancelled.push(id);
            await control(cfg.controlEndpoint, "/mark", {
              scenario: row.id,
              kind: "cancelled",
              id,
            });
            break;
          }
          case "accept":
          case "failOpen":
            await publish(request);
            break;
          case "emit": {
            if (!child) throw Error("emit requires stdio");
            const id = step.response.id,
              count = (discarded.get(id) ?? 0) + 1;
            await control(cfg.controlEndpoint, "/emit", {
              response: step.response,
            });
            await waitDiscard(id, count);
            actual.ignored.push(`unsolicited:${id}`);
            await control(cfg.controlEndpoint, "/mark", {
              scenario: row.id,
              kind: "discarded",
              id,
            });
            break;
          }
          case "upload": {
            const bytes =
              step.bodyBase64 !== undefined
                ? Buffer.from(step.bodyBase64, "base64")
                : Buffer.from(step.text ?? "", "utf8");
            const upload = {
              endpoint: new URL("/upload", cfg.controlEndpoint).href,
              ...cfg.upload,
              ...cfg.uploadPolicies?.[step.subscription],
              ...step.upload,
            };
            const negativeUpload =
              (step.size !== undefined && step.size !== bytes.length) ||
              (step.sha256 !== undefined &&
                step.sha256 !==
                  createHash("sha256").update(bytes).digest("hex")) ||
              step.upload?.auth !== undefined;
            const result = await (
              negativeUpload ? rawUploadBytes : uploadBytes
            )(upload, bytes, {
              allowLoopback: true,
              declaredSize: step.size,
              declaredHash: step.sha256,
            });
            actual.uploadStatuses.push(result.status);
            if (result.body) {
              contentBytes.set(
                JSON.stringify([step.subscription, result.body.ref]),
                {
                  descriptor: structuredClone(result.body),
                  bytes: bytes.toString("base64"),
                },
              );
              confirmed.set(
                JSON.stringify([step.subscription, step.ref]),
                result.body,
              );
              confirmed.set(
                JSON.stringify([step.subscription, result.body.ref]),
                result.body,
              );
            }
            break;
          }
          case "observe": {
            if (!settlements.has(id))
              throw Error("Observe before SDK settlement");
            const event = effectiveEvent(
              request.params.event,
              actual.states[id],
            );
            const input = structuredClone(
              Object.hasOwn(actual.states, id)
                ? actual.states[id].input
                : (event.tool?.input ?? event.input ?? {}),
            );
            if (event.tool) event.tool.input = input;
            if (Object.hasOwn(step, "items"))
              event.items = structuredClone(step.items);
            const notification = {
              jsonrpc: "2.0",
              method: "hooks/observe",
              params: { protocolVersion: "draft", event },
            };
            if (step.bypassSDK !== true) {
              validateObserve(notification);
              ready(event, step.subscription);
            }
            const settledState = structuredClone(actual.states);
            const settledDecision = structuredClone(
              settlements.get(id).response,
            );
            if (step.bypassSDK === true) {
              if (child) child.stdin.write(JSON.stringify(notification) + "\n");
              else
                await rawSend(
                  cfg.endpoint,
                  "/observe",
                  notification,
                  auth,
                  token,
                );
            } else {
              // Explicit lifecycle observe steps exercise the malicious legacy
              // observer contract. Catalogue notify and other paths do not.
              await sdkCall(
                notification,
                step.subscription,
                undefined,
                undefined,
                true,
              );
            }
            if (
              !isDeepStrictEqual(actual.states, settledState) ||
              !isDeepStrictEqual(settlements.get(id).response, settledDecision)
            )
              throw Error("Observation changed an already settled boundary");
            const count = (observedCounts.get(event.id) ?? 0) + 1;
            observedCounts.set(event.id, count);
            await control(cfg.controlEndpoint, "/wait-observed", {
              eventId: event.id,
              count,
            }).catch((error) => {
              throw new Error(
                `Observation wait failed (${row.id}; pending=${peerPending?.id}; transport=${transportError?.message})`,
                { cause: error },
              );
            });
            actual.observations.push({
              eventId: event.id,
              subscription: step.subscription,
              input,
            });
            break;
          }
          default:
            throw Error(`Unknown lifecycle op ${step.op}`);
        }
      }
      results.push({ id: row.id, actual });
    }
    const receipts = await control(cfg.controlEndpoint, "/receipts");
    await atomic(cfg.reportFile, {
      language: "typescript",
      results,
      receipts,
      sdkDeliveries,
      contentUploads,
    });
  }
} finally {
  if (peerPending) clearTimeout(peerPending.timer);
  // Abort SDK work before opening any fixture gate during cleanup.
  const closing = [...sdkClients.values()].map((client) => client.close());
  for (const gate of wireGates) gate.release("cleanup");
  await Promise.all(closing);
  for (const socket of bridgeSockets) socket.destroy();
  if (bridge) await new Promise((resolve) => bridge.close(resolve));
  if (child) {
    child.stdin.end();
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null)
        return resolve();
      const timer = setTimeout(() => child.kill("SIGKILL"), 1000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    lines?.close();
  }
  if (temp) await rm(temp, { recursive: true, force: true });
}
