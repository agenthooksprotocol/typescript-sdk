// @ts-check
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isDeepStrictEqual } from "node:util";
import { canonicalFixtureInjections } from "./common.mjs";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
// Resolve the package's public exports, not its implementation modules.
/** @type {typeof import("agenthooksprotocol/client")} */
export const {
  Hooks,
  BackendTransport,
  auth: hooksAuth,
} = await import(require.resolve("agenthooksprotocol/client"));
/** @type {typeof import("agenthooksprotocol/server")} */
export const { hooks: serverHooks } = await import(
  require.resolve("agenthooksprotocol/server")
);
/** @type {typeof import("agenthooksprotocol/draft")} */
const draft = await import(require.resolve("agenthooksprotocol/draft"));
// Fixture prechecks use the same public canonical validators as wire handling.
// Generated codecs alone intentionally accept unknown/extended shapes.
export function validateCanonical(name, value, _decoder) {
  if (name !== "registration" || !draft.validateRegistration(value).ok)
    throw Error(`Invalid canonical ${name}`);
}
export function validateObserve(value) {
  if (!draft.validateObserveNotification(value).ok)
    throw Error("Invalid canonical observe-notification");
}
export async function http(endpoint, path, value) {
  const response = await fetch(new URL(path, endpoint), {
    method: value === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: value === undefined ? undefined : JSON.stringify(value),
    signal: AbortSignal.timeout(15000),
    redirect: "error",
  });
  const text = await response.text();
  return { status: response.status, value: text ? JSON.parse(text) : null };
}
export async function control(endpoint, path, value) {
  const result = await http(endpoint, path, value);
  if (result.status >= 300) throw Error(`${path}: HTTP ${result.status}`);
  return result.value;
}

/** Build the public consumer boundary with checked registration and options.
 * @param {{transport: import("agenthooksprotocol/client").Registration["hooks"][number]["transport"],
 * source: string, event: import("agenthooksprotocol/client").EventType,
 * mode: "intercept" | "observe", capabilities?: import("agenthooksprotocol/client").Capabilities,
 * bodySelected: boolean, upload?: import("agenthooksprotocol/client").ContentUpload,
 * auth: import("agenthooksprotocol/client").AuthProvider, fetch?: typeof globalThis.fetch}} options
 */
export function lifecycleHooks(options) {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "interop.lifecycle",
          transport: options.transport,
          subscriptions: [
            {
              mode: options.mode,
              events: [options.event],
              ...(options.mode === "intercept"
                ? { timeoutMs: 15000, failurePolicy: "fail-open" }
                : {}),
              content: { default: options.bodySelected ? "body" : "metadata" },
              ...(options.upload ? { upload: options.upload } : {}),
            },
          ],
        },
      ],
    },
    {
      source: options.source,
      capabilities: {
        [options.event]: {
          modes: [options.mode],
          ...(options.capabilities ? { capabilities: options.capabilities } : {}),
        },
      },
      auth: options.auth,
      ...(options.fetch ? { fetch: options.fetch } : {}),
    },
  );
}
/** @param {InstanceType<typeof Hooks>} client
 * @param {{type: import("agenthooksprotocol/client").EventType, source: string} & import("agenthooksprotocol/client").BoundaryInput<import("agenthooksprotocol/client").EventType>} event
 * @param {import("agenthooksprotocol/client").BoundaryOptions["initialState"]} [state]
 * @param {AbortSignal} [signal]
 */
export function dispatchLifecycle(client, event, state, signal) {
  const { type, source, ...input } = event;
  return client.dispatch(type, input, {
    ...(state === undefined ? {} : { initialState: state }),
    ...(signal ? { signal } : {}),
  });
}

/** Adapt pinned lifecycle producer fixtures, leaving malformed wire probes intact. */
export function canonicalLifecycleFixture(row) {
  for (const [key, response] of Object.entries(row.responses ?? {})) {
    canonicalFixtureInjections({ id: `${row.id}:${key}`, response });
    for (const response of row.responseSequences?.[key] ?? [])
      canonicalFixtureInjections({ id: `${row.id}:${key}`, response });
  }
  const migrateItems = (items) => {
    for (const item of items ?? []) {
      // These fixtures exercise immutable uploaded bytes, not inline text.
      if (["text", "reasoning", "skill", "native"].includes(item.kind) &&
          (typeof item.body?.ref === "string" || item.gap)) {
        if (item.kind !== "text") item.category ??= item.kind;
        item.kind = "attachment";
        if (item.mediaType === "text/plain") item.mediaType = "application/octet-stream";
      }
    }
  };
  for (const request of Object.values(row.requests ?? {}))
    migrateItems(request.params?.event?.items);
  for (const step of row.steps ?? [])
    if (step.bypassSDK !== true) migrateItems(step.items);
  return row;
}

/** Lifecycle/catalogue rows contain request maps and controller steps, unlike core rows.
 * @param {string} path
 */
export async function lifecycleScenarios(path) {
  const value = JSON.parse(await readFile(path, "utf8"));
  if (
    value.version !== 1 ||
    !Array.isArray(value.scenarios) ||
    value.scenarios.some(
      (row) => typeof row.id !== "string" || !row.requests || !row.responses,
    )
  )
    throw Error("Invalid lifecycle scenario file");
  return value.scenarios.map(canonicalLifecycleFixture);
}

/** Compatibility network binding: route SDK-produced messages without constructing
 * or interpreting canonical effects. Auth headers, bytes and abort signals survive.
 * @param {typeof globalThis.fetch} network
 * @param {string | undefined} endpoint
 * @returns {typeof globalThis.fetch}
 */
export function lifecycleFetch(network, endpoint) {
  if (!endpoint) return network;
  const intercept = new URL("/intercept", endpoint).href;
  return (input, init = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === intercept && typeof init.body === "string") {
      const message = JSON.parse(init.body);
      if (message.method === "hooks/observe")
        return network(new URL("/observe", endpoint).href, init);
    }
    return network(input, init);
  };
}

// Transparent stdio bootstrap: the parent owns the selected foreign executable
// and its readiness/controller. This child only carries unchanged stream bytes.
if (process.argv[2] === "--lifecycle-bridge") {
  const { connect } = await import("node:net");
  const socket = connect(Number(process.argv[3]), "127.0.0.1");
  process.stdin.pipe(socket);
  socket.pipe(process.stdout);
  socket.on("error", (error) => {
    console.error(error);
    process.exitCode = 1;
  });
  socket.on("close", () => process.stdin.destroy());
}

/** Bounded fixture-only network rendezvous. Bytes are acquired outside the SDK;
 * only opening this gate makes them visible to its correlation/acceptance path.
 * The gate never validates, composes, or decides the response's effects.
 */
export function lifecycleWireGate(signal, timeoutMs = 15000) {
  let acquire, rejectAcquire, open, rejectRelease;
  let seen = false,
    opened = false,
    releaseReason;
  const abort = () => release("abort");
  const acquired = new Promise((resolve, reject) => {
    acquire = resolve;
    rejectAcquire = reject;
  });
  acquired.catch(() => {});
  const released = new Promise((resolve, reject) => {
    open = resolve;
    rejectRelease = reject;
  });
  released.catch(() => {});
  const timer = setTimeout(() => {
    const error = Error("Wire acquisition watchdog");
    opened = true;
    releaseReason = "timeout";
    rejectAcquire(error);
    rejectRelease(error);
    signal?.removeEventListener("abort", abort);
  }, timeoutMs);
  function release(reason = "accept") {
    if (opened) return;
    opened = true;
    releaseReason = reason;
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    open();
  }
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  return {
    acquired,
    get seen() {
      return seen;
    },
    get releaseReason() {
      return releaseReason;
    },
    async hold() {
      seen = true;
      acquire();
      await released;
    },
    release,
  };
}

// LIFECYCLE.md deliberately makes legacy foreign observers return this exact
// unsolicited denial. Recognizing it is fixture evidence, not SDK acceptance.
export const maliciousLifecycleObservation = {
  jsonrpc: "2.0",
  id: "unsolicited-observer",
  result: {
    protocolVersion: "draft",
    effects: [{ type: "deny", reason: "observer must not decide" }],
  },
};
export async function isMaliciousLifecycleObservation(response) {
  if (
    response.status !== 200 ||
    response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !==
      "application/json"
  )
    return false;
  const reader = response.clone().body?.getReader();
  if (!reader) return false;
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4096) return false;
      chunks.push(Buffer.from(value));
    }
    return isDeepStrictEqual(
      JSON.parse(Buffer.concat(chunks).toString("utf8")),
      maliciousLifecycleObservation,
    );
  } catch {
    return false;
  } finally {
    void reader.cancel().catch(() => {});
  }
}
