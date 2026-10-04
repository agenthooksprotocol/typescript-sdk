// @ts-check
import { createRequire } from "node:module";
const sdkRequire = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
// Resolve package exports from the SDK workspace, never internal build paths.
/** @type {typeof import("@agenthooksprotocol/sdk/draft")} */
export const sdkDraft = await import(
  sdkRequire.resolve("@agenthooksprotocol/sdk/draft")
);
/** @type {typeof import("@agenthooksprotocol/sdk/client")} */
export const sdkClient = await import(
  sdkRequire.resolve("@agenthooksprotocol/sdk/client")
);
/** @type {typeof import("@agenthooksprotocol/sdk/server")} */
export const sdkServer = await import(
  sdkRequire.resolve("@agenthooksprotocol/sdk/server")
);
import { readFile, writeFile, rename } from "node:fs/promises";
export async function config() {
  const i = process.argv.indexOf("--config");
  if (i < 0 || !process.argv[i + 1]) throw Error("Missing --config");
  return JSON.parse(await readFile(process.argv[i + 1], "utf8"));
}
export async function atomic(path, value) {
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, JSON.stringify(value));
  await rename(temp, path);
}
/**
 * @typedef {object} FixtureScenario
 * @property {string} id
 * @property {import("@agenthooksprotocol/sdk/draft").InterceptRequest} request
 * @property {unknown} [response] Negative fixtures deliberately permit malformed replies.
 * @property {Record<string, unknown>} [expected]
 * @property {boolean} [expectError]
 * @property {string} [barrier]
 * @property {string} [subscription]
 * @property {Array<{ref: string, bodyBase64: string}>} [contentBodies]
 * @property {import("./content-upload.mjs").ContentSource[]} [contentSources]
 */
/** @param {string} path @returns {Promise<FixtureScenario[]>} */
export async function scenarios(path) {
  const value = JSON.parse(await readFile(path, "utf8"));
  if (value.version !== 1 || !Array.isArray(value.scenarios))
    throw Error("Invalid scenario file");
  for (const row of value.scenarios) {
    const request = sdkDraft.validateInterceptRequest(row.request);
    if (typeof row.id !== "string" || !request.ok)
      throw Error("Invalid fixture request");
    row.request = request.value;
  }
  return value.scenarios;
}
export async function body(req) {
  let data = "";
  for await (const chunk of req) {
    data += chunk;
    if (data.length > 4_194_304) throw Error("Oversized request");
  }
  return JSON.parse(data);
}
export function reply(res, status, value) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(value));
}
export function listen(server, protocol = "http") {
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve(`${protocol}://127.0.0.1:${server.address().port}`),
    ),
  );
}
export const discovery = {
  protocolVersion: "draft",
  effects: [
    "deny",
    "allow",
    "ask",
    "modify",
    "message",
    "return",
    "flow",
    "inject",
  ],
  modify: { input: { replace: true, merge: true } },
  transports: ["http", "stdio"],
  authentication: ["bearer", "oauth"],
  flow: {
    operations: ["stop", "continue"],
    remainingContinuations: 2,
    maxContinuations: 2,
    continuationCount: 0,
  },
  inject: { context: { append: true, deliverAt: ["now", "next_turn"] } },
  coverage: {
    events: ["tool.before", "turn.finish.before"],
    gaps: [
      "No production harness mapping",
      "Content upload and task changes are local semantic slices",
    ],
  },
};

export const manifest = {
  transports: ["http", "stdio"],
  authentication: ["bearer", "oauth"],
  toolPaths: ["native"],
  contentCategories: [
    "text",
    "image",
    "audio",
    "video",
    "reasoning",
    "skill",
    "native",
  ],
  limits: { maxUploadBytes: 52428800, maxContinuations: 2 },
  managedPolicy: { scopes: ["user"], disableable: true },
  correlationIdentityFields: [
    "id",
    "source",
    "call.id",
    "parentEventId",
    "items.id",
  ],
  events: [
    {
      event: "tool.before",
      modes: ["intercept"],
      capabilities: { ...discovery, flow: { operations: ["stop"] } },
    },
    {
      event: "turn.finish.before",
      modes: ["intercept"],
      capabilities: { effects: ["flow", "message"], flow: discovery.flow },
    },
  ],
  gaps: [
    {
      path: "events.other",
      reason:
        "Synthetic adapter covers tool.before and turn.finish.before only",
    },
    {
      path: "production",
      reason:
        "Content upload, lineage and task changes are local semantic slices, not production host integration",
    },
  ],
};

/**
 * @typedef {object} FixtureConfig
 * @property {"http" | "stdio"} transport
 * @property {string[]} [serverCommand]
 * @property {string} [serverConfig]
 * @property {string} [serverCwd]
 * @property {string} [endpoint]
 * @property {{mode: string}} [auth]
 * @property {import("./content-upload.mjs").ContentSource[]} [contentSources]
 * @property {Array<{id?: string, timeoutMs?: number, failurePolicy?: "fail-open" | "fail-closed", content?: import("@agenthooksprotocol/sdk/client").ContentSelection, upload?: import("@agenthooksprotocol/sdk/client").ContentUpload}>} [subscriptions]
 */
/**
 * Translate fixture policy into schema-validated canonical registration.
 * @param {FixtureConfig} cfg
 * @param {Array<{request: import("@agenthooksprotocol/sdk/draft").InterceptRequest, subscription?: string}>} rows
 * @returns {import("@agenthooksprotocol/sdk/client").Registration}
 */
export function fixtureRegistration(cfg, rows) {
  if (
    cfg.transport === "stdio" &&
    (!cfg.serverCommand?.length || !cfg.serverConfig)
  )
    throw Error("Missing stdio configuration");
  if (cfg.transport === "http" && !cfg.endpoint)
    throw Error("Missing HTTP endpoint");
  const transport =
    cfg.transport === "stdio"
      ? {
          type: "stdio",
          command: cfg.serverCommand?.[0],
          args: [
            ...(cfg.serverCommand?.slice(1) ?? []),
            "--config",
            cfg.serverConfig,
          ],
          lifecycle: "persistent",
          ...(cfg.serverCwd ? { cwd: cfg.serverCwd } : {}),
        }
      : { type: "http", url: new URL("/intercept", cfg.endpoint).href };
  const parsed = sdkDraft.draftCodecs.parseRegistration({
    protocolVersion: "draft",
    hooks: [
      {
        id: "interop.fixture",
        transport,
        ...(cfg.auth?.mode === "bearer"
          ? {
              authentication: { type: "bearer", tokenEnv: "AHP_INTEROP_TOKEN" },
            }
          : {}),
        subscriptions: rows
          .map((row) => {
            const policy =
              cfg.subscriptions?.find(
                (value) => value.id === row.subscription,
              ) ??
              (cfg.subscriptions?.length === 1
                ? cfg.subscriptions[0]
                : undefined);
            return {
              events: [row.request.params.event.type],
              mode: "intercept",
              timeoutMs: policy?.timeoutMs ?? 15000,
              failurePolicy: policy?.failurePolicy ?? "fail-closed",
              content: policy?.content ?? { default: "metadata" },
              ...(policy?.upload ? { upload: policy.upload } : {}),
            };
          })
          .filter(
            (sub, i, subs) =>
              subs.findIndex(
                (other) => JSON.stringify(other) === JSON.stringify(sub),
              ) === i,
          ),
      },
    ],
  });
  if (!parsed.ok) throw Error("Invalid fixture registration");
  return parsed.value;
}

/**
 * Union the capabilities exercised by host fixtures. Per-occurrence narrowing is
 * passed separately to Hooks; a later scenario must not replace earlier support.
 * @param {Array<{request: import("@agenthooksprotocol/sdk/draft").InterceptRequest}>} rows
 * @returns {import("@agenthooksprotocol/sdk/client").EventCapabilities}
 */
export function fixtureCapabilities(rows) {
  /** @type {import("@agenthooksprotocol/sdk/client").EventCapabilities} */
  const result = {};
  for (const { request } of rows) {
    const type = request.params.event.type;
    const decoded = sdkDraft.validateCapabilities(
      unionCapabilities(result[type], request.params.capabilities),
    );
    if (!decoded.ok) throw Error("Invalid fixture capability union");
    result[type] = decoded.value;
  }
  return result;
}
/** @param {unknown} left @param {unknown} right @param {string} [key] @returns {unknown} */
function unionCapabilities(left, right, key = "") {
  if (left === undefined) return structuredClone(right);
  if (Array.isArray(left) && Array.isArray(right))
    return [...new Set([...left, ...right])];
  if (typeof left === "number" && typeof right === "number")
    return key === "continuationCount"
      ? Math.min(left, right)
      : Math.max(left, right);
  if (typeof left === "boolean" && typeof right === "boolean")
    return left || right;
  if (
    left &&
    right &&
    typeof left === "object" &&
    typeof right === "object" &&
    !Array.isArray(left) &&
    !Array.isArray(right)
  ) {
    /** @type {Record<string, unknown>} */
    const result = { ...left };
    for (const [key, value] of Object.entries(right))
      result[key] = unionCapabilities(result[key], value, key);
    return result;
  }
  if (left !== right) throw Error("Conflicting fixture capability identity");
  return left;
}
