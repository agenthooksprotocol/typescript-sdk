// @ts-check
import { sdkClient, sdkServer, sdkDraft } from "./common.mjs";
import { createServer } from "node:http";
import { Readable } from "node:stream";
const { Hooks, auth } = sdkClient;
const { attachments, hooks } = sdkServer;
import { connect as tcpConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash, randomUUID } from "node:crypto";
export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export function uploadURL(endpoint, allowLoopback = false) {
  const url = new URL(endpoint);
  if (
    url.username ||
    url.password ||
    url.hash ||
    (url.protocol !== "https:" &&
      !(
        allowLoopback &&
        url.protocol === "http:" &&
        (["localhost", "[::1]"].includes(url.hostname) ||
          /^127(?:\.[0-9]{1,3}){3}$/.test(url.hostname))
      ))
  )
    throw Error("Unsafe upload endpoint");
  return url;
}
/** Compatibility fixture: upload via an SDK boundary, never a second uploader.
 * A local hook captures the published descriptor; the configured upload endpoint
 * remains the receiver under test. SDK delivery failures reject.
 */
export async function uploadBytes(
  upload,
  bytes,
  { allowLoopback = false, env = process.env } = {},
) {
  uploadURL(upload.endpoint, allowLoopback);
  if (!(bytes instanceof Uint8Array)) throw Error("Invalid upload input");
  /** @type {{ref: string} | undefined} */
  let descriptor;
  const receiver = createServer(async (incoming, outgoing) => {
    try {
      const response = await hooks.handle(
        new Request("http://localhost/hooks", {
          method: incoming.method,
          headers: new Headers(
            incoming.rawHeaders.reduce(
              (pairs, name, i, values) =>
                i % 2 ? pairs : [...pairs, [name, values[i + 1]]],
              /** @type {[string, string][]} */ ([]),
            ),
          ),
          // Node and DOM declare distinct WHATWG stream types; IncomingMessage
          // emits Uint8Array chunks and toWeb preserves that runtime contract.
          body: /** @type {ReadableStream<Uint8Array>} */ (
            /** @type {unknown} */ (Readable.toWeb(incoming))
          ),
          ...{ duplex: "half" },
        }),
        (message) => {
          if (
            message.method !== "hooks/intercept" ||
            message.params.event.type !== "tool.before"
          )
            throw Error("Unexpected fixture event");
          const parsed = sdkDraft.draftCodecs.parseContentReference(
            message.params.event.items?.[0]?.body,
          );
          if (!parsed.ok) throw Error("Missing SDK upload descriptor");
          descriptor = parsed.value;
          return { effects: [] };
        },
      );
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(new Uint8Array(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(500).end();
    }
  });
  await new Promise((resolve) =>
    receiver.listen(0, "127.0.0.1", () => resolve(undefined)),
  );
  const address = receiver.address();
  if (!address || typeof address === "string")
    throw Error("Missing fixture address");
  let client;
  try {
    client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "interop.upload",
            transport: {
              type: "http",
              url: `http://127.0.0.1:${address.port}/hooks`,
            },
            subscriptions: [
              {
                mode: "intercept",
                events: ["tool.before"],
                failurePolicy: "fail-closed",
                timeoutMs: upload.timeoutMs ?? 15000,
                content: { default: "body" },
                upload: { timeoutMs: 15000, maxBytes: 52428800, ...upload },
              },
            ],
          },
        ],
      },
      {
        source: "urn:ahp:interop:upload",
        capabilities: { "tool.before": { effects: [] } },
        auth: auth({ resolveEnvironmentVariable: (name) => env[name] }),
      },
    );
    const result = await client.dispatch("tool.before", {
      call: { id: "upload" },
      path: "native",
      tool: { name: "upload", origin: "native", input: {} },
      items: [
        {
          id: "bytes",
          kind: "attachment",
          mediaType: "application/octet-stream",
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(bytes));
              controller.close();
            },
          }),
        },
      ],
    });
    if (result.errors.length || !descriptor)
      throw Object.assign(Error("Required SDK upload failed"), {
        errors: result.errors,
      });
    // The SDK verified the upload receipt before exposing the ref-only event.
    return { status: 201, body: { ref: descriptor.ref, size: bytes.length, sha256: digest(bytes) } };
  } finally {
    await client?.close();
    receiver.closeAllConnections();
    await new Promise((resolve) => receiver.close(resolve));
  }
}
/** Adversarial wire probes only: deliberately bypass SDK upload validation. */
/** @param {{endpoint: string, timeoutMs?: number, maxBytes?: number, auth?: {type: string, tokenEnv: string}}} upload
 * @param {Uint8Array} bytes
 * @param {{allowLoopback?: boolean, env?: Record<string, string | undefined>, declaredSize?: number, declaredHash?: string}} [options] */
export async function rawUploadBytes(upload, bytes, options = {}) {
  const {
    allowLoopback = false,
    env = process.env,
    declaredSize,
    declaredHash,
  } = options;
  if (
    upload.timeoutMs !== undefined &&
    (!Number.isSafeInteger(upload.timeoutMs) || upload.timeoutMs < 1)
  )
    throw Error("Invalid upload timeout");
  if (
    upload.maxBytes !== undefined &&
    (!Number.isSafeInteger(upload.maxBytes) || upload.maxBytes < 0)
  )
    throw Error("Invalid upload limit");
  if (
    upload.auth !== undefined &&
    (!upload.auth ||
      upload.auth.type !== "bearer" ||
      typeof upload.auth.tokenEnv !== "string" ||
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(upload.auth.tokenEnv))
  )
    throw Error("Invalid upload authentication");
  if (!(bytes instanceof Uint8Array)) throw Error("Invalid upload input");
  const snapshot = Buffer.from(bytes),
    headers = {
      "content-type": "application/octet-stream",
      "content-length": String(snapshot.length),
      "ahp-content-sha256": digest(snapshot),
    };
  if (declaredSize !== undefined)
    headers["content-length"] = String(declaredSize);
  if (declaredHash !== undefined) headers["ahp-content-sha256"] = declaredHash;
  if (upload.auth) {
    if (upload.auth.type !== "bearer" || !env[upload.auth.tokenEnv])
      throw Error("Missing upload credential");
    headers.authorization = `Bearer ${env[upload.auth.tokenEnv]}`;
  }
  if (snapshot.length > (upload.maxBytes ?? 52428800))
    throw Error("Upload limit");
  if (Object.values(headers).some((value) => /[\r\n]/.test(value)))
    throw Error("Invalid upload framing");
  const url = uploadURL(upload.endpoint, allowLoopback);
  if (declaredSize !== undefined && declaredSize !== snapshot.length) {
    const status = await new Promise((resolve, reject) => {
      const connect =
        url.protocol === "https:"
          ? (options, listener) => tlsConnect(options, listener)
          : (options, listener) => tcpConnect(options, listener);
      const socket = connect(
        {
          host: url.hostname,
          port: Number(url.port) || (url.protocol === "https:" ? 443 : 80),
          allowHalfOpen: true,
        },
        () => {
          socket.end(
            Buffer.concat([
              Buffer.from(
                `POST ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n${Object.entries(
                  headers,
                )
                  .map(([k, v]) => `${k}: ${v}`)
                  .join("\r\n")}\r\n\r\n`,
              ),
              snapshot,
            ]),
          );
        },
      );
      let response = "";
      socket.setTimeout(upload.timeoutMs ?? 15000, () =>
        socket.destroy(Error("Upload watchdog")),
      );
      socket.on("error", reject);
      socket.on("data", (chunk) => (response += chunk.toString()));
      socket.on("end", () => {
        const match = /^HTTP\/1\.[01] ([0-9]{3})/.exec(response);
        socket.destroy();
        match
          ? resolve(Number(match[1]))
          : reject(Error("No HTTP upload response"));
      });
    });
    return { status };
  }
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: snapshot,
    redirect: "error",
    signal: AbortSignal.timeout(upload.timeoutMs ?? 15000),
  });
  if (response.status !== 201) {
    await response.arrayBuffer();
    return { status: response.status };
  }
  if (
    response.headers.get("content-type")?.split(";")[0].trim() !==
    "application/json"
  )
    throw Error("Invalid upload confirmation media type");
  const body = await response.json();
  if (
    !body ||
    typeof body.ref !== "string" ||
    !body.ref ||
    !Number.isSafeInteger(body.size) ||
    body.size !== snapshot.length ||
    !/^[a-f0-9]{64}$/.test(body.sha256 ?? "") ||
    body.sha256 !== digest(snapshot)
  )
    throw Error("Invalid upload confirmation");
  return {
    status: 201,
    body: { ref: body.ref, size: body.size, sha256: body.sha256 },
  };
}
export class UploadStore {
  constructor(authorize, maxBytes = 52428800) {
    this.authorize = authorize;
    this.maxBytes = maxBytes;
    this.values = new Map();
  }
  async receive(req) {
    const metadata = {
      size: Number(req.headers["content-length"]),
      sha256: req.headers["ahp-content-sha256"],
    };
    const names = (req.rawHeaders ?? [])
      .filter((_, i) => i % 2 === 0)
      .map((name) => name.toLowerCase());
    if (
      [
        "authorization",
        "content-type",
        "content-length",
        "ahp-content-sha256",
      ].some((name) => names.filter((value) => value === name).length > 1)
    ) {
      req.resume();
      return { ...metadata, status: 400 };
    }
    const scope = this.authorize(req.headers.authorization);
    if (typeof scope !== "string" || !scope) {
      req.resume();
      return { ...metadata, status: typeof scope === "number" ? scope : 403 };
    }
    try {
      const upload = attachments.parse(
        new Request("http://localhost/upload", {
          method: req.method,
          headers: req.headers,
          body: /** @type {ReadableStream<Uint8Array>} */ (
            /** @type {unknown} */ (Readable.toWeb(req))
          ),
          ...{ duplex: "half" },
        }),
      );
      if (upload.size > this.maxBytes) {
        await upload.body.cancel();
        return { ...metadata, status: 413 };
      }
      // Publish only after the SDK stream verifies EOF.
      const bytes = Buffer.from(await new Response(upload.body).arrayBuffer());
      const ref = randomUUID();
      const descriptor = { ref, size: upload.size, sha256: upload.sha256 };
      this.values.set(JSON.stringify([scope, ref]), { bytes, ...descriptor });
      const response = attachments.response(descriptor);
      return { ...(await response.json()), status: response.status };
    } catch {
      req.resume();
      return { ...metadata, status: 400 };
    }
  }

  resolve(scope, body) {
    const stored = this.values.get(JSON.stringify([scope, body.ref]));
    if (!stored)
      throw Object.assign(Error("Unavailable scoped content"), { status: 409 });
    return Buffer.from(stored.bytes);
  }
}
/** Only authenticated upload policy selects a scope; message IDs never do. */
export function authorizeUpload(config, authorization) {
  if (config.uploadAuth) {
    const policy = config.uploadAuth;
    return typeof policy.token === "string" &&
      policy.token.length > 0 &&
      authorization === `Bearer ${policy.token}`
      ? (policy.scope ?? "default")
      : 401;
  }
  const matches = Object.entries(config.uploadSubscriptions ?? {}).filter(
    ([, policy]) => {
      if (policy.auth) {
        const token = process.env[policy.auth.tokenEnv];
        return (
          policy.auth.type === "bearer" &&
          token &&
          authorization === `Bearer ${token}`
        );
      }
      return policy.anonymous === true && authorization === undefined;
    },
  );
  if (matches.length === 0) return 401;
  if (matches.length !== 1) return 403;
  const [name, policy] = matches[0];
  return policy.authorized === false ? 403 : (policy.scope ?? name);
}
/** @typedef {{ref: string, size: number, sha256: string}} ContentDescriptor */
/** @typedef {{descriptor: ContentDescriptor, bytes: string}} ContentSource */
/** @typedef {{sourceRef: string, descriptor: ContentDescriptor}} ContentUploadReport */
/** Per-operation userland stream handoff and observation of real confirmations.
 * Use only on positive SDK paths. Bypass probes must retain their original wire
 * descriptors and must not call hydrate. No SDK content registry is involved.
 * @param {ContentSource[]} [contentSources]
 * @param {typeof fetch} [networkFetch]
 * @param {string[]} [uploadEndpoints]
 */
export function createContentAdapter(
  contentSources = [],
  networkFetch = fetch,
  uploadEndpoints = [],
) {
  /** @type {Array<{descriptor: ContentDescriptor, confirmed: boolean}>} */
  const selected = [];
  /** @type {ContentUploadReport[]} */
  const contentUploads = [];
  const endpoints = new Set(
    uploadEndpoints.map((endpoint) => new URL(endpoint).href),
  );
  return {
    contentUploads,
    /** @param {{items?: Array<{body?: unknown, [key: string]: unknown}>}} event */
    hydrate(event) {
      for (const item of event.items ?? []) {
        if (!item.body) continue;
        const parsed = sdkDraft.draftCodecs.parseContentReference(item.body);
        if (!parsed.ok) throw Error("Invalid content source descriptor");
        const descriptor = parsed.value;
        const source = contentSources.find(
          ({ descriptor: candidate }) =>
            candidate?.ref === descriptor.ref,
        );
        if (!source || typeof source.bytes !== "string")
          throw Error("Unavailable exact content source");
        const bytes = Buffer.from(source.bytes, "base64");
        if (
          bytes.length !== source.descriptor.size ||
          digest(bytes) !== source.descriptor.sha256
        )
          throw Error("Content source integrity mismatch");
        selected.push({ descriptor: { ...source.descriptor }, confirmed: false });
        item.body = new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(bytes));
            controller.close();
          },
        });
      }
    },
    /** @param {Parameters<typeof fetch>[0]} input @param {Parameters<typeof fetch>[1]} [init] */
    async fetch(input, init) {
      const request = new Request(input, init);
      const observe =
        endpoints.has(request.url) &&
        request.method === "POST" &&
        request.headers.get("content-type") === "application/octet-stream";
      const requestCopy = observe ? request.clone() : undefined;
      const response = await networkFetch(input, init);
      if (
        !requestCopy ||
        response.status !== 201 ||
        response.headers
          .get("content-type")
          ?.split(";")[0]
          .trim()
          .toLowerCase() !== "application/json"
      )
        return response;
      // Read clones only: the SDK still validates and consumes the real response.
      try {
        const [bytes, body] = await Promise.all([
          requestCopy.arrayBuffer(),
          response.clone().json(),
        ]);
        const parsed = sdkDraft.draftCodecs.parseContentUploadReceipt(body);
        const sha256 = digest(new Uint8Array(bytes));
        if (
          !parsed.ok ||
          parsed.value.size !== bytes.byteLength ||
          parsed.value.sha256 !== sha256
        )
          return response;
        const source = selected.find(
          (entry) =>
            !entry.confirmed &&
            entry.descriptor.size === bytes.byteLength &&
            entry.descriptor.sha256 === sha256,
        );
        if (source) {
          source.confirmed = true;
          contentUploads.push({
            sourceRef: source.descriptor.ref,
            descriptor: { ...parsed.value },
          });
        }
      } catch {
        // Invalid confirmations remain SDK errors, never manufactured reports.
      }
      return response;
    },
  };
}
/** Fixture labels select local policy, never wire encoding or authorization grants. */
export async function prepareRequestContent(
  request,
  bodies,
  config,
  subscription,
) {
  const policy =
    subscription === undefined && config.subscriptions?.length === 1
      ? config.subscriptions[0]
      : config.subscriptions?.find((value) => value.id === subscription);
  for (const item of request.params.event.items ?? [])
    if (item.body) {
      const category =
        item.kind === "reasoning" ? "reasoning" : (item.category ?? item.kind);
      if (
        !policy?.upload ||
        policy.authorizedContent?.includes(category) !== true ||
        (policy.content?.[category] ?? policy.content?.default) !== "body"
      )
        throw Error("Content not selected and authorized");
      const source = bodies?.find((value) => value.ref === item.body.ref);
      if (!source || typeof source.bodyBase64 !== "string")
        throw Error("Unavailable fixture bytes");
      const bytes = Buffer.from(source.bodyBase64, "base64");
      // Compatibility hydration only: the caller's real Hooks boundary owns upload.
      item.body = new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    }
}
