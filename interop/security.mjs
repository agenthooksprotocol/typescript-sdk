// @ts-check
import { sdkClient } from "./common.mjs";
const { Hooks, auth: sdkAuth, BackendTransport } = sdkClient;
import { createHmac, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import { readFileSync } from "node:fs";
import { request as http } from "node:http";
import { request as https } from "node:https";
/** Test-only network adapter. TLS identity is bound to exact event destinations;
 * upload and OAuth traffic retain their separate SDK/default bindings.
 * @param {{mode: string, caFile?: string, certFile?: string, keyFile?: string}} config
 * @param {string | string[]} [eventEndpoints]
 * @returns {typeof globalThis.fetch}
 */
export function fixtureFetch(config, eventEndpoints = []) {
  const endpoints = new Set(
    Array.isArray(eventEndpoints) ? eventEndpoints : [eventEndpoints],
  );
  return async (input, init = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    if (config.mode !== "mtls" || !endpoints.has(url))
      return fetch(input, init);
    if (!config.caFile || !config.certFile || !config.keyFile)
      throw Error("Missing TLS fixture identity");
    if (input instanceof Request)
      throw Error("Fixture TLS adapter expects SDK URL and init");
    if (
      init.body !== undefined &&
      typeof init.body !== "string" &&
      !(init.body instanceof Uint8Array)
    )
      throw Error("Unsupported fixture request body");
    const tls = {
      ca: readFileSync(config.caFile),
      cert: readFileSync(config.certFile),
      key: readFileSync(config.keyFile),
    };
    return new Promise((resolve, reject) => {
      const req = https(
        url,
        {
          method: init.method,
          headers: Object.fromEntries(new Headers(init.headers)),
          ...tls,
          ...(init.signal ? { signal: init.signal } : {}),
        },
        (response) => {
          const headers = new Headers();
          for (let i = 0; i < response.rawHeaders.length; i += 2)
            headers.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
          resolve(
            new Response(
              [204, 205, 304].includes(response.statusCode ?? 0)
                ? null
                : /** @type {ReadableStream<Uint8Array>} */ (
                    /** @type {unknown} */ (Readable.toWeb(response))
                  ),
              {
                status: response.statusCode,
                headers,
              },
            ),
          );
        },
      );
      req.on("error", reject);
      req.end(init.body);
    });
  };
}
export function authorize(req, auth) {
  // req.headers can silently retain only the first Authorization field.
  const raw = req.rawHeaders ?? [];
  if (
    raw.filter(
      (name, index) =>
        index % 2 === 0 && name.toLowerCase() === "authorization",
    ).length > 1
  )
    return false;
  if (auth.mode === "none") return true;
  if (auth.mode === "mtls") return req.socket.authorized === true;
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const token = header.slice(7);
  if (auth.mode === "bearer")
    return (
      typeof auth.token === "string" &&
      auth.token.length > 0 &&
      token === auth.token
    );
  if (!["oauth", "workload"].includes(auth.mode)) return false;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [h, p, s] = parts,
      header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
      claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    if (header.alg !== "HS256") return false;
    const key =
      auth.signingKey ?? `TEST-ONLY-ahp-interop-${auth.mode}-signing-key`;
    const expected = createHmac("sha256", key).update(`${h}.${p}`).digest(),
      supplied = Buffer.from(s, "base64url");
    const now = auth.clock ?? 1893456000;
    return (
      expected.length === supplied.length &&
      timingSafeEqual(expected, supplied) &&
      claims.iss === (auth.issuer ?? "urn:ahp:interop:local-issuer") &&
      claims.aud === (auth.audience ?? "urn:ahp:interop:local-server") &&
      claims.purpose === (auth.purpose ?? auth.mode) &&
      Number.isFinite(claims.exp) &&
      claims.exp > now &&
      (claims.nbf === undefined || claims.nbf <= now)
    );
  } catch {
    return false;
  }
}
/** Compose fixture credential sources with public SDK authentication defaults. */
export function fixtureAuth(config) {
  return sdkAuth({
    async authenticate(context, options) {
      // Upload bindings never inherit event bearer/workload/OAuth credentials,
      // including an explicitly anonymous upload at the same destination.
      if (context.purpose === "upload")
        return sdkAuth.authenticate(context, options);
      if (config.mode === "none" || config.mode === "mtls") return undefined;
      if (config.mode === "oauth") {
        const origin = new URL(config.tokenEndpoint).origin;
        return sdkAuth.clientCredentials(
          context,
          {
            client: {
              issuer: origin,
              resource: config.audience ?? "urn:ahp:interop:local-server",
              clientId: config.clientId,
              clientSecretRef: "fixture-secret",
              flow: "client_credentials",
            },
            metadata: {
              issuer: origin,
              token_endpoint: config.tokenEndpoint,
              grant_types_supported: ["client_credentials"],
              token_endpoint_auth_methods_supported: ["client_secret_post"],
            },
            parameters: new URLSearchParams({
              audience: config.audience ?? "urn:ahp:interop:local-server",
            }),
          },
          { ...options, allowedLoopbackOrigins: [origin] },
        );
      }
      if (config.mode === "workload") return { token: config.assertion };
      return sdkAuth.authenticate(
        {
          ...context,
          authentication: { type: "bearer", tokenRef: "fixture-token" },
        },
        options,
      );
    },
    resolveCredentialReference(name, context) {
      if (context?.purpose !== "upload") {
        if (name === "fixture-secret") return config.clientSecret;
        if (name === "fixture-token") return config.token;
      }
      return sdkAuth.resolveCredentialReference(name, context);
    },
  });
}
export async function accessToken(config) {
  const provider = fixtureAuth(config);
  return (
    await provider.authenticate({
      url: config.tokenEndpoint ?? "https://fixture.invalid",
      signal: AbortSignal.timeout(10000),
    })
  )?.token;
}
/** Raw status/duplicate-header/legacy mTLS probes and non-protocol fixture routes. */
export function sendStatus(endpoint, path, payload, auth, token) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, endpoint),
      tls =
        auth.mode === "mtls"
          ? {
              ca: readFileSync(auth.caFile),
              cert: readFileSync(auth.certFile),
              key: readFileSync(auth.keyFile),
            }
          : {};
    const req = (url.protocol === "https:" ? https : http)(
      url,
      {
        method: payload === undefined ? "GET" : "POST",
        ...tls,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (chunk) => {
          text += chunk;
          if (text.length > 4194304) req.destroy(Error("Oversized response"));
        });
        res.on("end", () => {
          try {
            resolve({
              status: res.statusCode,
              value: text ? JSON.parse(text) : null,
            });
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.setTimeout(15000, () => req.destroy(Error("HTTP watchdog")));
    req.on("error", reject);
    req.end(payload === undefined ? undefined : JSON.stringify(payload));
  });
}

/** Compatibility boundary bridge; the SDK owns event framing and response validation. */
export async function send(endpoint, path, payload, config, token) {
  if (["hooks/intercept", "hooks/observe"].includes(payload?.method)) {
    const observe = payload.method === "hooks/observe";
    const event = payload.params.event;
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "interop.fixture",
            transport: { type: "http", url: new URL(path, endpoint).href },
            subscriptions: [
              {
                mode: observe ? "observe" : "intercept",
                events: [event.type],
                ...(!observe
                  ? { timeoutMs: 15000, failurePolicy: "fail-closed" }
                  : {}),
                content: { default: "metadata" },
              },
            ],
          },
        ],
      },
      {
        source: event.source,
        capabilities: observe
          ? {}
          : { [event.type]: payload.params.capabilities },
        fetch: fixtureFetch(config, new URL(path, endpoint).href),
        auth: token
          ? sdkAuth({ authenticate: async () => ({ token }) })
          : fixtureAuth(config),
      },
    );
    try {
      const { type, source, ...input } = event;
      const result = await client.dispatch(type, input);
      const errors = [...result.errors, ...(await result.observations)];
      if (errors.length)
        throw Object.assign(Error("SDK delivery failed"), { errors });
      if (observe) return null;
      return { jsonrpc: "2.0", id: payload.id, result: result.response };
    } finally {
      await client.close();
    }
  }
  if (payload?.method === "hooks/capabilities") {
    const url = new URL(path, endpoint).href;
    const network = fixtureFetch(config, url);
    const provider = fixtureAuth(config);
    const transport = new BackendTransport(
      {
        id: "interop.discovery",
        transport: { type: "http", url },
        subscriptions: [],
      },
      async (target, init) => {
        const credential = token
          ? { token }
          : await provider.authenticate({ url: target });
        const headers = new Headers(init.headers);
        if (credential)
          headers.set("authorization", `Bearer ${credential.token}`);
        return network(target, { ...init, headers });
      },
    );
    try {
      return await transport.request(payload, AbortSignal.timeout(15000));
    } finally {
      await transport.close();
    }
  }
  // GET control routes and negative/raw protocol probes are not SDK boundaries.
  const response = await sendStatus(endpoint, path, payload, config, token);
  if (response.status !== 200) throw Error(`HTTP failure: ${response.status}`);
  return response.value;
}
