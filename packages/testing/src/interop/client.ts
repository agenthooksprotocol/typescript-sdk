import { spawn } from "node:child_process";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { readFileSync } from "node:fs";
import process from "node:process";
import { NdjsonDecoder } from "agenthooksprotocol";
import {
  parseInterceptRequest,
  parseInterceptResponse,
} from "agenthooksprotocol/draft";
import { createAuth, clientAuth } from "./auth.js";
import { Hooks, type BoundaryInput } from "agenthooksprotocol/client";

interface Scenario {
  id: string;
  transport: string;
  auth: string;
  credential: string;
  expected: string;
}
export interface ScenarioResult {
  id: string;
  transport: string;
  auth: string;
  status: "passed" | "failed" | "inapplicable";
  expected: string;
  actual: string;
}
const fixture = (name: string) =>
  readFileSync(
    new URL(`../../../interop/fixtures/${name}`, import.meta.url).pathname,
    "utf8",
  );
export function resolveCredential(
  reference: string,
  environment: Record<string, string | undefined>,
  credentials: Record<string, string>,
): string {
  const [kind, name] = reference.split(":");
  const value =
    name === undefined
      ? undefined
      : kind === "env"
        ? environment[name]
        : kind === "credential"
          ? credentials[name]
          : undefined;
  if (!value) throw new Error("Unresolved test credential reference");
  return value;
}
export function request(
  port: number,
  path: string,
  body: string,
  authorization?: string,
  tlsOptions?: object,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = (tlsOptions ? httpsRequest : httpRequest)(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: "POST",
        agent: false,
        ...tlsOptions,
        headers: {
          "content-type":
            path === "/token"
              ? "application/x-www-form-urlencoded"
              : "application/json",
          ...(authorization ? { authorization } : {}),
        },
      },
      (res: any) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          data += chunk;
          if (data.length > 1024 * 1024)
            req.destroy(new Error("Oversized response"));
        });
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
        res.on("error", reject);
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error("Request deadline")));
    req.on("error", reject);
    req.end(body);
  });
}
export async function runInterop(): Promise<{
  format: string;
  ok: boolean;
  results: ScenarioResult[];
}> {
  const definitions = JSON.parse(
    readFileSync(
      new URL("../../../interop/scenarios.json", import.meta.url).pathname,
      "utf8",
    ),
  ) as { request: unknown; scenarios: Scenario[] };
  const auth = createAuth();
  const child = spawn(
    process.execPath,
    [new URL("./server.js", import.meta.url).pathname],
    { stdio: ["pipe", "pipe", "pipe", "ipc"], shell: false },
  );
  let pending:
    | { resolve: (line: string) => void; reject: (error: Error) => void }
    | undefined;
  const decoder = new NdjsonDecoder();
  const tlsRejections = new Set<string>();
  child.on("message", (message: any) => {
    if (message.type === "tls-rejection") tlsRejections.add(message.code);
  });
  let stdoutFailure = false;
  // Never retain or report stderr: diagnostics may contain credentials in future adapters.
  child.stderr.resume();
  child.stdout.on("data", (chunk: Uint8Array) => {
    try {
      for (const line of decoder.push(chunk)) {
        if (!pending) throw new Error("Unsolicited stdout frame");
        const waiter = pending;
        pending = undefined;
        waiter.resolve(line);
      }
    } catch {
      stdoutFailure = true;
      pending?.reject(new Error("Invalid stdout framing"));
    }
  });
  const exited = new Promise<number | null>((resolve) =>
    child.once("exit", (code: number | null) => {
      pending?.reject(new Error("Server exited"));
      resolve(code);
    }),
  );
  let publicStdio: Hooks | undefined;
  const deadline = setTimeout(() => {
    child.kill();
  }, 15000);
  try {
    const ready = await new Promise<{ httpPort: number; httpsPort: number }>(
      (resolve, reject) => {
        child.once("message", (message: any) =>
          message.type === "ready"
            ? resolve(message)
            : reject(new Error("Invalid readiness")),
        );
        child.once("error", reject);
        child.once("exit", () =>
          reject(new Error("Server failed before readiness")),
        );
      },
    );
    // Platform TLS injection only: Hooks still composes, authenticates and validates AHP.
    // Exact endpoint matching prevents upload or OAuth traffic inheriting TLS identity.
    // Keep this typed adapter local: root interop/security.mjs is outside package rootDir
    // and loads its own SDK runtime through the root runner.
    const tlsOrigin = `https://127.0.0.1:${ready.httpsPort}`;
    const tlsFetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.href !== `${tlsOrigin}/mtls`) return fetch(input, init);
      const wire = new Request(input, init);
      const bytes = new Uint8Array(await wire.arrayBuffer());
      return new Promise<Response>((resolve, reject) => {
        const req = httpsRequest(
          {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: wire.method,
            headers: Object.fromEntries(wire.headers),
            ca: fixture("ca.pem"),
            cert: fixture("client.pem"),
            key: fixture("client-key.pem"),
            rejectUnauthorized: true,
            agent: false,
          },
          (res: {
            statusCode?: number;
            headers: Record<string, string | string[] | undefined>;
            on(event: "data", listener: (chunk: Uint8Array) => void): void;
            on(event: "error", listener: (error: Error) => void): void;
            on(event: "end", listener: () => void): void;
          }) => {
            const chunks: Uint8Array[] = [];
            let size = 0;
            res.on("data", (chunk: Uint8Array) => {
              size += chunk.byteLength;
              if (size > 1024 * 1024)
                req.destroy(new Error("Oversized response"));
              else chunks.push(chunk);
            });
            res.on("error", reject);
            res.on("end", () => {
              const headers = new Headers();
              for (const [name, value] of Object.entries(res.headers)) {
                if (Array.isArray(value))
                  for (const entry of value) headers.append(name, entry);
                else if (value !== undefined) headers.set(name, value);
              }
              resolve(
                new Response(Buffer.concat(chunks), {
                  status: res.statusCode ?? 500,
                  headers,
                }),
              );
            });
          },
        );
        const abort = () => req.destroy(new Error("Request aborted"));
        wire.signal.addEventListener("abort", abort, { once: true });
        req.on("close", () => wire.signal.removeEventListener("abort", abort));
        req.on("error", reject);
        req.setTimeout(5000, () => req.destroy(new Error("Request deadline")));
        if (wire.signal.aborted) abort();
        else req.end(bytes);
      });
    };
    const stdio = (body: string): Promise<string> =>
      new Promise((resolve, reject) => {
        pending = { resolve, reject };
        child.stdin.write(body + "\n");
      });
    const outcome = (line: string, malformed: boolean): string => {
      if (malformed)
        return JSON.parse(line).error?.code === -32600
          ? "invalid-request"
          : "unexpected-response";
      const result = parseInterceptResponse(line);
      if (!result.ok || result.value.id !== "synthetic-request")
        throw Error("Invalid canonical response");
      return result.value.result.effects.length === 0
        ? "no-effect"
        : "unexpected-effect";
    };
    async function positive(s: Scenario): Promise<string> {
      const parsed = parseInterceptRequest(JSON.stringify(definitions.request));
      if (!parsed.ok || parsed.value.params.event.type !== "tool.before")
        throw Error("Invalid tool fixture");
      const event = parsed.value.params.event as import("agenthooksprotocol/client").ToolBeforeEvent;
      const origin =
        s.auth === "mtls" ? tlsOrigin : `http://127.0.0.1:${ready.httpPort}`;
      const authentication =
        s.auth === "bearer"
          ? {
              type: "bearer",
              ...(s.credential === "env"
                ? { tokenEnv: "AHP_TEST_BEARER" }
                : { tokenRef: "bearer" }),
            }
          : s.auth === "oauth"
            ? {
                type: "oauth",
                issuer: "https://issuer.interop.test",
                resource: origin,
                clientId: auth.credentials.clientId,
                clientSecretRef: "client-secret",
                flow: "client_credentials",
              }
            : undefined;
      const hooks =
        s.transport === "stdio" && publicStdio
          ? publicStdio
          : new Hooks(
              {
                protocolVersion: "draft",
                hooks: [
                  {
                    id: "interop.public",
                    transport:
                      s.transport === "stdio"
                        ? {
                            type: "stdio",
                            lifecycle: "persistent",
                            command: process.execPath,
                            args: [
                              new URL("./server.js", import.meta.url).pathname,
                            ],
                          }
                        : { type: "http", url: `${origin}/${s.auth}` },
                    ...(authentication ? { authentication } : {}),
                    subscriptions: [
                      {
                        mode: "intercept",
                        events: ["tool.before"],
                        content: { default: "metadata" },
                        failurePolicy: "fail-closed",
                        timeoutMs: 5000,
                      },
                    ],
                  },
                ],
              },
              {
                source: event.source,
                capabilities: {
                  "tool.before": parsed.value.params.capabilities,
                },
                auth: clientAuth(s.auth, origin),
                ...(s.auth === "mtls" ? { fetch: tlsFetch } : {}),
              },
            );
      if (s.transport === "stdio") publicStdio = hooks;
      try {
        const boundary: BoundaryInput<"tool.before"> = {
          id: event.id,
          time: event.time,
          ...(event.session ? { session: event.session } : {}),
          call: event.call,
          path: event.path,
          tool: event.tool,
        };
        const result = await hooks.dispatch("tool.before", boundary);
        const observations = await result.observations;
        if (result.errors.length || observations.length || result.interrupted)
          return "sdk-delivery-error";
        if (result.event.id !== event.id) return "unexpected-event";
        return result.response.result.effects.length === 0
          ? "no-effect"
          : "unexpected-effect";
      } finally {
        if (s.transport !== "stdio") await hooks.close();
      }
    }
    async function execute(s: Scenario): Promise<ScenarioResult> {
      let actual = "adapter-error";
      if (s.transport === "stdio" && s.auth !== "process-trust")
        actual = "inapplicable";
      else
        try {
          const malformed = s.credential === "malformed";
          const body = malformed
            ? '{"jsonrpc":"2.0"}'
            : JSON.stringify(definitions.request);
          if (!malformed && !parseInterceptRequest(body).ok)
            throw Error("Invalid canonical request"); // client-side SDK validation, not JSON echo
          // Malformed and adversarial probes intentionally control raw wire.
          if (s.expected === "no-effect") actual = await positive(s);
          else if (s.transport === "stdio")
            actual = outcome(await stdio(body), malformed);
          else {
            let authorization: string | undefined;
            const c = s.credential;
            if (c === "invalid" && s.auth !== "mtls")
              authorization = "Bearer invalid-fixture";
            if (
              (s.auth === "bearer" && ["valid", "env"].includes(c)) ||
              c === "bearer"
            ) {
              const value = resolveCredential(
                c === "env" ? "env:AHP_TEST_BEARER" : "credential:bearer",
                { AHP_TEST_BEARER: auth.credentials.bearer },
                { bearer: auth.credentials.bearer },
              );
              authorization = `Bearer ${value}`;
            }
            if (
              (s.auth === "oauth" &&
                ["valid", "bad-client", "missing-client", "bad-grant"].includes(
                  c,
                )) ||
              c === "oauth"
            ) {
              const form = new URLSearchParams({
                grant_type:
                  c === "bad-grant" ? "password" : "client_credentials",
                client_id: auth.credentials.clientId,
                client_secret:
                  c === "missing-client"
                    ? ""
                    : c === "bad-client"
                      ? "wrong"
                      : auth.credentials.clientSecret,
              });
              const token = await request(
                ready.httpPort,
                "/token",
                form.toString(),
              );
              if (token.status !== 200)
                actual =
                  token.status === 401 || token.status === 400
                    ? "token-rejected"
                    : "unexpected-status";
              else
                authorization = `Bearer ${JSON.parse(token.body).access_token}`;
            }
            if (
              s.auth === "workload" &&
              ["valid", "untrusted", "issuer", "audience", "expired"].includes(
                c,
              )
            ) {
              authorization = `Bearer ${auth.assertion({ ...(c === "untrusted" ? { untrusted: true } : {}), ...(c === "issuer" ? { issuer: "untrusted" } : {}), ...(c === "audience" ? { audience: "wrong" } : {}), ...(c === "expired" ? { expired: true } : {}) })}`;
            }
            if (actual !== "token-rejected") {
              const tls =
                s.transport === "https"
                  ? {
                      ca: fixture(
                        c === "bad-server-ca" ? "untrusted-ca.pem" : "ca.pem",
                      ),
                      ...(c === "missing"
                        ? {}
                        : {
                            cert: fixture(
                              c === "invalid"
                                ? "untrusted-client.pem"
                                : "client.pem",
                            ),
                            key: fixture(
                              c === "invalid"
                                ? "untrusted-client-key.pem"
                                : "client-key.pem",
                            ),
                          }),
                    }
                  : undefined;
              try {
                const response = await request(
                  tls ? ready.httpsPort : ready.httpPort,
                  "/" + s.auth,
                  body,
                  authorization,
                  tls,
                );
                actual =
                  response.status === 401
                    ? "unauthorized"
                    : response.status === 200
                      ? outcome(response.body, malformed)
                      : "unexpected-status";
              } catch (error) {
                // Only TLS-specific failures count, never connection refusal or timeout.
                const code = (error as { code?: string }).code ?? "";
                actual =
                  tls && /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code)
                    ? "tls-rejected"
                    : tls && c === "invalid" && code === "ECONNRESET"
                      ? "tls-reset"
                      : "transport-error";
              }
            }
          }
        } catch {
          actual = "adapter-error";
        }
      return {
        id: s.id,
        transport: s.transport,
        auth: s.auth,
        expected: s.expected,
        actual,
        status:
          actual !== s.expected
            ? "failed"
            : actual === "inapplicable"
              ? "inapplicable"
              : "passed",
      };
    }
    // Both listeners are live in one process; HTTP executes while stdio is active.
    const stdioRows = definitions.scenarios.filter(
      (s) => s.transport === "stdio",
    );
    const httpRows = definitions.scenarios.filter(
      (s) => s.transport !== "stdio",
    );
    const [stdioResults, httpResults] = await Promise.all([
      (async () => {
        const rows: ScenarioResult[] = [];
        for (const s of stdioRows) rows.push(await execute(s));
        return rows;
      })(),
      Promise.all(httpRows.map(execute)),
    ]);
    child.stdin.end();
    const exitCode = await exited;
    decoder.end();
    // Node/OpenSSL may close an untrusted client handshake with ECONNRESET.
    // Require server-side certificate-verification evidence, not merely a reset.
    for (const row of httpResults) {
      if (
        row.id === "mtls-invalid" &&
        row.actual === "tls-reset" &&
        [...tlsRejections].some((code) =>
          /^(SELF_SIGNED_CERT_IN_CHAIN|DEPTH_ZERO_SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT_LOCALLY|CERT_SIGNATURE_FAILURE|ERR_SSL_INVALID_PADDING)$/.test(
            code,
          ),
        )
      ) {
        row.actual = "tls-rejected";
        row.status = "passed";
      }
    }
    const byId = new Map(
      [...stdioResults, ...httpResults].map((row) => [row.id, row]),
    );
    const results = definitions.scenarios.map((row) => byId.get(row.id)!);
    return {
      format: "ahp-synthetic-interop-results/1",
      ok:
        exitCode === 0 &&
        !stdoutFailure &&
        results.every((r) => r.status !== "failed"),
      results,
    };
  } finally {
    clearTimeout(deadline);
    await publicStdio?.close();
    child.kill();
    await exited;
  }
}
