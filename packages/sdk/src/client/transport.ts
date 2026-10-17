import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { channel } from "node:diagnostics_channel";
import type {
  Backend,
  HttpTransport,
  StdioTransport,
} from "../draft/raw.js";
import { HookOperationalError } from "../errors.js";
import { NdjsonDecoder } from "../framing.js";
import { parseJson, stringifyJson } from "../json.js";

import { resolveHeaders, validateHeaders, type HeaderResolver } from "./headers.js";

type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
type Pending = {
  message: any;
  notification: boolean;
  resolve(value: unknown): void;
  reject(error: unknown): void;
  response?: unknown;
};
type ProcessState = {
  child: ChildProcessWithoutNullStreams;
  closed: Promise<void>;
  pending: Map<unknown, Pending>;
  stopped: boolean;
};

/** SDK options for `BackendTransport`; not part of the protocol registration. */
export interface BackendTransportOptions {
  /** Start stdio backends with the full host environment instead of the minimal
   * base environment. Registration `env` entries still apply on top. Default false. */
  inheritEnvironment?: boolean;
  /** Resolve registration header sources within the event operation budget. */
  headerResolver?: HeaderResolver | undefined;
}

// Smallest practical base environment for stdio backends (transports/stdio.md).
const BASE_ENVIRONMENT = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP",
];
const WINDOWS_BASE_ENVIRONMENT = [
  "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
];

/** Build a stdio backend environment: a base allowlist (or the full host
 * environment when inherited), then registration `env` entries as literal
 * overrides. Windows names compare case-insensitively. Values are never logged. */
export function backendEnvironment(
  env: Readonly<Record<string, string>> | undefined,
  inherit: boolean,
  host: Readonly<Record<string, string | undefined>> = process.env,
  platform: string = process.platform,
): Record<string, string> {
  const windows = platform === "win32";
  const fold = (name: string) => (windows ? name.toUpperCase() : name);
  const allowed = new Set(
    (windows ? [...BASE_ENVIRONMENT, ...WINDOWS_BASE_ENVIRONMENT] : BASE_ENVIRONMENT).map(fold),
  );
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(host)) {
    if (value === undefined) continue;
    const key = fold(name);
    if (inherit || allowed.has(key) || key.startsWith("LC_")) result[name] = value;
  }
  for (const [name, value] of Object.entries(env ?? {})) {
    if (windows)
      for (const existing of Object.keys(result))
        if (fold(existing) === fold(name)) delete result[existing];
    result[name] = value;
  }
  return result;
}

function failure(message: string): Error {
  return new HookOperationalError("IO_ERROR", message);
}

/** Consecutive malformed frames a persistent backend may emit before it is terminated. */
const MALFORMED_FRAME_BUDGET = 3;

/** Out-of-band stdio diagnostics. Messages carry no frame content. */
export interface StdioDiagnostic {
  backendId: string;
  /** `unsolicited`: a well-formed response for no pending request.
   * `malformed`: a frame that is not one valid JSON-RPC response. */
  kind: "unsolicited" | "malformed";
  code?: HookOperationalError["code"];
  /** Consecutive malformed frames, including this one. */
  strikes: number;
  /** Whether this frame exhausted the budget and the backend was terminated. */
  terminated: boolean;
}
/** `node:diagnostics_channel` name that receives {@link StdioDiagnostic} messages. */
export const STDIO_DIAGNOSTICS_CHANNEL = "agenthooksprotocol:stdio";
const diagnostics = channel(STDIO_DIAGNOSTICS_CHANNEL);
function diagnose(diagnostic: StdioDiagnostic): void {
  if (diagnostics.hasSubscribers) diagnostics.publish(diagnostic);
}

/** Decoder errors that leave framing intact; anything else (an oversize frame) is fatal. */
function recoverableFrameError(error: unknown): boolean {
  return (
    error instanceof HookOperationalError &&
    (error.code === "MALFORMED_UTF8" || error.message === "Empty NDJSON frame")
  );
}

/** Validate only the JSON-RPC envelope; the caller validates method-specific results. */
function responseFor(value: any, message: any): unknown {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.jsonrpc !== "2.0" ||
    "result" in value === "error" in value ||
    "method" in value ||
    !("id" in value)
  ) {
    throw new HookOperationalError(
      "MALFORMED_JSON_RPC",
      "Expected one JSON-RPC response",
    );
  }
  if (value.id !== message.id) {
    throw new HookOperationalError(
      "ID_MISMATCH",
      "Backend response ID does not match request",
    );
  }
  if (
    "error" in value &&
    (!value.error ||
      typeof value.error !== "object" ||
      !Number.isInteger(value.error.code) ||
      typeof value.error.message !== "string")
  ) {
    throw new HookOperationalError(
      "MALFORMED_JSON_RPC",
      "Malformed JSON-RPC error",
    );
  }
  return value;
}

/** Client-side transport. Deadlines are supplied by the caller's AbortSignal. */
export class BackendTransport {
  readonly #backendId: string;
  readonly #transport: StdioTransport | HttpTransport;
  readonly #fetcher: Fetcher;
  readonly #headers: ReturnType<typeof validateHeaders>;
  readonly #headerResolver: HeaderResolver | undefined;
  readonly #inheritEnvironment: boolean;
  readonly #controllers = new Set<AbortController>();
  readonly #processes = new Set<ProcessState>();
  #process: ProcessState | undefined;
  #tail: Promise<unknown> = Promise.resolve();
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(backend: Backend, fetcher: Fetcher, options: BackendTransportOptions = {}) {
    const transport = backend.transport;
    if (transport.type !== "http" && transport.type !== "stdio") {
      throw new HookOperationalError(
        "INVALID_CONFIG",
        "Unsupported backend transport",
      );
    }
    if (
      transport.type === "stdio" &&
      transport.lifecycle !== "persistent" &&
      transport.lifecycle !== "per_event"
    ) {
      throw new HookOperationalError(
        "INVALID_CONFIG",
        "Unsupported stdio lifecycle",
      );
    }
    this.#headers = transport.type === "http" ? validateHeaders(transport.headers) : [];
    this.#headerResolver = options.headerResolver;
    this.#backendId = backend.id;
    // Freeze the selected HTTP destination independently of caller mutation.
    this.#transport = (transport.type === "http" ? { ...transport } : transport) as StdioTransport | HttpTransport;
    this.#fetcher = fetcher;
    this.#inheritEnvironment = options.inheritEnvironment === true;
  }

  request(message: any, signal?: AbortSignal): Promise<unknown> {
    return this.#send(message, false, signal);
  }

  async notify(message: any, signal?: AbortSignal): Promise<void> {
    await this.#send(message, true, signal);
  }

  #send(
    message: any,
    notification: boolean,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (this.#closed)
      return Promise.reject(failure("Backend transport is closed"));
    const controller = new AbortController();
    const abort = () => controller.abort(signal?.reason);
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
    this.#controllers.add(controller);
    let started = false;
    const run = async () => {
      controller.signal.throwIfAborted();
      started = true;
      return this.#transport.type === "http"
        ? this.#http(message, notification, controller.signal)
        : this.#stdio(message, notification, controller.signal);
    };
    // This revision permits only one outstanding intercept per persistent
    // backend. Keep the queue occupied through process shutdown on cancellation.
    const stdio = this.#transport.type === "stdio";
    const work = stdio ? this.#tail.then(run) : run();
    if (stdio) this.#tail = work.catch(() => {});
    // Also interrupt queued calls, and fetch implementations which ignore cancellation.
    return new Promise((resolve, reject) => {
      const cancel = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", cancel, { once: true });
      if (controller.signal.aborted) cancel();
      work.then(resolve, reject).finally(() => {
        controller.signal.removeEventListener("abort", cancel);
      });
    }).finally(async () => {
      // Retire queued work immediately, but reap an active SDK child before
      // completing its cancelled operation. The queue remains occupied too.
      if (stdio && started && controller.signal.aborted)
        await work.catch(() => {});
      signal?.removeEventListener("abort", abort);
      this.#controllers.delete(controller);
    });
  }

  async #http(
    message: any,
    notification: boolean,
    signal: AbortSignal,
  ): Promise<unknown> {
    const transport = this.#transport as HttpTransport;
    const event = message.method === "hooks/intercept" || message.method === "hooks/observe";
    // Preserve the existing eager fetch path when no event headers apply.
    const headers = event && this.#headers.length > 0
      ? await resolveHeaders(this.#headers, this.#headerResolver, {
          backendId: this.#backendId, url: transport.url, purpose: "event", signal,
        })
      : new Headers();
    signal.throwIfAborted();
    headers.set("Content-Type", "application/json");
    headers.set("Accept", "application/json");
    const response = await this.#fetcher(transport.url, {
      method: "POST",
      headers,
      body: stringifyJson(message),
      redirect: "error",
      signal,
    });
    try {
      signal.throwIfAborted();
      if (notification) {
        if (response.status !== 202 && response.status !== 204) {
          throw failure(
            `Unexpected notification HTTP status ${response.status}`,
          );
        }
        await this.#responseText(response, signal, 0);
        return;
      }
      if (response.status !== 200)
        throw failure(`Unexpected request HTTP status ${response.status}`);
      if (
        response.headers
          .get("content-type")
          ?.split(";")[0]
          ?.trim()
          .toLowerCase() !== "application/json"
      ) {
        throw new HookOperationalError(
          "MALFORMED_JSON_RPC",
          "Backend response must use application/json",
        );
      }
      // Match the SDK's 1 MiB NDJSON frame budget rather than buffering unbounded JSON.
      const text = await this.#responseText(response, signal, 1024 * 1024);
      signal.throwIfAborted();
      let decoded: unknown;
      try {
        decoded = parseJson(text);
      } catch {
        throw new HookOperationalError(
          "MALFORMED_JSON",
          "Malformed backend response",
        );
      }
      return responseFor(decoded, message);
    } finally {
      // Also release rejected responses and late results from fetchers that ignore abort.
      // A custom stream's cancellation hook must not hold a deadline or close hostage.
      if (response.body && !response.body.locked)
        void response.body.cancel().catch(() => {});
    }
  }

  async #responseText(
    response: Response,
    signal: AbortSignal,
    limit: number,
  ): Promise<string> {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const cancel = () => {
      void reader.cancel(signal.reason).catch(() => {});
    };
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let bytes = 0;
    let text = "";
    signal.addEventListener("abort", cancel, { once: true });
    try {
      signal.throwIfAborted();
      while (true) {
        const chunk = await reader.read();
        signal.throwIfAborted();
        if (chunk.done) return text + decoder.decode();
        bytes += chunk.value.byteLength;
        if (bytes > limit)
          throw failure(
            limit === 0
              ? "Notification response must be empty"
              : "HTTP JSON-RPC frame exceeds 1 MiB",
          );
        text += decoder.decode(chunk.value, { stream: true });
      }
    } finally {
      signal.removeEventListener("abort", cancel);
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }

  #start(): ProcessState {
    const transport = this.#transport as StdioTransport;
    const child = spawn(transport.command, transport.args ?? [], {
      cwd: transport.cwd,
      env: backendEnvironment(transport.env, this.#inheritEnvironment),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let onClose!: () => void;
    const state: ProcessState = {
      child,
      stopped: false,
      pending: new Map(),
      closed: new Promise<void>((resolve) => {
        onClose = resolve;
      }),
    };
    const decoder = new NdjsonDecoder();
    const fail = (error: unknown) => {
      for (const pending of state.pending.values()) pending.reject(error);
      state.pending.clear();
      this.#stop(state);
    };
    child.stderr.resume();
    child.on("error", fail);
    child.stdin.on("error", fail);
    child.stdout.on("error", fail);
    const persistent = transport.lifecycle === "persistent";
    // A persistent backend survives isolated bad frames; per-event output must be exact.
    const budget = persistent ? MALFORMED_FRAME_BUDGET : 1;
    let strikes = 0;
    const malformed = (error: unknown, value?: any) => {
      strikes++;
      const terminated = strikes >= budget;
      if (persistent)
        diagnose({
          backendId: this.#backendId,
          kind: "malformed",
          ...(error instanceof HookOperationalError ? { code: error.code } : {}),
          strikes,
          terminated,
        });
      if (terminated) return fail(error);
      // Fail only the request this frame answers: the one it names, or else the
      // single in-flight request (stdio calls are serialized). The process survives.
      const named = value && typeof value === "object" && !Array.isArray(value) && "id" in value;
      const target = named
        ? state.pending.get(value.id)
        : state.pending.size === 1
          ? state.pending.values().next().value
          : undefined;
      target?.reject(error);
    };
    const frame = (line: string) => {
      let value: any;
      try {
        value = parseJson(line);
      } catch {
        return malformed(
          new HookOperationalError("MALFORMED_JSON", "Malformed backend response"),
        );
      }
      if (persistent) {
        let response: unknown;
        try {
          response = responseFor(value, { id: value?.id });
        } catch (error) {
          return malformed(error, value);
        }
        strikes = 0;
        const pending = state.pending.get(value.id);
        if (pending) pending.resolve(response);
        // Never consume unmatched frames as the next response.
        else
          diagnose({ backendId: this.#backendId, kind: "unsolicited", strikes, terminated: false });
        return;
      }
      const pending = state.pending.values().next().value;
      if (!pending || pending.notification || pending.response !== undefined)
        return fail(failure("Unexpected backend response"));
      try {
        pending.response = responseFor(value, pending.message);
      } catch (error) {
        malformed(error);
      }
    };
    child.stdout.on("data", (chunk: Uint8Array) => {
      // Feed one line at a time so a bad frame cannot discard its neighbours.
      for (let start = 0; start < chunk.length && !state.stopped; ) {
        const newline = chunk.indexOf(0x0a, start);
        const end = newline === -1 ? chunk.length : newline + 1;
        let lines: string[];
        try {
          lines = decoder.push(chunk.subarray(start, end));
        } catch (error) {
          if (recoverableFrameError(error)) malformed(error);
          else fail(error);
          lines = [];
        }
        for (const line of lines) if (!state.stopped) frame(line);
        start = end;
      }
    });
    child.on("close", (code: number | null) => {
      try {
        decoder.end();
        for (const pending of state.pending.values()) {
          if (code !== 0)
            throw failure(`Backend exited with status ${String(code)}`);
          if (!pending.notification) {
            if (pending.response === undefined)
              throw failure("Backend exited without a response");
          }
          pending.resolve(pending.response);
        }
      } catch (error) {
        for (const pending of state.pending.values()) pending.reject(error);
      }
      state.pending.clear();
      state.stopped = true;
      if (this.#process === state) this.#process = undefined;
      this.#processes.delete(state);
      onClose();
    });
    this.#processes.add(state);
    this.#process = state;
    return state;
  }

  #stop(state: ProcessState): void {
    if (this.#process === state) this.#process = undefined;
    if (!state.stopped) {
      state.stopped = true;
      // Do not let an uncooperative backend retain owned processes after cancellation.
      state.child.kill("SIGKILL");
      // Descendants can inherit these pipes even after the SDK child exits.
      // Retire our handles so reaping does not wait for external descendants.
      state.child.stdin.destroy();
      state.child.stdout.destroy();
      state.child.stderr.destroy();
    }
  }

  async #stdio(
    message: any,
    notification: boolean,
    signal: AbortSignal,
  ): Promise<unknown> {
    const wire = stringifyJson(message) + "\n";
    const state = this.#process ?? this.#start();
    const perEvent =
      (this.#transport as StdioTransport).lifecycle === "per_event";
    if (!notification && state.pending.has(message.id))
      throw failure("Duplicate pending JSON-RPC request ID");
    try {
      return await new Promise<unknown>((resolve, reject) => {
        let pending: Pending | undefined;
        const cleanup = () => {
          signal.removeEventListener("abort", abort);
          if (pending && state.pending.get(message.id) === pending)
            state.pending.delete(message.id);
        };
        const abort = () => {
          cleanup();
          reject(signal.reason);
          // Abandoning an ID alone would leave the old intercept running when
          // the queue advances. Kill and reap it before starting another call.
          this.#stop(state);
        };
        const finish = (value: unknown) => {
          cleanup();
          resolve(value);
        };
        const fail = (error: unknown) => {
          cleanup();
          reject(error);
        };
        signal.addEventListener("abort", abort, { once: true });
        if (!notification || perEvent) {
          pending = { message, notification, resolve: finish, reject: fail };
          state.pending.set(message.id, pending);
        }
        const written = (error?: Error | null) => {
          if (error) fail(error);
          else if (notification && !perEvent) finish(undefined);
        };
        if (perEvent) state.child.stdin.end(wire, written);
        else state.child.stdin.write(wire, written);
      });
    } catch (error) {
      this.#stop(state);
      throw error;
    } finally {
      if (perEvent || state.stopped) {
        this.#stop(state);
        await state.closed;
      }
    }
  }

  close(): Promise<void> {
    if (this.#closing) return this.#closing;
    this.#closed = true;
    for (const controller of this.#controllers)
      controller.abort(failure("Backend transport is closed"));
    const processes = [...this.#processes];
    for (const state of processes) this.#stop(state);
    this.#closing = Promise.all(processes.map((state) => state.closed)).then(
      () => {},
    );
    return this.#closing;
  }
}
