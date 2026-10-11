import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type {
  Backend,
  HttpTransport,
  StdioTransport,
} from "../draft/raw.js";
import { HookOperationalError } from "../errors.js";
import { NdjsonDecoder } from "../framing.js";
import { parseJson, stringifyJson } from "../json.js";

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

function failure(message: string): Error {
  return new HookOperationalError("IO_ERROR", message);
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
  readonly #transport: StdioTransport | HttpTransport;
  readonly #fetcher: Fetcher;
  readonly #controllers = new Set<AbortController>();
  readonly #processes = new Set<ProcessState>();
  #process: ProcessState | undefined;
  #tail: Promise<unknown> = Promise.resolve();
  #closed = false;
  #closing: Promise<void> | undefined;

  constructor(backend: Backend, fetcher: Fetcher) {
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
    this.#transport = transport as StdioTransport | HttpTransport;
    this.#fetcher = fetcher;
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
    const response = await this.#fetcher(transport.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
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
    child.stdout.on("data", (chunk: Uint8Array) => {
      try {
        const lines = decoder.push(chunk);
        for (const line of lines) {
          const value = parseJson(line) as any;
          if (transport.lifecycle === "persistent") {
            // Validate protocol output, but ignore replies to abandoned/unknown IDs.
            const response = responseFor(value, { id: value?.id });
            const pending = state.pending.get(value.id);
            if (pending) pending.resolve(response);
          } else {
            const pending = state.pending.values().next().value;
            if (
              !pending ||
              pending.notification ||
              pending.response !== undefined
            )
              throw failure("Unexpected backend response");
            pending.response = responseFor(value, pending.message);
          }
        }
      } catch (error) {
        fail(error);
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
