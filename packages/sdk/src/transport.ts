import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { HookOperationalError, asOperationalError } from "./errors.js";
import { NdjsonDecoder } from "./framing.js";
import type { Lifecycle } from "./types.js";

export interface LineTransport {
  exchange(line: string, timeoutMs: number): Promise<string>;
  close(): void;
}

function start(command: string, args: readonly string[]): ChildProcessWithoutNullStreams {
  try {
    const child = spawn(command, [...args], { shell: false, stdio: ["pipe", "pipe", "pipe"] });
    child.stderr.resume();
    return child;
  } catch (error) {
    throw new HookOperationalError("SPAWN_ERROR", `Could not spawn ${command}`, { cause: error });
  }
}

class PerEventTransport implements LineTransport {
  readonly #command: string;
  readonly #args: readonly string[];

  constructor(command: string, args: readonly string[]) {
    this.#command = command;
    this.#args = args;
  }

  exchange(line: string, timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const decoder = new NdjsonDecoder();
      let child: ChildProcessWithoutNullStreams | undefined;
      let response: string | undefined;
      let settled = false;
      const finish = (error?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (child !== undefined && child.exitCode === null) child.kill();
        if (error !== undefined) reject(asOperationalError(error));
        else resolve(response as string);
      };
      const timer = setTimeout(() => finish(new HookOperationalError("TIMEOUT", `Hook exchange exceeded ${timeoutMs} ms`)), timeoutMs);
      try {
        child = start(this.#command, this.#args);
        child.once("error", (error: Error) => finish(new HookOperationalError("SPAWN_ERROR", `Could not run ${this.#command}`, { cause: error })));
        child.stdout.on("data", (chunk: Buffer) => {
          try {
            const frames = decoder.push(chunk);
            if (frames.length > 1 || (frames.length === 1 && response !== undefined)) {
              throw new HookOperationalError("MALFORMED_JSON_RPC", "Backend emitted multiple responses for one request");
            }
            if (frames.length === 1) response = frames[0];
          } catch (error) {
            finish(error);
          }
        });
        child.once("close", (code: number | null) => {
          if (settled) return;
          try { decoder.end(); } catch (error) { finish(error); return; }
          if (code !== 0) {
            finish(new HookOperationalError("IO_ERROR", `Backend exited with status ${String(code)}`));
          } else if (response === undefined) {
            finish(new HookOperationalError("IO_ERROR", "Backend exited before returning a response"));
          } else {
            finish();
          }
        });
        child.stdin.once("error", (error: Error) => finish(new HookOperationalError("IO_ERROR", "Could not write hook request", { cause: error })));
        child.stdin.end(`${line}\n`);
      } catch (error) {
        finish(error);
      }
    });
  }

  close(): void {}
}

class PersistentTransport implements LineTransport {
  readonly #command: string;
  readonly #args: readonly string[];
  #child: ChildProcessWithoutNullStreams | undefined;
  #decoder = new NdjsonDecoder();
  #tail: Promise<void> = Promise.resolve();

  constructor(command: string, args: readonly string[]) {
    this.#command = command;
    this.#args = args;
  }

  exchange(line: string, timeoutMs: number): Promise<string> {
    const result = this.#tail.then(() => this.#exchangeNow(line, timeoutMs));
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #exchangeNow(line: string, timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error?: unknown, response?: string): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdout.off("data", onData);
        child.off("error", onError);
        child.off("close", onClose);
        child.stdin.off("error", onStdinError);
        if (error !== undefined) {
          this.#discard();
          reject(asOperationalError(error));
        } else {
          resolve(response as string);
        }
      };
      const timer = setTimeout(() => finish(new HookOperationalError("TIMEOUT", `Hook exchange exceeded ${timeoutMs} ms`)), timeoutMs);
      let child: ChildProcessWithoutNullStreams;
      try {
        if (this.#child === undefined || this.#child.exitCode !== null) {
          this.#decoder = new NdjsonDecoder();
          this.#child = start(this.#command, this.#args);
        }
        child = this.#child;
      } catch (error) {
        clearTimeout(timer);
        reject(asOperationalError(error));
        return;
      }
      const onData = (chunk: Buffer): void => {
        try {
          const frames = this.#decoder.push(chunk);
          if (frames.length !== 1) {
            if (frames.length > 1) throw new HookOperationalError("MALFORMED_JSON_RPC", "Backend emitted multiple responses for one request");
            return;
          }
          finish(undefined, frames[0]);
        } catch (error) { finish(error); }
      };
      const onError = (error: Error): void => finish(new HookOperationalError("SPAWN_ERROR", `Could not run ${this.#command}`, { cause: error }));
      const onClose = (): void => {
        if (settled) return;
        try { this.#decoder.end(); } catch (error) { finish(error); return; }
        finish(new HookOperationalError("IO_ERROR", "Persistent backend exited before returning a response"));
      };
      const onStdinError = (error: Error): void => finish(new HookOperationalError("IO_ERROR", "Could not write hook request", { cause: error }));
      child.stdout.on("data", onData);
      child.once("error", onError);
      child.once("close", onClose);
      child.stdin.once("error", onStdinError);
      child.stdin.write(`${line}\n`, (error?: Error | null) => { if (error) onStdinError(error); });
    });
  }

  #discard(): void {
    const child = this.#child;
    this.#child = undefined;
    this.#decoder = new NdjsonDecoder();
    if (child !== undefined && child.exitCode === null) child.kill();
  }

  close(): void { this.#discard(); }
}

export function createTransport(command: string, args: readonly string[], lifecycle: Lifecycle): LineTransport {
  return lifecycle === "persistent" ? new PersistentTransport(command, args) : new PerEventTransport(command, args);
}
