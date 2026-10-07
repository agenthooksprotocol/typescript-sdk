/* Minimal declarations for the dependency-free Node 20+ reference slice. */
declare module "node:fs/promises" {
  export function readFile(path: string, encoding: "utf8"): Promise<string>;
}
declare class Buffer extends Uint8Array {
  static alloc(size: number): Buffer;
  static concat(chunks: readonly Uint8Array[]): Buffer;
  static from(value: string, encoding?: string): Buffer;
  includes(value: number): boolean;
  indexOf(value: number): number;
  subarray(start?: number, end?: number): Buffer;
}

declare const process: {
  argv: string[];
  stdin: unknown;
  stdout: { write(value: string | Uint8Array): boolean };
  stderr: { write(value: string | Uint8Array): boolean };
  exitCode?: number;
  exit(code?: number): never;
};
declare function setImmediate(callback: () => void): unknown;

declare module "node:crypto" {
  export function randomUUID(): string;
}
declare module "node:child_process" {
  export type ChildProcessWithoutNullStreams = any;
  export function spawn(
    command: string,
    args: string[],
    options: object,
  ): ChildProcessWithoutNullStreams;
  export function spawnSync(
    command: string,
    args?: string[],
    options?: object,
  ): { status: number | null; stdout: string; stderr: string };
}
declare module "node:fs" {
  export function appendFileSync(
    path: string,
    data: string,
    encoding?: string,
  ): void;
  export function mkdtempSync(prefix: string): string;
  export function readFileSync(path: string, encoding: string): string;
  export function existsSync(path: string): boolean;
}
declare module "node:os" {
  export function tmpdir(): string;
}
declare module "node:path" {
  export function join(...parts: string[]): string;
}
declare module "node:readline" {
  export function createInterface(options: object): AsyncIterable<string>;
}
declare module "node:url" {
  export function fileURLToPath(url: URL): string;
}
declare module "node:test" {
  export default function test(
    name: string,
    body: () => void | Promise<void>,
  ): void;
}
declare module "node:assert/strict" {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
    match(value: string, regexp: RegExp): void;
  };
  export default assert;
}

// Node-only stdio serving entrypoint.
declare module "node:stream" {
  export interface Readable extends AsyncIterable<Uint8Array | string> {}
  export const Writable: {
    new (options: {
      highWaterMark: number;
      write(
        chunk: Uint8Array,
        encoding: string,
        callback: (error?: Error | null) => void,
      ): void;
    }): Writable;
  };
  export interface Writable {
    destroy(error?: Error): this;
    write(
      chunk: string | Uint8Array,
      callback?: (error?: Error | null) => void,
    ): boolean;
    on(event: "error", listener: (error: Error) => void): this;
    on(event: "close", listener: () => void): this;
    removeListener(event: "error", listener: (error: Error) => void): this;
    removeListener(event: "close", listener: () => void): this;
  }
}
declare module "node:process" {
  export const stdin: import("node:stream").Readable;
  export const stdout: import("node:stream").Writable;
}
declare module "node:stream/promises" {
  export function pipeline(
    source: import("node:stream").Readable,
    transform: (
      source: AsyncIterable<Uint8Array | string>,
      options: { signal: AbortSignal },
    ) => AsyncIterable<string>,
    destination: import("node:stream").Writable,
    options: { signal?: AbortSignal },
  ): Promise<void>;
}
