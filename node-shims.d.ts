/* Minimal declarations for the dependency-free Node 20+ reference slice. */
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

declare module "node:crypto" { export function randomUUID(): string; }
declare module "node:child_process" {
  export type ChildProcessWithoutNullStreams = any;
  export function spawn(command: string, args: string[], options: object): ChildProcessWithoutNullStreams;
  export function spawnSync(command: string, args?: string[], options?: object): { status: number | null; stdout: string; stderr: string };
}
declare module "node:fs" {
  export function appendFileSync(path: string, data: string, encoding?: string): void;
  export function mkdtempSync(prefix: string): string;
  export function readFileSync(path: string, encoding: string): string;
  export function existsSync(path: string): boolean;
}
declare module "node:os" { export function tmpdir(): string; }
declare module "node:path" { export function join(...parts: string[]): string; }
declare module "node:readline" { export function createInterface(options: object): AsyncIterable<string>; }
declare module "node:url" { export function fileURLToPath(url: URL): string; }
declare module "node:test" { export default function test(name: string, body: () => void | Promise<void>): void; }
declare module "node:assert/strict" {
  const assert: { equal(actual: unknown, expected: unknown, message?: string): void; deepEqual(actual: unknown, expected: unknown, message?: string): void; ok(value: unknown, message?: string): void; match(value: string, regexp: RegExp): void };
  export default assert;
}
