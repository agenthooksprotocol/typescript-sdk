#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { parseInterceptRequest, PROTOCOL_VERSION } from "@agenthooksprotocol/sdk";

type Mode = "no-effect" | "deny" | "timeout" | "malformed-json" | "json-rpc-error" | "incompatible-version" | "unsupported-effect" | "multiple-effects" | "id-mismatch" | "malformed-deny" | "unknown-fields";

interface Options {
  mode: Mode;
  delayMs: number;
  chunkSize: number;
  reason: string;
  recordFile?: string;
  recordLabel: string;
}

function usage(): never {
  process.stderr.write("Usage: ahp-fake-backend --mode <no-effect|deny|timeout|malformed-json|json-rpc-error|incompatible-version|unsupported-effect|multiple-effects|id-mismatch|malformed-deny|unknown-fields> [--delay-ms N] [--chunk-size N] [--reason TEXT] [--record-file PATH] [--record-label TEXT]\n");
  process.exit(2);
}

function options(argv: string[]): Options {
  let mode: Mode | undefined;
  let delayMs = 0;
  let chunkSize = 0;
  let reason = "Denied by fake backend";
  let recordFile: string | undefined;
  let recordLabel = "";
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined) usage();
    if (flag === "--mode") mode = value as Mode;
    else if (flag === "--delay-ms") delayMs = Number(value);
    else if (flag === "--chunk-size") chunkSize = Number(value);
    else if (flag === "--reason") reason = value;
    else if (flag === "--record-file") recordFile = value;
    else if (flag === "--record-label") recordLabel = value;
    else usage();
    index += 1;
  }
  const modes: Mode[] = ["no-effect", "deny", "timeout", "malformed-json", "json-rpc-error", "incompatible-version", "unsupported-effect", "multiple-effects", "id-mismatch", "malformed-deny", "unknown-fields"];
  if (mode === undefined || !modes.includes(mode) || !Number.isInteger(delayMs) || delayMs < 0 || !Number.isInteger(chunkSize) || chunkSize < 0) usage();
  return recordFile === undefined ? { mode, delayMs, chunkSize, reason, recordLabel } : { mode, delayMs, chunkSize, reason, recordFile, recordLabel };
}

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const yieldTurn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

async function writeFrame(frame: string, chunkSize: number): Promise<void> {
  const bytes = Buffer.from(`${frame}\n`, "utf8");
  if (chunkSize === 0) { process.stdout.write(bytes); return; }
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    process.stdout.write(bytes.subarray(offset, offset + chunkSize));
    await yieldTurn();
  }
}

async function main(): Promise<void> {
  const config = options(process.argv.slice(2));
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
  for await (const line of lines) {
    if (config.recordFile !== undefined) appendFileSync(config.recordFile, `${config.recordLabel}\t${line}\n`, "utf8");
    if (config.mode === "timeout") { await wait(config.delayMs || 60_000); }
    else if (config.delayMs > 0) await wait(config.delayMs);
    if (config.mode === "malformed-json") { await writeFrame("{malformed", config.chunkSize); continue; }
    let request;
    try { request = parseInterceptRequest(line); } catch (error) {
      await writeFrame(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: error instanceof Error ? error.message : "Invalid Request" } }), config.chunkSize);
      continue;
    }
    if (config.mode === "json-rpc-error") {
      await writeFrame(JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32000, message: "Controlled fake error" } }), config.chunkSize);
      continue;
    }
    const id = config.mode === "id-mismatch" ? `${request.id}-wrong` : request.id;
    const protocolVersion = config.mode === "incompatible-version" ? "9.9" : PROTOCOL_VERSION;
    let effects: unknown[] = config.mode === "unknown-fields" ? [{ type: "deny", reason: "Unknown fields tolerated", code: "com.example.denied", extensions: { "com.example.detail": true }, ignoredEffect: true }] : [];
    if (config.mode === "deny") effects = [{ type: "deny", reason: config.reason }];
    else if (config.mode === "malformed-deny") effects = [{ type: "deny", reason: "   " }];
    else if (config.mode === "unsupported-effect") effects = [{ type: "rewrite", arguments: {} }];
    else if (config.mode === "multiple-effects") effects = [{ type: "deny" }, { type: "deny" }];
    const response = config.mode === "unknown-fields"
      ? { jsonrpc: "2.0", id, ignoredRoot: true, result: { protocolVersion, effects, ignoredResult: { future: true } } }
      : { jsonrpc: "2.0", id, result: { protocolVersion, effects } };
    await writeFrame(JSON.stringify(response), config.chunkSize);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
