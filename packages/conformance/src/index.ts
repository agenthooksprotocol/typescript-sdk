import { ToolBeforeRunner } from "@agenthooksprotocol/sdk";

export interface ConformanceOptions {
  command: string;
  args?: readonly string[];
  timeoutMs?: number;
}

export interface ConformanceReport {
  ok: boolean;
  checks: Array<{ name: string; ok: boolean; detail?: string }>;
}

export async function runConformance(options: ConformanceOptions): Promise<ConformanceReport> {
  const runner = new ToolBeforeRunner();
  runner.register({
    command: options.command,
    args: options.args ?? [],
    timeoutMs: options.timeoutMs ?? 1_000,
    failurePolicy: "fail-open",
    lifecycle: "persistent",
  });
  const checks: ConformanceReport["checks"] = [];
  try {
    const first = await runner.intercept({ source: "urn:agenthooksprotocol:conformance:runner", eventId: "conformance-event-1", time: "2026-01-02T03:04:05.000Z", session: { id: "conformance-session", cwd: "/workspace" }, tool: { callId: "conformance-call-1", name: "unicode_工具", kind: "file_write", input: { text: "Zażółć gęślą jaźń 🚀" } } });
    checks.push(first.failures.length === 0
      ? { name: "valid tool.before exchange", ok: true }
      : { name: "valid tool.before exchange", ok: false, detail: `${first.failures[0]?.code}: ${first.failures[0]?.message}` });
    const second = await runner.intercept({ source: "urn:agenthooksprotocol:conformance:runner", eventId: "conformance-event-2", session: { id: "conformance-session" }, tool: { callId: "conformance-call-2", name: "second_call", kind: "other", input: { values: [null, true, 2.5] } } });
    checks.push(second.failures.length === 0
      ? { name: "persistent sequential exchange", ok: true }
      : { name: "persistent sequential exchange", ok: false, detail: `${second.failures[0]?.code}: ${second.failures[0]?.message}` });
  } finally {
    runner.close();
  }
  return { ok: checks.every((check) => check.ok), checks };
}
