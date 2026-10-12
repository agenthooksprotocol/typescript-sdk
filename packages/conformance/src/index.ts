import { Hooks } from "agenthooksprotocol/client";

export interface ConformanceOptions {
  command: string;
  args?: readonly string[];
  timeoutMs?: number;
}

export interface ConformanceReport {
  ok: boolean;
  checks: Array<{ name: string; ok: boolean; detail?: string }>;
}

export async function runConformance(
  options: ConformanceOptions,
): Promise<ConformanceReport> {
  const runner = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [{
        id: "ahp.conformance",
        transport: {
          type: "stdio",
          command: options.command,
          args: [...(options.args ?? [])],
          lifecycle: "persistent",
        },
        subscriptions: [{
          mode: "intercept",
          events: ["tool.before"],
          timeoutMs: options.timeoutMs ?? 1_000,
          failurePolicy: "fail-open",
          content: { default: "metadata" },
        }],
      }],
    },
    {
      source: "urn:agenthooksprotocol:conformance:runner",
      capabilities: { toolBefore: { intercept: { deny: true } } },
    },
  );
  const checks: ConformanceReport["checks"] = [];
  try {
    const first = await runner.toolBefore({
      id: "conformance-event-1",
      time: "2026-01-02T03:04:05.000Z",
      session: { id: "conformance-session", cwd: "/workspace" },
      callId: "conformance-call-1",
      path: "native",
      name: "unicode_工具",
      origin: "native",
      input: { text: "Zażółć gęślą jaźń 🚀" },
    });
    checks.push(
      first.diagnostics.filter(d => d.phase !== "observation").length === 0
        ? { name: "valid tool.before exchange", ok: true }
        : {
            name: "valid tool.before exchange",
            ok: false,
            detail: `${first.diagnostics.filter(d => d.phase !== "observation")[0]?.phase}: ${first.diagnostics.filter(d => d.phase !== "observation")[0]?.code}`,
          },
    );
    const second = await runner.toolBefore({
      id: "conformance-event-2",
      session: { id: "conformance-session" },
      callId: "conformance-call-2",
      path: "native",
      name: "second_call",
      origin: "native",
      input: { values: [null, true, 2.5] },
    });
    checks.push(
      second.diagnostics.filter(d => d.phase !== "observation").length === 0
        ? { name: "persistent sequential exchange", ok: true }
        : {
            name: "persistent sequential exchange",
            ok: false,
            detail: `${second.diagnostics.filter(d => d.phase !== "observation")[0]?.phase}: ${second.diagnostics.filter(d => d.phase !== "observation")[0]?.code}`,
          },
    );
  } finally {
    await runner.close();
  }
  return { ok: checks.every((check) => check.ok), checks };
}
