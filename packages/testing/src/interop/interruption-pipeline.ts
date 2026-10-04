import type {
  BoundaryInput,
  BoundaryResult,
} from "@agenthooksprotocol/sdk/client";

export interface HostState {
  input: BoundaryInput<"tool.before">["tool"]["input"];
  candidate: {
    value: unknown;
    supplier: string;
    input: HostState["input"];
  } | null;
  permission: "native" | "allow" | "ask";
  approval: "pending" | "approved" | "not-required";
  denied: boolean;
  messages: string[];
}
export interface Exchange {
  response: Promise<BoundaryResult<"tool.before">>;
  cancel(): void;
}
/** Host acceptance of ONE boundary. Hooks owns all ordered subscribers,
 * composition, validation, deadlines and failure policy. No host staging pass. */
export class DecisionPipeline {
  state: HostState;
  readonly trace: string[] = [];
  readonly messages: string[] = [];
  executions = 0;
  failures = 0;
  interrupted = false;
  private pending: Exchange | undefined;
  constructor(initial: HostState) {
    this.state = structuredClone(initial);
  }
  interrupt(): void {
    if (this.interrupted) return;
    this.interrupted = true;
    this.trace.push("interrupt");
    this.pending?.cancel();
  }
  async run(
    id: string,
    start: () => Exchange,
    beforeExecute: () => Promise<void> = async () => {},
  ): Promise<void> {
    if (!this.interrupted) {
      this.trace.push(`dispatch:${id}`);
      const exchange = start();
      this.pending = exchange;
      if (this.interrupted) exchange.cancel();
      let result: BoundaryResult<"tool.before"> | undefined;
      try {
        result = await exchange.response;
      } finally {
        this.pending = undefined;
      }
      if (result?.interrupted) this.interrupted = true;
      if (result && !this.interrupted) {
        // Read the SDK's effective event; never replay modify or compose replies.
        this.state.input = structuredClone(result.event.tool.input);
        for (const effect of result.response.result.effects) {
          switch (effect.type) {
            case "modify":
              break;
            case "return":
              this.state.candidate = {
                value: structuredClone(effect.value),
                supplier: id,
                input: structuredClone(this.state.input),
              };
              break;
            case "allow":
              this.state.permission = "allow";
              break;
            case "ask":
              this.state.permission = "ask";
              this.state.approval = "pending";
              break;
            case "deny":
              this.state.denied = true;
              break;
            case "message":
              if (typeof effect.text !== "string")
                throw new Error("Expected textual host message");
              this.state.messages.push(effect.text);
              this.messages.push(effect.text);
              break;
            default:
              throw new Error(
                "Unsupported host action in interruption fixture",
              );
          }
        }
        this.failures = result.errors.length;
        if (this.failures)
          for (const error of result.errors)
            this.trace.push(
              `reject:${id}`,
              error.code === "DEADLINE_EXCEEDED"
                ? "timeout"
                : "backend-failure",
              `failure:${error.failurePolicy}`,
            );
        else this.trace.push(`accept:${id}`);
        this.trace.push(
          ...this.messages.map((message) => `message:${message}`),
        );
      }
    }
    if (!this.interrupted) await beforeExecute();
    if (this.interrupted) {
      this.trace.push("interrupted");
      return;
    }
    this.trace.push("policy");
    if (this.state.denied) this.trace.push("blocked");
    else if (this.state.candidate)
      this.trace.push(`candidate:${this.state.candidate.supplier}`);
    else {
      this.trace.push("execute");
      this.executions++;
    }
  }
}
