import { randomUUID } from "node:crypto";
import type {
  Authentication,
  Backend,
  Capabilities,
  Effect,
  InterceptResponse,
  InterceptSubscription,
  ObserveSubscription,
  Registration,
  StaticCapabilityManifest,
} from "../draft/generated.js";
import {
  validateCapabilities,
  validateInterceptRequest,
  validateInterceptResponse,
} from "../draft/index.js";
import { BackendTransport } from "./transport.js";
import { ContentManager } from "./content.js";
import { composeResponseAsync, normalizeEffects } from "./composition.js";
import { auth } from "./auth.js";
import { validateWire } from "./validation.js";
import {
  ConfigurationError,
  type BoundaryInput,
  type BoundaryOptions,
  type BoundaryResult,
  type Event,
  type EventType,
  type HooksOptions,
  type DeliveryError,
} from "./types.js";

type Subscription = InterceptSubscription | ObserveSubscription;
type Route = {
  backend: Backend;
  subscription: Subscription;
  index: number;
  transport: BackendTransport;
};
const interceptable = new Set<EventType>([
  "tool.before",
  "tool.after",
  "session.start",
  "config.change.before",
  "turn.start",
  "turn.finish.before",
  "model.request.before",
  "model.response.after",
  "model.switch.before",
  "tool.permission.request",
  "tool.batch.after",
  "context.compact.before",
  "context.compact.after",
  "task.change.before",
  "user.elicitation.request",
  "user.elicitation.result",
  "user.message.inbound",
  "user.message.outbound",
  "workspace.change.before",
]);
const eventTypes: EventType[] = [
  "tool.before",
  "tool.after",
  "session.start",
  "session.end",
  "config.change.before",
  "config.change.after",
  "turn.start",
  "turn.finish.before",
  "turn.end",
  "turn.progress",
  "model.request.before",
  "model.response.after",
  "model.error",
  "model.switch.before",
  "model.switch.after",
  "tool.permission.request",
  "tool.permission.resolved",
  "tool.progress",
  "tool.batch.after",
  "context.compact.before",
  "context.compact.after",
  "task.change.before",
  "task.change.after",
  "user.attention",
  "user.elicitation.request",
  "user.elicitation.result",
  "user.message.inbound",
  "user.message.outbound",
  "workspace.change.before",
  "workspace.change.after",
  "file.changed",
  "hook.failure",
];
const matches = (selector: string, type: string) =>
  selector === "*" ||
  selector === type ||
  (selector.endsWith(".*") && selector.slice(0, -2) === type.split(".")[0]);

/** Configuration-driven, harness-facing AHP client. No host operation is executed. */
export class Hooks {
  readonly initialized: Promise<void>;
  private readonly lifetime = new AbortController();
  private readonly options: HooksOptions;
  private readonly routes: Route[] = [];
  private readonly managers = new Set<ContentManager>();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly provider;
  private readonly authContexts = new Map<string, any>();
  private manifest!: StaticCapabilityManifest;
  private closed?: Promise<void>;
  private readonly elicitations = new Map<
    string,
    { event: any; bytes: Uint8Array }
  >();
  private elicitationBytes = 0;

  constructor(config: unknown, options: HooksOptions) {
    this.options = {
      ...options,
      capabilities: structuredClone(options.capabilities),
    };
    this.provider = options.auth ?? auth();
    // No credentials or processes are acquired until a matching boundary needs them.
    this.initialized = Promise.resolve().then(() => this.initialize(config));
    // An optional initialized wait must not cause an unhandled rejection.
    void this.initialized.catch(() => {});
  }

  private initialize(config: unknown): void {
    const issues = validateWire("registration", config).map((path) => ({
      path,
      code: "INVALID_REGISTRATION",
    }));
    for (const key of ["maxContentBytes", "observationTimeoutMs"] as const) {
      const value = this.options[key];
      if (
        value !== undefined &&
        (!Number.isSafeInteger(value) ||
          value <= 0 ||
          (key === "observationTimeoutMs" && value > 2147483647))
      )
        issues.push({ path: key, code: "INVALID_LIMIT" });
    }
    if (!this.options.source || typeof this.options.source !== "string")
      issues.push({ path: "source", code: "INVALID_SOURCE" });
    if (issues.length) throw new ConfigurationError(issues);
    const registration = structuredClone(config) as Registration;
    const c = this.options.capabilities;
    if (!c || typeof c !== "object" || Array.isArray(c))
      throw new ConfigurationError([
        { path: "capabilities", code: "INVALID_CAPABILITIES" },
      ]);
    this.manifest = Array.isArray((c as StaticCapabilityManifest).events)
      ? (c as StaticCapabilityManifest)
      : {
          authentication: ["bearer", "oauth"],
          contentCategories: [
            "text",
            "images",
            "audio",
            "video",
            "files",
            "reasoning",
          ],
          correlationIdentityFields: [
            "session.id",
            "turn.id",
            "call.id",
            "parentEventId",
          ],
          events: eventTypes.map((event) => ({
            event,
            modes:
              interceptable.has(event) && Object.hasOwn(c, event)
                ? ["intercept", "observe"]
                : ["observe"],
            ...(Object.hasOwn(c, event)
              ? { capabilities: (c as Record<string, Capabilities>)[event]! }
              : {}),
          })),
          gaps: [],
          limits: {
            maxUploadBytes: this.options.maxContentBytes ?? 64 * 1024 * 1024,
          },
          managedPolicy: {
            disableable: false,
            scopes: ["user", "project", "managed"],
          },
          toolPaths: ["*"],
          transports: ["stdio", "http"],
        };
    const manifestErrors = validateWire("capabilities-response", {
      jsonrpc: "2.0",
      id: "init",
      result: { protocolVersion: "draft", manifest: this.manifest },
    });
    for (const path of manifestErrors)
      issues.push({
        path: `capabilities${path}`,
        code: "INVALID_CAPABILITIES",
      });
    for (const item of this.manifest.events) {
      if (item.capabilities && !validateCapabilities(item.capabilities).ok)
        issues.push({
          path: `capabilities.${item.event}`,
          code: "INVALID_CAPABILITIES",
        });
      if (
        item.modes.includes("intercept") &&
        !interceptable.has(item.event as EventType)
      )
        issues.push({
          path: `capabilities.${item.event}`,
          code: "NOT_INTERCEPTABLE",
        });
    }
    const ids = new Set<string>();
    for (const backend of registration.hooks) {
      if (ids.has(backend.id))
        issues.push({ path: backend.id, code: "DUPLICATE_BACKEND" });
      ids.add(backend.id);
      if (backend.transport.type === "http") {
        try {
          secureEndpoint(String(backend.transport.url));
        } catch {
          issues.push({ path: backend.id, code: "UNSAFE_ENDPOINT" });
        }
      }
      if (!["stdio", "http"].includes(backend.transport.type))
        issues.push({ path: backend.id, code: "UNSUPPORTED_TRANSPORT" });
      for (const [index, raw] of backend.subscriptions.entries()) {
        const s = raw as Subscription;
        if (s.scope === "managed" && s.disableable !== false)
          issues.push({
            path: `${backend.id}.${index}`,
            code: "MANDATORY_SCOPE_DISABLEABLE",
          });
        if (s.scope && !this.manifest.managedPolicy.scopes.includes(s.scope))
          issues.push({
            path: `${backend.id}.${index}`,
            code: "UNSUPPORTED_SCOPE",
          });
        for (const selector of s.events) {
          if (!eventTypes.some((e) => matches(selector, e)))
            issues.push({
              path: `${backend.id}.${index}`,
              code: "UNSUPPORTED_EVENT",
            });
          if (
            !selector.includes("*") &&
            !this.manifest.events.some(
              (e) => e.event === selector && e.modes.includes(s.mode),
            )
          )
            issues.push({
              path: `${backend.id}.${index}`,
              code:
                s.mode === "intercept" ? "NOT_INTERCEPTABLE" : "NOT_OBSERVABLE",
            });
        }
      }
    }
    if (issues.length) throw new ConfigurationError(issues);
    for (const backend of registration.hooks) {
      const transport = new BackendTransport(backend, (url, init) =>
        this.fetchAuthenticated(url, init, backend.authentication),
      );
      backend.subscriptions.forEach((subscription, index) =>
        this.routes.push({
          backend,
          subscription: subscription as Subscription,
          index,
          transport,
        }),
      );
    }
  }

  // Each endpoint binding has its own provider context; upload auth never inherits
  // event auth. Contexts belong to this Hooks instance, even with a shared provider.
  private async fetchAuthenticated(
    url: string,
    init: RequestInit,
    authentication?: Authentication,
    purpose: "event" | "upload" = "event",
  ): Promise<Response> {
    secureEndpoint(url);
    const signal = init.signal ?? this.lifetime.signal;
    signal.throwIfAborted();
    const key = JSON.stringify([purpose, url, authentication ?? null]);
    let context = this.authContexts.get(key);
    if (!context) {
      context = {
        url,
        purpose,
        ...(authentication ? { authentication } : {}),
        cache: new Map(),
      };
      this.authContexts.set(key, context);
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const credential = await raceAbort(
        this.provider.authenticate({ ...context, signal }, {}),
        signal,
      );
      if (
        !credential &&
        (authentication !== undefined || context.challenged === true)
      )
        throw new Error("Authentication credential required");
      const headers = new Headers(init.headers);
      headers.delete("authorization");
      if (credential) {
        if (
          typeof credential.token !== "string" ||
          !credential.token ||
          /[\s\x00-\x1f\x7f]/.test(credential.token) ||
          (credential.expiresAt !== undefined &&
            (!Number.isFinite(credential.expiresAt) ||
              credential.expiresAt <= Date.now()))
        )
          throw new Error("Invalid authentication credential");
        headers.set("authorization", `Bearer ${credential.token}`);
      }
      const response = await raceAbort(
        (this.options.fetch ?? fetch)(url, {
          ...init,
          headers,
          redirect: "error",
          signal,
        }),
        signal,
      );
      if (response.status !== 401 || attempt === 1) {
        delete context.challenge;
        delete context.challenged;
        return response;
      }
      context.challenged = true;
      context.challenge = response.headers.get("www-authenticate") ?? undefined;
      void response.body?.cancel().catch(() => {});
    }
    throw new Error("Authentication failed");
  }

  /** Generic typed boundary dispatch; named methods below cover the complete catalogue. */
  async dispatch<K extends EventType>(
    type: K,
    input: BoundaryInput<K>,
    options: BoundaryOptions = {},
  ): Promise<BoundaryResult<K>> {
    // Calls made after close remain misuse; cancellation of an active boundary
    // (including before initialization settles) is an interrupted result.
    this.lifetime.signal.throwIfAborted();
    // Initialization only resolves configuration; it acquires no credentials or
    // processes. Let run return the normal interrupted result for early aborts.
    await this.initialized;
    const signal = combineSignals(this.lifetime.signal, options.signal);
    const work = this.run(type, input, options, signal);
    this.pending.add(work);
    try {
      return await work;
    } finally {
      this.pending.delete(work);
    }
  }

  private async run<K extends EventType>(
    type: K,
    input: BoundaryInput<K>,
    options: BoundaryOptions,
    signal: AbortSignal,
  ): Promise<BoundaryResult<K>> {
    let event: any = cloneInput({
      ...input,
      type,
      source: this.options.source,
      id: input.id ?? randomUUID(),
      time: input.time ?? new Date().toISOString(),
    });
    if (type === "session.start")
      event.manifest = structuredClone(this.manifest);
    const requestId = event.id;
    if (signal.aborted)
      return {
        event,
        response: {
          jsonrpc: "2.0",
          id: requestId,
          result: { protocolVersion: "draft", effects: [] },
        },
        errors: [],
        observations: Promise.resolve([]),
        interrupted: true,
      } as BoundaryResult<K>;
    const originalRequest = this.elicitationFor(event);
    let effects: Effect[] = [];
    let state = structuredClone(options.initialState);
    // A supplied snapshot is input to the first receiver, not a newly accepted
    // result in this chain. Composition settles terminal state after acceptance.
    let shortCircuit = false;
    let interrupted = false;
    const errors: DeliveryError[] = [];
    const advertised = this.manifest.events.find((e) => e.event === type);
    if (!advertised)
      throw new ConfigurationError([
        { path: type, code: "UNADVERTISED_EVENT" },
      ]);
    const staticCaps = advertised.capabilities ?? { effects: [] };
    const caps: Capabilities = structuredClone(
      options.capabilities ?? staticCaps,
    );
    // Reject widening before deriving occurrence counters or clamping budgets.
    if (!validateCapabilities(caps).ok || !isNarrower(caps, staticCaps))
      throw new ConfigurationError([
        { path: type, code: "INVALID_CAPABILITY_NARROWING" },
      ]);
    if (type === "turn.finish.before" && caps.flow) {
      caps.flow.continuationCount = event.continuationCount;
      if (caps.flow.maxContinuations !== undefined)
        caps.flow.remainingContinuations = Math.max(
          0,
          Math.min(
            caps.flow.remainingContinuations ?? 0,
            caps.flow.maxContinuations - event.continuationCount,
          ),
        );
    }
    if (
      !validateCapabilities(caps).ok ||
      !isNarrower(caps, advertised.capabilities ?? { effects: [] })
    )
      throw new ConfigurationError([
        { path: type, code: "INVALID_CAPABILITY_NARROWING" },
      ]);
    const manager = new ContentManager({
      maxSnapshotBytes: this.options.maxContentBytes ?? 64 * 1024 * 1024,
      allowLoopback: true,
    });
    this.managers.add(manager);
    const called = new Set<Route>();
    const matching = this.routes.filter(
      (r) =>
        r.subscription.events.some((s) => matches(s, type)) &&
        advertised.modes.includes(r.subscription.mode),
    );
    try {
      // Validate a metadata-only view before any delivery (this does not consume bytes).
      const metadata = await manager.prepare(
        event,
        { default: "metadata" },
        undefined,
        () => Promise.reject(new Error("Unexpected upload")),
        signal,
      );
      const invalid = validateWire("observe-notification", {
        jsonrpc: "2.0",
        method: "hooks/observe",
        params: { protocolVersion: "draft", event: metadata },
      });
      if (invalid.length)
        throw new ConfigurationError(
          invalid.map((path) => ({ path, code: "INVALID_EVENT" })),
        );
      const invalidState =
        state === undefined
          ? []
          : validateWire("intercept-request", {
              jsonrpc: "2.0",
              id: requestId,
              method: "hooks/intercept",
              params: {
                protocolVersion: "draft",
                event: metadata,
                capabilities: caps,
                ...(state !== undefined ? { state } : {}),
              },
            });
      if (invalidState.length)
        throw new ConfigurationError(
          invalidState.map((path) => ({
            path,
            code: "INVALID_BOUNDARY_STATE",
          })),
        );
      for (const route of matching) {
        if (route.subscription.mode !== "intercept" || shortCircuit) continue;
        if (signal.aborted) {
          interrupted = true;
          break;
        }
        called.add(route);
        const s = route.subscription;
        let phase: DeliveryError["phase"] = "preparation";
        let deadline: AbortSignal | undefined;
        let budget: ReturnType<typeof deadlineAfter> | undefined;
        try {
          const projected = await raceAbort(
            manager.prepare(
              projectNative(event, s.includeNative),
              s.content,
              s.upload,
              (url, init, upload) =>
                this.fetchAuthenticated(url, init, upload.auth, "upload"),
              signal,
            ),
            signal,
          );
          if (
            type === "user.elicitation.request" &&
            projected.elicitation?.request?.selection === "body" &&
            event.elicitation?.request?.body instanceof ReadableStream
          ) {
            const bytes = await manager.readBody(
              event.elicitation.request.body,
              signal,
            );
            this.rememberElicitation(event, bytes);
          }
          const request = {
            jsonrpc: "2.0",
            id: requestId,
            method: "hooks/intercept",
            params: {
              protocolVersion: "draft",
              event: projected,
              capabilities: caps,
              ...(state ? { state } : {}),
            },
          };
          const valid = validateInterceptRequest(request);
          if (!valid.ok) throw new Error("Invalid interception request");
          phase = "interception";
          budget = deadlineAfter(s.timeoutMs, signal);
          deadline = budget.signal;
          const reply = await raceAbort(
            route.transport.request(request, deadline),
            deadline,
          );
          budget.check();
          const decoded = validateInterceptResponse(reply);
          if (!decoded.ok || decoded.value.id !== requestId)
            throw new Error("Invalid interception response");
          // Elicitation terminals are mutually exclusive. Check the raw reply
          // before generic composition normalizes return + deny to denial.
          if (
            type === "user.elicitation.request" &&
            decoded.value.result.effects.some(
              (effect) => effect.type === "return",
            ) &&
            decoded.value.result.effects.some(
              (effect) => effect.type === "deny",
            )
          )
            throw new Error("Conflicting elicitation terminal effects");
          if (
            type === "user.elicitation.request" &&
            decoded.value.result.effects.some(
              (effect) => effect.type === "return" || effect.type === "deny",
            ) &&
            (projected.elicitation?.request?.selection !== "body" ||
              !projected.elicitation.request.body ||
              projected.elicitation.request.gap !== undefined)
          )
            throw new Error(
              "Elicitation terminals require selected request body",
            );
          const staged = await raceAbort(
            composeResponseAsync(event, effects, decoded.value, caps, {
              readContent: (body) => manager.readBody(body, deadline),
              selectedEvent: projected,
              state,
              ...(originalRequest
                ? { elicitationRequest: originalRequest }
                : {}),
            }),
            deadline,
          );
          budget.check();
          event = staged.event;
          effects = staged.effects;
          state = staged.state;
          shortCircuit = staged.shortCircuit;
        } catch {
          interrupted = signal.aborted;
          const syntheticDenial =
            !interrupted && s.failurePolicy === "fail-closed";
          errors.push({
            backendId: route.backend.id,
            subscriptionIndex: route.index,
            phase,
            code: interrupted
              ? "INTERRUPTED"
              : deadline?.aborted
                ? "DEADLINE_EXCEEDED"
                : phase === "preparation"
                  ? "PREPARATION_FAILED"
                  : "DELIVERY_FAILED",
            failurePolicy: s.failurePolicy as "fail-open" | "fail-closed",
            syntheticDenial,
          });
          if (interrupted) break;
          if (syntheticDenial) {
            const denial: Effect = {
              type: "deny",
              reason: "Required policy backend unavailable.",
            };
            const settled = normalizeEffects([denial], state);
            effects = normalizeEffects([...effects, denial]).effects;
            state = settled.state;
            shortCircuit = settled.shortCircuit;
          }
        } finally {
          budget?.dispose();
        }
      }
      interrupted ||= signal.aborted;
      if (interrupted)
        effects = effects.filter(
          (e) =>
            e.type !== "allow" &&
            e.type !== "return" &&
            !(e.type === "flow" && e.operation === "continue"),
        );
      // Observers cannot hold the interception result or keep interrupted work alive.
      const observations = matching.filter(
        (r) =>
          r.subscription.mode === "observe" ||
          ((shortCircuit || interrupted) && !called.has(r)),
      );
      let observed: Promise<DeliveryError[]> = Promise.resolve([]);
      // Caller cancellation ends decisions, not best-effort settlement delivery.
      // A closed client or a boundary canceled before any interception starts
      // must not initiate new callbacks. Observers have their own bounded budget.
      if (
        !this.lifetime.signal.aborted &&
        (!interrupted || called.size > 0) &&
        observations.length
      ) {
        const snapshot = cloneInput(event);
        const jobs = observations.map((route) =>
          this.observe(
            route,
            snapshot,
            manager,
            interrupted ? this.lifetime.signal : signal,
          ),
        );
        observed = Promise.all(jobs)
          .then((results) =>
            results.filter(
              (result): result is DeliveryError => result !== undefined,
            ),
          )
          .finally(async () => {
            await manager.close();
            this.managers.delete(manager);
          });
        this.pending.add(observed);
        void observed.finally(() => this.pending.delete(observed));
      } else {
        await manager.close();
        this.managers.delete(manager);
      }
      if (type === "user.elicitation.result")
        this.forgetElicitation(event.parentEventId);
      if (
        type === "user.elicitation.request" &&
        (interrupted || effects.some((e) => e.type === "deny"))
      )
        this.forgetElicitation(event.id);
      if (type === "session.end")
        for (const [id, entry] of this.elicitations)
          if (entry.event.session?.id === event.session?.id)
            this.forgetElicitation(id);
      const response = {
        jsonrpc: "2.0",
        id: requestId,
        result: { protocolVersion: "draft", effects },
      } as InterceptResponse;
      return {
        event,
        response,
        errors,
        observations: observed,
        interrupted,
      } as BoundaryResult<K>;
    } catch (error) {
      await manager.close();
      this.managers.delete(manager);
      throw error;
    }
  }

  private async observe(
    route: Route,
    event: any,
    manager: ContentManager,
    parentSignal: AbortSignal,
  ): Promise<DeliveryError | undefined> {
    const budget = deadlineAfter(
      this.options.observationTimeoutMs ?? 15000,
      parentSignal,
    );
    const signal = budget.signal;
    try {
      const s = route.subscription;
      const projected = await raceAbort(
        manager.prepare(
          projectNative(event, s.includeNative),
          s.content,
          s.upload,
          (url, init, upload) =>
            this.fetchAuthenticated(url, init, upload.auth, "upload"),
          signal,
        ),
        signal,
      );
      await raceAbort(
        route.transport.notify(
          {
            jsonrpc: "2.0",
            method: "hooks/observe",
            params: { protocolVersion: "draft", event: projected },
          },
          signal,
        ),
        signal,
      );
    } catch {
      return {
        backendId: route.backend.id,
        subscriptionIndex: route.index,
        phase: "observation",
        code: parentSignal.aborted
          ? "INTERRUPTED"
          : signal.aborted
            ? "DEADLINE_EXCEEDED"
            : "DELIVERY_FAILED",
        syntheticDenial: false,
      };
    } finally {
      budget.dispose();
    }
  }

  private rememberElicitation(event: any, bytes: Uint8Array): void {
    if (this.elicitations.has(event.id)) return;
    const limit = this.options.maxContentBytes ?? 64 * 1024 * 1024;
    if (bytes.byteLength > limit)
      throw new Error("Elicitation request exceeds retention budget");
    while (
      this.elicitationBytes + bytes.byteLength > limit ||
      this.elicitations.size >= 128
    )
      this.forgetElicitation(this.elicitations.keys().next().value!);
    const stored = cloneInput(event);
    delete stored.elicitation.request.body;
    this.elicitations.set(event.id, { event: stored, bytes });
    this.elicitationBytes += bytes.byteLength;
  }
  private elicitationFor(event: any): Event | undefined {
    if (event.type !== "user.elicitation.result") return undefined;
    const entry = this.elicitations.get(event.parentEventId);
    if (!entry) return undefined;
    const copy = cloneInput(entry.event),
      bytes = entry.bytes.slice();
    copy.elicitation.request.body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(bytes);
        c.close();
      },
    });
    return copy;
  }
  private forgetElicitation(id: string): void {
    const entry = this.elicitations.get(id);
    if (entry) this.elicitationBytes -= entry.bytes.byteLength;
    this.elicitations.delete(id);
  }

  /** Cancel pending work and release SDK-owned resources; injected stores remain owned by the host. */
  close(): Promise<void> {
    if (!this.closed) {
      this.lifetime.abort(new Error("Hooks closed"));
      this.closed = (async () => {
        await this.initialized.catch(() => {});
        await Promise.allSettled(
          [...new Set(this.routes.map((r) => r.transport))].map((t) =>
            t.close(),
          ),
        );
        await Promise.allSettled([...this.managers].map((m) => m.close()));
        await Promise.allSettled([...this.pending]);
        this.authContexts.clear();
        this.elicitations.clear();
        this.elicitationBytes = 0;
      })();
    }
    return this.closed;
  }
  toolBefore(
    input: BoundaryInput<"tool.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.before">> {
    return this.dispatch("tool.before", input, options);
  }
  toolAfter(
    input: BoundaryInput<"tool.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.after">> {
    return this.dispatch("tool.after", input, options);
  }
  sessionStart(
    input: BoundaryInput<"session.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.start">> {
    return this.dispatch("session.start", input, options);
  }
  sessionEnd(
    input: BoundaryInput<"session.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.end">> {
    return this.dispatch("session.end", input, options);
  }
  configChangeBefore(
    input: BoundaryInput<"config.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.before">> {
    return this.dispatch("config.change.before", input, options);
  }
  configChangeAfter(
    input: BoundaryInput<"config.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.after">> {
    return this.dispatch("config.change.after", input, options);
  }
  turnStart(
    input: BoundaryInput<"turn.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.start">> {
    return this.dispatch("turn.start", input, options);
  }
  turnFinishBefore(
    input: BoundaryInput<"turn.finish.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.finish.before">> {
    return this.dispatch("turn.finish.before", input, options);
  }
  turnEnd(
    input: BoundaryInput<"turn.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.end">> {
    return this.dispatch("turn.end", input, options);
  }
  turnProgress(
    input: BoundaryInput<"turn.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.progress">> {
    return this.dispatch("turn.progress", input, options);
  }
  modelRequestBefore(
    input: BoundaryInput<"model.request.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.request.before">> {
    return this.dispatch("model.request.before", input, options);
  }
  modelResponseAfter(
    input: BoundaryInput<"model.response.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.response.after">> {
    return this.dispatch("model.response.after", input, options);
  }
  modelError(
    input: BoundaryInput<"model.error">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.error">> {
    return this.dispatch("model.error", input, options);
  }
  modelSwitchBefore(
    input: BoundaryInput<"model.switch.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.before">> {
    return this.dispatch("model.switch.before", input, options);
  }
  modelSwitchAfter(
    input: BoundaryInput<"model.switch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.after">> {
    return this.dispatch("model.switch.after", input, options);
  }
  toolPermissionRequest(
    input: BoundaryInput<"tool.permission.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.request">> {
    return this.dispatch("tool.permission.request", input, options);
  }
  toolPermissionResolved(
    input: BoundaryInput<"tool.permission.resolved">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.resolved">> {
    return this.dispatch("tool.permission.resolved", input, options);
  }
  toolProgress(
    input: BoundaryInput<"tool.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.progress">> {
    return this.dispatch("tool.progress", input, options);
  }
  toolBatchAfter(
    input: BoundaryInput<"tool.batch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.batch.after">> {
    return this.dispatch("tool.batch.after", input, options);
  }
  contextCompactBefore(
    input: BoundaryInput<"context.compact.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.before">> {
    return this.dispatch("context.compact.before", input, options);
  }
  contextCompactAfter(
    input: BoundaryInput<"context.compact.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.after">> {
    return this.dispatch("context.compact.after", input, options);
  }
  taskChangeBefore(
    input: BoundaryInput<"task.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.before">> {
    return this.dispatch("task.change.before", input, options);
  }
  taskChangeAfter(
    input: BoundaryInput<"task.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.after">> {
    return this.dispatch("task.change.after", input, options);
  }
  userAttention(
    input: BoundaryInput<"user.attention">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.attention">> {
    return this.dispatch("user.attention", input, options);
  }
  userElicitationRequest(
    input: BoundaryInput<"user.elicitation.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.request">> {
    return this.dispatch("user.elicitation.request", input, options);
  }
  userElicitationResult(
    input: BoundaryInput<"user.elicitation.result">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.result">> {
    return this.dispatch("user.elicitation.result", input, options);
  }
  userMessageInbound(
    input: BoundaryInput<"user.message.inbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.inbound">> {
    return this.dispatch("user.message.inbound", input, options);
  }
  userMessageOutbound(
    input: BoundaryInput<"user.message.outbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.outbound">> {
    return this.dispatch("user.message.outbound", input, options);
  }
  workspaceChangeBefore(
    input: BoundaryInput<"workspace.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.before">> {
    return this.dispatch("workspace.change.before", input, options);
  }
  workspaceChangeAfter(
    input: BoundaryInput<"workspace.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.after">> {
    return this.dispatch("workspace.change.after", input, options);
  }
  fileChanged(
    input: BoundaryInput<"file.changed">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"file.changed">> {
    return this.dispatch("file.changed", input, options);
  }
  hookFailure(
    input: BoundaryInput<"hook.failure">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"hook.failure">> {
    return this.dispatch("hook.failure", input, options);
  }
}

function cloneInput(value: any): any {
  if (value instanceof ReadableStream) return value;
  if (Array.isArray(value)) return value.map(cloneInput);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, cloneInput(v)]),
    );
  return value;
}
function projectNative(event: any, includeNative?: boolean): any {
  const copy = cloneInput(event);
  if (includeNative !== true) delete copy.native;
  return copy;
}
// Only known capability fields carry permission semantics. Extension fields at
// every level remain opaque; their values must not affect local narrowing.
const modifyOperations = { replace: true, merge: true };
const capabilitySemantics = {
  effects: true,
  elicitation: { form: {}, url: {} },
  flow: {
    operations: true,
    continuationCount: true,
    maxContinuations: true,
    remainingContinuations: true,
  },
  inject: { context: { append: true, deliverAt: true } },
  modify: Object.fromEntries(
    [
      "content",
      "input",
      "instructions",
      "output",
      "prompt",
      "request",
      "response",
      "summary",
      "workspace",
    ].map((target) => [target, modifyOperations]),
  ),
};
function isNarrower(
  next: any,
  previous: any,
  semantics: any = capabilitySemantics,
): boolean {
  if (semantics === true) {
    if (Array.isArray(next))
      return Array.isArray(previous) && next.every((v) => previous.includes(v));
    if (typeof next === "number" && typeof previous === "number")
      return next <= previous;
    return next === previous || next === false;
  }
  return Object.entries(next).every(
    ([key, value]) =>
      !Object.hasOwn(semantics, key) ||
      (key === "continuationCount"
        ? typeof value === "number" && value >= (previous?.[key] ?? 0)
        : (semantics[key] === true || previous?.[key] !== undefined) &&
          isNarrower(value, previous?.[key], semantics[key])),
  );
}
function combineSignals(first: AbortSignal, second?: AbortSignal): AbortSignal {
  return second ? AbortSignal.any([first, second]) : first;
}
function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}

function secureEndpoint(value: string): void {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.username ||
    url.password ||
    url.hash ||
    !(url.protocol === "https:" || (url.protocol === "http:" && loopback))
  )
    throw new Error("Unsafe endpoint");
}

function deadlineAfter(ms: number, parent: AbortSignal) {
  const controller = new AbortController();
  const expires = Date.now() + ms;
  const timer = setTimeout(
    () => controller.abort(new Error("Hook deadline exceeded")),
    ms,
  );
  const signal = combineSignals(parent, controller.signal);
  return {
    signal,
    dispose: () => clearTimeout(timer),
    check: () => {
      if (Date.now() >= expires)
        controller.abort(new Error("Hook deadline exceeded"));
      signal.throwIfAborted();
    },
  };
}
