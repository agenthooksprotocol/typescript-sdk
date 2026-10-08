import {
  toEventInput,
  contentSlots,
  CapabilityBuilder,
  Permission,
} from "../draft/generated.js";
import { HookOperationalError } from "../errors.js";
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
import { ContentManager, ContentSource } from "./content.js";
import { composeResponseAsync, normalizeEffects } from "./composition.js";
import { auth } from "./auth.js";
import { validateWire } from "./validation.js";
import {
  ConfigurationError,
  type BoundaryInput,
  type EventInput,
  type BoundaryOptions,
  type BoundaryResult,
  type Event,
  type EventType,
  type HooksOptions,
  type DeliveryError,
  type DeliveryDiagnostic,
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

type ElicitationLifetime = {
  id: string;
  sessionId: string | undefined;
  retired: boolean;
};

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
  // Tokens exist only for active calls, including preparation before any bytes
  // can be retained. Retirement invalidates those calls without tombstones.
  private readonly activeElicitations = new Set<ElicitationLifetime>();

  constructor(config: unknown, options: HooksOptions) {
    this.options = {
      ...options,
      capabilities: structuredClone(
        Array.isArray(
          (options.capabilities as StaticCapabilityManifest)?.events,
        )
          ? options.capabilities
          : Object.fromEntries(
              Object.entries(options.capabilities ?? {}).map(
                ([event, grant]) => [
                  event,
                  grant instanceof CapabilityBuilder ? grant.build() : grant,
                ],
              ),
            ),
      ),
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
          events: Object.entries(c).map(([event, grant]) => {
            const explicit = Object.hasOwn(grant ?? {}, "modes");
            return {
              event,
              modes: explicit ? grant.modes : ["intercept"],
              ...(explicit
                ? grant.capabilities === undefined
                  ? {}
                  : { capabilities: grant.capabilities }
                : { capabilities: grant }),
            };
          }),
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
        this.fetchAuthenticated(
          url,
          init,
          backend.authentication,
          "event",
          backend.id,
        ),
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
    authentication: Authentication | undefined,
    purpose: "event" | "upload",
    backendId: string,
  ): Promise<Response> {
    secureEndpoint(url);
    const signal = init.signal ?? this.lifetime.signal;
    signal.throwIfAborted();
    const key = JSON.stringify([
      backendId,
      purpose,
      url,
      authentication ?? null,
    ]);
    let context = this.authContexts.get(key);
    if (!context) {
      context = {
        url,
        backendId,
        purpose,
        ...(authentication ? { authentication } : {}),
        cache: new Map(),
      };
      this.authContexts.set(key, context);
    }
    // Challenge state belongs to this delivery attempt, never another caller.
    context = { ...context };
    for (let attempt = 0; attempt < 2; attempt++) {
      const credential = await raceAbort(
        Promise.resolve(
          "credential" in this.provider
            ? this.provider.credential({ ...context, signal })
            : this.provider.authenticate({ ...context, signal }, {}),
        ),
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
          ("credential" in this.provider &&
            (!("type" in credential) || credential.type !== "bearer")) ||
          ("expiresAt" in credential &&
            credential.expiresAt !== undefined &&
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
        }).then((response) => {
          if (signal.aborted) {
            void response.body?.cancel().catch(() => {});
            signal.throwIfAborted();
          }
          return response;
        }),
        signal,
      );
      if (response.status === 401 && "credential" in this.provider) {
        try {
          await raceAbort(
            Promise.resolve(
              this.provider.challenge({
                ...context,
                signal,
                response,
                credential,
              }),
            ),
            signal,
          );
        } catch (error) {
          void response.body?.cancel().catch(() => {});
          throw error;
        }
      }
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
    const manager = new ContentManager({
      // Invalid configuration still transfers unused-source cleanup ownership;
      // initialize rejects it before any preparation can use this fallback.
      maxSnapshotBytes:
        Number.isSafeInteger(this.options.maxContentBytes) &&
        this.options.maxContentBytes! > 0
          ? this.options.maxContentBytes!
          : 64 * 1024 * 1024,
      allowLoopback: true,
    });
    manager.own(input);
    manager.own(options.contentSources);
    this.managers.add(manager);
    const signal = combineSignals(this.lifetime.signal, options.signal);
    const exchange: ElicitationLifetime | undefined =
      type === "user.elicitation.request"
        ? {
            id: input.id ?? randomUUID(),
            sessionId: (input as any).session?.id,
            retired: false,
          }
        : undefined;
    if (exchange) this.activeElicitations.add(exchange);
    let completed = false;
    const work = (async () => {
      // Calls after close are misuse. Active calls return interruption evidence.
      this.lifetime.signal.throwIfAborted();
      await this.initialized;
      return this.run(type, input, options, signal, manager, exchange);
    })();
    this.pending.add(work);
    try {
      const result = await work;
      completed = true;
      return result;
    } finally {
      // Terminal exchanges retire even when validation or cancellation bypasses run.
      if (type === "user.elicitation.result")
        this.forgetElicitation((input as any).parentEventId);
      if (
        type === "user.elicitation.request" &&
        (!completed || signal.aborted) &&
        input.id
      )
        this.forgetElicitation(input.id);
      if (type === "session.end")
        this.retireSessionElicitations((input as any).session?.id);
      if (exchange) this.activeElicitations.delete(exchange);
      await manager.close();
      this.managers.delete(manager);
      this.pending.delete(work);
    }
  }

  private async run<K extends EventType>(
    type: K,
    input: BoundaryInput<K>,
    options: BoundaryOptions,
    signal: AbortSignal,
    manager: ContentManager,
    exchange?: ElicitationLifetime,
  ): Promise<BoundaryResult<K>> {
    let event: any = cloneInput({
      ...input,
      type,
      source: this.options.source,
      id: exchange?.id ?? input.id ?? randomUUID(),
      time: input.time ?? new Date().toISOString(),
    });
    bindContentSources(type, event, options.contentSources);
    if (type === "session.start")
      event.manifest = structuredClone(this.manifest);
    const requestId = event.id;
    // Project actual settled state, never replay cumulative effects: that would
    // duplicate injections/instructions and lose candidate invalidation.
    const snapshotState = (
      value: BoundaryOptions["initialState"],
    ): BoundaryResult<K>["state"] => {
      const snapshot = structuredClone(
        value ?? { candidate: null, permission: "none" },
      );
      if (
        !Object.values(Permission).includes(snapshot.permission as Permission)
      )
        throw new ConfigurationError([
          { path: "initialState.permission", code: "INVALID_BOUNDARY_STATE" },
        ]);
      const freeze = (value: unknown): void => {
        if (value !== null && typeof value === "object") {
          for (const child of Object.values(value)) freeze(child);
          Object.freeze(value);
        }
      };
      freeze(snapshot);
      return snapshot;
    };
    if (signal.aborted)
      return {
        event: await resultEvent(event, manager),
        response: {
          jsonrpc: "2.0",
          id: requestId,
          result: { protocolVersion: "draft", effects: [] },
        },
        state: snapshotState(options.initialState),
        get permission() {
          return this.state.permission as `${Permission}`;
        },
        get input(): unknown {
          return (this.event as any).tool?.input;
        },
        errors: [],
        diagnostics: [],
        observations: Promise.resolve([]),
        interrupted: true,
      } as BoundaryResult<K>;
    const localSources = new Set<ReadableStream<Uint8Array>>();
    const originalRequest = this.elicitationFor(event);
    manager.own(originalRequest);
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
        let received = false;
        let budget: ReturnType<typeof deadlineAfter> | undefined;
        try {
          const projected = await raceAbort(
            manager.prepare(
              projectNative(event, s.includeNative),
              s.content,
              s.upload,
              (url, init, upload) =>
                this.fetchAuthenticated(
                  url,
                  init,
                  upload.auth,
                  "upload",
                  route.backend.id,
                ),
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
            this.rememberElicitation(event, bytes, exchange!);
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
          const reply = await route.transport.request(request, deadline);
          received = true;
          budget.check();
          if (reply && typeof reply === "object" && "error" in reply)
            throw new HookOperationalError(
              "JSON_RPC_ERROR",
              "Backend returned a JSON-RPC error",
            );
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
              ownContent: (body) => {
                manager.own(body);
                localSources.add(body);
              },
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
        } catch (cause) {
          interrupted = signal.aborted;
          const syntheticDenial =
            !interrupted && s.failurePolicy === "fail-closed";
          const error: DeliveryError = {
            backendId: route.backend.id,
            subscriptionIndex: route.index,
            phase,
            code: interrupted
              ? cancellationCode(signal)
              : deadline?.aborted
                ? "DEADLINE_EXCEEDED"
                : phase === "preparation"
                  ? "PREPARATION_FAILED"
                  : "DELIVERY_FAILED",
            failurePolicy: s.failurePolicy as "fail-open" | "fail-closed",
            syntheticDenial,
          };
          diagnosticCauses.set(
            error,
            classifyDiagnostic(
              cause,
              signal.aborted ? signal : deadline,
              phase === "preparation",
              received,
            ),
          );
          errors.push(error);
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
      // Observation deliveries are owned by this call, but cannot change its decision.
      const observations = matching.filter(
        (r) =>
          advertised.modes.includes("observe") &&
          (r.subscription.mode === "observe" ||
            ((shortCircuit || interrupted) && !called.has(r))),
      );
      let observed: Promise<DeliveryError[]> = Promise.resolve([]);
      // Cancellation stops new work, including settlement notifications. Each
      // observer budget can shorten, but never extend, the operation signal.
      if (!signal.aborted && observations.length) {
        const snapshot = cloneInput(event);
        const jobs = observations.map((route) =>
          this.observe(route, snapshot, manager, signal),
        );
        observed = Promise.all(jobs).then((results) =>
          results.filter(
            (result): result is DeliveryError => result !== undefined,
          ),
        );
        await observed;
      }
      interrupted ||= signal.aborted;
      if (type === "user.elicitation.result")
        this.forgetElicitation(event.parentEventId);
      if (
        type === "user.elicitation.request" &&
        (interrupted ||
          errors.length > 0 ||
          (await observed).length > 0 ||
          effects.some((e) => e.type === "deny"))
      )
        this.forgetElicitation(event.id);
      if (type === "session.end")
        this.retireSessionElicitations(event.session?.id);
      const response = {
        jsonrpc: "2.0",
        id: requestId,
        result: { protocolVersion: "draft", effects },
      } as InterceptResponse;
      return {
        event: await resultEvent(event, manager, localSources),
        response,
        state: snapshotState(state),
        get permission() {
          return this.state.permission as `${Permission}`;
        },
        get input(): unknown {
          return (this.event as any).tool?.input;
        },
        errors,
        diagnostics: [...errors, ...(await observed)].map(deliveryDiagnostic),
        observations: observed,
        interrupted,
      } as BoundaryResult<K>;
    } catch (error) {
      if (type === "user.elicitation.request")
        this.forgetElicitation(requestId);
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
    let preparing = true;
    try {
      const s = route.subscription;
      const projected = await raceAbort(
        manager.prepare(
          projectNative(event, s.includeNative),
          s.content,
          s.upload,
          (url, init, upload) =>
            this.fetchAuthenticated(
              url,
              init,
              upload.auth,
              "upload",
              route.backend.id,
            ),
          signal,
        ),
        signal,
      );
      preparing = false;
      await route.transport.notify(
        {
          jsonrpc: "2.0",
          method: "hooks/observe",
          params: { protocolVersion: "draft", event: projected },
        },
        signal,
      );
    } catch (cause) {
      const error: DeliveryError = {
        backendId: route.backend.id,
        subscriptionIndex: route.index,
        phase: "observation",
        code: parentSignal.aborted
          ? cancellationCode(parentSignal)
          : signal.aborted
            ? "DEADLINE_EXCEEDED"
            : "DELIVERY_FAILED",
        syntheticDenial: false,
      };
      diagnosticCauses.set(
        error,
        classifyDiagnostic(cause, signal, preparing, false),
      );
      return error;
    } finally {
      budget.dispose();
    }
  }

  private rememberElicitation(
    event: any,
    bytes: Uint8Array,
    exchange: ElicitationLifetime,
  ): void {
    if (exchange.retired || this.lifetime.signal.aborted) return;
    if (this.elicitations.has(event.id)) return;
    const limit = this.options.maxContentBytes ?? 64 * 1024 * 1024;
    if (bytes.byteLength > limit)
      throw new Error("Elicitation request exceeds retention budget");
    if (
      this.elicitationBytes + bytes.byteLength > limit ||
      this.elicitations.size >= 128
    )
      throw new Error("Active elicitation exchanges exceed retention budget");
    // Pending exchanges own only correlation facts and selected request bytes.
    const stored = {
      type: event.type,
      id: event.id,
      source: event.source,
      session: event.session ? { id: event.session.id } : undefined,
      elicitation: {
        mode: event.elicitation.mode,
        server: event.elicitation.server,
        request: { mediaType: event.elicitation.request.mediaType },
      },
    };
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
  /** End an abandoned host elicitation exchange without delivering a result. */
  discardElicitation(requestEventId: string): void {
    this.forgetElicitation(requestEventId);
  }

  private retireSessionElicitations(sessionId: string | undefined): void {
    for (const exchange of this.activeElicitations)
      if (exchange.sessionId === sessionId) exchange.retired = true;
    for (const [id, entry] of this.elicitations)
      if (entry.event.session?.id === sessionId) this.forgetElicitation(id);
  }

  private forgetElicitation(id: string): void {
    for (const exchange of this.activeElicitations)
      if (exchange.id === id) exchange.retired = true;
    const entry = this.elicitations.get(id);
    if (entry) this.elicitationBytes -= entry.bytes.byteLength;
    this.elicitations.delete(id);
  }

  /** Cancel pending work and release SDK-owned resources; injected stores remain owned by the host. */
  close(): Promise<void> {
    if (!this.closed) {
      for (const exchange of this.activeElicitations) exchange.retired = true;
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
  private boundary<K extends EventType>(
    type: K,
    input: EventInput<K>,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<K>> {
    // Generated projection preserves owned source identities; dispatch clones
    // host facts, owns cleanup, and validates the canonical request before I/O.
    return this.dispatch(
      type,
      toEventInput(type, input as any) as unknown as BoundaryInput<K>,
      options,
    );
  }

  toolBefore(
    input: EventInput<"tool.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.before">> {
    return this.boundary("tool.before", input, options);
  }
  toolAfter(
    input: EventInput<"tool.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.after">> {
    return this.boundary("tool.after", input, options);
  }
  sessionStart(
    input: EventInput<"session.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.start">> {
    return this.boundary("session.start", input, options);
  }
  sessionEnd(
    input: EventInput<"session.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.end">> {
    return this.boundary("session.end", input, options);
  }
  configChangeBefore(
    input: EventInput<"config.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.before">> {
    return this.boundary("config.change.before", input, options);
  }
  configChangeAfter(
    input: EventInput<"config.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.after">> {
    return this.boundary("config.change.after", input, options);
  }
  turnStart(
    input: EventInput<"turn.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.start">> {
    return this.boundary("turn.start", input, options);
  }
  turnFinishBefore(
    input: EventInput<"turn.finish.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.finish.before">> {
    return this.boundary("turn.finish.before", input, options);
  }
  turnEnd(
    input: EventInput<"turn.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.end">> {
    return this.boundary("turn.end", input, options);
  }
  turnProgress(
    input: EventInput<"turn.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.progress">> {
    return this.boundary("turn.progress", input, options);
  }
  modelRequestBefore(
    input: EventInput<"model.request.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.request.before">> {
    return this.boundary("model.request.before", input, options);
  }
  modelResponseAfter(
    input: EventInput<"model.response.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.response.after">> {
    return this.boundary("model.response.after", input, options);
  }
  modelError(
    input: EventInput<"model.error">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.error">> {
    return this.boundary("model.error", input, options);
  }
  modelSwitchBefore(
    input: EventInput<"model.switch.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.before">> {
    return this.boundary("model.switch.before", input, options);
  }
  modelSwitchAfter(
    input: EventInput<"model.switch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.after">> {
    return this.boundary("model.switch.after", input, options);
  }
  toolPermissionRequest(
    input: EventInput<"tool.permission.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.request">> {
    return this.boundary("tool.permission.request", input, options);
  }
  toolPermissionResolved(
    input: EventInput<"tool.permission.resolved">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.resolved">> {
    return this.boundary("tool.permission.resolved", input, options);
  }
  toolProgress(
    input: EventInput<"tool.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.progress">> {
    return this.boundary("tool.progress", input, options);
  }
  toolBatchAfter(
    input: EventInput<"tool.batch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.batch.after">> {
    return this.boundary("tool.batch.after", input, options);
  }
  contextCompactBefore(
    input: EventInput<"context.compact.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.before">> {
    return this.boundary("context.compact.before", input, options);
  }
  contextCompactAfter(
    input: EventInput<"context.compact.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.after">> {
    return this.boundary("context.compact.after", input, options);
  }
  taskChangeBefore(
    input: EventInput<"task.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.before">> {
    return this.boundary("task.change.before", input, options);
  }
  taskChangeAfter(
    input: EventInput<"task.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.after">> {
    return this.boundary("task.change.after", input, options);
  }
  userAttention(
    input: EventInput<"user.attention">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.attention">> {
    return this.boundary("user.attention", input, options);
  }
  userElicitationRequest(
    input: EventInput<"user.elicitation.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.request">> {
    return this.boundary("user.elicitation.request", input, options);
  }
  userElicitationResult(
    input: EventInput<"user.elicitation.result">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.result">> {
    return this.boundary("user.elicitation.result", input, options);
  }
  userMessageInbound(
    input: EventInput<"user.message.inbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.inbound">> {
    return this.boundary("user.message.inbound", input, options);
  }
  userMessageOutbound(
    input: EventInput<"user.message.outbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.outbound">> {
    return this.boundary("user.message.outbound", input, options);
  }
  workspaceChangeBefore(
    input: EventInput<"workspace.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.before">> {
    return this.boundary("workspace.change.before", input, options);
  }
  workspaceChangeAfter(
    input: EventInput<"workspace.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.after">> {
    return this.boundary("workspace.change.after", input, options);
  }
  fileChanged(
    input: EventInput<"file.changed">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"file.changed">> {
    return this.boundary("file.changed", input, options);
  }
  hookFailure(
    input: EventInput<"hook.failure">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"hook.failure">> {
    return this.boundary("hook.failure", input, options);
  }
}

// Return independent copies of prepared or synthesized payloads. Never read an
// unselected producer stream solely to construct a result.
async function resultEvent(
  value: any,
  manager: ContentManager,
  localSources = new Set<ReadableStream<Uint8Array>>(),
): Promise<any> {
  if (value instanceof ContentSource) value = value.stream;
  if (value instanceof ReadableStream) {
    const bytes = localSources.has(value)
      ? await manager.readBody(value)
      : await manager.copySnapshot(value);
    if (!bytes) return undefined;
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });
  }
  if (Array.isArray(value))
    return Promise.all(
      value.map((child) => resultEvent(child, manager, localSources)),
    );
  if (value && typeof value === "object") {
    const entries = await Promise.all(
      Object.entries(value).map(async ([key, child]) =>
        [key, await resultEvent(child, manager, localSources)] as const),
    );
    const copy = Object.fromEntries(
      entries.filter(([, child]) => child !== undefined),
    );
    if (
      (value.body instanceof ReadableStream || value.body instanceof ContentSource) &&
      !copy.body
    )
      copy.selection = "metadata";
    return copy;
  }
  return value;
}

function cloneInput(value: any): any {
  if (value instanceof ContentSource) return value.stream;
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
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
    // The operation already exists: own its rejection even if cancellation
    // occurred synchronously while constructing it.
    if (signal.aborted) abort();
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
    () =>
      controller.abort(
        new DOMException("Hook deadline exceeded", "TimeoutError"),
      ),
    ms,
  );
  const signal = combineSignals(parent, controller.signal);
  return {
    signal,
    dispose: () => clearTimeout(timer),
    check: () => {
      if (Date.now() >= expires)
        controller.abort(
          new DOMException("Hook deadline exceeded", "TimeoutError"),
        );
      signal.throwIfAborted();
    },
  };
}

function cancellationCode(
  signal: AbortSignal,
): "DEADLINE_EXCEEDED" | "INTERRUPTED" {
  return signal.reason?.name === "TimeoutError"
    ? "DEADLINE_EXCEEDED"
    : "INTERRUPTED";
}

// Causes remain separate from delivery stage and never retain raw endpoint data.
const diagnosticCauses = new WeakMap<
  DeliveryError,
  DeliveryDiagnostic["code"]
>();
function deliveryDiagnostic(error: DeliveryError): DeliveryDiagnostic {
  return { ...error, code: diagnosticCauses.get(error) ?? "transport" };
}
function classifyDiagnostic(
  cause: unknown,
  signal: AbortSignal | undefined,
  preparing: boolean,
  received: boolean,
): DeliveryDiagnostic["code"] {
  if (signal?.aborted)
    return signal.reason?.name === "TimeoutError"
      ? "deadline_exceeded"
      : "cancelled";
  if (cause instanceof Error && cause.name === "TimeoutError")
    return "deadline_exceeded";
  if (cause instanceof HookOperationalError) {
    if (cause.code === "JSON_RPC_ERROR") return "remote_rpc";
    if (
      [
        "MALFORMED_UTF8",
        "MALFORMED_JSON",
        "MALFORMED_JSON_RPC",
        "ID_MISMATCH",
        "INCOMPATIBLE_VERSION",
        "UNSUPPORTED_EVENT",
        "UNSUPPORTED_EFFECT",
        "MULTIPLE_EFFECTS",
      ].includes(cause.code)
    )
      return "protocol_rejection";
  }
  if (preparing) return "preparation";
  return received ? "protocol_rejection" : "transport";
}

/** Only schema-derived named slots may receive out-of-band sources. */
function bindContentSources(
  type: EventType,
  event: any,
  bindings: BoundaryOptions["contentSources"],
): void {
  const used = new Set<string>();
  for (const binding of bindings ?? []) {
    const source =
      binding.source instanceof ContentSource
        ? binding.source.stream
        : binding.source;
    if (!(source instanceof ReadableStream))
      throw new TypeError("Expected an owned content source");
    const path = binding.path;
    const allowed = Object.values(contentSlots[type]).some((factory) => {
      const bind = factory as (...args: any[]) => {
        path: readonly (string | number)[];
      };
      const expected = (factory.length === 2 ? bind(0, source) : bind(source))
        .path;
      return (
        path.length === expected.length &&
        expected.every((part, index) =>
          typeof part === "number"
            ? Number.isSafeInteger(path[index]) && Number(path[index]) >= 0
            : path[index] === part,
        )
      );
    });
    const key = JSON.stringify(path);
    if (!allowed || used.has(key))
      throw new TypeError("Invalid or duplicate content source slot");
    used.add(key);
    let parent = event;
    for (const part of path.slice(0, -1)) {
      parent = parent?.[part];
      if (!parent || typeof parent !== "object")
        throw new TypeError("Missing content source descriptor");
    }
    const last = path[path.length - 1]!;
    const descriptor = parent[last];
    if (descriptor && typeof descriptor === "object" && "kind" in descriptor) {
      if (descriptor.body !== undefined)
        throw new TypeError("Content source conflicts with an existing body");
      descriptor.body = source;
    } else {
      if (descriptor !== undefined)
        throw new TypeError(
          "Content source conflicts with an existing reference",
        );
      parent[last] = source;
    }
  }
}
