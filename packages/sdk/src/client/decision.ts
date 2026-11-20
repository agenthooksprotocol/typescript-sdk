import { AuthError, type AuthErrorCode } from "./auth-routing.js";
import { bearerParameters } from "./challenge.js";

/**
 * The scope decision procedure shared by `managedOAuth` and the built-in `auth()`
 * provider (AHP SDK scope contract v2, sections 2 and 4). No other code decides
 * scopes, attaches scopes to an error or chooses a scope-related error code.
 */

/** RFC 6749 section 3.3 scope token. */
const TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
/** RFC 6749 section 3.3 scope list: tokens separated by exactly one SP. */
const LIST = /^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/;

/**
 * A parsed challenge: the response that triggered this operation, if any. `status` is
 * the (possibly inferred) response status, kept for an unparseable challenge too, so a
 * 401 always retires its token (step 0).
 */
export type Challenge = (
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "unauthorized"; hint: readonly string[] }>
  | Readonly<{ kind: "insufficient_scope"; scopes: readonly string[] | undefined }>
  | Readonly<{ kind: "forbidden" }>
  | Readonly<{ kind: "invalid" }>
) & Readonly<{ status?: 401 | 403 }>;

/**
 * Classify a challenge. `status` is the response status; when a host passes only the
 * header (for example on a `prepare` context) it is inferred: `error="insufficient_scope"`
 * means 403, anything else 401. `challenged` without a header is a 401.
 */
export function parseChallenge(status: number | undefined, header: string | undefined, challenged = false): Challenge {
  if (header === undefined) {
    if (status === 403) return { kind: "forbidden", status };
    return status === 401 || (status === undefined && challenged) ? { kind: "unauthorized", hint: [], status: 401 } : { kind: "none" };
  }
  if (status !== undefined && status !== 401 && status !== 403) return { kind: "none" };
  let parameters: Map<string, string> | undefined;
  try { parameters = bearerParameters(header); } catch { parameters = undefined; }
  const resolved = status ?? (parameters?.get("error") === "insufficient_scope" ? 403 : 401);
  const scope = parameters?.get("scope");
  if (!parameters || (scope !== undefined && !LIST.test(scope))) return { kind: "invalid", status: resolved };
  const tokens = scope === undefined ? undefined : scope.split(" ");
  if (resolved === 401) return { kind: "unauthorized", hint: tokens ?? [], status: resolved };
  return parameters.get("error") === "insufficient_scope"
    ? { kind: "insufficient_scope", scopes: tokens, status: resolved } : { kind: "forbidden", status: resolved };
}

export interface DecisionConfig {
  readonly flow: "authorization_code_pkce" | "client_credentials";
  /** S: the client's configured (requested) scopes. */
  readonly requested: readonly string[];
  /** C: the ceiling; defaults to S. */
  readonly ceiling?: readonly string[];
  /** H: host-required scopes. */
  readonly hostRequired?: readonly string[];
  /** E: explicit `prepare` requirements. */
  readonly explicit?: readonly string[];
  /** A preset binding's `scopes`: omitted means no constraint, present must equal S. */
  readonly presetScopes?: readonly string[];
}
export interface DecisionGrant {
  readonly generation: string;
  readonly granted: readonly string[];
  readonly tokenValid: boolean;
  readonly refresh: boolean;
}
export type DecisionOperation = "prepare" | "credential" | "challenge";
export interface DecisionInput {
  readonly op: DecisionOperation;
  readonly config: DecisionConfig;
  /** Undefined when no grant is stored, or for the pre-grant gate. */
  readonly grant?: DecisionGrant | undefined;
  /** The grant generation whose token was sent on the rejected request. */
  readonly sent?: string | undefined;
  readonly challenge: Challenge;
}
export type Outcome =
  | Readonly<{ type: "fail"; error: AuthError; step: number }>
  | Readonly<{ type: "use" }>
  | Readonly<{ type: "refresh" }>
  | Readonly<{ type: "acquire"; request: readonly string[] }>
  | Readonly<{ type: "login"; request: readonly string[] }>;
export interface Decision {
  readonly outcome: Outcome;
  /** R = H ∪ E ∪ Ch, sorted; empty before step 4 can compute it. */
  readonly required: readonly string[];
  /** Step 0: a 401 retires generation `sent` (compare-and-retire) first, whatever the outcome. */
  readonly retire: boolean;
  /** Step 3: P′ = P ∩ C, for a client-credentials acquisition in this operation only. */
  readonly hint: readonly string[];
}

const decided = new WeakSet<AuthError>();
const sorted = (values: Iterable<string>) => [...new Set(values)].sort();
const covers = (set: readonly string[], required: readonly string[]) => required.every(scope => set.includes(scope));
/** The only constructor of a scoped error: `decide`'s and `complete`'s scope outcomes. */
function scoped(code: "access_denied" | "interaction_required", required: readonly string[]): AuthError {
  const error = new AuthError(code, required);
  decided.add(error);
  return error;
}
function fail(step: number, code: AuthErrorCode, required?: readonly string[]): Outcome {
  return { type: "fail", step, error: required && (code === "access_denied" || code === "interaction_required") ? scoped(code, required) : new AuthError(code) };
}

let observer: ((input: DecisionInput, decision: Decision) => void) | undefined;
/** Test probe (not a public export): observe every decision. Returns an unsubscribe. */
export function observeDecisions(listener: (input: DecisionInput, decision: Decision) => void): () => void {
  observer = listener;
  return () => { if (observer === listener) observer = undefined; };
}

/** Section 2: exactly one outcome; the first matching step wins. */
export function decide(input: DecisionInput): Decision {
  const decision = evaluate(input);
  observer?.(input, decision);
  return decision;
}

function evaluate({ op, config, grant, sent, challenge }: DecisionInput): Decision {
  // 0. A 401 retires the rejected generation before every other step.
  const retire = challenge.status === 401 && sent !== undefined;
  const none = (outcome: Outcome, required: readonly string[] = []): Decision => ({ outcome, required, retire, hint: [] });
  // 1. Configuration.
  const S = config.requested, C = config.ceiling ?? config.requested, H = config.hostRequired ?? [], E = config.explicit ?? [];
  const lists = [S, C, H, E, ...(config.presetScopes ? [config.presetScopes] : [])];
  if (lists.some(list => !Array.isArray(list) || list.some(scope => typeof scope !== "string" || !TOKEN.test(scope))) ||
      !covers(C, S) ||
      (config.presetScopes !== undefined && JSON.stringify(sorted(config.presetScopes)) !== JSON.stringify(sorted(S)))) {
    return none(fail(1, "invalid_configuration"));
  }
  // 2. Challenge form.
  if (challenge.kind === "invalid" || challenge.kind === "forbidden") return none(fail(2, "access_denied"));
  if (challenge.kind === "insufficient_scope" && challenge.scopes === undefined && H.length === 0 && E.length === 0) {
    return none(fail(2, "access_denied"));
  }
  // 3. A 401's hint stays in this operation.
  const hint = challenge.kind === "unauthorized" ? sorted(challenge.hint.filter(scope => C.includes(scope))) : [];
  const Ch = challenge.kind === "insufficient_scope" ? challenge.scopes ?? [] : [];
  const R = sorted([...H, ...E, ...Ch]);
  const result = (outcome: Outcome): Decision => ({ outcome, required: R, retire, hint });
  // 4. Ceiling.
  if (!covers(C, R)) return result(fail(4, "access_denied", R));
  const effective = grant ? grant.granted.filter(scope => C.includes(scope)) : [];
  const current = grant !== undefined && !(retire && grant.generation === sent);
  // 5. The server disagrees with our record.
  if (challenge.kind === "insufficient_scope" && grant && covers(effective, R)) {
    if (sent === undefined || grant.generation === sent) return result(fail(5, "access_denied", R));
    if (grant.tokenValid) return result({ type: "use" });
  }
  // 6. Use.
  if (current && grant.tokenValid && covers(effective, R)) return result({ type: "use" });
  // 7. Refresh: never broadens a grant.
  if (grant?.refresh && covers(grant.granted, R)) return result({ type: "refresh" });
  const previous = grant?.granted ?? [];
  // 8. Client credentials.
  if (config.flow === "client_credentials") {
    return result({ type: "acquire", request: sorted([...previous, ...[...S, ...R, ...hint].filter(scope => C.includes(scope))]) });
  }
  // 9. PKCE.
  if (op === "prepare") return result({ type: "login", request: sorted([...previous, ...[...S, ...R].filter(scope => C.includes(scope))]) });
  return result(fail(9, "interaction_required", R));
}

/**
 * Steps 7 and 8 (and `complete` step 7) after the grant is persisted: the effective
 * grant must cover R, else `access_denied` with R.
 */
export function coverage(required: readonly string[], granted: readonly string[], ceiling: readonly string[]): AuthError | undefined {
  const effective = granted.filter(scope => ceiling.includes(scope));
  return covers(effective, required) ? undefined : scoped("access_denied", sorted(required));
}

/**
 * Section 4: the boundary classification. Scopes survive only on `decide`'s and
 * `complete`'s own outcomes; every other error (host callbacks, stores, network,
 * token endpoint) is reduced to its code. `loginEnded` is never copied.
 */
export function classify(error: AuthError): AuthError {
  return decided.has(error) ? error : new AuthError(error.code);
}
/** True for a scoped outcome of `decide`/`complete`. */
export function isDecided(error: unknown): boolean {
  return error instanceof AuthError && decided.has(error);
}
