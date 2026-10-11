/** Canonical draft validation and synthetic, request-capability-gated runtime slices. */
import { Ajv2020 } from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv";
import { fullFormats } from "ajv-formats/dist/formats.js";
import { addCanonicalSchemas, parseJson } from "../json.js";
import {
  parseEffect as decodeEffect,
  parseInterceptRequest as decodeRequest,
  parseInterceptResponse as decodeResponse,
  parseCapabilities as decodeCapabilities,
  parseCapabilitiesRequest as decodeCapabilitiesRequest,
  parseCapabilitiesResponse as decodeCapabilitiesResponse,
  parseObserveNotification as decodeObserveNotification,
  parseRegistration as decodeRegistration,
} from "./raw.js";
import type {
  Effect,
  InterceptRequest,
  InterceptResponse,
  Capabilities,
  CapabilitiesRequest,
  CapabilitiesResponse,
  ParseResult,
  ObserveNotification,
  Registration,
} from "./raw.js";

export type {
  AdditionalProperties,
  AllowEffect,
  AskEffect,
  AttachmentBodyPart,
  AttachmentGapPart,
  AttachmentMetadataPart,
  AttachmentOmittedPart,
  Authentication,
  Backend,
  Candidate,
  CanonicalMessage,
  CanonicalMessages,
  Capabilities,
  CapabilitiesRequest,
  CapabilitiesResponse,
  CapabilityDeclaration,
  CapabilityDelivery,
  CapabilityFlowOperation,
  CapabilityModifyOperations,
  CapabilityObservation,
  CatalogueEvent,
  ConfigChangeAfterEvent,
  ConfigChangeAfterInput,
  ConfigChangeBeforeCapabilities,
  ConfigChangeBeforeEffect,
  ConfigChangeBeforeEvent,
  ConfigChangeBeforeInput,
  ConfigChangeBeforeInterceptResponse,
  ContentItem,
  ContentReference,
  ContentSelection,
  ContentSourceBinding,
  ContentUpload,
  ContentUploadReceipt,
  ContextCompactAfterCapabilities,
  ContextCompactAfterEffect,
  ContextCompactAfterEvent,
  ContextCompactAfterInput,
  ContextCompactAfterInterceptResponse,
  ContextCompactAfterModifyEffect,
  ContextCompactBeforeCapabilities,
  ContextCompactBeforeEffect,
  ContextCompactBeforeEvent,
  ContextCompactBeforeInput,
  ContextCompactBeforeInterceptResponse,
  ContextCompactBeforeModifyEffect,
  ContinueFlowEffect,
  DeliveryDiagnosticCode,
  DenyEffect,
  Effect,
  EffectName,
  ElicitResult,
  ElicitResultCandidate,
  ElicitResultState,
  Event,
  EventInputs,
  EventResponses,
  EventType,
  ExecutionEvent,
  ExecutionEventAttempt,
  ExecutionEventAttemptusage,
  ExecutionEventBatch,
  ExecutionEventContextCompactAfter,
  ExecutionEventContextCompactBefore,
  ExecutionEventError,
  ExecutionEventExecution,
  ExecutionEventFilechange,
  ExecutionEventMcp,
  ExecutionEventModel,
  ExecutionEventModelError,
  ExecutionEventModelRequestBefore,
  ExecutionEventModelResponseAfter,
  ExecutionEventModelSwitchAfter,
  ExecutionEventModelSwitchBefore,
  ExecutionEventTokencounts,
  ExecutionEventTool,
  ExecutionEventToolBatchAfter,
  ExecutionEventToolPermissionRequest,
  ExecutionEventToolPermissionResolved,
  ExecutionEventToolProgress,
  ExecutionEventTurnEnd,
  ExecutionEventTurnFinishBefore,
  ExecutionEventTurnProgress,
  ExecutionEventTurnStart,
  ExecutionEventTurnusage,
  ExecutionEventUsage,
  Extensions,
  FileChangedEvent,
  FileChangedInput,
  FormAnswerValue,
  FormAnswers,
  HookFailureEvent,
  HookFailureInput,
  HostAttachmentPart,
  HostContentPart,
  HostEventInputs,
  HostMessage,
  HostTextPart,
  HttpTransport,
  InitialState,
  InjectEffect,
  InteractionEvent,
  InteractionEventConfigChangeAfter,
  InteractionEventConfigChangeBefore,
  InteractionEventHookFailure,
  InteractionEventUserAttention,
  InteractionEventUserElicitationRequest,
  InteractionEventUserElicitationResult,
  InteractionEventUserMessageInbound,
  InteractionEventUserMessageOutbound,
  InterceptDenyResponse,
  InterceptNoEffectResponse,
  InterceptRequest,
  InterceptResponse,
  InterceptSubscription,
  JsonPrimitive,
  JsonRpcErrorResponse,
  JsonRpcId,
  JsonRpcMessage,
  JsonRpcNotification,
  JsonRpcRequest,
  JsonRpcResponseId,
  JsonRpcSuccessResponse,
  JsonValue,
  McpElicitationBooleanSchema,
  McpElicitationElicitRequestFormParams,
  McpElicitationElicitRequestParams,
  McpElicitationElicitRequestURLParams,
  McpElicitationElicitResult,
  McpElicitationLegacyTitledEnumSchema,
  McpElicitationNumberSchema,
  McpElicitationPrimitiveSchemaDefinition,
  McpElicitationProgressToken,
  McpElicitationRequest,
  McpElicitationResult,
  McpElicitationStringSchema,
  McpElicitationTaskMetadata,
  McpElicitationTitledMultiSelectEnumSchema,
  McpElicitationTitledSingleSelectEnumSchema,
  McpElicitationUntitledMultiSelectEnumSchema,
  McpElicitationUntitledSingleSelectEnumSchema,
  MessageEffect,
  MessagesCandidate,
  MessagesState,
  ModelErrorEvent,
  ModelErrorInput,
  ModelRequestBeforeCapabilities,
  ModelRequestBeforeEffect,
  ModelRequestBeforeEvent,
  ModelRequestBeforeInput,
  ModelRequestBeforeInterceptResponse,
  ModelRequestBeforeModifyEffect,
  ModelResponseAfterCapabilities,
  ModelResponseAfterEffect,
  ModelResponseAfterEvent,
  ModelResponseAfterInput,
  ModelResponseAfterInterceptResponse,
  ModelResponseAfterModifyEffect,
  ModelSwitchAfterEvent,
  ModelSwitchAfterInput,
  ModelSwitchBeforeCapabilities,
  ModelSwitchBeforeEffect,
  ModelSwitchBeforeEvent,
  ModelSwitchBeforeInput,
  ModelSwitchBeforeInterceptResponse,
  ModelVisibleItem,
  ModifyFormEffect,
  ModifyInputEffect,
  ModifyMessagesEffect,
  ModifyTextEffect,
  ModifyWorkspaceEffect,
  NativeEvent,
  ObserveNotification,
  ObserveSubscription,
  OpenString,
  OwnedAttachment,
  ParseDiagnostic,
  ParseResult,
  ProtocolVersion,
  Registration,
  RegistrationContentreceiver,
  ResponseFor,
  ReturnElicitResultEffect,
  ReturnMessagesEffect,
  ReturnTextEffect,
  ReturnToolEffect,
  ReverseDnsName,
  Session,
  SessionCounters,
  SessionEndEvent,
  SessionEndInput,
  SessionStartCapabilities,
  SessionStartEffect,
  SessionStartEvent,
  SessionStartInput,
  SessionStartInterceptResponse,
  StateCandidate,
  StaticCapabilityManifest,
  StdioTransport,
  StopFlowEffect,
  TaskChangeAfterEvent,
  TaskChangeAfterInput,
  TaskChangeBeforeCapabilities,
  TaskChangeBeforeEffect,
  TaskChangeBeforeEvent,
  TaskChangeBeforeInput,
  TaskChangeBeforeInterceptResponse,
  TaskWorkspaceEvent,
  TaskWorkspaceEventFileChanged,
  TaskWorkspaceEventTaskChangeAfter,
  TaskWorkspaceEventTaskChangeBefore,
  TaskWorkspaceEventWorkspaceChangeAfter,
  TaskWorkspaceEventWorkspaceChangeBefore,
  TextBodyPart,
  TextCandidate,
  TextGapPart,
  TextMetadataPart,
  TextOmittedPart,
  TextPart,
  TextParts,
  TextState,
  ToolAfterCapabilities,
  ToolAfterEffect,
  ToolAfterEvent,
  ToolAfterInput,
  ToolAfterInterceptResponse,
  ToolAfterModifyEffect,
  ToolBatchAfterCapabilities,
  ToolBatchAfterEffect,
  ToolBatchAfterEvent,
  ToolBatchAfterInput,
  ToolBatchAfterInterceptResponse,
  ToolBeforeCapabilities,
  ToolBeforeEffect,
  ToolBeforeEvent,
  ToolBeforeInput,
  ToolBeforeInterceptResponse,
  ToolBeforeModifyEffect,
  ToolCandidate,
  ToolPermissionRequestCapabilities,
  ToolPermissionRequestEffect,
  ToolPermissionRequestEvent,
  ToolPermissionRequestInput,
  ToolPermissionRequestInterceptResponse,
  ToolPermissionRequestModifyEffect,
  ToolPermissionResolvedEvent,
  ToolPermissionResolvedInput,
  ToolProgressEvent,
  ToolProgressInput,
  ToolState,
  TurnEndEvent,
  TurnEndInput,
  TurnFinishBeforeCapabilities,
  TurnFinishBeforeEffect,
  TurnFinishBeforeEvent,
  TurnFinishBeforeInput,
  TurnFinishBeforeInterceptResponse,
  TurnFinishBeforeModifyEffect,
  TurnProgressEvent,
  TurnProgressInput,
  TurnStartCapabilities,
  TurnStartEffect,
  TurnStartEvent,
  TurnStartInput,
  TurnStartInterceptResponse,
  TurnStartModifyEffect,
  UnknownVariant,
  UserAttentionEvent,
  UserAttentionInput,
  UserElicitationRequestCapabilities,
  UserElicitationRequestEffect,
  UserElicitationRequestEvent,
  UserElicitationRequestInput,
  UserElicitationRequestInterceptResponse,
  UserElicitationResultCapabilities,
  UserElicitationResultEffect,
  UserElicitationResultEvent,
  UserElicitationResultInput,
  UserElicitationResultInterceptResponse,
  UserElicitationResultModifyEffect,
  UserMessageInboundCapabilities,
  UserMessageInboundEffect,
  UserMessageInboundEvent,
  UserMessageInboundInput,
  UserMessageInboundInterceptResponse,
  UserMessageInboundModifyEffect,
  UserMessageOutboundCapabilities,
  UserMessageOutboundEffect,
  UserMessageOutboundEvent,
  UserMessageOutboundInput,
  UserMessageOutboundInterceptResponse,
  UserMessageOutboundModifyEffect,
  WireMessage,
  WorkspaceChange,
  WorkspaceChangeAfterEvent,
  WorkspaceChangeAfterInput,
  WorkspaceChangeBeforeCapabilities,
  WorkspaceChangeBeforeEffect,
  WorkspaceChangeBeforeEvent,
  WorkspaceChangeBeforeInput,
  WorkspaceChangeBeforeInterceptResponse,
  WorkspaceChangeBeforeModifyEffect,
} from "./types.js";
export {
  CapabilityBuilder,
  PROTOCOL_VERSION,
  Permission,
  SCHEMA_REVISION,
  capabilities,
  capabilitiesRequestSchemaRevision,
  capabilitiesResponseSchemaRevision,
  capabilitiesSchemaRevision,
  catalogueEventSchemaRevision,
  contentItemSchemaRevision,
  contentReferenceSchemaRevision,
  contentSelectionSchemaRevision,
  contentSlots,
  contentUploadReceiptSchemaRevision,
  contentUploadSchemaRevision,
  denyEffectSchemaRevision,
  effectNames,
  effectSchemaRevision,
  effects,
  encodeCapabilities,
  encodeCapabilitiesRequest,
  encodeCapabilitiesResponse,
  encodeCatalogueEvent,
  encodeContentItem,
  encodeContentReference,
  encodeContentSelection,
  encodeContentUpload,
  encodeContentUploadReceipt,
  encodeDenyEffect,
  encodeEffect,
  encodeEvent,
  encodeExecutionEvent,
  encodeExtensions,
  encodeInteractionEvent,
  encodeInterceptDenyResponse,
  encodeInterceptNoEffectResponse,
  encodeInterceptRequest,
  encodeInterceptResponse,
  encodeJsonRpcMessage,
  encodeObserveNotification,
  encodeRegistration,
  encodeSessionEndEvent,
  encodeSessionStartEvent,
  encodeTaskWorkspaceEvent,
  encodeToolAfterEvent,
  encodeToolBeforeEvent,
  encodeWireMessage,
  eventSchemaRevision,
  events,
  executionEventSchemaRevision,
  extensionsSchemaRevision,
  interactionEventSchemaRevision,
  interceptDenyResponseSchemaRevision,
  interceptNoEffectResponseSchemaRevision,
  interceptRequestSchemaRevision,
  interceptResponseSchemaRevision,
  jsonRpcMessageSchemaRevision,
  observeNotificationSchemaRevision,
  ownedAttachment,
  parseCapabilities,
  parseCapabilitiesRequest,
  parseCapabilitiesResponse,
  parseCatalogueEvent,
  parseContentItem,
  parseContentReference,
  parseContentSelection,
  parseContentUpload,
  parseContentUploadReceipt,
  parseDenyEffect,
  parseEffect,
  parseEvent,
  parseExecutionEvent,
  parseExtensions,
  parseInteractionEvent,
  parseInterceptDenyResponse,
  parseInterceptNoEffectResponse,
  parseJsonRpcMessage,
  parseObserveNotification,
  parseRegistration,
  parseSessionEndEvent,
  parseSessionStartEvent,
  parseTaskWorkspaceEvent,
  parseToolAfterEvent,
  parseToolBeforeEvent,
  parseWireMessage,
  registrationSchemaRevision,
  responseForEvent,
  responseForRequest,
  sessionEndEventSchemaRevision,
  sessionStartEventSchemaRevision,
  state,
  supports,
  taskWorkspaceEventSchemaRevision,
  toEventInput,
  toolAfterEventSchemaRevision,
  toolBeforeEventSchemaRevision,
  wireMessageSchemaRevision,
} from "./public.js";
export * as draftCodecs from "./codecs.js";
export * as reference from "./reference.js";

export type DraftValidationResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly string[] };

// Initialize canonical validation only when used; the narrow root runner does not
// pay catalogue compilation costs while starting a short-lived stdio backend.
let registry: Ajv2020 | undefined;
const base = "https://agenthooksprotocol.org/schemas/draft/";
function validator(name: string): ValidateFunction {
  if (registry === undefined) {
    // No coercion, default insertion, removal of unknown fields, or partial acceptance.
    registry = new Ajv2020({
      allErrors: true,
      strict: false,
      ownProperties: true,
    });
    registry.addFormat("uri", fullFormats.uri);
    registry.addFormat("date-time", fullFormats["date-time"]);
    addCanonicalSchemas(registry);
  }
  return registry.getSchema(base + name + ".schema.json")!;
}

// JSON Schema operates on JSON, not arbitrary JS objects (NaN, undefined, cycles, etc.).
function isJson(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return true;
  if (typeof value === "bigint") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || ancestors.has(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (
    !Array.isArray(value) &&
    prototype !== Object.prototype &&
    prototype !== null
  )
    return false;
  ancestors.add(value);
  const valid = Array.isArray(value)
    ? Object.keys(value).length === value.length &&
      Array.from(value).every((item) => isJson(item, ancestors))
    : Reflect.ownKeys(value).every((key) => {
        const property = Object.getOwnPropertyDescriptor(value, key);
        return (
          typeof key === "string" &&
          property?.enumerable === true &&
          "value" in property &&
          isJson(property.value, ancestors)
        );
      });
  ancestors.delete(value);
  return valid;
}

function validate<T>(
  value: unknown,
  canonical: ValidateFunction,
  decode: (value: unknown) => ParseResult<T>,
): DraftValidationResult<T> {
  try {
    if (!isJson(value))
      return { ok: false, errors: ["Expected a finite, acyclic JSON value"] };
    if (!canonical(value)) {
      return {
        ok: false,
        errors: (canonical.errors ?? []).map(
          (error) =>
            `${error.instancePath || "/"}: ${error.message ?? error.keyword}`,
        ),
      };
    }
    // Generated decoding is deliberately permissive; canonical validation above is mandatory.
    const decoded = decode(value);
    return decoded.ok
      ? { ok: true, value: decoded.value }
      : {
          ok: false,
          errors: decoded.diagnostics.map(
            (error) => `${error.path}: ${error.message}`,
          ),
        };
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }
}

/** Strict canonical validation for transport-neutral notification consumers. */
export function validateObserveNotification(
  value: unknown,
): DraftValidationResult<ObserveNotification> {
  return validate(
    value,
    validator("observe-notification"),
    decodeObserveNotification,
  );
}

/** Schema/codec validation only; Hooks initialization resolves host capabilities. */
export function validateRegistration(
  value: unknown,
): DraftValidationResult<Registration> {
  return validate(value, validator("registration"), decodeRegistration);
}

export function validateEffect(value: unknown): DraftValidationResult<Effect> {
  return validate(value, validator("effect"), decodeEffect);
}

export function validateCapabilities(
  value: unknown,
): DraftValidationResult<Capabilities> {
  return validate(value, validator("capabilities"), decodeCapabilities);
}
export function validateCapabilitiesRequest(
  value: unknown,
): DraftValidationResult<CapabilitiesRequest> {
  return validate(
    value,
    validator("capabilities-request"),
    decodeCapabilitiesRequest,
  );
}
export function validateCapabilitiesResponse(
  value: unknown,
): DraftValidationResult<CapabilitiesResponse> {
  return validate(
    value,
    validator("capabilities-response"),
    decodeCapabilitiesResponse,
  );
}

export function validateInterceptRequest(
  value: unknown,
): DraftValidationResult<InterceptRequest> {
  const result = validate(value, validator("intercept-request"), decodeRequest);
  if (result.ok && result.value.id !== result.value.params.event.id)
    return { ok: false, errors: ["Request id must equal event id"] };
  return result;
}

export function validateInterceptResponse(
  value: unknown,
): DraftValidationResult<InterceptResponse> {
  return validate(value, validator("intercept-response"), decodeResponse);
}

function parse<T>(
  text: string,
  validator: (value: unknown) => DraftValidationResult<T>,
): DraftValidationResult<T> {
  try {
    return validator(parseJson(text));
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }
}

export function parseInterceptRequest(
  text: string,
): DraftValidationResult<InterceptRequest> {
  return parse(text, validateInterceptRequest);
}

export function parseInterceptResponse(
  text: string,
): DraftValidationResult<InterceptResponse> {
  return parse(text, validateInterceptResponse);
}
