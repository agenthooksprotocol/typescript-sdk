import type { CanonicalMessage as GeneratedMessage, Effect as GeneratedEffect, InterceptNoEffectResponse } from 'agenthooksprotocol/generated';
import type { CanonicalMessage as ClientMessage } from 'agenthooksprotocol/client';
import type { CanonicalMessage as DraftMessage } from 'agenthooksprotocol/draft';
// @ts-expect-error Generated public facade must not expose runtime projection.
import { _projectHostInput as generatedProjection } from 'agenthooksprotocol/generated';
// @ts-expect-error Generated public facade must not expose runtime-private types.
import type { PendingAttachment as GeneratedPending } from 'agenthooksprotocol/generated';
// @ts-expect-error Generated public facade must not expose projection bookkeeping.
import type { HostInputProjection as GeneratedProjection } from 'agenthooksprotocol/generated';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type MessageIdentity = Assert<Equal<GeneratedMessage, ClientMessage>>;
type DraftMessageIdentity = Assert<Equal<GeneratedMessage, DraftMessage>>;
type HarnessIdentity = Assert<Equal<import("agenthooksprotocol/client").Harness, import("agenthooksprotocol/generated").Harness>>;
type DraftHarnessIdentity = Assert<Equal<import("agenthooksprotocol/draft").Harness, import("agenthooksprotocol/generated").Harness>>;
type HostInputsWithHarness = {
  [K in import("agenthooksprotocol/client").EventType]: "harness" extends keyof import("agenthooksprotocol/client").EventInput<K> ? K : never;
}[import("agenthooksprotocol/client").EventType];
type ConstructorOwnedHarness = Assert<Equal<HostInputsWithHarness, never>>;
type NoEffectResult = NonNullable<InterceptNoEffectResponse['result']>;
type NoEffectArray = Assert<Equal<NoEffectResult['effects'], GeneratedEffect[] | undefined>>;
const noEffectResponse: InterceptNoEffectResponse = { jsonrpc: '2.0', id: 'none', result: { protocolVersion: 'draft' } };
const typedEffectResponse: InterceptNoEffectResponse = { jsonrpc: '2.0', id: 'effect', result: { protocolVersion: 'draft', effects: [{ type: 'allow' }] } };
// @ts-expect-error Effects must be typed effects, not arbitrary JSON values.
const invalidEffectResponse: InterceptNoEffectResponse = { jsonrpc: '2.0', id: 'invalid', result: { protocolVersion: 'draft', effects: [null, 1, 'allow'] } };
void [noEffectResponse, typedEffectResponse, invalidEffectResponse];

import { draftCodecs } from 'agenthooksprotocol/draft';
// @ts-expect-error Host projection stays behind the filtered draft facade.
import { _projectHostInput } from 'agenthooksprotocol/draft';
// @ts-expect-error Pending attachment bookkeeping is runtime-private.
import type { PendingAttachment } from 'agenthooksprotocol/draft';
// @ts-expect-error Host projection bookkeeping is runtime-private.
import type { HostInputProjection } from 'agenthooksprotocol/draft';
// @ts-expect-error The public codec namespace does not expose host projection.
draftCodecs._projectHostInput;
// @ts-expect-error Raw generated runtime is not an exported package subpath.
import * as rawDraft from 'agenthooksprotocol/draft/raw';
// @ts-expect-error Obsolete generated runtime is not an exported package subpath.
import * as obsoleteDraft from 'agenthooksprotocol/draft/generated';

import {
  Attachment, BackendTransport, ContentManager, Hooks, Type, contract, form,
  type Backend, type Codec, type ContentManagerOptions, type ToolBeforeInput,
  type ToolBeforeResult, type ToolBeforeEvent, type InterceptResponse,
} from 'agenthooksprotocol/client';
// @ts-expect-error Upload scheduling is internal.
import { UploadLimiter } from 'agenthooksprotocol/client';
// @ts-expect-error Shared coordinator creation is internal.
import { createSharedContentManager } from 'agenthooksprotocol/client';
// @ts-expect-error Response coordination is internal.
import { composeResponse } from 'agenthooksprotocol/client';
// @ts-expect-error Async response coordination is internal.
import { composeResponseAsync } from 'agenthooksprotocol/client';
// @ts-expect-error Effect normalization is internal.
import { normalizeEffects } from 'agenthooksprotocol/client';
// @ts-expect-error Use the public contract's decode method.
import { decodeContract } from 'agenthooksprotocol/client';
// @ts-expect-error Composition configuration is internal.
import type { CompositionOptions } from 'agenthooksprotocol/client';
// @ts-expect-error Composition results are internal.
import type { CompositionResult } from 'agenthooksprotocol/client';
// @ts-expect-error Coordination event types are internal.
import type { ClientEvent } from 'agenthooksprotocol/client';
// @ts-expect-error Contextual response composition is internal.
import type { ContextualResponse } from 'agenthooksprotocol/client';
// @ts-expect-error Composed effect bookkeeping is internal.
import type { ComposedEffect } from 'agenthooksprotocol/client';
// @ts-expect-error Host projection is internal.
import type { HostEventInputs } from 'agenthooksprotocol/client';
// @ts-expect-error Owner planning is internal.
import type { OwnedAttachment } from 'agenthooksprotocol/client';
// @ts-expect-error Upload planning is internal.
import type { PendingAttachment } from 'agenthooksprotocol/client';
// @ts-expect-error Host projection is internal.
import type { HostInputProjection } from 'agenthooksprotocol/client';
// @ts-expect-error External inference helpers are not facade APIs.
import type { Static } from 'agenthooksprotocol/client';
// @ts-expect-error External schema inference helpers are not facade APIs.
import type { TSchema } from 'agenthooksprotocol/client';
// @ts-expect-error The domain name is ToolBeforeInput.
import type { TypedToolBeforeInput } from 'agenthooksprotocol/client';
// @ts-expect-error The domain name is ToolBeforeResult.
import type { TypedToolBeforeResult } from 'agenthooksprotocol/client';

const options: ContentManagerOptions = { maxConcurrentUploads: 8 };
// @ts-expect-error Public options cannot supply internal coordination state.
options.uploadLimiter = {};
// @ts-expect-error Public construction cannot supply internal coordination state.
new ContentManager({ uploadLimiter: {} });
const manager = new ContentManager(options);
const argumentsContract = contract(Type.Object({ count: Type.Integer() }));
const resultContract = contract(Type.Object({ answer: Type.String() }));
const decoded: { count: number } = argumentsContract.decode({ count: 1 });
const codec: Codec<{ count: number }> = argumentsContract;
const input: ToolBeforeInput<{ count: number }> = {
  callId: 'call', name: 'read', path: 'native', origin: 'native', input: decoded,
};
declare const hooks: Hooks;
void hooks.toolBefore(input, { contracts: { arguments: codec, result: resultContract } }).then(result => {
  const typed: ToolBeforeResult<{ count: number }, { answer: string }, unknown> = result;
  const count: number = typed.event.tool.input.count;
  if (typed.state.candidate !== null) {
    const answer: string = typed.state.candidate.value.answer;
    // @ts-expect-error The result contract does not declare count.
    typed.state.candidate.value.count;
    void answer;
  }
  void count;
});
const answer = form(Type.Object({ approved: Type.Boolean() }));
const accepted = answer.decode({ action: 'accept', content: { approved: true } });
if (accepted.action === 'accept' && accepted.content !== undefined) {
  const approved: boolean = accepted.content.approved;
  // @ts-expect-error TypeBox inference must not become any.
  const wrong: string = accepted.content.approved;
  void [approved, wrong];
}
declare const backend: Backend;
const transport = new BackendTransport(backend, async (url, init) => fetch(url, init));
void transport.close();
void manager.close();
void Attachment.bytes(new Uint8Array([1]));
declare const event: ToolBeforeEvent;
declare const response: InterceptResponse;
void [event, response];

// @ts-expect-error Attachment is the sole owner; no native-source compatibility adapter.
import type { ContentSource } from 'agenthooksprotocol/client';
// @ts-expect-error The credential model has one name.
import type { AuthCredential } from 'agenthooksprotocol/client';
// @ts-expect-error AuthOptions is the sole factory configuration type.
import type { AuthOverrides } from 'agenthooksprotocol/client';
void hooks.modelRequestBefore({ model: { provider: 'provider', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] }).then(result => {
  const canonicalType: 'model.request.before' = result.event.type;
  // @ts-expect-error There is one authoritative typed event, not a second settlement view.
  void result.settledEvent;
  // @ts-expect-error Observations settle before return and use structured diagnostics.
  void result.observations;
  void canonicalType;
});

// @ts-expect-error Hooks accepts only the canonical delivery provider, not authenticate-only helpers.
const legacyAuth: import('agenthooksprotocol/client').HooksOptions['auth'] = { authenticate: async () => ({ token: 'secret' }) };
void legacyAuth;

// @ts-expect-error Generic dispatch requires canonical content selection, not implicit body decoding.
const missingSelection: import('agenthooksprotocol/client').BoundaryInput<'turn.start'>['items'][number]['parts'][number] = { id: 'text', kind: 'text', mediaType: 'text/plain', text: 'body' };
void missingSelection;

// @ts-expect-error Canonical AttachmentBodyPart is not duplicated by a stream-item interface.
import type { StreamContentItem } from 'agenthooksprotocol/client';
// @ts-expect-error Attachment has one native-source factory, stream.
Attachment.fromStream(new ReadableStream<Uint8Array>());

// @ts-expect-error Interception diagnostics use the sole public DeliveryDiagnostic model.
import type { DeliveryError } from 'agenthooksprotocol/client';
void hooks.toolBefore(input).then(result => {
  // @ts-expect-error Receiver envelopes belong only to acceptedResponses.
  void result.response;
  // @ts-expect-error Structured diagnostics are the sole delivery evidence.
  void result.errors;
  // @ts-expect-error Accepted arguments belong to the typed event.
  void result.input;
  // @ts-expect-error Canonical permission belongs to state.
  void result.permission;
  for (const effect of result.effects) { const family: string = effect.type; void family; }
});

const staticInterest: boolean = hooks.subscribes('tool.before');
// @ts-expect-error Interest requires a generated canonical event name.
const unknownInterest: boolean = hooks.subscribes('future.event');
declare const arbitraryEventName: string;
// @ts-expect-error Arbitrary strings are not canonical event identifiers.
hooks.subscribes(arbitraryEventName);
const concreteEvents = Object.values(events).filter(
  (name): name is import('agenthooksprotocol/client').EventType => typeof name === 'string' && !name.includes('*'),
);
for (const name of concreteEvents) hooks.subscribes(name);
// @ts-expect-error Wildcards are subscription selectors, not occurrence event types.
hooks.subscribes(events.all);
void [staticInterest, unknownInterest];
const staticInterception: boolean = hooks.intercepts('model.response.after');
// @ts-expect-error Interception interest requires a generated canonical event name.
const unknownInterception: boolean = hooks.intercepts('future.event');
// @ts-expect-error Arbitrary strings are not canonical event identifiers.
hooks.intercepts(arbitraryEventName);
for (const name of concreteEvents) hooks.intercepts(name);
void [staticInterception, unknownInterception];
// @ts-expect-error Selector matching stays internal to the client.
hooks.selects('tool.before', ['intercept']);

import type { HostCapabilities } from 'agenthooksprotocol/client';
const metadata: NonNullable<import('agenthooksprotocol/client').HooksOptions['manifestMetadata']> = {
  authentication: ['bearer'], transports: ['http'], contentCategories: ['text'],
  correlationIdentityFields: ['call.id'], gaps: [], limits: { maxUploadBytes: 4096 },
  managedPolicy: { disableable: false, scopes: ['project'] }, toolPaths: ['native'],
  extension: { settings: true },
};
// @ts-expect-error Metadata cannot advertise event grants or observation interest.
metadata.events = [{ event: 'tool.before', modes: ['intercept'], capabilities: { effects: ['deny'] } }];
new Hooks({}, { source: 'urn:test:metadata', harness: { name: 'test', version: '1' }, capabilities: {}, manifestMetadata: metadata });
// @ts-expect-error Harness identity is required at construction.
new Hooks({}, { source: 'urn:test:metadata', capabilities: {} });

// @ts-expect-error Generic capability builders are not a client API.
import { CapabilityBuilder, capabilities } from 'agenthooksprotocol/client';
// @ts-expect-error Canonical wire grants are not high-level host declarations.
import type { EventGrant, EventCapabilities } from 'agenthooksprotocol/client';
const host = { sessionStart: { observe: true }, toolBefore: { intercept: { allow: true, deny: true, returnResult: true, modifyInput: 'replace-and-merge' }, observe: true } } satisfies HostCapabilities;
const elicitationFacility = { userElicitationRequest: { intercept: { elicitation: { form: true } } } } satisfies HostCapabilities;
// @ts-expect-error Empty interception grants no facility.
const emptyIntercept = { toolBefore: { intercept: {} } } satisfies HostCapabilities;
// Empty or observe: false entries are valid declarations that grant nothing.
const missingMode = { toolBefore: {}, sessionEnd: { observe: false } } satisfies HostCapabilities;
// @ts-expect-error Observation-only events cannot intercept.
const wrongMode = { sessionEnd: { intercept: { deny: true } } } satisfies HostCapabilities;
const widerWrongTarget = { toolBefore: { intercept: { deny: true as const, modifySummary: 'replace' as const } } };
// @ts-expect-error Unsupported known capabilities remain forbidden through a wider variable.
const wrongTarget = widerWrongTarget satisfies HostCapabilities;
void [host, elicitationFacility, emptyIntercept, missingMode, wrongMode, wrongTarget];

import { events } from "agenthooksprotocol/client";
import { reference, responseForRequest } from 'agenthooksprotocol/draft';
// @ts-expect-error Contextual response admission requires a canonical event name.
responseForRequest(arbitraryEventName, {});
// @ts-expect-error Unknown wire names must stay at explicit raw admission boundaries.
responseForRequest('future.event', {});
import type { EventType } from 'agenthooksprotocol/client';
const canonicalNames = [
  'tool.before', 'tool.after', 'session.start', 'session.end',
  'config.change.before', 'config.change.after', 'turn.start', 'turn.finish.before',
  'turn.end', 'turn.progress', 'model.request.before', 'model.response.after', 'model.error',
  'model.switch.before', 'model.switch.after', 'tool.permission.request', 'tool.permission.resolved',
  'tool.progress', 'tool.batch.after', 'context.compact.before', 'context.compact.after',
  'task.change.before', 'task.change.after', 'user.attention', 'user.elicitation.request',
  'user.elicitation.result', 'user.message.inbound', 'user.message.outbound',
  'workspace.change.before', 'workspace.change.after', 'file.changed', 'hook.failure',
] as const satisfies readonly EventType[];
for (const type of canonicalNames) {
  hooks.subscribes(type);
  hooks.intercepts(type);
  responseForRequest(type, {});
  const observation = { id: 'occurrence', source: 'urn:test:source', type } satisfies reference.ObservationEvent;
  void observation;
}
// @ts-expect-error Dispatch requires a canonical event identifier, not an arbitrary string.
hooks.dispatch(arbitraryEventName, {} as never);
// @ts-expect-error Reference observation names use the same generated catalogue.
const unknownObservation: reference.ObservationEvent = { id: 'occurrence', source: 'urn:test:source', type: 'future.event' };
// @ts-expect-error Dynamic strings are not canonical observation names.
const dynamicObservation: reference.ObservationEvent = { id: 'occurrence', source: 'urn:test:source', type: arbitraryEventName };
const taskChange = reference.actualTaskChange({ count: 1 }, { count: 2 }, 'occurrence');
const taskChangeName: Extract<EventType, 'task.change.after'> | undefined = taskChange?.type;
void [unknownObservation, dynamicObservation, taskChangeName];
