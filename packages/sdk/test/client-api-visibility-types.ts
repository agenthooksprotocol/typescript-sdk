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
  const count: number = typed.input.count;
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
