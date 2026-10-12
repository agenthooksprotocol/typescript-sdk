import type { CanonicalMessages, TextParts, FormAnswers, WorkspaceChange, JsonValue, AdditionalProperties, CapabilityDelivery } from '../draft/raw.js';

/** Literal effect constructors. Contextual replies constrain the allowed event;
 * request grants and canonical validation remain runtime authority. */
export const effect = {
  allow() { return { type: 'allow' as const }; },
  deny(reason: string) { return { type: 'deny' as const, reason }; },
  ask() { return { type: 'ask' as const }; },
  message(text: string) { return { type: 'message' as const, text }; },
  returnResult<T extends JsonValue>(value: T) { return { type: 'return' as const, value }; },
  replaceInput(value: AdditionalProperties) { return { type: 'modify' as const, target: 'input' as const, operation: 'replace' as const, value }; },
  mergeInput(value: AdditionalProperties) { return { type: 'modify' as const, target: 'input' as const, operation: 'merge' as const, value }; },
  replaceInstructions(value: TextParts) { return { type: 'modify' as const, target: 'instructions' as const, operation: 'replace' as const, value }; },
  mergeInstructions(value: TextParts) { return { type: 'modify' as const, target: 'instructions' as const, operation: 'merge' as const, value }; },
  replaceSummary(value: TextParts) { return { type: 'modify' as const, target: 'summary' as const, operation: 'replace' as const, value }; },
  mergeSummary(value: TextParts) { return { type: 'modify' as const, target: 'summary' as const, operation: 'merge' as const, value }; },
  replacePrompt(value: CanonicalMessages) { return { type: 'modify' as const, target: 'prompt' as const, operation: 'replace' as const, value }; },
  mergePrompt(value: CanonicalMessages) { return { type: 'modify' as const, target: 'prompt' as const, operation: 'merge' as const, value }; },
  replaceRequest(value: CanonicalMessages) { return { type: 'modify' as const, target: 'request' as const, operation: 'replace' as const, value }; },
  mergeRequest(value: CanonicalMessages) { return { type: 'modify' as const, target: 'request' as const, operation: 'merge' as const, value }; },
  replaceResponse(value: CanonicalMessages) { return { type: 'modify' as const, target: 'response' as const, operation: 'replace' as const, value }; },
  mergeResponse(value: CanonicalMessages) { return { type: 'modify' as const, target: 'response' as const, operation: 'merge' as const, value }; },
  replaceOutput(value: CanonicalMessages) { return { type: 'modify' as const, target: 'output' as const, operation: 'replace' as const, value }; },
  mergeOutput(value: CanonicalMessages) { return { type: 'modify' as const, target: 'output' as const, operation: 'merge' as const, value }; },
  replaceContent(value: CanonicalMessages) { return { type: 'modify' as const, target: 'content' as const, operation: 'replace' as const, value }; },
  mergeContent(value: CanonicalMessages) { return { type: 'modify' as const, target: 'content' as const, operation: 'merge' as const, value }; },
  replaceFormContent(value: FormAnswers) { return { type: 'modify' as const, target: 'content' as const, operation: 'replace' as const, value }; },
  mergeFormContent(value: FormAnswers) { return { type: 'modify' as const, target: 'content' as const, operation: 'merge' as const, value }; },
  replaceWorkspace(value: WorkspaceChange) { return { type: 'modify' as const, target: 'workspace' as const, operation: 'replace' as const, value }; },
  mergeWorkspace(value: WorkspaceChange) { return { type: 'modify' as const, target: 'workspace' as const, operation: 'merge' as const, value }; },
  stop(reason: string) { return { type: 'flow' as const, operation: 'stop' as const, reason }; },
  continue(instruction?: string) { return { type: 'flow' as const, operation: 'continue' as const, ...(instruction === undefined ? {} : { instruction }) }; },
  appendContext(value: CanonicalMessages, deliverAt: CapabilityDelivery) { return { type: 'inject' as const, target: 'context' as const, operation: 'append' as const, value, deliverAt }; },
};
