import { Attachment, Hooks, type EventInput } from 'agenthooksprotocol/client';

declare const hooks: Hooks;
const attachment = Attachment.bytes(new Uint8Array([1, 2, 3]));
const input: EventInput<'turn.start'> = {
  turn: { id: 'turn' }, trigger: 'user',
  items: [{ role: 'user', parts: [
    { kind: 'text', text: JSON.stringify({ ask: 'inspect' }) },
    { kind: 'attachment', mediaType: 'application/octet-stream', body: attachment },
  ] }],
};
void hooks.turnStart(input);
void hooks.userMessageInbound({ message: { messages: [{ role: 'user', parts: [{ kind: 'text', text: 'hello' }] }], channel: 'chat', sender: 'user' } });
// @ts-expect-error an owned body must be an Attachment, not a byte array
const badPart: EventInput<'turn.start'>['items'][number]['parts'][number] = { kind: 'attachment', mediaType: 'application/octet-stream', body: new Uint8Array() };
// @ts-expect-error canonical parts have no JSON kind
const badJson: EventInput<'turn.start'>['items'][number]['parts'][number] = { kind: 'json', value: {} };
void badPart; void badJson;
