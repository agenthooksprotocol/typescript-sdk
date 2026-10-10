import test from "node:test";
import assert from "node:assert/strict";
import { draftCodecs, contentReference, ContentReceiver } from "agenthooksprotocol/draft";
import { validateWire } from "../dist/src/client/validation.js";

const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const receipt = { ref: "stored", size: 3, sha256: digest };
const item = { id: "item", kind: "attachment", mediaType: "application/octet-stream", selection: "body", body: { ref: "stored" } };

test("receipts are upload-only; structural and canonical references reject deprecated metadata", () => {
  assert.equal(draftCodecs.parseContentUploadReceipt(receipt).ok, true);
  assert.deepEqual(validateWire("content-upload-receipt", receipt), []);
  assert.deepEqual(contentReference(receipt), { ref: "stored" });
  assert.equal(draftCodecs.parseContentReference({ ref: "stored" }).ok, true);
  assert.deepEqual(validateWire("content-reference", { ref: "stored" }), []);
  for (const extra of [{ size: 3 }, { sha256: digest }, { size: null }, { sha256: null }, receipt]) {
    const value = { ref: "stored", ...extra };
    assert.equal(draftCodecs.parseContentReference(value).ok, false);
    assert.notEqual(validateWire("content-reference", value).length, 0);
  }
  assert.equal(draftCodecs.parseContentUploadReceipt({ ref: "stored" }).ok, false);
});

test("body items reject outer metadata while metadata and gap items retain disclosure", () => {
  assert.equal(draftCodecs.parseContentItem(item).ok, true);
  assert.deepEqual(validateWire("content-item", item), []);
  for (const extra of [{ size: 3 }, { sha256: digest }, { size: null }, { sha256: null }, { body: receipt }]) {
    const value = { ...item, ...extra };
    assert.equal(draftCodecs.parseContentItem(value).ok, false);
    assert.notEqual(validateWire("content-item", value).length, 0);
  }
  const { body, ...base } = item;
  for (const value of [
    { ...base, selection: "metadata", size: 3, sha256: digest },
    { ...base, gap: { reason: "source_unavailable" }, size: 3, sha256: digest },
  ]) {
    assert.equal(draftCodecs.parseContentItem(value).ok, true);
    assert.deepEqual(validateWire("content-item", value), []);
  }
});

test("scoped storage resolves ref-only handles independently of wire metadata", async () => {
  const store = new ContentReceiver();
  const bytes = new TextEncoder().encode("abc");
  const uploaded = await store.upload("principal-a", bytes);
  assert.equal(uploaded.size, 3);
  assert.equal(uploaded.sha256, digest);
  const reference = contentReference(uploaded);
  bytes.fill(0);
  assert.deepEqual(store.read("principal-a", reference.ref), new TextEncoder().encode("abc"));
  assert.equal(store.read("principal-b", reference.ref), undefined);
  const copy = store.read("principal-a", reference.ref);
  copy.fill(0);
  assert.deepEqual(store.read("principal-a", reference.ref), new TextEncoder().encode("abc"));
});

test("both request envelopes share Event decoding and reject receipt metadata in events", () => {
  const event = {
    id: "event", source: "urn:test", time: "2026-01-01T00:00:00Z",
    type: "user.message.inbound", message: { channel: "chat", sender: "user", messages: [{ id: "message", role: "user", parts: [item] }] },
  };
  for (const [method, schema, parse, extra] of [
    ["hooks/intercept", "intercept-request", draftCodecs.parseInterceptRequest, { capabilities: { effects: ["deny"] }, state: { candidate: null, permission: "none" } }],
    ["hooks/observe", "observe-notification", draftCodecs.parseObserveNotification, {}],
  ]) {
    const envelope = {
      jsonrpc: "2.0", ...(method === "hooks/intercept" ? { id: "event" } : {}), method,
      params: { protocolVersion: "draft", ...extra, event },
    };
    const parsed = parse(envelope);
    assert.equal(parsed.ok, true, JSON.stringify(parsed));
    assert.deepEqual(validateWire(schema, envelope), []);
    assert.equal(draftCodecs.parseEvent(parsed.value.params.event).ok, true);
    assert.deepEqual({ ...parsed.value.params.event.message.messages[0].parts[0].body }, { ref: "stored" });
    for (const invalidItem of [{ ...item, body: receipt }, { ...item, size: 3 }, { ...item, sha256: digest }]) {
      const invalid = structuredClone(envelope);
      invalid.params.event.message.messages[0].parts = [invalidItem];
      assert.equal(parse(invalid).ok, false);
      assert.notEqual(validateWire(schema, invalid).length, 0);
    }
  }
});


test("standalone subset codecs preserve existing subset-relative unknown variants", () => {
  const tool = { id: "tool", source: "urn:test", time: "2026-01-01T00:00:00Z", type: "tool.before", call: { id: "call" }, path: "native", tool: { name: "read", origin: "native", input: {} } };
  const user = { id: "user", source: "urn:test", time: "2026-01-01T00:00:00Z", type: "user.message.inbound", message: { channel: "chat", sender: "user", messages: [{ id: "message", role: "user", parts: [item] }] } };
  for (const event of [tool, user]) assert.equal(draftCodecs.parseEvent(event).ok, true);
  assert.equal(draftCodecs.parseExecutionEvent(tool).ok, true);
  assert.equal(draftCodecs.parseInteractionEvent(user).ok, true);
  assert.equal(draftCodecs.parseExecutionEvent(user).ok, true);
  assert.equal(draftCodecs.parseInteractionEvent(tool).ok, true);
});


test("intercept rejects known observe-only events but observe accepts shared Event", () => {
  const event = { id: "file", source: "urn:test", time: "2026-01-01T00:00:00Z", type: "file.changed", changes: [{ path: "file.txt", operation: "update", agentCaused: true, before: { ...item, id: "before", body: { ref: "before" } }, after: { ...item, id: "after", body: { ref: "after" } } }] };
  assert.equal(draftCodecs.parseEvent(event).ok, true);
  const request = { jsonrpc: "2.0", id: "file", method: "hooks/intercept", params: { protocolVersion: "draft", capabilities: { effects: [] }, event } };
  assert.equal(draftCodecs.parseInterceptRequest(request).ok, false);
  assert.notEqual(validateWire("intercept-request", request).length, 0);
  const notification = { jsonrpc: "2.0", method: "hooks/observe", params: { protocolVersion: "draft", event } };
  assert.equal(draftCodecs.parseObserveNotification(notification).ok, true);
  assert.deepEqual(validateWire("observe-notification", notification), []);
});
