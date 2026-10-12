import type { ServerHandlers, ServerReply } from 'agenthooksprotocol/server';
import { effect, hooks } from 'agenthooksprotocol/server';
import { serveStdio } from 'agenthooksprotocol/server/stdio';
// @ts-expect-error The broad wire-message application handler is not public.
import type { Handler } from 'agenthooksprotocol/server';
// @ts-expect-error Broad uncorrelated effect constructors are not a server API.
import { effects } from 'agenthooksprotocol/server';
void effects;
const handlers = {
  intercept: { toolBefore(ctx) {
    const type: 'tool.before' = ctx.event.type;
    void type;
    return { effects: [effect.replaceInput({ ...ctx.event.tool.input, limit: 10 }), effect.allow()] };
  } },
  observe: { sessionEnd(ctx) { const type: 'session.end' = ctx.event.type; void type; }, toolBefore(ctx) { const type: 'tool.before' = ctx.event.type; void type; } },
} satisfies ServerHandlers;
declare const request: Request;
void hooks.handle(request, handlers);
void serveStdio(handlers);
const emptyReply: ServerReply<'tool.before'> = {};
void emptyReply;
// @ts-expect-error Handler registration needs at least one callback.
const emptyHandlers: ServerHandlers = {};
// @ts-expect-error An empty observation map is not a callback.
const emptyObservers: ServerHandlers = { observe: {} };
// @ts-expect-error An intercept callback cannot return void.
const missingReply: ServerHandlers = { intercept: { toolBefore() {} } };
// @ts-expect-error Compaction returns must contain text parts, not a string.
const wrongReturn: ServerHandlers = { intercept: { contextCompactBefore() { return { effects: [effect.returnResult('summary')] }; } } };
// @ts-expect-error After-compaction callbacks cannot return allow effects.
const wrongEffect: ServerHandlers = { intercept: { contextCompactAfter() { return { effects: [effect.allow()] }; } } };
// @ts-expect-error Observe-only events cannot return controls.
const observationControl: ServerHandlers = { observe: { sessionEnd() { return { effects: [effect.deny('no')] }; } } };
// @ts-expect-error Observation callbacks for interceptable events cannot return controls.
const observeInterceptControl: ServerHandlers = { observe: { toolBefore() { return { effects: [{ type: 'allow' }] }; } } };
// @ts-expect-error Correlation and protocolVersion are server-owned.
const version: ServerReply<'tool.before'> = { protocolVersion: 'draft' };
// @ts-expect-error The old broad callback overload is removed.
void hooks.handle(request, () => ({ effects: [] }));
// @ts-expect-error Stdio consumes the same typed handlers, not a broad Request callback.
void serveStdio(() => new Response(null));
void [emptyHandlers, emptyObservers, missingReply, wrongReturn, wrongEffect, observationControl, observeInterceptControl, version];
